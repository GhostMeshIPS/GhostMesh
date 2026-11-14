"""GhostMesh IPS dashboard. Reads the logs live.py writes and refreshes every second.

Terminal 1:  streamlit run dashboard.py
Terminal 2:  python3 live.py --file test_session.jsonl --speed 5
"""
import html
import json
import os
import time
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from detect import BENCH_PATH
from explain import EVIDENCE, NODE_NAMES, OLLAMA_MODEL, display_name, top_evidence
import chat
from live import (BLOCK_SECONDS, COMMANDS_LOG, CONFIRM_WINDOWS, EVENTS_LOG, EXPLAIN_LOG, MODE_PATH,
                  STATUS_PATH, WINDOWS_LOG)

st.set_page_config(page_title="GhostMesh IPS", page_icon="👻", layout="wide")

# ---------------------------------------------------------------- look & feel
BLUE, TEAL, RED, AMBER, GREEN, GREY = "#3B5BFD", "#2CD9C5", "#FF5B6E", "#FFB547", "#05CD99", "#8F9BBA"
INK = "#E9EDF7"          # main text (light on dark)
BAR_SECONDS = 5   # each bar in the traffic chart covers this many seconds

# Plain-English names for what the model says
ATTACKS = {
    "flood":   ("Flooding",      "spamming packets far faster than a normal node"),
    "routing": ("Routing abuse", "fake TTL and extra HELLOs to pull traffic through itself"),
    "replay":  ("Replay",        "re-sending old captured packets"),
    "spoof":   ("Spoofing",      "pretending to be another node"),
    "manual":  ("Manual block",  "blocked by the operator from the dashboard"),
}
CLASS_COLORS = {"normal": BLUE, "flood": RED, "routing": AMBER, "replay": TEAL, "spoof": "#868CFF"}


st.markdown(f"""
<style>
  .block-container {{ padding-top: 2rem; max-width: 1400px; }}
  header[data-testid="stHeader"] {{ background: transparent; }}

  /* dark rounded "cards" (any container whose key starts with card) */
  [class*="st-key-card"] {{
      background: #111C44; border-radius: 20px; padding: 22px 24px;
      box-shadow: 0 18px 40px rgba(0,0,0,.35);
  }}
  .card-title {{ font-size: 1.05rem; font-weight: 700; color: {INK}; margin: 0 0 2px; }}
  .card-sub   {{ font-size: .8rem; color: {GREY}; margin-bottom: 8px; }}

  /* KPI tiles */
  .kpi {{ background:#111C44; border-radius:20px; padding:18px 20px; display:flex; gap:14px;
          align-items:center; box-shadow: 0 18px 40px rgba(0,0,0,.35); }}
  .kpi-icon {{ width:52px; height:52px; border-radius:50%; display:flex; align-items:center;
               justify-content:center; font-size:22px; flex-shrink:0; }}
  .kpi-label {{ color:{GREY}; font-size:.82rem; }}
  .kpi-value {{ color:{INK}; font-size:1.6rem; font-weight:700; line-height:1.2; }}

  /* status pills */
  .pill {{ display:inline-block; padding:3px 10px; border-radius:999px; font-size:.72rem; font-weight:700; }}
  .pill-ok      {{ background:rgba(5,205,153,.15); color:{GREEN}; }}
  .pill-attack  {{ background:rgba(255,181,71,.15); color:#FFB547; }}
  .pill-blocked {{ background:rgba(255,91,110,.15); color:{RED}; }}
  .pill-silent  {{ background:#1F2A5C; color:{GREY}; }}
  .pill-live    {{ background:rgba(5,205,153,.15); color:{GREEN}; }}

  /* transmitter rows */
  .tx {{ display:flex; align-items:center; justify-content:space-between; padding:11px 0;
         border-bottom:1px solid #1F2A5C; }}
  .tx:last-child {{ border-bottom:none; }}
  .tx-name {{ font-weight:700; color:{INK}; }}
  .tx-meta {{ font-size:.75rem; color:{GREY}; }}
  .tx-rate {{ text-align:right; font-weight:700; color:{INK}; }}

  /* activity feed */
  .ev {{ display:flex; gap:12px; padding:10px 0; border-bottom:1px solid #1F2A5C; }}
  .ev:last-child {{ border-bottom:none; }}
  .ev-dot {{ width:34px; height:34px; border-radius:10px; display:flex; align-items:center;
             justify-content:center; flex-shrink:0; font-size:16px; }}
  .ev-title {{ font-weight:700; color:{INK}; font-size:.9rem; }}
  .ev-sub {{ font-size:.75rem; color:{GREY}; }}
  .why {{ margin-top:6px; padding:6px 10px; border-radius:10px; background:#0B1437;
          font-size:.75rem; color:{GREY}; }}
  .why b {{ color:{INK}; }}
  .why.llm {{ color:{INK}; border-left:3px solid {BLUE}; line-height:1.45; }}
  .llm-src {{ font-size:.68rem; color:{GREY}; margin-top:4px; }}

  /* progress bars (rule vs AI) */
  .bar {{ height:8px; border-radius:99px; background:#1F2A5C; overflow:hidden; margin:4px 0; }}
  .bar > div {{ height:100%; border-radius:99px; }}

  /* sidebar */
  section[data-testid="stSidebar"] {{ background:#111C44; min-width:380px; }}
  [class*="st-key-card_pending"] {{ border:1px solid {RED}; box-shadow:0 0 24px rgba(255,91,110,.25); }}
  [class*="st-key-chatbox"] {{ background:#0B1437; border-radius:16px; border:none; }}
  [class*="st-key-sugg"] button, [class*="st-key-clear_chat"] button {{
      font-size:.72rem; padding:4px 8px; min-height:0; border-radius:12px;
      background:#1A2560; border:1px solid #2A3770; color:{INK}; text-align:left; }}
  .brand {{ font-size:1.5rem; font-weight:800; color:{INK}; }}
  .brand span {{ color:{BLUE}; }}
  .side-h {{ font-size:.75rem; font-weight:700; color:{GREY}; text-transform:uppercase;
             letter-spacing:.06em; margin:18px 0 6px; }}
  .side-row {{ display:flex; justify-content:space-between; font-size:.85rem; padding:3px 0; color:{INK}; }}
  .side-row b {{ color:{INK}; }}
  .legend-item {{ font-size:.8rem; color:{INK}; margin:6px 0; }}
  .legend-item small {{ color:{GREY}; display:block; margin-left:18px; }}
  .sw {{ display:inline-block; width:10px; height:10px; border-radius:3px; margin-right:8px; }}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------- helpers
def read_log(path):
    """Read a live.py log; empty table if it doesn't exist yet or is mid-write."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return pd.DataFrame()
    try:
        return pd.read_json(path, lines=True)
    except ValueError:
        return pd.DataFrame()            # caught a half-written last line; next refresh is fine


name = display_name   # "Node A", or "Unknown ·00:EE" for radios we don't recognise


def clock(wall):
    """Real clock time (Unix seconds) -> '3:42:15 PM' in this laptop's time zone."""
    return datetime.fromtimestamp(wall).strftime("%-I:%M:%S %p")


def ago(seconds):
    seconds = max(int(seconds), 0)
    return "just now" if seconds < 2 else f"{seconds} s ago" if seconds < 120 else f"{seconds // 60} min ago"


def send_command(action, mac):
    """Operator click -> data/operator_commands.jsonl. live.py applies it within ~1 second."""
    os.makedirs("data", exist_ok=True)
    with open(COMMANDS_LOG, "a") as f:
        f.write(json.dumps({"ts": time.time(), "action": action, "mac": mac}) + "\n")


def read_auto_block():
    try:
        with open(MODE_PATH) as f:
            return bool(json.load(f).get("auto_block", True))
    except (OSError, ValueError):
        return True                          # default: block automatically


def write_auto_block(value):
    os.makedirs("data", exist_ok=True)
    with open(MODE_PATH, "w") as f:
        json.dump({"auto_block": value}, f)


def read_status():
    try:
        with open(STATUS_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def kpi(icon, bg, label, value):
    return (f'<div class="kpi"><div class="kpi-icon" style="background:{bg}">{icon}</div>'
            f'<div><div class="kpi-label">{label}</div><div class="kpi-value">{value}</div></div></div>')


def time_to_block(windows, events):
    """For each BLOCK: seconds between the attacker's first flagged window and the BLOCK."""
    delays = []
    for _, b in events[events["kind"] == "BLOCK"].iterrows():
        flagged = windows[(windows["mac"] == b["mac"]) & (windows["pred"] != "normal")
                          & (windows["t"] <= b["t"]) & (windows["t"] >= b["t"] - 10)]
        if not flagged.empty:
            delays.append(b["t"] - flagged["t"].min())
    return sum(delays) / len(delays) if delays else None


def status(row, active, now):
    """One transmitter's current state -> (label, colour, css pill class)."""
    if row["mac"] in active:
        return "BLOCKED", RED, "pill-blocked"
    if now - row["t"] > 5:
        return "SILENT", GREY, "pill-silent"
    if row["pred"] != "normal":
        return ATTACKS.get(row["pred"], (row["pred"],))[0].upper(), AMBER, "pill-attack"
    return "NORMAL", GREEN, "pill-ok"


def evidence_html(features, baseline):
    """'TTL <b>10</b> (normal 1)' strings for the features that differ most from normal."""
    return [f"{label} <b>{x}</b> (normal {base})" for label, x, base in top_evidence(features, baseline)]


def badge(text, ok):
    color, bg = (GREEN, "rgba(5,205,153,.15)") if ok else (RED, "rgba(255,91,110,.15)")
    return f'<span class="pill" style="background:{bg};color:{color};margin-right:6px">{text}</span>'


# Where each node sits on the mesh map. Links come from the routing plan:
# A-B, B-C, A-D, D-C (A can't reach C directly, so A->C must hop through B or D).
MAP_POS = {"Node A": (0, 0.5), "Node B": (1, 1), "Node C": (2, 0.5), "Node D": (1, 0),
           "Watchtower": (1, 0.5)}
MESH_LINKS = [("Node A", "Node B"), ("Node B", "Node C"), ("Node A", "Node D"), ("Node D", "Node C")]


def mesh_map(latest, active, now):
    fig = go.Figure()
    pos = dict(MAP_POS)
    # Unknown transmitters (attackers, rotated MACs) get slots on the right-hand side
    unknown = [m for m in latest["mac"] if m not in NODE_NAMES]
    for i, mac in enumerate(unknown):
        pos[name(mac)] = (2.8, 0.9 - i * 0.4)

    def line(a, b, **style):
        (x0, y0), (x1, y1) = pos[a], pos[b]
        fig.add_scatter(x=[x0, x1], y=[y0, y1], mode="lines", hoverinfo="skip", showlegend=False, line=style)

    for a, b in MESH_LINKS:                                    # radio links between boards
        line(a, b, color="#3B4A8C", width=3)
    for n in list(NODE_NAMES.values()) + [name(m) for m in unknown]:   # watchtower hears everyone
        line("Watchtower", n, color="#2A3770", width=1, dash="dot")

    xs, ys, colors, labels, hovers, tags = [], [], [], [], [], []
    for _, r in latest.iterrows():
        label, color, _ = status(r, active, now)
        n = name(r["mac"])
        xs.append(pos[n][0]); ys.append(pos[n][1]); colors.append(color)
        labels.append(f"<b>{n}</b><br>{r['pkt_count']:.0f} pkt/s")
        hovers.append(f"{n} · {r['mac']}<br>{label} · {r['pkt_count']:.0f} pkt/s · {r['rssi_mean']:.0f} dBm")
        tags.append("🚫" if label == "BLOCKED" else "")
    fig.add_scatter(x=xs, y=ys, mode="markers+text", text=labels, textposition="bottom center",
                    hovertext=hovers, hoverinfo="text", showlegend=False, textfont=dict(color=INK, size=11),
                    marker=dict(size=34, color=colors, line=dict(color="#0B1437", width=3)))
    fig.add_scatter(x=xs, y=[y + 0.17 for y in ys], mode="text", text=tags, hoverinfo="skip",
                    showlegend=False, textfont=dict(size=18))
    wx, wy = pos["Watchtower"]
    fig.add_scatter(x=[wx], y=[wy], mode="markers+text", text=["<b>Watchtower</b>"], textposition="bottom center",
                    hovertext=["Watchtower: listens to every packet, sends BLOCKs"], hoverinfo="text",
                    showlegend=False, textfont=dict(color=GREY, size=11),
                    marker=dict(size=26, symbol="diamond", color=BLUE, line=dict(color="#0B1437", width=3)))
    fig.update_layout(height=330, margin=dict(l=10, r=10, t=10, b=10),
                      plot_bgcolor="#111C44", paper_bgcolor="#111C44",
                      xaxis=dict(visible=False, range=[-0.4, 3.3]), yaxis=dict(visible=False, range=[-0.35, 1.3]))
    return fig


# ---------------------------------------------------------------- sidebar: chat + about
SUGGESTIONS = ["Is the network safe right now?", "Why was the last radio blocked?",
               "What does routing abuse mean?", "What should I do if my node gets blocked?"]

with st.sidebar:
    st.markdown('<div class="brand">👻 Ghost<span>Mesh</span></div>'
                '<div class="card-sub">AI watchtower · intrusion prevention</div>', unsafe_allow_html=True)

    # ---- IPS controls: auto-block vs. confirm-click mode
    st.markdown('<div class="side-h">🛡️ IPS controls</div>', unsafe_allow_html=True)
    auto = st.toggle("Auto-block attackers", value=read_auto_block(), key="auto_block",
                     help="On: the IPS blocks confirmed attacks by itself. Off: it waits for you to click "
                          "Confirm BLOCK (confirm-click mode).")
    if auto != read_auto_block():
        write_auto_block(auto)
    st.markdown(f'<div class="tx-meta">{"The IPS blocks confirmed attacks automatically." if auto else "Confirm-click mode: you approve every BLOCK."}</div>',
                unsafe_allow_html=True)

    # ---- "Ask the watchtower" chatbot (local LLM, read-only, history auto-deleted after 24 h)
    st.markdown('<div class="side-h">💬 Ask the watchtower</div>', unsafe_allow_html=True)
    history = chat.load_history()            # re-read every run: picks up deletions older than 24 h
    box = st.container(height=430, key="chatbox")
    with box:
        if not history:
            with st.chat_message("assistant", avatar="👻"):
                st.markdown("Hi! Ask me what's happening on the mesh, what a term means, "
                            "or what to do in a situation.")
        for m in history:
            with st.chat_message(m["role"], avatar="👻" if m["role"] == "assistant" else "🧑"):
                st.markdown(m["content"])

    picked = None
    if not history:                          # suggestion chips until the first question
        s1, s2 = st.columns(2)
        for i, text in enumerate(SUGGESTIONS):
            if (s1 if i % 2 == 0 else s2).button(text, key=f"sugg{i}", width="stretch"):
                picked = text
    question = st.chat_input("Ask about the network…") or picked

    if question:
        chat.save_message("user", question)
        status_text = chat.live_status(read_log(WINDOWS_LOG), read_log(EVENTS_LOG), read_status())
        past = [{"role": m["role"], "content": m["content"]} for m in history]
        with box:
            with st.chat_message("user", avatar="🧑"):
                st.markdown(question)
            with st.chat_message("assistant", avatar="👻"):
                answer = st.write_stream(chat.ask(past, question, status_text))   # streams word by word
        chat.save_message("assistant", answer)
        st.rerun()                           # redraw with the saved history (and hide the suggestions)

    c1, c2 = st.columns([1, 1])
    c1.markdown(f'<div class="tx-meta">Local {OLLAMA_MODEL} · read-only · history deleted after 24 h</div>',
                unsafe_allow_html=True)
    if history and c2.button("Clear chat", key="clear_chat", width="stretch"):
        chat.clear_history()
        st.rerun()

    with st.expander("About this IPS"):
        st.markdown('<div class="side-h">How it decides</div>'
                    f'<div class="side-row">Model <b>Random Forest</b></div>'
                    f'<div class="side-row">Window <b>1 second</b></div>'
                    f'<div class="side-row">Confirm after <b>{CONFIRM_WINDOWS} windows</b></div>'
                    f'<div class="side-row">Block lasts <b>{BLOCK_SECONDS} s</b></div>'
                    f'<div class="side-row">Explainer <b>{OLLAMA_MODEL} (local)</b></div>'
                    '<div class="tx-meta" style="margin-top:4px">The language model only explains alerts in '
                    'plain English. It never decides who gets blocked.</div>', unsafe_allow_html=True)
        st.markdown('<div class="side-h">What it looks for</div>' + "".join(
            f'<div class="legend-item"><span class="sw" style="background:{CLASS_COLORS[k]}"></span>'
            f'<b>{title}</b><small>{desc}</small></div>' for k, (title, desc) in ATTACKS.items()
            if k in CLASS_COLORS                     # attack types only (not "manual")
        ), unsafe_allow_html=True)
        st.markdown('<div class="side-h">Privacy</div><div class="tx-meta">Metadata only: who transmits, '
                    'how often, how strongly. Message content is encrypted and never read. Traffic logs keep '
                    'the last 6 hours, chat the last 24 hours.</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------- live part (refreshes every second)
@st.fragment(run_every=1.0)
def live_view():
    windows = read_log(WINDOWS_LOG)
    events = read_log(EVENTS_LOG)

    head_l, head_r = st.columns([4, 1])
    head_l.markdown(f'<div style="font-size:.85rem;color:{GREY}">Watchtower / Overview</div>'
                    f'<div style="font-size:2rem;font-weight:800;color:{INK}">Network overview</div>',
                    unsafe_allow_html=True)
    if windows.empty:
        st.info("Waiting for data... start live.py in another terminal.")
        return

    # t    = packet timeline (used for the maths)
    # wall = real clock time of the same moment (used for everything shown on screen)
    now = windows["t"].max()
    wall_now = windows["wall"].max()
    status_info = read_status()
    if status_info.get("mode") == "replay":
        speed = status_info.get("speed", 1)
        speed_txt = "instant" if speed == 0 else f"{speed:g}×"
        badge_html = f'<span class="pill pill-attack">⏩ REPLAY {speed_txt} · {clock(wall_now)}</span>'
    else:
        badge_html = f'<span class="pill pill-live">● LIVE · {clock(wall_now)}</span>'
    head_r.markdown(f'<div style="text-align:right;padding-top:22px">{badge_html}</div>', unsafe_allow_html=True)

    # Blocks active right now = BLOCK events whose expiry is still in the future
    active, pending = set(), {}               # pending: mac -> attack waiting for the operator
    if not events.empty:
        for _, e in events.iterrows():
            if e["kind"] == "BLOCK":
                active.add(e["mac"])
                pending.pop(e["mac"], None)
            elif e["kind"] == "UNBLOCK":
                active.discard(e["mac"])
            elif e["kind"] == "PENDING":
                pending[e["mac"]] = e["attack"]
            elif e["kind"] == "DISMISS":
                pending.pop(e["mac"], None)

    # ---- KPI row
    n_attacks = 0 if events.empty else int((events["kind"] == "BLOCK").sum() + (events["kind"] == "ALERT").sum())
    ttb = None if events.empty else time_to_block(windows, events)
    k1, k2, k3, k4 = st.columns(4)
    k1.markdown(kpi("📡", "rgba(59,91,253,.20)", "Packets analysed", f"{int(windows['pkt_count'].sum()):,}"), unsafe_allow_html=True)
    k2.markdown(kpi("🛰️", "rgba(44,217,197,.15)", "Transmitters seen", windows["mac"].nunique()), unsafe_allow_html=True)
    k3.markdown(kpi("🛡️", "rgba(255,91,110,.15)", "Attacks stopped", n_attacks), unsafe_allow_html=True)
    k4.markdown(kpi("⏱️", "rgba(255,181,71,.15)", "Avg. time to block", f"{ttb:.0f} s" if ttb is not None else "–"),
                unsafe_allow_html=True)
    st.write("")

    # ---- confirm-click mode: attacks waiting for the operator's decision
    for mac, attack in pending.items():
        with st.container(key=f"card_pending_{mac.replace(':', '')}"):
            msg, b1, b2 = st.columns([4, 1, 1], vertical_alignment="center")
            title = ATTACKS.get(attack, (attack,))[0]
            msg.markdown(f'<div class="card-title">⏳ {name(mac)} looks like <span style="color:{RED}">{title}</span>'
                         f'</div><div class="card-sub">The AI detected this while Auto-block was off, so it is waiting for your decision. '
                         f'See the Activity feed for its evidence.</div>', unsafe_allow_html=True)
            if b1.button("Confirm BLOCK", key=f"confirm_{mac}", type="primary", width="stretch"):
                send_command("block", mac)
                st.toast(f"BLOCK sent for {name(mac)}")
            if b2.button("Dismiss", key=f"dismiss_{mac}", width="stretch"):
                send_command("dismiss", mac)
                st.toast(f"Alert on {name(mac)} dismissed")
        st.write("")

    # ---- traffic chart: packets per second, split by what the model said
    with st.container(key="card_traffic"):
        st.markdown('<div class="card-title">Traffic</div>'
                    '<div class="card-sub">Packets per second heard by the watchtower, coloured by what the AI '
                    'thinks each transmitter is doing</div>', unsafe_allow_html=True)
        recent = windows[windows["wall"] >= wall_now - 300].copy()      # last 5 minutes
        # Group into 5-second bars (HELLOs come every 2 s, so 1-second bars look like a barcode)
        recent["bar"] = (recent["wall"] // BAR_SECONDS * BAR_SECONDS).map(datetime.fromtimestamp)
        per_sec = recent.pivot_table(index="bar", columns="pred", values="pkt_count",
                                     aggfunc="sum", fill_value=0) / BAR_SECONDS   # -> packets per second
        fig = go.Figure()
        for cls in ["normal"] + [c for c in per_sec.columns if c != "normal"]:
            if cls in per_sec.columns:
                label = "Normal" if cls == "normal" else ATTACKS.get(cls, (cls,))[0]
                fig.add_bar(x=per_sec.index, y=per_sec[cls], name=label,
                            marker_color=CLASS_COLORS.get(cls, GREY),
                            hovertemplate=f"{label}: %{{y:.1f}} pkts/s at %{{x|%-I:%M:%S %p}}<extra></extra>")
        # shade the time each block was active
        if not events.empty:
            for _, b in events[events["kind"] == "BLOCK"].iterrows():
                end = events[(events["kind"] == "UNBLOCK") & (events["mac"] == b["mac"]) & (events["t"] > b["t"])]
                x1 = end["wall"].min() if not end.empty else wall_now
                fig.add_vrect(x0=datetime.fromtimestamp(b["wall"]), x1=datetime.fromtimestamp(x1),
                              fillcolor=RED, opacity=0.06, line_width=0,
                              annotation_text=f"🚫 {name(b['mac'])} blocked", annotation_position="top left",
                              annotation_font=dict(size=11, color=RED))
        fig.update_layout(barmode="stack", bargap=0.25, barcornerradius=3, height=320,
                          margin=dict(l=0, r=0, t=10, b=0), plot_bgcolor="#111C44", paper_bgcolor="#111C44",
                          font=dict(color=INK), legend=dict(orientation="h", y=1.12, x=1, xanchor="right"),
                          xaxis=dict(title="time", showgrid=False, tickformat="%-I:%M:%S %p"),
                          yaxis=dict(title="packets / s", gridcolor="#1F2A5C"))
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False}, key="traffic_chart")
    st.write("")

    # ---- signals: anomaly score + signal strength per radio over time
    with st.container(key="card_signals"):
        st.markdown('<div class="card-title">Signals</div>'
                    '<div class="card-sub">Per radio, last 5 minutes</div>', unsafe_allow_html=True)
        recent = windows[windows["wall"] >= wall_now - 300].copy()
        recent["time"] = recent["wall"].map(datetime.fromtimestamp)
        tab_score, tab_rssi = st.tabs(["Anomaly score", "Signal strength (RSSI)"])

        def line_chart(col, y_title, extra=None, smooth=1):
            fig = go.Figure()
            for mac, g in recent.sort_values("time").groupby("mac"):
                # Radios the AI ever flagged are drawn bold; normal ones faded, so attacks stand out
                flagged = (g["pred"] != "normal").any()
                y = g[col].rolling(smooth, min_periods=1).mean()     # smooth=5 -> 5-second average
                # Break the line where the radio went quiet (> 3 s), instead of joining the dots across the gap
                x = g["time"].tolist()
                y = y.tolist()
                gaps = [i for i in range(1, len(x)) if (x[i] - x[i - 1]).total_seconds() > 3]
                for i in reversed(gaps):
                    x.insert(i, x[i - 1])
                    y.insert(i, None)
                fig.add_scatter(x=x, y=y, mode="lines", name=name(mac), connectgaps=False,
                                line=dict(width=3 if flagged else 1.5), opacity=1 if flagged else 0.55,
                                hovertemplate=f"{name(mac)}: %{{y:.2f}} at %{{x|%-I:%M:%S %p}}<extra></extra>")
            if extra:
                extra(fig)
            fig.update_layout(height=260, margin=dict(l=0, r=0, t=10, b=0), plot_bgcolor="#111C44",
                              paper_bgcolor="#111C44", font=dict(color=INK),
                              legend=dict(orientation="h", y=1.15, x=1, xanchor="right"),
                              xaxis=dict(showgrid=False, tickformat="%-I:%M:%S %p"),
                              yaxis=dict(title=y_title, gridcolor="#1F2A5C"))
            return fig

        with tab_score:
            if "anomaly" in recent and recent["anomaly"].notna().any():
                def threshold(fig):
                    fig.add_hline(y=0, line=dict(color=RED, dash="dash", width=1),
                                  annotation_text="alarm threshold", annotation_font=dict(color=RED, size=11))
                st.plotly_chart(line_chart("anomaly", "how unusual (higher = stranger)", threshold, smooth=5),
                                width="stretch", config={"displayModeBar": False}, key="anomaly_chart")
                st.markdown('<div class="tx-meta">From the Isolation Forest, which only ever saw normal traffic (5-second average). '
                            'Above the dashed line = unlike anything it learned as normal.</div>',
                            unsafe_allow_html=True)
            else:
                st.markdown('<div class="tx-meta">No anomaly scores yet: run <code>python3 detect.py</code> '
                            'to train the Isolation Forest.</div>', unsafe_allow_html=True)
        with tab_rssi:
            st.plotly_chart(line_chart("rssi_mean", "signal (dBm, closer to 0 = stronger)"),
                            width="stretch", config={"displayModeBar": False}, key="rssi_chart")
            st.markdown('<div class="tx-meta">Each board has its own steady level, set by its distance to the '
                        'watchtower. One identity suddenly showing a different level is the sign of spoofing.'
                        '</div>', unsafe_allow_html=True)
    st.write("")

    latest = windows.sort_values("t").groupby("mac").tail(1).sort_values("mac")   # newest window per radio

    map_col, cmp_col = st.columns([1.25, 1])

    # ---- mesh map
    with map_col, st.container(key="card_map"):
        st.markdown('<div class="card-title">Mesh map</div>'
                    '<div class="card-sub">Solid lines = radio links (A can\'t reach C directly, so messages hop '
                    'via B or D). Dotted = the watchtower listening.</div>', unsafe_allow_html=True)
        st.plotly_chart(mesh_map(latest, active, now), width="stretch",
                        config={"displayModeBar": False}, key="mesh_map")

    # ---- rule vs AI
    with cmp_col, st.container(key="card_compare"):
        st.markdown('<div class="card-title">Rule vs. AI</div>'
                    '<div class="card-sub">Scored on a session none of the models trained on '
                    '(slow flood + routing abuse)</div>', unsafe_allow_html=True)
        if os.path.exists(BENCH_PATH):
            with open(BENCH_PATH) as f:
                bench = json.load(f)
            rows_html = []
            for who, s in bench.items():
                caught = s["recall"] * 100
                color = RED if caught < 50 else (AMBER if caught < 95 else GREEN)
                rows_html.append(
                    f'<div style="margin:12px 0 4px"><div class="side-row"><b>{who}</b>'
                    f'<span style="color:{color};font-weight:700">{caught:.0f}% caught</span></div>'
                    f'<div class="bar"><div style="width:{max(caught, 1.5):.0f}%;background:{color}"></div></div>'
                    f'<div class="tx-meta">alarms correct {s["precision"]:.0%} · false alarms '
                    f'{s["fpr"]:.1%} of normal traffic</div></div>')
            st.markdown("".join(rows_html), unsafe_allow_html=True)
        else:
            st.markdown('<div class="tx-meta">Run <code>python3 detect.py</code> to create the benchmark.</div>',
                        unsafe_allow_html=True)

        # Live: of the windows the AI called an attack, how many would the others have caught?
        flagged = windows[windows["pred"] != "normal"]
        if not flagged.empty:
            n = len(flagged)
            by_rule = int(flagged["rule"].fillna(False).astype(bool).sum())
            by_if = int(flagged["iforest"].fillna(False).astype(bool).sum())
            st.markdown(f'<div class="side-h">This session</div><div class="tx-meta">The Random Forest flagged '
                        f'<b style="color:{INK}">{n}</b> attack windows. The rule would have caught '
                        f'<b style="color:{RED if by_rule < n / 2 else INK}">{by_rule}</b>, the Isolation Forest '
                        f'<b style="color:{INK}">{by_if}</b>.</div>', unsafe_allow_html=True)
    st.write("")

    left, mid, right = st.columns([1.15, 0.85, 1.25])

    # ---- transmitters
    with left, st.container(key="card_tx"):
        st.markdown('<div class="card-title">Transmitters</div>'
                    '<div class="card-sub">Every radio the watchtower can hear</div>', unsafe_allow_html=True)
        for _, r in latest.iterrows():
            label, _, css = status(r, active, now)
            pill = f'<span class="pill {css}">{label}</span>'
            seen = ago(now - r["t"])
            info, btn = st.columns([3.3, 1], vertical_alignment="center")
            info.markdown(f'<div class="tx"><div><div class="tx-name">{name(r["mac"])} &nbsp;{pill}</div>'
                          f'<div class="tx-meta">{r["mac"]} · {r["pkt_count"]:.0f} pkts/s · '
                          f'{r["rssi_mean"]:.0f} dBm · seen {seen}</div></div></div>', unsafe_allow_html=True)
            # Manual override: the operator can always block or lift a block by hand
            if r["mac"] in active:
                if btn.button("Unblock", key=f"unblock_{r['mac']}", width="stretch"):
                    send_command("unblock", r["mac"])
                    st.toast(f"Unblocking {name(r['mac'])}")
            elif btn.button("Block", key=f"block_{r['mac']}", width="stretch"):
                send_command("block", r["mac"])
                st.toast(f"BLOCK sent for {name(r['mac'])}")

    # ---- traffic mix donut
    with mid, st.container(key="card_mix"):
        st.markdown('<div class="card-title">Traffic mix</div>'
                    '<div class="card-sub">Share of 1-second windows by verdict</div>', unsafe_allow_html=True)
        mix = windows["pred"].value_counts()
        normal_pct = 100 * mix.get("normal", 0) / mix.sum()
        donut = go.Figure(go.Pie(
            labels=["Normal" if c == "normal" else ATTACKS.get(c, (c,))[0] for c in mix.index],
            values=mix.values, hole=0.72, sort=False,
            marker=dict(colors=[CLASS_COLORS.get(c, GREY) for c in mix.index]),
            textinfo="none", hovertemplate="%{label}: %{value} windows<extra></extra>"))
        donut.update_layout(height=250, margin=dict(l=0, r=0, t=0, b=0), paper_bgcolor="#111C44",
                            legend=dict(orientation="h", y=-0.05), font=dict(color=INK),
                            annotations=[dict(text=f"<b style='font-size:26px'>{normal_pct:.0f}%</b><br>"
                                              f"<span style='color:{GREY}'>normal</span>",
                                              showarrow=False, font=dict(color=INK))])
        st.plotly_chart(donut, width="stretch", config={"displayModeBar": False}, key="mix_chart")

    # ---- activity feed in plain English
    with right, st.container(key="card_events"):
        st.markdown('<div class="card-title">Activity</div>'
                    '<div class="card-sub">What the IPS did, newest first</div>', unsafe_allow_html=True)
        if events.empty:
            st.markdown('<div class="tx-meta">All quiet. No attacks detected yet.</div>', unsafe_allow_html=True)
        else:
            # "Normal" reference values = median of every window the AI called normal
            baseline = windows[windows["pred"] == "normal"][list(EVIDENCE)].median().to_dict()

            # LLM summaries arrive a few seconds after their event; match them by (time, mac)
            explanations = read_log(EXPLAIN_LOG)
            summaries = {} if explanations.empty else {
                (round(r["event_t"], 3), r["mac"]): (r["text"], r["source"]) for _, r in explanations.iterrows()}

            def why_html(e):
                """LLM summary (or the evidence line) + detector badges for a BLOCK/ALERT event."""
                ev = e.get("evidence")
                if not isinstance(ev, dict):
                    return ""
                badges = badge(f"AI {ev['conf']:.0%} sure", ev["conf"] >= 0.8)
                badges += badge("Rule: caught" if ev["rule_caught"] else "Rule: missed", ev["rule_caught"])
                if ev.get("iforest_caught") is not None:
                    badges += badge("Isolation Forest: " + ("caught" if ev["iforest_caught"] else "missed"),
                                    ev["iforest_caught"])

                summary = summaries.get((round(e["t"], 3), e["mac"]))
                if summary and summary[1] not in ("template", "error"):
                    # Written by the local LLM. Escaped, since it's model output, not our own HTML.
                    box = (f'<div class="why llm">🤖 {html.escape(summary[0])}'
                           f'<div class="llm-src">explained by {html.escape(summary[1])} · running locally</div></div>')
                else:
                    reasons = " · ".join(evidence_html(ev["features"], baseline))
                    box = f'<div class="why">Why: {reasons}</div>' if reasons else ""
                    if summary is None:
                        box += '<div class="llm-src">🤖 writing explanation…</div>'
                return box + f'<div style="margin-top:6px">{badges}</div>'

            items = []
            for _, e in events.sort_values("t", ascending=False).head(8).iterrows():
                when = f"{clock(e['wall'])} ({ago(wall_now - e['wall'])})"
                if e["kind"] == "BLOCK":
                    title, why = ATTACKS.get(e["attack"], (e["attack"], ""))
                    by_you = " (by you)" if "operator" in str(e["note"]) and e["attack"] != "manual" else ""
                    items.append(("🚫", "rgba(255,91,110,.15)", f"Blocked {name(e['mac'])}: {title}{by_you}",
                                  f"{when} · {why}. BLOCK sent to watchtower for {BLOCK_SECONDS} s." + why_html(e)))
                elif e["kind"] == "UNBLOCK" and "operator" in str(e["note"]):
                    items.append(("🔓", "#1F2A5C", f"{name(e['mac'])} unblocked by you", f"{when} · manual override"))
                elif e["kind"] == "UNBLOCK":
                    items.append(("🔓", "#1F2A5C", f"Block on {name(e['mac'])} expired",
                                  f"{when} · blocks are temporary, so a wrongly blocked node is never cut off for good"))
                elif e["kind"] == "PENDING":
                    title, why = ATTACKS.get(e["attack"], (e["attack"], ""))
                    items.append(("⏳", "rgba(255,181,71,.15)", f"Waiting for you: {name(e['mac'])}, {title}",
                                  f"{when} · {why}. Auto-block is off, so the IPS asked before blocking."
                                  + why_html(e)))
                elif e["kind"] == "DISMISS":
                    items.append(("✋", "#1F2A5C", f"You dismissed the alert on {name(e['mac'])}",
                                  f"{when} · no BLOCK sent; the IPS won't ask again until this attack stops"))
                else:
                    title, why = ATTACKS.get(e["attack"], (e["attack"], ""))
                    items.append(("⚠️", "rgba(255,181,71,.15)", f"Alert: {name(e['mac'])}, {title}",
                                  f"{when} · {e['note']}" + why_html(e)))
            st.markdown("".join(
                f'<div class="ev"><div class="ev-dot" style="background:{bg}">{icon}</div>'
                f'<div><div class="ev-title">{t}</div><div class="ev-sub">{s}</div></div></div>'
                for icon, bg, t, s in items), unsafe_allow_html=True)


live_view()
