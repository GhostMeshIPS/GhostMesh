"""'Ask the watchtower': a local chatbot that answers questions about the IPS.

Rules (same spirit as explain.py):
  * READ-ONLY: it can explain and advise, but it can't block, unblock or change anything.
  * Grounded: it gets the live state, a glossary and a playbook we wrote. For "what should I do"
    questions it must stick to the playbook and say "I don't know" otherwise, because a small
    model will confidently invent advice if you let it.
  * Local: everything goes to Ollama on this laptop. Never message content, never raw packet text.
  * Chat history is saved to data/chat_history.jsonl and auto-deleted after 24 hours.
"""
import json
import os
import time
import urllib.request
from datetime import datetime

from explain import ATTACK_TEXT, OLLAMA_MODEL, display_name, top_evidence
from retention import CHAT_MAX_AGE_S, prune_jsonl

CHAT_URL = os.environ.get("OLLAMA_CHAT_URL", "http://localhost:11434/api/chat")
CHAT_LOG = "data/chat_history.jsonl"
HISTORY_TURNS = 6          # how many recent messages the model sees (keeps prompts small and fast)

GLOSSARY = """\
- Mesh network: radios (nodes A, B, C, D) that pass messages along for each other, no internet needed.
- Watchtower: a listening radio wired to this laptop. It hears every packet and sends BLOCK commands.
- Packet: one radio message. The IPS only reads its metadata (who sent it, when, how strong), never its content.
- HELLO: a "I'm here" beacon each node sends about every 2 seconds so neighbours know it exists.
- TTL (time to live): how many more hops a message may travel. Honest HELLOs use 1.
- Hop count: how many relays a message has already passed through.
- RSSI / signal: how strong a radio sounds at the watchtower, in dBm. The values are negative: -45 dBm is a STRONG signal (radio is close), -75 dBm is a WEAK signal (radio is far). Closer to zero = stronger.
- Window: the IPS judges each radio once per 1-second slice of time.
- Random Forest: the AI model that decides normal / flooding / routing abuse / replay / spoofing.
- Confidence: the share of the Random Forest's 100 decision trees that agreed.
- Rule baseline: a simple "more than 15 packets per second = attack" check, shown for comparison.
- Isolation Forest: a second AI model that flags anything unusual without knowing attack types.
- BLOCK: a signed command telling every node to ignore a radio for 60 seconds. Blocks expire on purpose.
- MAC rotation: radios change their hardware address every 60 seconds for privacy.
- Flooding: a radio sending packets far faster than normal to drown out the mesh.
- Routing abuse: a radio advertising fake routes (fake TTL, extra HELLOs) so messages flow through it.
- Replay: a radio re-sending old captured packets.
- Spoofing: a radio pretending to be another node. Only an alert, because blocking that identity would also cut off the real node."""

PLAYBOOK = """\
- An unknown radio is flooding or doing routing abuse: nothing to do, the IPS blocks it automatically within ~2 seconds. If it keeps attacking after the 60-second block expires, it is blocked again. To find the device physically, a stronger signal (RSSI closer to 0) means it is closer to the watchtower.
- One of our own nodes (A, B, C or D) was blocked: it could be a false alarm or a faulty/compromised board. Wait 60 seconds for the block to expire. If it is blocked again, unplug that node and check it (firmware bug causing rapid resends, or tampering). The mesh reroutes around it automatically.
- Spoofing alert: the IPS deliberately does NOT block, because that would also cut off the real node. Confirm with the real node's owner in person, and watch whether its signal strength suddenly jumps.
- Replay attack: replayed packets are still encrypted, so the attacker cannot read them. Nodes ignore duplicates. The IPS blocks the replaying radio.
- A node shows SILENT: it stopped transmitting. Usually unplugged, out of range or out of battery. Messages reroute through the other nodes (e.g. A to C via D instead of B) within about 10 seconds.
- A message did not arrive (no double tick): the sender retries automatically 3 times (after 1, 2 and 4 seconds). If it still fails, check that a path exists on the mesh map, then resend.
- Is the network safe right now: it is safe if there are no active blocks or attacking radios in the live status.
- Want to block or unblock a radio by hand: use the Block / Unblock button next to it in the Transmitters list. Blocks also expire on their own after 60 seconds.
- An attack is waiting for confirmation (auto-block is off): read its evidence in the Activity feed, then click Confirm BLOCK, or Dismiss if it's a false alarm. Turn "Auto-block attackers" back on in the sidebar to let the IPS block by itself.
- Change thresholds or retrain the models: not possible from this chat. That has to be done in the code."""

SYSTEM = f"""You are the GhostMesh watchtower assistant, built into the IPS dashboard of an encrypted,
off-grid mesh network. Answer questions about what the dashboard shows, what terms mean, and what
the user can do.

Rules:
- Be brief: 1-4 short sentences, plain everyday language. No headings.
- For "what does X mean" questions, use the glossary.
- For "what should I do" questions, ONLY give advice that is in the playbook. If the playbook does not
  cover it, say you're not sure and suggest asking the team.
- For questions about what is happening, use ONLY the live status below. Never invent attacks, nodes,
  numbers or times. If something isn't in the live status, say you don't see it.
- When you mention evidence, copy the evidence phrases word for word (including HIGHER/LOWER, written
  in lowercase). Never compare numbers yourself. Each block is for ONE attack type; don't merge them.
- You cannot block, unblock or change anything. You only explain.
- You never see message content (it is encrypted), only traffic patterns.

Glossary:
{GLOSSARY}

Playbook:
{PLAYBOOK}"""


# ---------------------------------------------------------------- live status for the model
def clock(wall):
    return datetime.fromtimestamp(wall).strftime("%-I:%M:%S %p")


def live_status(windows, events, status=None):
    """A short plain-text summary of what the IPS sees right now (built from OUR logs only)."""
    if windows is None or windows.empty:
        return "No traffic data yet: the IPS is not running."
    now = windows["wall"].max()
    lines = [f"Current time: {clock(now)}."]
    if status:
        lines.append("Data source: " + ("live watchtower" if status.get("mode") == "watchtower"
                                        else f"replay of a recorded session at {status.get('speed')}x speed") + ".")

    active = set()
    if events is not None and not events.empty:
        for _, e in events.sort_values("wall").iterrows():
            if e["kind"] == "BLOCK":
                active.add(e["mac"])
            elif e["kind"] == "UNBLOCK":
                active.discard(e["mac"])

    lines.append("Radios heard:")
    latest = windows.sort_values("wall").groupby("mac").tail(1)
    for _, r in latest.iterrows():
        ago = now - r["wall"]
        state = ("BLOCKED" if r["mac"] in active else "silent" if ago > 5
                 else r["pred"] if r["pred"] != "normal" else "normal")
        lines.append(f"- {display_name(r['mac'])}: {state}, {r['pkt_count']:.0f} packets/s, "
                     f"signal {r['rssi_mean']:.0f} dBm, last heard {ago:.0f} s ago.")
    lines.append(f"Active blocks: {', '.join(display_name(m) for m in active) or 'none'}.")
    pending = {}
    if events is not None and not events.empty:
        for _, e in events.sort_values("wall").iterrows():
            if e["kind"] == "PENDING":
                pending[e["mac"]] = e["attack"]
            elif e["kind"] in ("BLOCK", "DISMISS"):
                pending.pop(e["mac"], None)
    if pending:
        lines.append("Waiting for the operator to click Confirm BLOCK or Dismiss (auto-block is off): "
                     + ", ".join(f"{display_name(m)} ({a})" for m, a in pending.items()) + ".")
    # Pre-sorted rankings, because the model compares numbers badly (especially negative dBm)
    by_signal = latest.sort_values("rssi_mean", ascending=False)
    lines.append("Signal strength ranking, STRONGEST first: "
                 + ", ".join(f"{display_name(m)} ({v:.0f} dBm)" for m, v in zip(by_signal["mac"], by_signal["rssi_mean"])) + ".")
    by_rate = latest.sort_values("pkt_count", ascending=False)
    lines.append("Packet rate ranking, BUSIEST first: "
                 + ", ".join(f"{display_name(m)} ({v:.0f}/s)" for m, v in zip(by_rate["mac"], by_rate["pkt_count"])) + ".")

    if events is not None and not events.empty:
        baseline = windows[windows["pred"] == "normal"][["pkt_count", "hello_count", "ttl_max", "hop_min",
                                                         "gap_mean", "link_fail"]].median().to_dict()
        # Small models struggle to work out "which is newest", so spell it out
        blocks = events[events["kind"].isin(["BLOCK", "ALERT"])].sort_values("wall")
        if not blocks.empty:
            for label, b in (("FIRST", blocks.iloc[0]), ("MOST RECENT", blocks.iloc[-1])):
                lines.append(f"{label} block/alert: {b['kind']} {display_name(b['mac'])} at {clock(b['wall'])} "
                             f"for {ATTACK_TEXT.get(b['attack'], b['attack']).split(':')[0]}.")
            lines.append(f"Total blocks/alerts so far: {len(blocks)}.")
        lines.append("Recent IPS actions (NEWEST FIRST):")
        for _, e in events.sort_values("wall", ascending=False).head(6).iterrows():
            who = display_name(e["mac"])
            if e["kind"] == "UNBLOCK":
                lines.append(f"- {clock(e['wall'])}: block on {who} expired.")
                continue
            ev = e.get("evidence") if isinstance(e.get("evidence"), dict) else None
            text = f"- {clock(e['wall'])}: {e['kind']} {who} for {ATTACK_TEXT.get(e['attack'], e['attack'])}."
            if ev:
                # Spell out higher/lower here: the model copies phrases well but compares numbers badly
                proof = "; ".join(
                    f"{l} was {x}, {'HIGHER' if float(x.split()[0]) > float(b.split()[0]) else 'LOWER'} "
                    f"than the normal {b}" for l, x, b in top_evidence(ev["features"], baseline))
                text += (f" Evidence: {proof}. AI {ev['conf']:.0%} sure. Rule baseline "
                         f"{'caught' if ev['rule_caught'] else 'missed'} it.")
            lines.append(text)
    else:
        lines.append("No attacks detected so far.")
    return "\n".join(lines)


# ---------------------------------------------------------------- talking to the model
def ask(history, question, status_text):
    """Stream the answer, piece by piece. `history` = earlier [{"role", "content"}] messages."""
    messages = ([{"role": "system", "content": SYSTEM},
                 {"role": "system", "content": "Live status:\n" + status_text}]
                + history[-HISTORY_TURNS:]
                + [{"role": "user", "content": question}])
    body = json.dumps({"model": OLLAMA_MODEL, "messages": messages, "stream": True,
                       "options": {"temperature": 0.1, "num_ctx": 8192}}).encode()   # low = sticks to facts
    req = urllib.request.Request(CHAT_URL, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            for line in resp:                         # Ollama streams one JSON object per line
                chunk = json.loads(line)
                yield chunk.get("message", {}).get("content", "")
                if chunk.get("done"):
                    break
    except Exception:
        yield ("I can't reach the local language model. Open the Ollama app (llama icon in the menu bar) "
               "and try again. The IPS itself keeps working without it.")


# ---------------------------------------------------------------- history with 24 h auto-delete
def load_history():
    os.makedirs("data", exist_ok=True)
    prune_jsonl(CHAT_LOG, "ts", CHAT_MAX_AGE_S, now=time.time())     # forget anything older than 24 h
    if not os.path.exists(CHAT_LOG):
        return []
    with open(CHAT_LOG) as f:
        return [json.loads(line) for line in f if line.strip()]


def save_message(role, content):
    with open(CHAT_LOG, "a") as f:
        f.write(json.dumps({"ts": time.time(), "role": role, "content": content}) + "\n")


def clear_history():
    open(CHAT_LOG, "w").close()


if __name__ == "__main__":
    # Quick test from the terminal: python3 chat.py "why was the unknown radio blocked?"
    import sys
    import pandas as pd
    w = pd.read_json("data/live_windows.jsonl", lines=True)
    e = pd.read_json("data/live_events.jsonl", lines=True)
    status_text = live_status(w, e)
    question = " ".join(sys.argv[1:]) or "Is the network safe right now?"
    print(status_text, "\n\nQ:", question, "\nA: ", end="")
    for piece in ask([], question, status_text):
        print(piece, end="", flush=True)
    print()
