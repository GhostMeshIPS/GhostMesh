"""Generate the GhostMesh security map: two SVGs plus a standalone HTML page.

    python docs/diagrams/make_diagrams.py                 # writes docs/diagrams/*.svg + security-map.html
    python docs/diagrams/make_diagrams.py page.html       # also writes an HTML fragment (for publishing)

Figure 1: keys, flows and CIA protections. Figure 2: the same testbed with weak points marked.
Edit WEAK_RAW (below) and the text in base() when the threat model changes, then rerun.
Sources: security/threat-model.md, docs/decisions.md section 4.7.
"""
import sys, pathlib
from html import escape as esc

REPO = pathlib.Path(__file__).resolve().parents[2]
FRAGMENT = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None
UPDATED = "Nov 20"

BG, PANEL, LINE, INK, MUTED, REGION = "#f4f6fa", "#ffffff", "#c9d1de", "#172033", "#5b6678", "#e8edf6"
NODE, WT, XS = "#39507a", "#8a5a00", "#7a2e2e"
C, I, A, RED = "#2563c9", "#b26a00", "#1f8a52", "#e11d2e"
SANS = "Inter, 'Segoe UI', Arial, sans-serif"
MONO = "'JetBrains Mono', Consolas, monospace"


def t(x, y, s, size=12, fill=INK, weight=400, anchor="start", family=SANS, extra=""):
    return (f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" fill="{fill}" '
            f'font-weight="{weight}" text-anchor="{anchor}" {extra}>{esc(s)}</text>')


def box(x, y, w, h, stroke=LINE, fill=PANEL, dash="", r=10, sw=1.5):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>'


def chip(x, y, letter):
    col = {"C": C, "I": I, "A": A}[letter]
    return (f'<circle cx="{x}" cy="{y}" r="9" fill="{col}"/>'
            + t(x, y + 4, letter, 11, "#ffffff", 700, "middle"))


def node(x, y, title, k1, k2, stroke=NODE, dash="", fill=PANEL):
    return (box(x, y, 150, 74, stroke, fill, dash, 10, 2)
            + t(x + 12, y + 22, title, 13, INK, 700)
            + t(x + 12, y + 42, k1, 10.5, MUTED, 400, family=MONO)
            + t(x + 12, y + 58, k2, 10.5, MUTED, 400, family=MONO))


def base(p, title, subtitle, height):
    """p = id prefix so two SVGs can sit in one page."""
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 {height}" role="img" '
         f'aria-label="{esc(title)}. {esc(subtitle)}">',
         f'<defs><marker id="{p}ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
         f'<path d="M0,0 L10,5 L0,10 z" fill="{INK}"/></marker>'
         f'<marker id="{p}arx" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
         f'<path d="M0,0 L10,5 L0,10 z" fill="{XS}"/></marker></defs>',
         f'<rect width="1280" height="{height}" fill="{BG}"/>',
         t(30, 44, title, 22, INK, 700, family="'Space Grotesk', " + SANS),
         t(30, 68, subtitle, 13, MUTED)]
    ar, arx = f'marker-end="url(#{p}ar)"', f'marker-end="url(#{p}arx)"'
    both = f'marker-start="url(#{p}ar)" marker-end="url(#{p}ar)"'

    # left column
    o += [box(30, 90, 240, 118),
          t(46, 116, "Provisioning laptop", 13, INK, 700),
          t(46, 138, "keygen.py · OS randomness", 12, MUTED),
          t(46, 158, "roster.json: public fingerprints", 12, MUTED),
          t(46, 178, "offline, used once per board", 12, MUTED),
          chip(250, 154, "I"),
          box(30, 256, 240, 74),
          t(46, 282, "Chat laptop (A's owner)", 13, INK, 700),
          t(46, 304, "serial JSON: send / rx text", 12, MUTED),
          box(30, 400, 240, 170),
          t(46, 426, "How to read this", 13, INK, 700),
          chip(52, 450, "C"), t(68, 454, "Confidentiality: who can read", 12, INK),
          chip(52, 474, "I"), t(68, 478, "Integrity: who can change or forge", 12, INK),
          chip(52, 498, "A"), t(68, 502, "Availability: keeps delivering", 12, INK),
          t(46, 530, "Key names on each board:", 12, INK, 600),
          t(46, 550, "net · ps_N · sk_N · pks · W pk", 11, MUTED, family=MONO)]
    o.append(f'<path d="M270,150 L344,150" stroke="{INK}" stroke-width="1.5" stroke-dasharray="5 4" fill="none" {ar}/>')
    o.append(t(307, 140, "flash keys", 10.5, MUTED, 400, "middle"))
    o.append(f'<path d="M272,293 L378,293" stroke="{INK}" stroke-width="1.5" fill="none" {both}/>')
    o.append(t(325, 284, "USB", 10.5, MUTED, 400, "middle"))

    # radio region
    o += [box(350, 90, 610, 480, "#b8c3d6", REGION, "", 16, 1.5)]
    # e2e arc
    o.append(f'<path d="M455,256 C455,60 855,60 855,256" stroke="{C}" stroke-width="2.5" fill="none" stroke-dasharray="8 5" {both.replace(p + "ar", p + "arc")}/>')
    o[1] = o[1].replace("</defs>", f'<marker id="{p}arc" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{C}"/></marker></defs>')
    o.append(t(655, 100, "end-to-end: pair key ck[e] (epoch DH ratchet) + XChaCha20-Poly1305", 12, C, 600, "middle"))
    o += [chip(884, 96, "C"), chip(904, 96, "I")]
    # radio links
    for x1, y1, x2, y2, dash in [(530, 276, 580, 210, ""), (730, 210, 780, 276, ""),
                                 (530, 312, 580, 380, "6 4"), (730, 380, 780, 312, "6 4")]:
        d = f' stroke-dasharray="{dash}"' if dash else ""
        o.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{NODE}" stroke-width="2"{d}/>')
    o += [t(655, 282, "DATA / ACK frames", 12, INK, 700, "middle"),
          chip(724, 278, "I"), chip(744, 278, "A"),
          t(655, 299, "link_tag re-made at each hop", 11, MUTED, 400, "middle"),
          t(655, 315, "flooded, k-suppression", 11, MUTED, 400, "middle"),
          t(655, 438, "backup path via D", 11, MUTED, 400, "middle")]
    # nodes
    o += [node(380, 256, "A · sender", "net · ps_A · sk_A", "pks · W pk"),
          node(580, 166, "B · main relay", "net · ps_B · sk_B", "pks · W pk"),
          node(780, 256, "C · receiver", "net · ps_C · sk_C", "pks · W pk"),
          node(580, 346, "D · backup relay", "net · ps_D · sk_D", "pks · W pk"),
          node(380, 446, "X · insider attacker", "net · ps_X · sk_X", "pks · W pk", XS, "6 4"),
          node(780, 446, "W · watchtower", "net · every ps_*", "Ed25519 sk · no sk_*", WT, "", "#fff8ea")]
    # X insider arrow
    o.append(f'<path d="M400,446 L400,334" stroke="{XS}" stroke-width="1.8" stroke-dasharray="6 4" fill="none" {arx}/>')
    o += [t(412, 380, "holds network_key:", 11, XS, 600),
          t(412, 396, "can flood, spoof, forge hops", 11, XS)]
    # W CTRL + listening
    o.append(f'<path d="M780,458 L734,422" stroke="{WT}" stroke-width="2" fill="none" {ar}/>')
    o += [t(655, 470, "W → all: CTRL (TIME 10 s, BLOCK)", 11, WT, 700, "middle"),
          t(655, 486, "Ed25519-signed, relayed once verified", 11, MUTED, 400, "middle"),
          t(655, 508, "W ← all: hears every frame", 11, MUTED, 400, "middle"),
          chip(748, 504, "I")]
    for r in (14, 22, 30):
        o.append(f'<path d="M{855 - r},446 A{r},{r} 0 0 1 {855 + r},446" stroke="{WT}" stroke-width="1.2" fill="none" stroke-dasharray="2 3" transform="translate(0,-2)"/>')
    # footer of region
    o += [t(366, 536, "ESP-NOW broadcast · one Wi-Fi channel · every frame 240 B", 11.5, INK, 600),
          t(366, 551, "metal shielding keeps A and C out of range, so multi-hop is real", 11, MUTED),
          t(366, 565, "KEYS flooded ~10 s · HELLO off · pseudonym + MAC rotate every 60 s", 11, MUTED),
          chip(866, 561, "C")]

    # right column
    o += [box(1020, 90, 230, 140),
          t(1036, 116, "Keys", 13, INK, 700),
          t(1036, 138, "net   network_key (all boards)", 11, MUTED, family=MONO),
          t(1036, 156, "ps_N  pseudonym + MAC secret", 11, MUTED, family=MONO),
          t(1036, 174, "sk_N  X25519 static secret", 11, MUTED, family=MONO),
          t(1036, 192, "pks   peers' public keys", 11, MUTED, family=MONO),
          t(1036, 210, "W pk  watchtower's signing pk", 11, MUTED, family=MONO),
          box(1020, 256, 230, 74),
          t(1036, 282, "Chat laptop (C's owner)", 13, INK, 700),
          t(1036, 304, "serial JSON: rx text, ✓✓", 12, MUTED),
          box(1020, 342, 230, 74, C, PANEL, "5 4"),
          t(1036, 366, "Sniffer view (Wireshark)", 13, INK, 700), chip(1232, 362, "C"),
          t(1036, 386, "gm_pcap.py + ghostmesh.lua", 11, MUTED, family=MONO),
          t(1036, 404, "header + ciphertext only, no keys", 12, MUTED),
          box(1020, 430, 230, 120),
          t(1036, 456, "IPS laptop", 13, INK, 700), chip(1124, 452, "A"),
          t(1036, 478, "features → rules + ML", 12, MUTED),
          t(1036, 498, "decides BLOCKs, sets the clock", 12, MUTED),
          t(1036, 518, "spoof → alert only (O9)", 12, MUTED),
          t(1036, 538, "live logs auto-delete", 12, MUTED)]
    o.append(f'<path d="M932,293 L1018,293" stroke="{INK}" stroke-width="1.5" fill="none" {both}/>')
    o.append(t(975, 284, "USB", 10.5, MUTED, 400, "middle"))
    o.append(f'<path d="M932,466 L1018,466" stroke="{INK}" stroke-width="1.5" fill="none" {ar}/>')
    o.append(f'<path d="M1018,500 L932,500" stroke="{INK}" stroke-width="1.5" fill="none" {ar}/>')
    o.append(f'<path d="M1135,430 L1135,418" stroke="{C}" stroke-width="1.5" fill="none" {ar}/>')
    o += [t(975, 458, "frame logs", 10.5, MUTED, 400, "middle"),
          t(975, 518, "block, time", 10.5, MUTED, 400, "middle")]

    # CIA panel
    cols = [("Confidentiality: who can read", C, [
                "Pair keys from an epoch DH ratchet (FS + healing)",
                "XChaCha20-Poly1305; hidden ACKs; fixed 240 B",
                "No destination in header; hop padding; ACK delay",
                "Pseudonym + MAC rotate together every 60 s",
                "Watchtower maps IDs but holds no X25519 keys"]),
            ("Integrity: who can change or forge", I, [
                "link_tag over every byte, checked first",
                "AEAD tag, header fields bound as AD",
                "TIME/BLOCK Ed25519-signed; only verified relayed",
                "Replay: caches, ±1 epoch, 5 s freshness, seq set",
                "Boot fingerprints checked against roster.json"]),
            ("Availability: keeps delivering", A, [
                "Flooding with k-suppression; backup path via D",
                "Retries at 1/2/4 s, new msg_id each attempt",
                "Insert ~20/s per sender; only failed CTRL verifies cost",
                "IPS detects in ≤ 5 s; BLOCK by node or pseudo+MAC",
                "Free-running clock; no_beacon / no_dh alerts"])]
    for i, (head, col, items) in enumerate(cols):
        x = 30 + i * 412
        o += [box(x, 600, 396, 196), f'<rect x="{x}" y="600" width="396" height="6" rx="3" fill="{col}"/>',
              chip(x + 22, 630, head[0]), t(x + 40, 635, head, 13.5, col, 700)]
        for j, s in enumerate(items):
            o += [f'<circle cx="{x + 22}" cy="{660 + j * 26}" r="2.5" fill="{col}"/>', t(x + 34, 664 + j * 26, s, 12, INK)]
    return o


def marker(cx, cy, n, open_):
    fill, fg = (RED, "#ffffff") if open_ else ("#ffffff", RED)
    return (f'<circle cx="{cx}" cy="{cy}" r="12" fill="{fill}" stroke="{RED}" stroke-width="2.5"/>'
            + t(cx, cy + 5.5, "!", 16, fg, 800, "middle")
            + t(cx + 14, cy - 8, str(n), 11, RED, 800, "start",
                extra=f'stroke="{BG}" stroke-width="3" paint-order="stroke"'))


# (x, y, open?, text) — open items first
WEAK_RAW = [
    (370, 420, True, "Insider frames reach every parser; KEYS relayed before anyone checks them (O24)"),
    (975, 546, False, "Opening W's serial port can reset W; laptop tools now re-send the clock (Nov 19 fix)"),
    (926, 446, False, "Watchtower: locatable single point of failure; blocks lapse ~2 min without it (16c)"),
    (782, 520, False, "Boards that reboot while the watchtower is down stay mute until it returns (16b)"),
    (975, 483, False, "Watchtower → IPS log caps at ~120 frames/s; demo floods kept below it (16e)"),
    (1246, 434, False, "Low-and-slow evasion, baseline drift (16f); full spoof can mislead the operator (O9)"),
    (266, 94, False, "Provisioning laptop is the root of trust and holds every key (O16, out of scope)"),
    (726, 170, False, "Keys sit unencrypted in every board's flash; a seized board gives up its keys (O15)"),
    (526, 450, False, "One shared network_key: any captured board is an insider everywhere (O14)"),
    (726, 350, False, "If W ever runs on relay D, D holds W's secrets (O21); a dedicated W board is planned"),
    (315, 312, False, "Serial ports are unauthenticated; physical access means compromise (O16)"),
    (956, 94, False, "One fixed channel: jamming and junk floods are detected, not stopped (O17)"),
    (555, 240, False, "Timing and RSSI can reveal originators and track static boards (O1–O3)"),
    (906, 546, False, "All boards rotate at the same public moment (MAC swap ~5.5 ms); attacks can be timed to it"),
    (944, 558, False, "KEYS/CTRL can be jammed selectively (O18, O19); KEYS show the key graph (O23)"),
    (497, 162, False, "Stolen static key + forged KEYS frames takes over that board's pairs (A4, 10d)"),
]

WEAK = [w for w in WEAK_RAW if w[2]] + [w for w in WEAK_RAW if not w[2]]

T1 = f"GhostMesh testbed: keys, flows and protections ({UPDATED})"
S1 = "Which keys each board holds, what crosses each link, and how confidentiality, integrity and availability are kept"
T2 = f"GhostMesh testbed: weak points and attack surfaces ({UPDATED})"
S2 = "Same testbed. Red marks are where an attacker, a censor or a failure can hurt the mesh (threat-model.md §6–8)"

svg1 = "\n".join(base("k", T1, S1, 820) + ["</svg>"])

o = base("w", T2, S2, 1130)
for n, (x, y, op, _) in enumerate(WEAK, 1):
    o.append(marker(x, y, n, op))
o += [box(30, 826, 1220, 280),
      t(46, 856, "Weak points", 15, INK, 700, family="'Space Grotesk', " + SANS),
      f'<circle cx="190" cy="851" r="8" fill="{RED}"/>', t(204, 855, "open: needs a decision or a fix", 12, MUTED),
      f'<circle cx="420" cy="851" r="8" fill="#ffffff" stroke="{RED}" stroke-width="2"/>',
      t(434, 855, "accepted and documented, or out of scope", 12, MUTED)]
for n, (_, _, op, s) in enumerate(WEAK, 1):
    col, row = divmod(n - 1, 9)
    x, y = 46 + col * 620, 886 + row * 23
    o += [t(x, y, f"{n}", 12, RED, 800), t(x + 24, y, s, 11.5, INK if op else MUTED, 600 if op else 400)]
svg2 = "\n".join(o + ["</svg>"])

out = REPO / "docs" / "diagrams"
out.mkdir(parents=True, exist_ok=True)
(out / "testbed-keyflow.svg").write_text(svg1, encoding="utf-8")
(out / "testbed-weakpoints.svg").write_text(svg2, encoding="utf-8")

_p3 = out / "packet-anatomy.svg"
svg3 = _p3.read_text(encoding="utf-8") if _p3.exists() else "<p>Run make_packet_diagram.py first.</p>"

STYLE = f"""<style>
/* layout: two stacked full-width figures, each in its own horizontal scroller */
:root {{ --bg: {BG}; --ink: {INK}; --muted: {MUTED}; --line: {LINE}; --red: {RED};
  --display: 'Space Grotesk', Inter, 'Segoe UI', Arial, sans-serif; --body: Inter, 'Segoe UI', Arial, sans-serif; color-scheme: light; }}
body {{ background: var(--bg); color: var(--ink); font-family: var(--body); line-height: 1.5; margin: 0;
  padding-left: max(16px, env(safe-area-inset-left, 0px)); padding-right: max(16px, env(safe-area-inset-right, 0px)); padding-block: 32px 48px; }}
main {{ max-width: 1320px; margin: 0 auto; display: grid; gap: 40px; }}
header h1 {{ font-family: var(--display); font-size: 1.9rem; margin: 0 0 6px; text-wrap: balance; }}
header p {{ margin: 0; color: var(--muted); max-width: 75ch; }}
figure {{ margin: 0; display: grid; gap: 10px; }}
.scroll {{ overflow-x: auto; border: 1px solid var(--line); border-radius: 12px; background: #fff; }}
.scroll svg {{ display: block; width: 100%; min-width: 900px; height: auto; }}
figcaption {{ color: var(--muted); max-width: 80ch; font-size: .95rem; }}
figcaption b {{ color: var(--ink); }}
code {{ font-family: 'JetBrains Mono', Consolas, monospace; font-size: .88em; }}
</style>"""

BODY = f"""<main>
<header>
<h1>GhostMesh security map</h1>
<p>The testbed (A → B → C with D as backup relay, watchtower W with the IPS laptop, insider attacker X), drawn twice: first with the keys and protections, then with the weak points marked. Updated {UPDATED}. Sources: <code>security/threat-model.md</code> and the decision log in <code>docs/decisions.md</code> §4.7. Regenerate with <code>python docs/diagrams/make_diagrams.py</code>.</p>
</header>
<figure>
<div class="scroll">{svg1}</div>
<figcaption><b>Figure 1.</b> Only A and C hold their pair key, so relays B and D, the watchtower and X carry the message without reading it. Every hop re-makes <code>link_tag</code> with the shared network key, which stops outsiders but not insiders like X. The watchtower identifies every board through the pseudonym secrets and signs TIME and BLOCK frames, but holds no X25519 secrets. The Wireshark view (<code>security/gm_pcap.py</code> + <code>ghostmesh.lua</code>) shows what a sniffer gets: cleartext headers and ciphertext.</figcaption>
</figure>
<figure>
<div class="scroll">{svg2}</div>
<figcaption><b>Figure 2.</b> The filled mark is the one open item (O24). The first-sync factory-MAC leak was fixed on Nov 19 and is no longer marked. Outlined marks are limitations we accept and document, or that are out of scope. Most marks cluster on the watchtower: it is the one board whose loss or overload takes away detection, blocking and time at once.</figcaption>
</figure>
<figure>
<div class="scroll">{svg3}</div>
<figcaption><b>Figure 3.</b> What each of the 240 bytes does. Only the 30-byte header is readable, and it carries no destination, no fixed identity and no length; everything about the conversation is inside the ciphertext, sealed by the Poly1305 tag together with the header fields relays never change. Meshtastic's 16-byte header, by contrast, is never encrypted. Generated by <code>docs/diagrams/make_packet_diagram.py</code>.</figcaption>
</figure>
</main>
"""

FONTS = '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono&family=Space+Grotesk:wght@700&display=swap">'
(out / "security-map.html").write_text(
    f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GhostMesh Security Map</title>
{FONTS}
{STYLE}
</head>
<body>
{BODY}</body>
</html>
""", encoding="utf-8")
if FRAGMENT:
    FRAGMENT.write_text(f"""<title>GhostMesh Security Map</title>
<meta name="claude:viewport-fit-sides" content="cover">
{FONTS}
{STYLE}
{BODY}""", encoding="utf-8")
print("wrote", out, FRAGMENT or "")
