"""Generate docs/diagrams/packet-anatomy.svg: what each of the 240 bytes of a GhostMesh frame does.

    python docs/diagrams/make_packet_diagram.py

Rows: the whole frame to scale; the 30-byte cleartext header zoomed in, one speech bubble per field; the
encrypted part (nonce, ciphertext with what's inside it, tag); Meshtastic's 16-byte cleartext header for
comparison. Offsets: PROTOCOL.md §9.4–9.5. Meshtastic layout: meshtastic.org/docs/overview/mesh-algo and
/encryption (read Nov 20, 2026). make_diagrams.py puts this SVG on the security-map page as Figure 3.
"""
import pathlib
from html import escape as esc

OUT = pathlib.Path(__file__).resolve().parent / "packet-anatomy.svg"

W, H = 1600, 1150
BG, PANEL, LINE, INK, MUTED = "#f4f6fa", "#ffffff", "#c9d1de", "#172033", "#5b6678"
C, I, A, RED, OKG = "#2563c9", "#b26a00", "#1f8a52", "#d92332", "#1f8a52"
SANS = "Inter, 'Segoe UI', Arial, sans-serif"
MONO = "'JetBrains Mono', Consolas, monospace"
DISPLAY = "'Space Grotesk', " + SANS

X0, X1 = 60, 1540                       # drawing width for every bar


def t(x, y, s, size=12, fill=INK, weight=400, anchor="start", family=SANS):
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-family="{family}" font-size="{size}" fill="{fill}" '
            f'font-weight="{weight}" text-anchor="{anchor}">{esc(s)}</text>')


def rect(x, y, w, h, fill, stroke="none", r=0, sw=1.5, dash=""):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>'


def chip(x, y, letter):
    col = {"C": C, "I": I, "A": A}[letter]
    return f'<circle cx="{x}" cy="{y}" r="8" fill="{col}"/>' + t(x, y + 4, letter, 10, "#fff", 700, "middle")


def bubble(x, y, w, h, target, color, title, lines, chips=(), title_color=None, line_colors=None):
    """Speech bubble with a tail pointing at target=(tx, ty) above or below the box."""
    tx, ty = target
    cx = min(max(tx, x + 24), x + w - 24)
    edge = y if ty < y else y + h
    out = [f'<polygon points="{cx - 9:.1f},{edge:.1f} {cx + 9:.1f},{edge:.1f} {tx:.1f},{ty:.1f}" fill="{PANEL}" stroke="{color}" stroke-width="1.6"/>',
           rect(x, y, w, h, PANEL, color, 10, 1.6),
           f'<line x1="{cx - 8:.1f}" y1="{edge:.1f}" x2="{cx + 8:.1f}" y2="{edge:.1f}" stroke="{PANEL}" stroke-width="3"/>',
           t(x + 12, y + 20, title, 12.5, title_color or color, 700)]
    for i, ch in enumerate(chips):
        out.append(chip(x + w - 16 - 20 * i, y + 15, ch))
    for j, ln in enumerate(lines):
        col = (line_colors[j] if line_colors else INK)
        out.append(t(x + 12, y + 39 + j * 17, ln, 11.5, col))
    return "".join(out)


def bar(x, y, h, segs, label_size=11.5):
    """segs: [(width, fill, label, sublabel)]. Returns (svg, [(x0, x1)])."""
    out, spans, cx = [], [], x
    for w, fill, label, sub in segs:
        out.append(rect(cx, y, w, h, fill, "#ffffff", 0, 1.5))
        if label:
            ly = y + h / 2 + (0 if sub else 4)
            out.append(t(cx + w / 2, ly, label, label_size, "#ffffff", 700, "middle"))
            if sub:
                out.append(t(cx + w / 2, ly + 15, sub, 10, "#e8ecf5", 400, "middle"))
        spans.append((cx, cx + w))
        cx += w
    return "".join(out), spans


def build():
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" role="img" '
         f'aria-label="Anatomy of a 240-byte GhostMesh frame: what each field does, how it protects confidentiality, '
         f'integrity and availability, and what Meshtastic\'s cleartext header leaks by comparison.">',
         rect(0, 0, W, H, BG),
         t(X0, 48, "Anatomy of a GhostMesh frame: 240 bytes, every frame the same size", 24, INK, 700, family=DISPLAY),
         t(X0, 74, "What each byte does, how it keeps messages confidential, intact and deliverable, and why a sniffer learns "
                   "so little. Offsets from PROTOCOL.md §9.4–9.5.", 13.5, MUTED)]

    # ---- row 1: whole frame to scale ---------------------------------------------------------
    bpx = (X1 - X0) / 240
    y1 = 104
    o.append(t(X0, y1 - 8, "1  The whole frame, to scale", 13, INK, 700))
    svg, sp1 = bar(X0, y1 + 4, 46, [(30 * bpx, "#475569", "header", "30 B, cleartext"),
                                    (24 * bpx, "#6b7280", "nonce", "24 B"),
                                    (170 * bpx, "#1e3a8a", "ciphertext", "170 B: encrypted"),
                                    (16 * bpx, I, "tag", "16 B")])
    o.append(svg)
    for b in (0, 30, 54, 224, 240):
        o.append(t(X0 + b * bpx, y1 + 66, str(b), 10.5, MUTED, 400, "middle", MONO))

    # ---- row 2: cleartext header zoomed ------------------------------------------------------
    y2 = 340
    hpx = (X1 - X0) / 30
    fields = [(1, "#5a6b8c", "type", "0"), (1, "#7a5a8c", "flags", "1"), (8, "#3f7f8c", "msg_id", "2–9"),
              (1, "#8c6a3f", "ttl", "10"), (1, "#a07845", "hop", "11"), (4, "#2f6fb5", "src_pseudo", "12–15"),
              (4, "#4f8a5c", "next_hop", "16–19"), (2, "#8c4f6a", "epoch", "20–21"), (8, I, "link_tag", "22–29")]
    # zoom wedge from the header segment to the zoomed bar
    hx0, hx1 = sp1[0]
    o.append(f'<polygon points="{hx0},{y1 + 50} {hx1},{y1 + 50} {X1},{y2} {X0},{y2}" fill="#475569" opacity="0.07"/>')
    o.append(t(X0, y2 - 132, "2  The 30-byte header, zoomed: the only part anyone can read", 13, INK, 700))
    svg, sp2 = bar(X0, y2, 50, [(n * hpx, col, name, f"bytes {rng}") for n, col, name, rng in fields], 11)
    o.append(svg)
    mid = {f[2]: ((sp2[i][0] + sp2[i][1]) / 2) for i, f in enumerate(fields)}
    col = {f[2]: f[1] for f in fields}
    top, bot = y2, y2 + 50

    BW, BH = 340, 92
    above_y = y2 - 116
    below_y = y2 + 76
    # above the bar
    o.append(bubble(60, above_y, BW, BH, ((mid["type"] + mid["flags"]) / 2, top), col["type"], "type + flags  (bytes 0–1)",
                    ["type: DATA, HELLO, CTRL or KEYS; ACKs travel as DATA", "flags: only an SOS bit, no needs-ACK bit",
                     "Visible: the frame's class and SOS. Bound to the AEAD"], ("I",)))
    o.append(bubble(420, above_y, BW, BH, ((mid["ttl"] + mid["hop"]) / 2, top), col["ttl"], "ttl + hop  (bytes 10–11)",
                    ["Hop padding: the sender starts at hop 0, 1 or 2", "ttl + hop is always 5, so hop 0 ≠ the sender",
                     "Outsiders can't edit them (link_tag)"], ("I", "C")))
    o.append(bubble(780, above_y, BW, BH, (mid["next_hop"], top), col["next_hop"], "next_hop  (bytes 16–19)",
                    ["Always 0 = flood: no route, no destination", "Every node tries to decrypt every frame;",
                     "only the real recipient succeeds"], ("C",)))
    o.append(bubble(1140, above_y, 400, BH, (mid["link_tag"], top), col["link_tag"], "link_tag  (bytes 22–29)",
                    ["Keyed BLAKE2b (network key) over all other 232 bytes", "Checked first: outsiders' frames die at hop 1",
                     "Re-made by each relay; constant-time compare"], ("A", "I")))
    # below the bar
    o.append(bubble(200, below_y, BW, BH, (mid["msg_id"], bot), col["msg_id"], "msg_id  (bytes 2–9)",
                    ["Random 8 bytes, never a counter", "Duplicate + replay caches (60 s and 180 s)",
                     "Bound to the AEAD: can't be swapped"], ("A", "I")))
    o.append(bubble(580, below_y, BW, BH, (mid["src_pseudo"], bot), col["src_pseudo"], "src_pseudo  (bytes 12–15)",
                    ["Who TRANSMITTED (last hop), not who wrote it", "Rotates every 60 s, with the radio MAC",
                     "Each relay overwrites it with its own"], ("C",)))
    o.append(bubble(960, below_y, BW, BH, (mid["epoch"], bot), col["epoch"], "epoch  (bytes 20–21)",
                    ["Which 60 s epoch (mesh clock)", "Only ±1 epoch is accepted: replays expire",
                     "Bound to the AEAD: can't be re-dated"], ("I",)))

    # ---- row 3: encrypted part ---------------------------------------------------------------
    y3 = 640
    o.append(t(X0, y3 - 16, "3  The encrypted part: only the sender and the recipient can open it (not to scale)", 13, INK, 700))
    inner = [(150, "#6b7280", "nonce", "bytes 30–53"),
             (110, "#1e3a8a", "sender", "real ID"), (110, "#24438f", "recipient", "real ID"),
             (110, "#2a4c96", "time", "ms"), (100, "#30559c", "seq", ""), (70, "#365ea3", "type", "DATA/ACK"),
             (60, "#3c67aa", "len", ""), (610, C, "message body  ≤ 152 B, zero-padded", "bytes 72–223"),
             (160, I, "Poly1305 tag", "bytes 224–239")]
    svg, sp3 = bar(X0, y3, 50, inner, 11)
    o.append(svg)
    # bracket over the ciphertext
    cx0, cx1 = sp3[1][0], sp3[7][1]
    o.append(f'<path d="M{cx0},{y3 - 4} L{cx0},{y3 - 10} L{cx1},{y3 - 10} L{cx1},{y3 - 4}" fill="none" stroke="#1e3a8a" stroke-width="1.5"/>')
    o.append(t((cx0 + cx1) / 2, y3 - 15, "ciphertext, bytes 54–223 (XChaCha20)", 10.5, "#1e3a8a", 600, "middle"))
    m3 = [((a + b) / 2) for a, b in sp3]
    yb = y3 + 50 + 26
    o.append(bubble(60, yb, 280, 92, (m3[0], y3 + 50), "#6b7280", "nonce  (24 B)",
                    ["Random XChaCha20 nonce per frame", "192 random bits: never repeats,", "no counter to track"], ("C",)))
    o.append(bubble(360, yb, 420, 92, ((sp3[1][0] + sp3[6][1]) / 2, y3 + 50), "#1e3a8a", "inner header  (18 B, encrypted)",
                    ["Real sender + recipient, send time, sequence number,", "real type (DATA or ACK) and length",
                     "Recipient checks: for me? from that peer? fresh (5 s)?"], ("C", "I")))
    o.append(bubble(800, yb, 380, 92, (m3[7], y3 + 50), C, "message body",
                    ["Padded so every frame is 240 B: length never leaks", "Key: per pair of nodes, re-keyed every epoch",
                     "(DH ratchet: forward secrecy + healing)"], ("C",)))
    o.append(bubble(1200, yb, 340, 92, (m3[8], y3 + 50), I, "Poly1305 tag  (16 B)",
                    ["Seals the ciphertext AND type, flags,", "msg_id, epoch (associated data)",
                     "One bit changed → the recipient drops it"], ("I",)))

    # ---- row 4: Meshtastic -------------------------------------------------------------------
    y4 = 880
    o.append(t(X0, y4 - 44, "4  The same job in Meshtastic: a 16-byte header that is never encrypted", 13, INK, 700))
    o.append(t(X0, y4 - 24, "Layout from meshtastic.org/docs/overview/mesh-algo and /encryption. Red: what a sniffer learns. Green: GhostMesh's answer.",
               11.5, MUTED))
    mfields = [(150, "#7f1d1d", "destination", "4 B, fixed ID"), (150, "#991b1b", "sender", "4 B, fixed ID"),
               (130, "#a63d3d", "packet ID", "4 B"), (95, "#b45555", "flags", "hop limit…"),
               (95, "#b96a6a", "channel", "hash"), (95, "#be7b7b", "next hop", ""), (95, "#c48c8c", "relay", ""),
               (670, "#9ca3af", "payload: AES, length varies with the message", "up to 239 B, unused bytes not sent")]
    svg, sp4 = bar(X0, y4, 50, mfields, 11)
    o.append(svg)
    o.append(f'<path d="M{sp4[7][1] - 40},{y4} l20,25 l-20,25" fill="none" stroke="{BG}" stroke-width="10"/>')
    m4 = [((a + b) / 2) for a, b in sp4]
    yb4 = y4 + 50 + 26
    red, grn = RED, OKG
    o.append(bubble(60, yb4, 360, 108, ((sp4[0][0] + sp4[1][1]) / 2, y4 + 50), red, "destination + sender",
                    ["Leaks who talks to whom, every packet", "IDs are fixed (CRC-32 of the node's key)",
                     "GhostMesh: no destination field; the sender", "is a 60 s pseudonym of the last hop"],
                    line_colors=[INK, INK, grn, grn]))
    o.append(bubble(440, yb4, 340, 108, (m4[3], y4 + 50), red, "flags: hop limit + hop start",
                    ["Hops travelled = hop start − hop limit:", "how far you are from the sender",
                     "GhostMesh: hop padding hides the start;", "ACKs look like ordinary DATA"],
                    line_colors=[INK, INK, grn, grn]))
    o.append(bubble(800, yb4, 340, 108, ((sp4[4][0] + sp4[6][1]) / 2, y4 + 50), red, "channel hash, next hop, relay",
                    ["A key hint and relay IDs in the clear", "",
                     "GhostMesh: no key hint (trial decryption),", "flood only, relay pseudonyms rotate"],
                    line_colors=[INK, INK, grn, grn]))
    o.append(bubble(1160, yb4, 380, 108, (m4[7], y4 + 50), red, "payload",
                    ["Length follows the message; the default", "channel's key (AQ==) is published",
                     "GhostMesh: always 240 B; per-pair keys", "that change every epoch"],
                    line_colors=[INK, INK, grn, grn]))

    # ---- legend ------------------------------------------------------------------------------
    yl = H - 30
    o += [chip(X0 + 8, yl - 4, "C"), t(X0 + 22, yl, "Confidentiality", 12, INK),
          chip(X0 + 148, yl - 4, "I"), t(X0 + 162, yl, "Integrity", 12, INK),
          chip(X0 + 252, yl - 4, "A"), t(X0 + 266, yl, "Availability", 12, INK),
          t(X0 + 390, yl, "Outside the 240 bytes: the radio MAC also changes every 60 s, together with src_pseudo.", 12, MUTED)]
    o.append("</svg>")
    return "\n".join(o)


if __name__ == "__main__":
    OUT.write_text(build(), encoding="utf-8")
    print("wrote", OUT)
