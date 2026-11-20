"""Two-room RSSI survey: which links are strong, which are weak, and does a gate fit between them.

Positions (diamond across a wall; the wall is between P2/P3 and P4):
    P1 = room 2 far from wall     P2 = room 2 close to wall, top     P3 = room 2 close to wall, bottom
    P4 = room 1 far from wall

Boards per test (A moves; B, C, D send to A every 2 s; A's chat client logs):
    test1: A=P1 B=P2 C=P3 D=P4        test3: B=P1 C=P2 A=P3 D=P4
    test2: B=P1 A=P2 C=P3 D=P4        test4: B=P1 C=P2 D=P3 A=P4

Record with W as the meter (recommended): W sits where the table puts A, A stays off. Every frame W
hears is tagged with the board that actually transmitted it (src_pseudo is the last hop), so relays
can't mix in. Any traffic works, e.g. B, C, D on /auto.
    python tools/chat_client.py --port COM5 --sync --log docs/results/rssi_rooms_w.jsonl
    /mark test1          (then ~40 s)
    /mark test2 ...

Or with A's chat client (--log on A). Less clean: an "rx" is the first copy to reach A, which is a
relay's copy whenever the direct one is lost, so weak links read too strong.

Run:   python tools/rssi_matrix.py docs/results/rssi_rooms.jsonl
"""
import json
import statistics
import sys

LAYOUT = {
    "test1": {"A": 1, "B": 2, "C": 3, "D": 4},
    "test2": {"B": 1, "A": 2, "C": 3, "D": 4},
    "test3": {"B": 1, "C": 2, "A": 3, "D": 4},
    "test4": {"B": 1, "C": 2, "D": 3, "A": 4},
}
NAMES = {1: "R2 far", 2: "R2 wall top", 3: "R2 wall bot", 4: "R1 far"}
PER_SENDER = 30          # only the first ~20 per sender after a mark (later = moving things around)
MARGIN_DB = 6            # gap needed between the weakest kept link and the strongest cut link


def pct(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, max(0, round(p / 100 * (len(v) - 1))))]


def direct_only(v):
    """A's rx RSSI is the LAST hop: a copy relayed by another board carries the relay's RSSI.
    The direct copy usually arrives first (relays wait 10-50 ms), so per sender keep the majority
    cluster: split at the biggest jump if it's >= 8 dB, keep the bigger side."""
    v = sorted(v)
    if len(v) < 4:
        return v
    gaps = [(v[i + 1] - v[i], i) for i in range(len(v) - 1)]
    g, i = max(gaps)
    if g < 8:
        return v
    lo, hi = v[:i + 1], v[i + 1:]
    return lo if len(lo) >= len(hi) else hi


def load(path):
    raw, test, counts = {}, "test1", {}      # readings before the first mark count as test1
    for line in open(path, encoding="utf-8"):
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("ev") == "mark":
            note = ev.get("note", "").lower().replace(" ", "")
            test = next((t for t in LAYOUT if note.startswith(t)), None)
            counts = {}
        elif test and "rssi" in ev and (ev.get("ev") == "rx" or (ev.get("id_ok") and "node" in ev)):
            frm = ev.get("from") if ev.get("ev") == "rx" else ev["node"]       # rx on A, or a frame W heard
            limit = PER_SENDER if ev.get("ev") == "rx" else PER_SENDER * 3
            if frm not in LAYOUT[test] or frm == "A" or counts.get(frm, 0) >= limit:
                continue
            counts[frm] = counts.get(frm, 0) + 1
            raw.setdefault((test, frm), []).append(ev["rssi"])
    pairs = {}
    for (test, frm), v in raw.items():
        key = tuple(sorted((LAYOUT[test]["A"], LAYOUT[test][frm])))
        pairs.setdefault(key, []).extend(direct_only(v))
    return pairs


def judge(pairs, name, keep, cut):
    if not all(k in pairs for k in keep + cut):
        missing = [f"{NAMES[a]}-{NAMES[b]}" for a, b in keep + cut if (a, b) not in pairs]
        print(f"\n{name}: can't judge, no data for {', '.join(missing)}")
        return
    weakest_keep = min(pct(pairs[k], 10) for k in keep)      # a bad moment on a kept link
    strongest_cut = max(pct(pairs[k], 90) for k in cut)       # a good moment on a cut link
    gap = weakest_keep - strongest_cut
    gate = (weakest_keep + strongest_cut) // 2
    verdict = "GOOD" if gap >= MARGIN_DB else ("RISKY" if gap > 0 else "WON'T WORK")
    print(f"\n{name}: {verdict}  (weakest kept link {weakest_keep} dBm, strongest cut link "
          f"{strongest_cut} dBm, gap {gap} dB; need {MARGIN_DB}+)")
    if gap > 0:
        print(f'  gate on every node: {{"cmd":"rssi_gate","dbm":{gate}}}')


def main(path):
    pairs = load(path)
    print(f"{'link':<28}{'n':>4}{'median':>8}{'p10':>6}{'p90':>6}")
    for (a, b), v in sorted(pairs.items()):
        print(f"{NAMES[a] + ' - ' + NAMES[b]:<28}{len(v):>4}{statistics.median(v):>8.1f}"
              f"{pct(v, 10):>6}{pct(v, 90):>6}")

    # Demo 1 diamond: A at R2 far, relays B and D at the two wall spots, C at R1 far (through the wall).
    # Kept: both ends reach both relays. Cut: A-C directly. Wall top - wall bottom doesn't matter.
    judge(pairs, "Diamond: A=R2 far, B/D=R2 wall top+bottom, C=R1 far",
          keep=[(1, 2), (1, 3), (2, 4), (3, 4)], cut=[(1, 4)])
    # If only one wall spot reaches R1 far well, demo 1 can still be a chain (no unplug-B shot).
    for relay in (2, 3):
        judge(pairs, f"Chain via {NAMES[relay]} only", keep=[(1, relay), (relay, 4)], cut=[(1, 4)])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
