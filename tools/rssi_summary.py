"""Summarise a node's RSSI log, one row per setup.

Record with the chat client on the node (not W), and /mark each setup change:

    python tools/chat_client.py --port COM8 --log docs/results/rssi_C.jsonl
    /mark no pans 1.5m
    ... ~20 messages ...
    /mark 2 pans 1.5m

Then:  python tools/rssi_summary.py docs/results/rssi_C.jsonl

Every received message ("ev": "rx") carries the RSSI of the frame that delivered it. With only the
two boards on (B, D, X off) that is the direct link, so this measures what the shield does.
"""
import json
import statistics
import sys


def main(path):
    rows, label, vals = [], "(before first /mark)", {}
    for line in open(path, encoding="utf-8"):
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("ev") == "mark":
            rows.append((label, vals))
            label, vals = ev.get("note", "mark"), {}
        elif ev.get("ev") == "rx" and "rssi" in ev:
            vals.setdefault(ev.get("from", "?"), []).append(ev["rssi"])
    rows.append((label, vals))

    print(f"{'setup':<28}{'from':>5}{'n':>5}{'median':>8}{'min':>6}{'max':>6}{'stdev':>7}")
    for label, by_from in rows:
        for frm, v in sorted(by_from.items()):
            sd = statistics.pstdev(v) if len(v) > 1 else 0.0
            print(f"{label[:27]:<28}{frm:>5}{len(v):>5}{statistics.median(v):>8.1f}"
                  f"{min(v):>6}{max(v):>6}{sd:>7.1f}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
