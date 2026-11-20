"""Run attacks from X: one variant, or a full recording session (decision 20).

    python security/attacks/run.py --port COM7 list
    python security/attacks/run.py --port COM7 attack flood loud --secs 120 --labels ips/datasets/2026-11-20_flood_01.labels.jsonl
    python security/attacks/run.py --port COM7 session flood --labels ips/datasets/2026-11-20_flood_01.labels.jsonl

The watchtower recording itself is made on the IPS laptop (chat_client --log, or the IPS). Name the labels
file after that recording: <date>_<type>_<nn>.jsonl  <->  <date>_<type>_<nn>.labels.jsonl.

Mesh clock: by default X learns it from W's TIME beacons. If this laptop is the one that set W's clock
(the IPS laptop), --laptop-clock skips the wait.
--scale 0.1 runs a session 10x shorter (dry runs); --mock runs without hardware.
Ctrl+C stops cleanly: the current attack's label row is still written.
"""
import argparse
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import attacks  # noqa: E402
import gmx  # noqa: E402

NORMAL_FIRST_S = 300        # IPS learns each node's normal behaviour first (DEMO_RUNBOOK: >= 2 min)
VARIANT_S = 120
GAP_S = 60

SESSIONS = {
    "flood":   [("flood", v) for v in ("loud", "slow", "outsider", "low_slow")],
    "replay":  [("replay", v) for v in ("age_30s", "age_90s", "age_240s")],
    "spoof":   [("spoof", v) for v in ("pseudo", "pseudo_mac")],
    "routing": [("routing", v) for v in ("hop0", "hop0_ttlfix")],
    "extras":  [("flood", "cycling"), ("flood", "ctrl_forgery"), ("outage", "slow")],
    # held-out test set: one variant of each core attack, a different order, shorter gaps
    "mixed":   [("spoof", "pseudo"), ("routing", "hop0_ttlfix"), ("replay", "age_90s"), ("flood", "slow")],
}
MIXED_GAP_S = 45
OUTAGE_S = 360              # W outage runs inside a 6 min `slow` flood
OUTAGE_PROMPTS = [(0, "UNPLUG the watchtower (W) now  ->  /mark W unplugged"),
                  (60, "REBOOT one node (press its reset button)  ->  /mark node rebooted while W down"),
                  (180, "PLUG the watchtower back in and set its clock  ->  /mark W back")]


def say(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def wait(ctx, secs, what):
    end = time.monotonic() + secs
    last = None
    while not ctx.stop.is_set():
        left = end - time.monotonic()
        if left <= 0:
            return
        mark = int(left // 30)
        if mark != last:
            say(f"{what}: {left:.0f} s left (X silent)")
            last = mark
        time.sleep(min(1.0, left))


def run_variant(ctx, labels, label, variant, secs):
    fn = attacks.ATTACKS[(label, variant)]
    say(f"ATTACK {label}/{variant} for {secs:.0f} s")
    with labels.run(label, variant=variant):
        n = fn(ctx, secs)
    say(f"  done: {n} frames sent")
    return n


def run_outage(ctx, labels, secs, scale):
    """`slow` flood while the operator takes W down, reboots a node, and brings W back."""
    stop_prompts = threading.Event()

    def prompts():
        t0 = time.monotonic()
        for at, msg in OUTAGE_PROMPTS:
            while time.monotonic() - t0 < at * scale:
                if stop_prompts.wait(0.2) or ctx.stop.is_set():
                    return
            say(f">>> OPERATOR: {msg}")
    th = threading.Thread(target=prompts, daemon=True)
    th.start()
    try:
        return run_variant(ctx, labels, "flood", "slow", secs)
    finally:
        stop_prompts.set()


def run_session(ctx, labels, name, scale=1.0, normal_first=True):
    steps = SESSIONS[name]
    gap = (MIXED_GAP_S if name == "mixed" else GAP_S) * scale
    if normal_first:
        wait(ctx, NORMAL_FIRST_S * scale, "normal traffic first")
    total = 0
    for i, (label, variant) in enumerate(steps):
        if ctx.stop.is_set():
            break
        if i:
            wait(ctx, gap, "normal gap")
        if label == "outage":
            total += run_outage(ctx, labels, OUTAGE_S * scale, scale)
        else:
            total += run_variant(ctx, labels, label, variant, VARIANT_S * scale)
    if not ctx.stop.is_set():
        wait(ctx, gap, "normal tail")
    return total


def open_radio(args):
    if args.mock:
        r = gmx.MockRadio()
        r.clock.assume_laptop_clock()
        return r
    return gmx.XRadio(args.port)


def sync_clock(radio, laptop_clock, timeout=30):
    if laptop_clock:
        radio.clock.assume_laptop_clock()
        return True
    say("waiting for a TIME beacon from W ...")
    end = time.time() + timeout
    while not radio.clock.synced and time.time() < end:
        time.sleep(0.2)
    if radio.clock.synced:
        say(f"mesh clock synced (offset {radio.clock.offset_ms:+.0f} ms), epoch {radio.clock.epoch()}")
    return radio.clock.synced


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run attacks from X (decision 20).")
    ap.add_argument("--port", help="X's serial port (not needed with --mock)")
    ap.add_argument("--keys", help="X's keys header (default firmware/config/keys/keys_X.h)")
    ap.add_argument("--labels", help="ground-truth file, e.g. ips/datasets/2026-11-20_flood_01.labels.jsonl")
    ap.add_argument("--laptop-clock", action="store_true", help="this laptop set W's clock: don't wait for a beacon")
    ap.add_argument("--victim", help="spoof: start with this pseudonym (8 hex digits)")
    ap.add_argument("--mock", action="store_true", help="no hardware (dry run)")
    ap.add_argument("--scale", type=float, default=1.0, help="multiply every duration (0.1 = 10x shorter)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    a = sub.add_parser("attack"); a.add_argument("label"); a.add_argument("variant")
    a.add_argument("--secs", type=float, default=VARIANT_S)
    s = sub.add_parser("session"); s.add_argument("name", choices=sorted(SESSIONS))
    s.add_argument("--no-normal-first", action="store_true", help="skip the 5 min of normal traffic at the start")
    args = ap.parse_args(argv)

    if args.cmd == "list":
        for (label, variant) in attacks.ATTACKS:
            print(f"{label:8} {variant}")
        print("sessions:", ", ".join(f"{k} ({', '.join(f'{l}/{v}' for l, v in s)})" for k, s in SESSIONS.items()))
        return 0
    if args.cmd == "attack" and (args.label, args.variant) not in attacks.ATTACKS:
        print(f"unknown attack {args.label}/{args.variant}; see `list`", file=sys.stderr)
        return 2
    if not args.labels:
        print("--labels is required: name it after the watchtower recording (<date>_<type>_<nn>.labels.jsonl)",
              file=sys.stderr)
        return 2
    if not args.mock and not args.port:
        print("--port is required (or --mock)", file=sys.stderr)
        return 2

    keys = gmx.load_keys(args.keys) if not args.mock or args.keys else gmx.XKeys(
        "X", 6, bytes(32), bytes(range(32)), bytes(32), bytes(32))
    radio = open_radio(args)
    ctx = attacks.AttackContext(radio, keys)
    if args.victim:
        ctx.victim_hint = int(args.victim, 16)
    try:
        radio.sniff(True) if hasattr(radio, "sniff") else None
        if not sync_clock(radio, args.laptop_clock or args.mock):
            print("no TIME beacon: is W on with its clock set? (or use --laptop-clock on the IPS laptop)", file=sys.stderr)
            return 1
        labels = gmx.LabelLog(args.labels, radio.clock)
        say(f"labels -> {args.labels}")
        try:
            if args.cmd == "attack":
                run_variant(ctx, labels, args.label, args.variant, args.secs * args.scale)
            else:
                run_session(ctx, labels, args.name, args.scale, not args.no_normal_first)
        except KeyboardInterrupt:
            ctx.stop.set()
            say("stopped (label row for the running attack was written)")
    finally:
        ctx.close()
        radio.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
