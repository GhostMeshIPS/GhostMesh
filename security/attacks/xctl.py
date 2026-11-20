"""Bring-up and manual control for attacker X (decision 18). No attacks here: those get their own scripts.

    python security/attacks/xctl.py --port COM7 status
    python security/attacks/xctl.py --port COM7 sniff [--secs 30]      decoded frames X hears
    python security/attacks/xctl.py --port COM7 clock                  wait for a TIME beacon, print mesh time + epoch
    python security/attacks/xctl.py --port COM7 set-mac 02:11:22:33:44:55
    python security/attacks/xctl.py --port COM7 own-mac               set X's MAC to its own derived MAC for this epoch

`sniff` checks link_tag with X's network key when firmware/config/keys/keys_X.h exists.
"""
import argparse
import queue
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gmx  # noqa: E402


def try_keys(path):
    try:
        return gmx.load_keys(path)
    except (OSError, ValueError) as e:
        print(f"(no X keys: {e}; link_tag not checked)", file=sys.stderr)
        return None


def cmd_sniff(radio, keys, secs):
    end = time.time() + secs if secs else None
    n = 0
    while end is None or time.time() < end:
        try:
            h = radio.heard.get(timeout=0.5)
        except queue.Empty:
            continue
        f = h.frame
        ok = "" if keys is None else ("  link ok" if f.link_ok(keys.network_key) else "  BAD link_tag")
        extra = ""
        t = f.ctrl_time_ms()
        if t is not None:
            extra = f"  TIME {time.strftime('%H:%M:%S', time.gmtime(t / 1000))} UTC"
        print(f"{f.type_name:5} src {f.src_pseudo:08x} mac {h.mac} rssi {h.rssi:4} epoch {f.epoch:5} "
              f"hop {f.hop} ttl {f.ttl} msg {f.msg_id.hex()}{ok}{extra}", flush=True)
        n += 1
    print(f"{n} frames", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Control attacker X (bring-up only).")
    ap.add_argument("--port", required=True, help="X's serial port, e.g. COM7 or /dev/cu.usbmodem1101")
    ap.add_argument("--keys", help="X's keys header (default firmware/config/keys/keys_X.h)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sniff"); s.add_argument("--secs", type=float, default=0, help="0 = until Ctrl+C")
    sub.add_parser("status")
    c = sub.add_parser("clock"); c.add_argument("--timeout", type=float, default=15)
    m = sub.add_parser("set-mac"); m.add_argument("mac")
    sub.add_parser("own-mac")
    args = ap.parse_args(argv)

    with gmx.XRadio(args.port) as radio:
        if args.cmd == "status":
            print(radio.status())
        elif args.cmd == "sniff":
            radio.sniff(True)
            try:
                cmd_sniff(radio, try_keys(args.keys), args.secs)
            except KeyboardInterrupt:
                pass
        elif args.cmd == "clock":
            radio.sniff(True)
            end = time.time() + args.timeout
            while not radio.clock.synced and time.time() < end:
                time.sleep(0.2)
            if not radio.clock.synced:
                print("no TIME beacon heard: is the watchtower on and its clock set?", file=sys.stderr)
                return 1
            print(f"mesh time {radio.clock.now_s():.3f}  epoch {radio.clock.epoch()}  "
                  f"offset vs this laptop {radio.clock.offset_ms:+.0f} ms")
        elif args.cmd == "set-mac":
            print(radio.set_mac(args.mac))
        elif args.cmd == "own-mac":
            keys = gmx.load_keys(args.keys)
            radio.sniff(True)
            end = time.time() + 15
            while not radio.clock.synced and time.time() < end:
                time.sleep(0.2)
            if not radio.clock.synced:
                print("no TIME beacon heard", file=sys.stderr)
                return 1
            ep = radio.clock.epoch()
            mac = gmx.mac_for(keys.pseudo_secret, ep)
            print(f"epoch {ep}: pseudonym {gmx.pseudonym(keys.pseudo_secret, ep):08x}, MAC {gmx.mac_str(mac)}")
            print(radio.set_mac(mac))
    return 0


if __name__ == "__main__":
    sys.exit(main())
