"""Record every hardware dataset and measurement the team asked for, from one laptop.

What it covers (and who asked):
  Hannan  ips/datasets/README.md + decision 16f   normal   clean normal traffic, X powered OFF
  Jose    security/attacks/RECORDING.md part 3     flood, routing, spoof, replay, extras, mixed
  Hannan  ips/datasets/README.md (<type> unplugB)  unplugB  W log of the reroute trials below
  Rashad  PROTOCOL.md section 13 (reroute time)    unplugB  10 trials: unplug B, time to first new msg at C
  Results table (project doc 7.2, G1)               delivery 50 messages A -> C, delivery rate
  Results table (encrypt + decrypt time on S3)      bench    crypto benchmark on A

Ports (one laptop): W always. X for the attack sessions. A for unplugB / delivery / bench
(C optional: in the two-room layout C can't reach the laptop, so delivery is counted from A's ACKs).
Only one program can hold a port: close every chat client / live.py / pio monitor first.

    python tools/record_all.py --w COM5 --x COM7 --a COM9 --c COM11            everything, in order
    python tools/record_all.py --w COM5 --x COM7 --only flood replay           just those
    python tools/record_all.py --w COM5 --a COM9 --c COM11 --only unplugB delivery bench
    python tools/record_all.py --list                                          the plan, no hardware

Outputs:
  ips/datasets/<date>_<type>_<nn>.jsonl (+ .labels.jsonl for attacks)   for Hannan / Jose
  docs/results/hardware-measurements-<date>.md                         numbers for Rashad + results table,
                                                                       and rows for the datasets README
Ctrl+C skips the current step (the files written so far are kept) and moves on.
"""
import argparse
import json
import queue
import statistics
import subprocess
import sys
import threading
import time
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASETS = ROOT / "ips" / "datasets"
RESULTS = ROOT / "docs" / "results"
RUN_PY = ROOT / "security" / "attacks" / "run.py"
BAUD = 921600                       # W and X are WROOM-32E (UART bridge); the S3 nodes ignore it

# key, file <type>, who asked, ~minutes, what the operator must set up first
PLAN = [
    ("normal",   "normal",  "Hannan (16f)",  20, "X UNPLUGGED. A-D on /auto (e.g. A:/auto C 20, B:/auto A 20, C:/auto A 20, D:/auto B 30)"),
    ("flood",    "flood",   "Jose",          17, "X plugged in, near B and W"),
    ("routing",  "routing", "Jose",          11, "X plugged in"),
    ("spoof",    "spoof",   "Jose",          11, "X right next to the board it should impersonate"),
    ("replay",   "replay",  "Jose",          14, "X plugged in"),
    ("extras",   "extras",  "Jose",          17, "Free hand needed: follow the >>> OPERATOR prompts (unplug W, reset a node, W back)"),
    ("mixed",    "mixed",   "Jose/Hannan",   16, "Held-out TEST set: Hannan must never train on it"),
    ("unplugB",  "unplugB", "Rashad + Hannan", 10, "A on the laptop; B, C, D on power. Demo layout + rssi_gate on A and C"),
    ("delivery", None,      "results table", 2, "A on the laptop; B, C, D on power. Demo layout + rssi_gate on A and C"),
    ("bench",    None,      "results table", 1, "A on the laptop"),
]
ATTACKS = {"flood", "routing", "spoof", "replay", "extras", "mixed"}


def say(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def ask(msg):
    print(f"\n>>> {msg}", flush=True)
    return input(">>> press Enter when ready (or type s + Enter to skip): ").strip().lower() != "s"


def next_path(kind):
    today = date.today().isoformat()
    for nn in range(1, 100):
        p = DATASETS / f"{today}_{kind}_{nn:02d}.jsonl"
        if not p.exists():
            return p
    raise SystemExit("too many recordings today")


# ---- serial ---------------------------------------------------------------------------------------

def open_port(port):
    import serial
    s = serial.Serial()
    s.port, s.baudrate, s.timeout = port, BAUD, 0.5
    s.dtr = False                   # don't pulse reset (it wipes W's clock)
    s.rts = False
    s.open()
    return s


def send(ser, obj):
    ser.write((json.dumps(obj) + "\n").encode())


class Board:
    """A node or W on a serial port: a reader thread keeps (time, event) pairs and can log lines."""

    def __init__(self, port, name, is_w=False):
        self.ser, self.name, self.is_w = open_port(port), name, is_w
        self.events = queue.Queue()
        self.logf, self.log_lines, self.warnings = None, 0, []
        self.lock = threading.Lock()
        self.stop = False
        self._last_sync = 0.0
        threading.Thread(target=self._read, daemon=True).start()
        if is_w:
            self.sync()

    def sync(self):
        if time.time() - self._last_sync > 2:
            send(self.ser, {"cmd": "set_time", "unix_ms": int(time.time() * 1000)})
            self._last_sync = time.time()

    def _read(self):
        buf = b""
        while not self.stop:
            try:
                chunk = self.ser.read(4096)
            except Exception as e:                      # cable pulled (W during extras)
                self.warnings.append(f"{self.name} serial error: {e}")
                time.sleep(1)
                continue
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("{"):
                    continue
                now = time.time()
                with self.lock:
                    if self.logf:
                        self.logf.write(line + "\n")
                        self.log_lines += 1
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if self.is_w and ev.get("ev") in ("clock_not_set", "boot"):
                    self.warnings.append(f"W {ev['ev']} at {time.strftime('%H:%M:%S')}")
                    self.sync()
                if "ev" in ev:
                    self.events.put((now, ev))

    def start_log(self, path):
        with self.lock:
            self.logf, self.log_lines = open(path, "a", encoding="utf-8"), 0
        self.warnings = []

    def mark(self, note):
        with self.lock:
            if self.logf:
                self.logf.write(json.dumps({"ev": "mark", "t": round(time.time(), 3), "note": note}) + "\n")
        say(f"mark: {note}")

    def stop_log(self):
        with self.lock:
            if self.logf:
                self.logf.close()
            self.logf = None
        return self.log_lines

    def drain(self):
        out = []
        while True:
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                return out


# ---- steps ----------------------------------------------------------------------------------------

def wait_secs(secs, what):
    end = time.time() + secs
    while (left := end - time.time()) > 0:
        say(f"{what}: {left / 60:.1f} min left")
        time.sleep(min(60, left))


def record_w_only(w, kind, minutes, report):
    path = next_path(kind)
    w.start_log(path)
    w.mark(f"{kind} start (record_all)")
    try:
        wait_secs(minutes * 60, f"recording {path.name}")
    finally:
        n = w.stop_log()
        report["datasets"].append((path.name, kind, minutes, n, w.warnings[:]))
        say(f"saved {path.name}: {n} lines")


def record_attack(w, xport, session, report, scale):
    path = next_path(session)
    labels = path.with_name(path.stem + ".labels.jsonl")
    w.start_log(path)
    w.mark(f"{session} session start (record_all)")
    cmd = [sys.executable, str(RUN_PY), "--port", xport, "--laptop-clock", "--labels", str(labels)]
    if scale != 1:
        cmd += ["--scale", str(scale)]
    cmd += ["session", session]
    say("running " + " ".join(cmd[1:]))
    t0 = time.time()
    proc = subprocess.Popen(cmd, cwd=ROOT)
    try:
        proc.wait()
    except KeyboardInterrupt:
        say("stopping the attack runner (its label rows are still written)")
        proc.terminate()
        proc.wait()
        raise
    finally:
        n = w.stop_log()
        report["datasets"].append((path.name, session, round((time.time() - t0) / 60), n, w.warnings[:]))
        say(f"saved {path.name} + {labels.name}: {n} lines, exit code {proc.returncode}")


def quiet_auto(a):
    """A's own /auto traffic to C would mix with the test messages: stop it for the test."""
    send(a.ser, {"cmd": "auto", "to": "", "every_s": 0})
    time.sleep(0.5)
    say("A's /auto turned off for this test (turn it back on with /auto C 20 afterwards if you need it)")


def a_sends(a, c, texts_sent, t_unplug=None):
    """Arrival time per message. With C on the laptop: C's rx (exact). Without: A's 'delivered' ACK
    (C got it; includes the ACK's trip back, so slightly later than the real arrival)."""
    a_ev = a.drain()
    if c is not None:
        arrived = {}
        for ts, ev in c.drain():
            if ev.get("ev") == "rx" and ev.get("from") == "A" and ev.get("text") in texts_sent:
                arrived.setdefault(ev["text"], ts)
        return {txt: (texts_sent[txt], arrived.get(txt)) for txt in texts_sent}, a_ev
    sent_h = [(ts, ev["handle"]) for ts, ev in a_ev if ev.get("ev") == "sent" and ev.get("to") == "C"]
    done = {ev["handle"]: ts for ts, ev in a_ev if ev.get("ev") == "delivered" and ev.get("to") == "C"}
    return {f"h{h}": (ts, done.get(h)) for ts, h in sent_h}, a_ev


def reroute_trials(w, a, c, trials, report):
    """PROTOCOL 13: A -> C every 1 s; reroute time = unplug -> C shows the first msg A sent after it."""
    path = next_path("unplugB")
    w.start_log(path)
    quiet_auto(a)
    results = []
    try:
        for t in range(1, trials + 1):
            if not ask(f"Trial {t}/{trials}: B plugged in and its OLED shows SYNC?"):
                break
            a.drain()
            if c is not None:
                c.drain()
            sent, stop = {}, threading.Event()

            def sender():
                i = 0
                while not stop.is_set():
                    text = f"rr{t}-{i}"
                    send(a.ser, {"cmd": "send", "to": "C", "text": text})
                    sent[text] = time.time()
                    i += 1
                    stop.wait(1.0)

            th = threading.Thread(target=sender, daemon=True)
            th.start()
            time.sleep(8)
            input(">>> PULL B's power now, and press Enter AT THE MOMENT you pull it: ")
            t_unplug = time.time()
            w.mark(f"trial {t}: B unplugged")
            time.sleep(15)
            stop.set(); th.join()
            time.sleep(10)                                  # let retries / ACKs land
            msgs, _ = a_sends(a, c, sent)
            after = sorted((st, arr) for st, arr in msgs.values() if st > t_unplug)
            first_after = next((arr for st, arr in after if arr is not None), None)
            lost = sum(1 for st, arr in msgs.values() if arr is None)
            rr = None if first_after is None else first_after - t_unplug
            results.append({"trial": t, "reroute_s": rr, "sent": len(msgs), "lost": lost})
            say(f"trial {t}: reroute {'-' if rr is None else f'{rr:.2f} s'}, {lost}/{len(msgs)} not delivered")
            w.mark(f"trial {t}: B back in")
            print(">>> Plug B back in (it resyncs from W in ~10 s).")
    except KeyboardInterrupt:
        say("reroute trials stopped")
    finally:
        n = w.stop_log()
        report["datasets"].append((path.name, "unplugB", None, n, w.warnings[:]))
    report["reroute"] = results
    report["measured_at"] = "C's laptop (rx)" if c is not None else "A, via C's end-to-end ACK (includes the ACK's trip back: an upper bound)"


def delivery_test(a, c, n, report):
    quiet_auto(a)
    a.drain()
    if c is not None:
        c.drain()
    sent = {}
    for i in range(n):
        txt = f"dl-{i}"
        send(a.ser, {"cmd": "send", "to": "C", "text": txt})
        sent[txt] = time.time()
        time.sleep(1.0)
    say("waiting 15 s for the last messages / retries")
    time.sleep(15)
    msgs, a_ev = a_sends(a, c, sent)
    got = sum(1 for st, arr in msgs.values() if arr is not None)
    failed = sum(1 for _, ev in a_ev if ev.get("ev") == "failed")
    report["delivery"] = {"sent": n, "delivered": got, "failed_at_a": failed,
                          "how": "rx at C" if c is not None else "ACK back at A (a message whose ACK was lost counts as not delivered: a lower bound)"}
    say(f"delivery: {got}/{n} delivered, {failed} failed")


def bench(a, report):
    a.drain()
    send(a.ser, {"cmd": "bench", "runs": 1000})
    end = time.time() + 90
    while time.time() < end:
        try:
            _, ev = a.events.get(timeout=1)
        except queue.Empty:
            continue
        if ev.get("ev") == "bench":
            report["bench"] = ev
            say(f"bench: {ev}")
            return
    say("bench: no answer in 90 s (is A on the demo firmware with the bench command?)")


# ---- report ---------------------------------------------------------------------------------------

def write_report(report):
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"hardware-measurements-{date.today().isoformat()}.md"
    if path.exists():                       # a second run the same day must not wipe the first run's numbers
        path = path.with_name(f"{path.stem}-{time.strftime('%H%M')}.md")
    L = [f"# Hardware measurements, {date.today().isoformat()}", "",
         "Made with `tools/record_all.py`. Boards: A-D ESP32-S3 Super Mini, W and X ESP32-WROOM-32E.", ""]
    rr = [r for r in report.get("reroute", []) if r["reroute_s"] is not None]
    if report.get("reroute"):
        L += ["## Reroute time (PROTOCOL.md section 13)", "",
              "A sends C one message per second; B is unplugged; time until C shows the first message A sent after.",
              f"Measured at: {report.get('measured_at', '')}.", "",
              "| Trial | Reroute time | Sent | Lost |", "|---|---|---|---|"]
        for r in report["reroute"]:
            v = "-" if r["reroute_s"] is None else f"{r['reroute_s']:.2f} s"
            L.append(f"| {r['trial']} | {v} | {r['sent']} | {r['lost']} |")
        if rr:
            vals = [r["reroute_s"] for r in rr]
            L += ["", f"**Median {statistics.median(vals):.2f} s, max {max(vals):.2f} s** over {len(vals)} trials; "
                  f"{sum(r['lost'] for r in report['reroute'])} messages lost in total.", ""]
    if "delivery" in report:
        d = report["delivery"]
        L += ["## Delivery rate, A -> C (results table, G1)", "",
              f"{d['delivered']}/{d['sent']} delivered (**{100 * d['delivered'] / d['sent']:.1f}%**), "
              f"{d['failed_at_a']} reported failed at A. Counted by: {d['how']}.", ""]
    if "bench" in report:
        b = report["bench"]
        L += ["## Crypto benchmark on the S3 (results table)", "", "```", json.dumps(b), "```", ""]
    if report["datasets"]:
        L += ["## Rows for `ips/datasets/README.md` (Recordings table)", "",
              "| File | Date | Boards | Length | Contents | Notes |", "|---|---|---|---|---|---|"]
        for name, kind, mins, n, warns in report["datasets"]:
            boards = "W + A, B, C, D" + ("" if kind in ("normal", "unplugB") else " + X")
            length = f"~{mins} min, {n} lines" if mins else f"{n} lines"
            contents = {"normal": "Normal traffic only, X powered off (16f)",
                        "unplugB": "Reroute trials: B unplugged and replugged, `mark` lines at each",
                        "mixed": "**Held-out TEST set: never train on it**"}.get(kind, f"Jose's `{kind}` session; labels in the matching `.labels.jsonl`")
            notes = "; ".join(warns) if warns else ""
            L.append(f"| `{name}` | {date.today().isoformat()} | {boards} | {length} | {contents} | {notes} |")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    say(f"wrote {path.relative_to(ROOT)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--w", help="W's port")
    ap.add_argument("--x", help="X's port (attack sessions)")
    ap.add_argument("--a", help="A's port (unplugB, delivery, bench)")
    ap.add_argument("--c", help="C's port (optional: without it, delivery is counted from A's ACKs)")
    ap.add_argument("--only", nargs="+", choices=[p[0] for p in PLAN], help="run only these steps")
    ap.add_argument("--trials", type=int, default=10, help="reroute trials (default 10, the section 13 minimum)")
    ap.add_argument("--messages", type=int, default=50, help="delivery test size (default 50)")
    ap.add_argument("--normal-min", type=float, default=20, help="length of the normal recording (default 20)")
    ap.add_argument("--scale", type=float, default=1.0, help="shorten attack sessions, e.g. 0.1 for a dry run")
    ap.add_argument("--list", action="store_true", help="print the plan and exit")
    a = ap.parse_args()

    steps = [p for p in PLAN if not a.only or p[0] in a.only]
    print(f"{'step':<10}{'for':<17}{'min':>5}  setup")
    for key, _, who, mins, setup in steps:
        print(f"{key:<10}{who:<17}{mins:>5}  {setup}")
    print(f"{'':<27}{sum(s[3] for s in steps):>5}  total (plus setup between steps)")
    if a.list:
        return

    need = {"w": any(s[0] != "bench" for s in steps),
            "x": any(s[0] in ATTACKS for s in steps),
            "a": any(s[0] in ("unplugB", "delivery", "bench") for s in steps),
            "c": False}                    # optional: without C on the laptop, A's ACKs are used
    missing = [f"--{k}" for k, v in need.items() if v and not getattr(a, k)]
    if missing:
        raise SystemExit(f"these steps need {' '.join(missing)} (find ports with: python -m serial.tools.list_ports)")

    DATASETS.mkdir(parents=True, exist_ok=True)
    w = Board(a.w, "W", is_w=True) if need["w"] else None
    nodes = {}

    def node(k):                                    # open A / C only when a step needs them
        if k not in nodes:
            nodes[k] = Board(getattr(a, k), k.upper())
        return nodes[k]
    say("W clock set; give A-D ~20 s to show SYNC")
    report = {"datasets": []}
    try:
        for key, kind, who, mins, setup in steps:
            print("\n" + "=" * 70)
            say(f"STEP {key} ({who}, ~{mins} min)")
            if not ask(setup):
                say(f"skipped {key}")
                continue
            try:
                if key == "normal":
                    record_w_only(w, kind, a.normal_min, report)
                elif key in ATTACKS:
                    record_attack(w, a.x, key, report, a.scale)
                elif key == "unplugB":
                    reroute_trials(w, node("a"), node("c") if a.c else None, a.trials, report)
                elif key == "delivery":
                    delivery_test(node("a"), node("c") if a.c else None, a.messages, report)
                elif key == "bench":
                    bench(node("a"), report)
            except KeyboardInterrupt:
                say(f"{key} interrupted; moving on (Ctrl+C again within 3 s to quit)")
                time.sleep(3)
            except Exception as e:                  # e.g. a port that isn't there: skip the step, keep going
                say(f"{key} FAILED: {e}  (check ports: python -m serial.tools.list_ports)")
            write_report(report)                            # after every step, so nothing is lost
    except KeyboardInterrupt:
        say("quitting")
    finally:
        write_report(report)
        print("\nNext: check each attack recording (RECORDING.md part 4), paste the README rows from the report,"
              "\ncommit ips/datasets/*.jsonl + the report (never keys_X.h), and tell Hannan which file is `mixed`.")


if __name__ == "__main__":
    main()
