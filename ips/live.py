"""The live IPS: packets in -> 1-second windows -> Random Forest -> alerts / BLOCKs.

Run on a replayed log (works today):
    python3 live.py --file test_session.jsonl --speed 10
Run on the real watchtower (when hardware is ready):
    python3 live.py --port /dev/tty.usbserial-0001

Writes what it sees to data/live_windows.jsonl and data/live_events.jsonl,
which dashboard.py reads.
"""
import argparse
import json
import os
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

import joblib
import pandas as pd

from detect import FEATURES, IF_PATH, RF_PATH, iforest_detect, rule_detect, train_rf
from explain import EVIDENCE, explain
from features import WINDOW, build_features
from ingest import open_serial, replay, read_file, serial_stream
from retention import WINDOWS_MAX_AGE_S, prune_jsonl
from schema import encode_cmd, make_block_cmd, make_unblock_cmd

BUFFER_SECONDS = 10   # recent history kept in memory (needed for gaps across windows)
CONFIRM_WINDOWS = 2   # attack must be seen in this many windows in a row before acting
BLOCK_SECONDS = 60    # how long a BLOCK lasts before it expires

BLOCK_ATTACKS = {"flood", "routing", "replay"}   # we BLOCK these
ALERT_ONLY = {"spoof"}                           # blocking a spoofed ID would cut off the real victim

WINDOWS_LOG = "data/live_windows.jsonl"
EVENTS_LOG = "data/live_events.jsonl"
EXPLAIN_LOG = "data/live_explanations.jsonl"   # LLM summaries, written a few seconds after each event
STATUS_PATH = "data/live_status.json"          # replay or watchtower, speed, start time (for the dashboard)
COMMANDS_LOG = "data/operator_commands.jsonl"  # Block / Unblock / Confirm / Dismiss clicks from the dashboard
MODE_PATH = "data/ips_mode.json"               # {"auto_block": true/false}, set by the dashboard switch
PRUNE_EVERY_S = 600                            # check the 6-hour log limit every 10 minutes


class LiveIPS:
    def __init__(self, model, send_cmd, iforest=None):
        self.model = model                    # Random Forest: makes the decisions
        self.iforest = iforest                # Isolation Forest: only logged, for the rule-vs-AI comparison
        self.send_cmd = send_cmd              # function that delivers a BLOCK (print, serial, ...)
        self.buffer = []                      # recent packets
        self.current_window = None
        self.streak = defaultdict(int)        # mac -> attack windows in a row
        self.streak_rows = defaultdict(list)  # mac -> the windows in the current streak (the evidence)
        self.last_attack_w = {}               # mac -> last window it was flagged in
        self.blocks = {}                      # mac -> time the block expires
        self.pending = {}                     # mac -> (attack, evidence) waiting for the operator (confirm mode)
        self.dismissed = set()                # macs whose current attack the operator chose to ignore
        self.cmd_offset = 0                   # how far into COMMANDS_LOG we've read
        self.recent_normal = deque(maxlen=300)   # recent normal windows: "what normal looks like"
        self.offset = 0.0                     # real clock time minus packet time (t), from rx_t
        self.last_prune = 0.0
        # One background worker for the LLM, so a slow explanation never delays a BLOCK
        self.explainer = ThreadPoolExecutor(max_workers=1)

    def feed(self, pkt):
        """Take one packet. When a new second starts, analyse the second that just ended."""
        if pkt["type"] == "BLOCK":
            return                            # our own BLOCK broadcasts are not traffic to judge
        # t = the packet's own timeline (used for all the maths);
        # offset turns it into real clock time for display ("wall" in the logs)
        self.offset = pkt.get("rx_t", pkt["t"]) - pkt["t"]
        w = int(pkt["t"] // WINDOW)
        if self.current_window is None:
            self.current_window = w
        if w > self.current_window:           # the previous window is complete
            self.close_window(self.current_window, now=pkt["t"])
            self.current_window = w
        self.buffer.append(pkt)
        # forget packets older than BUFFER_SECONDS
        cutoff = pkt["t"] - BUFFER_SECONDS
        while self.buffer and self.buffer[0]["t"] < cutoff:
            self.buffer.pop(0)

    def close_window(self, w, now):
        self.process_commands(now)            # operator clicks from the dashboard (at most ~1 s old)
        self.expire_blocks(now)
        wall_now = now + self.offset
        if wall_now - self.last_prune > PRUNE_EVERY_S:  # keep only the last 6 hours of windows
            prune_jsonl(WINDOWS_LOG, "wall", WINDOWS_MAX_AGE_S, now=wall_now)
            self.last_prune = wall_now
        feats = build_features(pd.DataFrame(self.buffer))
        rows = feats[feats["window"] == w]
        if rows.empty:
            return
        preds = self.model.predict(rows[FEATURES])
        # How sure the Random Forest is: the share of its 100 trees that voted for the winner
        confs = self.model.predict_proba(rows[FEATURES]).max(axis=1)
        # What the other two detectors would have said (logged for comparison, they don't act)
        rule_says = rule_detect(rows).tolist()
        if_says = iforest_detect(self.iforest, rows).tolist() if self.iforest else [None] * len(rows)
        # Anomaly score: how unusual each window looks to the Isolation Forest.
        # Flipped so that HIGHER = MORE unusual; above 0 = past the model's alarm threshold.
        anomaly = ((-self.iforest.decision_function(rows[FEATURES])).round(3).tolist()
                   if self.iforest else [None] * len(rows))

        for (_, row), pred, conf, by_rule, by_if, score in zip(rows.iterrows(), preds, confs,
                                                                rule_says, if_says, anomaly):
            mac = row["mac"]
            record = {"t": w * WINDOW, "wall": round(w * WINDOW + self.offset, 3),
                      "mac": mac, "pred": pred, "conf": round(float(conf), 3),
                      "rule": by_rule, "iforest": by_if, "anomaly": score,
                      "label": row.get("label"),               # ground truth, only in synthetic data
                      **{f: float(row[f]) for f in FEATURES}}
            log_line(WINDOWS_LOG, record)

            if pred == "normal":
                self.streak[mac] = 0
                self.streak_rows[mac] = []
                self.dismissed.discard(mac)            # a dismissed attack that ended: watch it fresh again
                self.recent_normal.append(record)
                continue
            # Count only CONSECUTIVE attack windows: a gap (node went quiet) restarts the count
            if self.last_attack_w.get(mac) == w - 1:
                self.streak[mac] += 1
            else:
                self.streak[mac] = 1
                self.streak_rows[mac] = []
                self.dismissed.discard(mac)
            self.last_attack_w[mac] = w
            self.streak_rows[mac].append(record)

            if self.streak[mac] >= CONFIRM_WINDOWS:
                self.respond(mac, pred, now, first=self.streak[mac] == CONFIRM_WINDOWS)

    def evidence(self, mac):
        """Why we're acting: average features, confidence, and what the other detectors said."""
        rows = self.streak_rows[mac]
        return {
            "conf": round(sum(r["conf"] for r in rows) / len(rows), 3),
            "rule_caught": any(r["rule"] for r in rows),
            "iforest_caught": None if rows[0]["iforest"] is None else any(r["iforest"] for r in rows),
            "features": {f: round(sum(r[f] for r in rows) / len(rows), 3) for f in FEATURES},
        }

    def respond(self, mac, attack, now, first):
        """Act on a confirmed attack. `first` = the moment it was confirmed (avoid repeat alerts)."""
        if attack in ALERT_ONLY:
            if first:
                self.event(now, "ALERT", mac, attack, "alert only (blocking would cut off the victim)",
                           self.evidence(mac))
        elif attack in BLOCK_ATTACKS and mac not in self.blocks and mac not in self.dismissed:
            # new attack, or still attacking after an old block expired
            if auto_block_enabled():
                self.block(mac, attack, now, self.evidence(mac), f"blocked for {BLOCK_SECONDS}s")
            elif mac not in self.pending:
                # Confirm-click mode: ask the operator instead of blocking on our own
                ev = self.evidence(mac)
                self.pending[mac] = (attack, ev)
                self.event(now, "PENDING", mac, attack, "waiting for the operator to confirm the BLOCK", ev)

    def block(self, mac, attack, now, evidence, note):
        """Send a BLOCK to the watchtower (which signs and broadcasts it) and record it."""
        pseudo = next((p["pseudo"] for p in reversed(self.buffer) if p["mac"] == mac), "")
        until = now + BLOCK_SECONDS
        self.blocks[mac] = until
        self.pending.pop(mac, None)
        self.send_cmd(make_block_cmd(mac, pseudo, attack, until))
        self.event(now, "BLOCK", mac, attack, note, evidence)

    def process_commands(self, now):
        """Apply new operator clicks (written by the dashboard) since we last looked."""
        if not os.path.exists(COMMANDS_LOG):
            return
        with open(COMMANDS_LOG) as f:
            f.seek(self.cmd_offset)
            lines = f.readlines()
            self.cmd_offset = f.tell()
        for line in lines:
            try:
                cmd = json.loads(line)
            except json.JSONDecodeError:
                continue
            mac, action = cmd.get("mac"), cmd.get("action")
            if action == "block" and mac not in self.blocks:
                attack, ev = self.pending.get(mac, ("manual", None))   # confirming a pending alert, or a manual block
                self.block(mac, attack, now, ev, f"blocked by the operator for {BLOCK_SECONDS}s")
            elif action == "unblock" and mac in self.blocks:
                del self.blocks[mac]
                self.send_cmd(make_unblock_cmd(mac))
                self.event(now, "UNBLOCK", mac, "", "unblocked by the operator")
            elif action == "dismiss" and mac in self.pending:
                attack, _ = self.pending.pop(mac)
                self.dismissed.add(mac)                # don't ask again until this attack stops
                self.event(now, "DISMISS", mac, attack, "operator dismissed the alert")

    def expire_blocks(self, now):
        for mac, until in list(self.blocks.items()):
            if now >= until:
                del self.blocks[mac]
                self.event(now, "UNBLOCK", mac, "", "block expired")

    def event(self, t, kind, mac, attack, note, evidence=None):
        e = {"t": round(t, 3), "wall": round(t + self.offset, 3), "kind": kind, "mac": mac,
             "attack": attack, "note": note, "evidence": evidence}
        extra = f"  ({evidence['conf']:.0%} sure)" if evidence else ""
        print(f"[{kind:7}] {mac}  {attack:8} {note}{extra}")
        log_line(EVENTS_LOG, e)
        if evidence:                                   # BLOCK / ALERT -> explain it in the background
            self.explainer.submit(self.write_explanation, e, self.normal_baseline())

    def normal_baseline(self):
        """Median of recent normal windows, per evidence feature."""
        if not self.recent_normal:
            return {}
        df = pd.DataFrame(list(self.recent_normal))
        return df[list(EVIDENCE)].median().to_dict()

    def write_explanation(self, event, baseline):
        """Runs on the background thread: ask the LLM (or template), then log the result."""
        try:
            text, source = explain(event, baseline, BLOCK_SECONDS)
        except Exception as err:                       # the explainer must never crash the IPS
            text, source = f"(no explanation: {err})", "error"
        print(f"  [explain/{source}] {text}")
        log_line(EXPLAIN_LOG, {"event_t": event["t"], "mac": event["mac"], "text": text, "source": source})


def auto_block_enabled():
    """The dashboard's Auto-block switch. Missing/unreadable file = auto (the safe default for a demo)."""
    try:
        with open(MODE_PATH) as f:
            return bool(json.load(f).get("auto_block", True))
    except (OSError, ValueError):
        return True


def log_line(path, obj):
    """Append one JSON line to a log file (the dashboard reads these)."""
    with open(path, "a") as f:
        f.write(json.dumps(obj, default=str) + "\n")


def load_model():
    """Load the saved Random Forest; if there isn't one yet, train it now."""
    if os.path.exists(RF_PATH):
        return joblib.load(RF_PATH)
    print(f"{RF_PATH} not found, training on train_session.jsonl ...")
    return train_rf(build_features(read_file("train_session.jsonl")))


def load_iforest():
    """The Isolation Forest is optional: only used to show rule vs. AI on the dashboard."""
    return joblib.load(IF_PATH) if os.path.exists(IF_PATH) else None


def main():
    parser = argparse.ArgumentParser(description="GhostMesh live IPS")
    parser.add_argument("--file", help="replay a .jsonl log")
    parser.add_argument("--port", help="watchtower serial port, e.g. /dev/tty.usbserial-0001")
    parser.add_argument("--speed", type=float, default=1.0, help="replay speed (10 = 10x faster)")
    args = parser.parse_args()

    # Start each run with empty logs so the dashboard shows only this run
    os.makedirs("data", exist_ok=True)
    for path in (WINDOWS_LOG, EVENTS_LOG, EXPLAIN_LOG, COMMANDS_LOG):
        open(path, "w").close()

    # Tell the dashboard where the data comes from (shown as LIVE or "5x replay")
    with open(STATUS_PATH, "w") as f:
        json.dump({"mode": "watchtower" if args.port else "replay", "speed": args.speed,
                   "source": args.port or args.file or "test_session.jsonl", "started": time.time()}, f)

    if args.port:
        ser = open_serial(args.port)
        source = serial_stream(ser)
        send_cmd = lambda cmd: ser.write(encode_cmd(cmd))        # real BLOCK to the watchtower
    else:
        source = replay(args.file or "test_session.jsonl", speed=args.speed)
        send_cmd = lambda cmd: print("  -> would send:", json.dumps(cmd))   # no hardware yet

    ips = LiveIPS(load_model(), send_cmd, iforest=load_iforest())
    print("IPS running. Ctrl+C to stop.")
    try:
        for pkt in source:
            ips.feed(pkt)
    except KeyboardInterrupt:
        print("\nstopped")
    ips.explainer.shutdown(wait=True)        # let any explanation still being written finish


if __name__ == "__main__":
    main()
