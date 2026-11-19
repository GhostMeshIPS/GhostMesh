#!/usr/bin/env python3
"""GhostMesh laptop chat client (PROTOCOL.md §10).

    pip install pyserial
    python tools/chat_client.py --port COM5              # macOS: /dev/cu.usbmodem*, Linux: /dev/ttyACM0
    python tools/chat_client.py --port COM5 --sync       # also set the node's clock (bench test, no watchtower)

Type `B: hello` to send to node B.
  /time         set the clock from the laptop (watchtower: the real source; node: DEBUG only)
  /status       counters        /verbose  toggle routing events / watchtower log lines   /raw  raw JSON
  /auto C 20    node sends a test message to C every 20 s once synced (saved on the board; works unplugged)
  /auto off     stop it
  /block C      (watchtower) block node C for 2 min      /unblock C
  /mark text    write a timestamped note into the --log file (e.g. /mark unplugged B)

  --log FILE    save every JSON line from the board (W: the IPS log) to FILE, e.g. data/normal_01.jsonl
Lines starting with `{` are sent as-is. Ctrl-C quits.
"""
import argparse
import json
import os
import sys
import threading
import time

import serial

QUIET = {"log", "oled", "debug_time"}


def fmt_log(ev):
    """Watchtower log line (ips/schema.py)."""
    ok = "" if ev.get("link_ok") else "  BAD LINK TAG"
    idm = "" if ev.get("id_ok", True) else "  (MAC doesn't match pseudonym!)"
    return (f"   W heard {ev.get('node', '?')}: {ev['type']:<5} ttl {ev['ttl']} hop {ev['hop']} "
            f"{ev['rssi']} dBm  pseudo {ev['pseudo']}{ok}{idm}")


def fmt(ev):
    e = ev.get("ev")
    if e is None and "node" in ev and "type" in ev:
        return fmt_log(ev)
    if e == "status" and ev.get("name") == "W":
        nodes = "  ".join(f"{k}:{v['frames']}@{v['rssi']}dBm" for k, v in ev.get("nodes", {}).items())
        return (f"-- W clock {'SET' if ev['clock_set'] else 'NOT SET'} epoch {ev['epoch']}: {ev['frames']} frames, "
                f"{ev['beacons']} beacons, {ev['unknown']} unknown, {ev['bad_link_tag']} bad tag\n   per node  {nodes}")
    if e == "clock_set":
        return f"-- W clock set, epoch {ev['epoch']}: beacons every 10 s from now"
    if e == "auto":
        return f"-- auto: {'every ' + str(ev['every_s']) + ' s to ' + ev['to'] if ev['every_s'] else 'off'}"
    if e == "rx":
        return f"<< {ev['from']}: {ev['text']}   ({ev.get('rssi', '?')} dBm)"
    if e == "sent":
        return f"   ✓   to {ev['to']} (#{ev['handle']})"
    if e == "delivered":
        return f"   ✓✓  to {ev['to']} (#{ev['handle']})"
    if e == "failed":
        return f"   ✗   to {ev['to']} (#{ev['handle']}) NOT delivered"
    if e == "queued":
        return f"   …   queued for {ev['to']} until the clock syncs ({ev['waiting']} waiting)"
    if e == "boot":
        fp = ev["fp"]
        return (f"-- node {ev['name']} (id {ev['id']}) fw {ev['fw']}, {ev['peers']} peers\n"
                f"   fingerprints: self {fp['self']}  network {fp['network']}  watchtower {fp['watchtower']}"
                f"   (compare with firmware/config/roster.json)")
    if e == "synced":
        return f"-- SYNCED, epoch {ev['epoch']}, MAC change took {ev['mac_outage_us'] / 1000:.1f} ms"
    if e == "epoch":
        return f"-- epoch {ev['epoch']}: new pseudonym {ev['pseudo']}, MAC change took {ev['mac_outage_us'] / 1000:.1f} ms"
    if e == "radio":
        line = (f"   radio: airtime {ev.get('airtime_avg_us', '?')} us/frame, rx overflow {ev.get('rx_overflow', '?')}, "
                f"tx fail {ev.get('tx_fail', '?')}, heap {ev.get('free_heap', '?')}")
        if "rotate_mac" in ev:      # node-only fields
            line += (f", rotate_mac {ev['rotate_mac']}, rssi_gate {ev.get('rssi_gate')}, "
                     f"allowlist {ev.get('allow_n')}, auto {ev.get('auto_to')}/{ev.get('auto_every_s')}s")
        return line
    if e in ("error", "warning"):
        return f"!! {e}: {ev.get('reason')}  {json.dumps({k: v for k, v in ev.items() if k not in ('ev', 'reason')}) if len(ev) > 2 else ''}"
    return "   " + json.dumps(ev)


def safe_fmt(ev):
    """Never let one unexpected line kill the reader thread."""
    try:
        return fmt(ev)
    except (KeyError, TypeError, ValueError):
        return "   " + json.dumps(ev)


def is_log(ev):
    return ev.get("ev") is None and "node" in ev


def log_write(state, line):
    if state["logf"]:
        state["logf"].write(line + "\n")
        state["logf"].flush()


def reader(port, state):
    while True:
        try:
            line = port.readline().decode("utf-8", errors="replace").strip()
        except serial.SerialException:
            print("!! serial port closed (board reset or unplugged?)")
            return
        if not line.startswith("{"):
            if line and state["raw"]:
                print("   (dbg) " + line)
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        log_write(state, line)
        if state["raw"]:
            print(line, flush=True)
        elif is_log(ev):
            state["log_lines"] += 1
            if state["verbose"]:
                print(safe_fmt(ev), flush=True)
        elif ev.get("ev") not in QUIET or state["verbose"]:
            print(safe_fmt(ev), flush=True)


def send(port, obj):
    port.write((json.dumps(obj) + "\n").encode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--sync", action="store_true", help="set the clock from this laptop at start")
    ap.add_argument("--log", help="append every JSON line to this file (JSON lines)")
    args = ap.parse_args()

    port = serial.Serial(args.port, args.baud, timeout=1)
    state = {"raw": False, "verbose": False, "log_lines": 0, "logf": None}
    if args.log:
        os.makedirs(os.path.dirname(os.path.abspath(args.log)), exist_ok=True)   # create ips/data/raw/ etc.
        state["logf"] = open(args.log, "a", encoding="utf-8")
        print(f"   logging to {args.log}")
    threading.Thread(target=reader, args=(port, state), daemon=True).start()
    send(port, {"cmd": "status"})
    if args.sync:
        send(port, {"cmd": "set_time", "unix_ms": int(time.time() * 1000)})

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            if line == "/raw":
                state["raw"] = not state["raw"]
            elif line == "/verbose":
                state["verbose"] = not state["verbose"]
                send(port, {"cmd": "verbose", "on": state["verbose"]})
            elif line == "/time":
                send(port, {"cmd": "set_time", "unix_ms": int(time.time() * 1000)})
            elif line == "/status":
                send(port, {"cmd": "status"})
                if state["log_lines"]:
                    print(f"   ({state['log_lines']} watchtower log lines so far; /verbose to see them)")
            elif line.startswith("/mark"):
                note = line[5:].strip() or "mark"
                log_write(state, json.dumps({"ev": "mark", "t": round(time.time(), 3), "note": note}))
                print(f"   marked: {note}" + ("" if state["logf"] else "  (no --log file, not saved)"))
            elif line.startswith("/block ") or line.startswith("/unblock "):
                cmd, node = line[1:].split(maxsplit=1)
                log_write(state, json.dumps({"ev": "mark", "t": round(time.time(), 3), "note": f"{cmd} {node.strip().upper()}"}))
                msg = {"cmd": cmd, "node": node.strip().upper()}
                if cmd == "block":
                    msg.update(reason="flood", until=round(time.time() + 120, 3))
                send(port, msg)
            elif line.startswith("/auto"):
                parts = line.split()
                if len(parts) == 3 and len(parts[1]) == 1 and parts[2].isdigit():
                    send(port, {"cmd": "auto", "to": parts[1].upper(), "every_s": int(parts[2])})
                else:
                    send(port, {"cmd": "auto", "to": "", "every_s": 0})

            elif line.startswith("{"):
                port.write((line + "\n").encode())
            elif ":" in line and len(line.split(":", 1)[0].strip()) == 1:
                to, text = line.split(":", 1)
                text = text.strip()
                if len(text.encode()) > 152:
                    print("   message too long (152 bytes max)")
                    continue
                send(port, {"cmd": "send", "to": to.strip().upper(), "text": text})
            else:
                print("   usage:  B: your message  |  /time /status /verbose /raw  |  /auto C 20, /auto off  |  /block C, /unblock C")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
