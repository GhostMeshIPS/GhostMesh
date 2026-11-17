#!/usr/bin/env python3
"""GhostMesh laptop chat client (PROTOCOL.md §10).

    pip install pyserial
    python tools/chat_client.py --port COM5              # macOS: /dev/cu.usbmodem*, Linux: /dev/ttyACM0
    python tools/chat_client.py --port COM5 --sync       # also set the node's clock (bench test, no watchtower)

Type `B: hello` to send to node B.
  /time     set this node's clock from the laptop (DEBUG: the watchtower's beacon is the real source)
  /status   counters        /verbose  toggle every routing event      /raw  print raw JSON
Lines starting with `{` are sent as-is. Ctrl-C quits.
"""
import argparse
import json
import sys
import threading
import time

import serial

QUIET = {"log", "oled", "debug_time"}


def fmt(ev):
    e = ev.get("ev")
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
        return (f"   radio: airtime {ev['airtime_avg_us']} us/frame, rx overflow {ev['rx_overflow']}, "
                f"tx fail {ev['tx_fail']}, heap {ev['free_heap']}, rotate_mac {ev['rotate_mac']}, "
                f"rssi_gate {ev['rssi_gate']}, allowlist {ev['allow_n']}")
    if e in ("error", "warning"):
        return f"!! {e}: {ev.get('reason')}  {json.dumps({k: v for k, v in ev.items() if k not in ('ev', 'reason')}) if len(ev) > 2 else ''}"
    return "   " + json.dumps(ev)


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
        if state["raw"]:
            print(line, flush=True)
        elif ev.get("ev") not in QUIET or state["verbose"]:
            print(fmt(ev), flush=True)


def send(port, obj):
    port.write((json.dumps(obj) + "\n").encode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--sync", action="store_true", help="set the node's clock from this laptop at start (DEBUG)")
    args = ap.parse_args()

    port = serial.Serial(args.port, args.baud, timeout=1)
    state = {"raw": False, "verbose": False}
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
                print("   usage:  B: your message   |  /time  /status  /verbose  /raw  |  {raw json}")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
