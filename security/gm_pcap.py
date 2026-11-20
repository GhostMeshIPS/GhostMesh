"""Turn watchtower logs into .pcap files that Wireshark opens with the GhostMesh dissector.

    python security/gm_pcap.py ips/datasets/2026-11-18_normal_01.jsonl            # -> ..._normal_01.pcap
    python security/gm_pcap.py in.jsonl out.pcap
    python security/gm_pcap.py --follow ips/data/raw/run1.jsonl - | wireshark -k -i -   # live view

Input: the watchtower's JSON lines (PROTOCOL.md §10–11, `ips/schema.py`), as saved by
`tools/chat_client.py --log`. Only frame lines that carry `raw` (the full 240-byte frame) and a set
mesh clock (`t` >= 1e9) become packets; event lines ({"ev": ...}) are skipped.

Each packet (link type DLT_USER0 = 147) is a 16-byte capture header followed by the 240 on-air bytes.
The capture header is watchtower metadata, NOT something a sniffer would see on the air:

    offset size  field
    0      2     magic "GM"
    2      1     version (1)
    3      1     header length (16)
    4      1     flags: bit0 link_ok, bit1 id_ok, bit2 node present, bit3 rx_us present
    5      1     rssi (dBm, signed)
    6      1     node: ASCII 'A'-'D', 'W', 'X', '?' (0 if the log has no node field)
    7      1     rate
    8      1     sig_mode
    9      1     mcs
    10     4     rx_us (radio microseconds, big-endian, wraps)
    14     2     reserved (0)

Packet timestamps are the mesh clock `t` (the same Unix clock as the IPS and the labels files).
Decision: project-breakdown.md §4.7 (pcap exporter). Dissector: security/ghostmesh.lua.
"""
import argparse
import json
import os
import struct
import sys
import time

DLT_USER0 = 147
FRAME_BYTES = 240
HDR_BYTES = 16
MIN_MESH_TIME = 1e9            # before W's clock is set, `t` is seconds since boot

F_LINK_OK, F_ID_OK, F_NODE, F_RX_US = 0x01, 0x02, 0x04, 0x08


def pcap_global_header(linktype=DLT_USER0, snaplen=65535):
    """Classic libpcap header, microsecond timestamps, little-endian."""
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)


def capture_header(rec):
    """16-byte GhostMesh capture header from one watchtower log record."""
    flags = 0
    if rec.get("link_ok") in (True, "true", "True"):
        flags |= F_LINK_OK
    if rec.get("id_ok") in (True, "true", "True"):
        flags |= F_ID_OK
    node = rec.get("node")
    node_b = 0
    if isinstance(node, str) and len(node) == 1 and node.isascii():
        flags |= F_NODE
        node_b = ord(node)
    rx_us = rec.get("rx_us")
    if isinstance(rx_us, int):
        flags |= F_RX_US
    else:
        rx_us = 0
    rssi = max(-128, min(127, int(rec.get("rssi", 0))))

    def u8(name):
        v = rec.get(name, 0)
        return v & 0xFF if isinstance(v, int) else 0

    return struct.pack(">2sBBBbBBBBIH", b"GM", 1, HDR_BYTES, flags, rssi, node_b,
                       u8("rate"), u8("sig_mode"), u8("mcs"), rx_us & 0xFFFFFFFF, 0)


def record_to_packet(rec):
    """(timestamp, packet bytes) for a frame line, or None if it can't become a packet."""
    raw, t = rec.get("raw"), rec.get("t")
    if not isinstance(raw, str) or not isinstance(t, (int, float)) or t < MIN_MESH_TIME:
        return None
    try:
        frame = bytes.fromhex(raw)
    except ValueError:
        return None
    if len(frame) != FRAME_BYTES:
        return None
    return float(t), capture_header(rec) + frame


def pcap_record(ts, data):
    sec = int(ts)
    usec = int(round((ts - sec) * 1_000_000))
    if usec >= 1_000_000:
        sec, usec = sec + 1, usec - 1_000_000
    return struct.pack("<IIII", sec, usec, len(data), len(data)) + data


def parse(line):
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    return rec if isinstance(rec, dict) and "ev" not in rec else None


class Stats:
    def __init__(self):
        self.packets = self.no_raw = self.no_clock = self.bad = self.events = 0

    def take(self, line):
        """Packet for this line, or None (and count why)."""
        rec = parse(line)
        if rec is None:
            self.events += 1
            return None
        if "raw" not in rec:
            self.no_raw += 1
            return None
        t = rec.get("t")
        if isinstance(t, (int, float)) and t < MIN_MESH_TIME:
            self.no_clock += 1
            return None
        pkt = record_to_packet(rec)
        if pkt is None:
            self.bad += 1
            return None
        self.packets += 1
        return pkt

    def summary(self):
        return (f"{self.packets} packets; skipped {self.events} event/non-JSON lines, "
                f"{self.no_raw} frames without raw, {self.no_clock} before W's clock was set, "
                f"{self.bad} malformed")


def convert(in_path, out):
    stats = Stats()
    out.write(pcap_global_header())
    with open(in_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            pkt = stats.take(line)
            if pkt:
                out.write(pcap_record(*pkt))
    return stats


def follow(in_path, out, from_start=False, poll_s=0.2, stop=None):
    """Stream a growing log into `out` as pcap until Ctrl+C (or until `stop`, a threading.Event, is set)."""
    stats = Stats()
    out.write(pcap_global_header())
    out.flush()
    running = lambda: stop is None or not stop.is_set()
    while running() and not os.path.exists(in_path):
        time.sleep(poll_s)
    if not running():
        return stats
    with open(in_path, encoding="utf-8", errors="replace") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        buf = ""
        while running():
            chunk = f.readline()
            if not chunk:
                time.sleep(poll_s)
                continue
            buf += chunk
            if not buf.endswith("\n"):
                continue                        # half-written line: wait for the rest
            pkt = stats.take(buf)
            buf = ""
            if pkt:
                out.write(pcap_record(*pkt))
                out.flush()
    return stats


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("input", help="watchtower .jsonl log")
    ap.add_argument("output", nargs="?", help="output .pcap (default: input name with .pcap; '-' = stdout)")
    ap.add_argument("--follow", action="store_true", help="keep reading as the log grows (live view)")
    ap.add_argument("--from-start", action="store_true", help="with --follow: include lines already in the file")
    args = ap.parse_args(argv)

    out_name = args.output or ("-" if args.follow else os.path.splitext(args.input)[0] + ".pcap")
    out = sys.stdout.buffer if out_name == "-" else open(out_name, "wb")
    try:
        if args.follow:
            try:
                follow(args.input, out, args.from_start)
            except (KeyboardInterrupt, BrokenPipeError):
                pass
            return 0
        stats = convert(args.input, out)
    finally:
        if out is not sys.stdout.buffer:
            out.close()
    print(f"{out_name}: {stats.summary()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
