#!/usr/bin/env python3
"""Tests for security/gm_pcap.py and security/ghostmesh.lua.

    python security/test_gm_pcap.py

1. Unit checks of the capture header and pcap layout.
2. Converts every recorded dataset in ips/datasets/, then decodes it with tshark + the Lua dissector
   and checks every packet's decoded fields against the JSON line it came from (skipped if tshark
   isn't installed).
3. --follow: lines appended to a growing log come out as pcap packets, half-written lines wait.
"""
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import gm_pcap  # noqa: E402

LUA = HERE / "ghostmesh.lua"
DATASETS = sorted((REPO / "ips" / "datasets").glob("*.jsonl"))
DATASETS = [p for p in DATASETS if not p.name.endswith(".labels.jsonl")]

results = []
def ok(cond, name):
    results.append((bool(cond), name))


def read_pcap(data):
    """[(ts, bytes)] from a classic pcap written by gm_pcap."""
    magic, vmaj, vmin, _, _, snap, link = struct.unpack("<IHHiIII", data[:24])
    assert magic == 0xA1B2C3D4 and link == gm_pcap.DLT_USER0
    out, i = [], 24
    while i < len(data):
        sec, usec, incl, orig = struct.unpack("<IIII", data[i:i + 16])
        out.append((sec + usec / 1e6, data[i + 16:i + 16 + incl]))
        i += 16 + incl
    return out


def sample_line(**over):
    rec = {"t": 1795052674.387, "mac": "3c:0f:02:e3:bb:00", "pseudo": "23c91361", "type": "DATA",
           "msg_id": "bef6824f1a2b6f4e", "ttl": 3, "hop": 2, "rssi": -73, "len": 240, "link_ok": True,
           "node": "A", "id_ok": True, "epoch": 31753, "flags": 0, "rx_us": 15593875, "rate": 0,
           "sig_mode": 0, "mcs": 0, "raw": bytes(range(240)).hex()}
    rec.update(over)
    return json.dumps(rec) + "\n"


def unit_tests():
    rec = json.loads(sample_line())
    h = gm_pcap.capture_header(rec)
    ok(len(h) == 16, "capture header is 16 bytes")
    magic, ver, hl, flags, rssi, node, rate, sig, mcs, rx, rsv = struct.unpack(">2sBBBbBBBBIH", h)
    ok((magic, ver, hl) == (b"GM", 1, 16), "magic GM, version 1, length 16")
    ok(flags == 0x0F, "flags: link_ok, id_ok, node, rx_us all set")
    ok(rssi == -73 and chr(node) == "A" and rx == 15593875, "rssi, node and rx_us encoded")
    h2 = gm_pcap.capture_header(json.loads(sample_line(link_ok=False, id_ok=False, node="?")))
    ok(h2[4] == 0x0C and chr(h2[6]) == "?", "bad link_tag / id and unknown node encoded")
    rec3 = json.loads(sample_line()); del rec3["node"]; del rec3["rx_us"]
    ok(gm_pcap.capture_header(rec3)[4] == 0x03 and gm_pcap.capture_header(rec3)[6] == 0,
       "missing optional fields leave their flag bits clear")

    lines = [sample_line(), sample_line(t=100.0), '{"ev":"status"}\n', "garbage\n",
             sample_line(raw="00" * 10), json.dumps({"t": 1795052675.0, "type": "DATA"}) + "\n"]
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "in.jsonl"
        src.write_text("".join(lines))
        buf = io.BytesIO()
        stats = gm_pcap.convert(str(src), buf)
    pk = read_pcap(buf.getvalue())
    ok(stats.packets == 1 and len(pk) == 1, "only the valid frame becomes a packet")
    ok((stats.no_clock, stats.events, stats.bad, stats.no_raw) == (1, 2, 1, 1),
       "skips: before clock, events/garbage, wrong length, no raw")
    ts, data = pk[0]
    ok(abs(ts - 1795052674.387) < 1e-6, "timestamp is the mesh clock t")
    ok(data[16:] == bytes(range(240)), "frame bytes follow the header unchanged")


def tshark_path():
    for p in (shutil.which("tshark"), r"C:\Program Files\Wireshark\tshark.exe", "/usr/bin/tshark",
              "/Applications/Wireshark.app/Contents/MacOS/tshark"):
        if p and os.path.exists(p):
            return p
    return None


FIELDS = ["ghostmesh.type", "ghostmesh.ttl", "ghostmesh.hop", "ghostmesh.src_pseudo", "ghostmesh.epoch",
          "ghostmesh.msg_id", "ghostmesh.flags", "ghostmesh.cap.rssi", "ghostmesh.cap.node",
          "ghostmesh.cap.link_ok", "ghostmesh.cap.id_ok", "_ws.expert.message"]
TYPE_NUM = {"DATA": 1, "HELLO": 2, "CTRL": 3, "KEYS": 4}


def dataset_tests(tshark):
    for ds in DATASETS:
        with tempfile.TemporaryDirectory() as d:
            pcap = Path(d) / "x.pcap"
            with open(pcap, "wb") as out:
                stats = gm_pcap.convert(str(ds), out)
            recs = []
            for line in open(ds, encoding="utf-8"):
                r = gm_pcap.parse(line)
                if r and gm_pcap.record_to_packet(r):
                    recs.append(r)
            ok(stats.packets == len(recs) and stats.packets > 0, f"{ds.name}: {stats.packets} packets written")
            if not tshark:
                continue
            cmd = [tshark, "-X", f"lua_script:{LUA}", "-r", str(pcap), "-T", "fields", "-E", "separator=\t"]
            for f in FIELDS:
                cmd += ["-e", f]
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
            ok(res.returncode == 0 and "Lua" not in res.stderr, f"{ds.name}: tshark ran the dissector cleanly")
            rows = [r.split("\t") for r in res.stdout.splitlines()]
            ok(len(rows) == len(recs), f"{ds.name}: tshark decoded every packet ({len(rows)})")
            bad, bugs = 0, 0
            for row, rec in zip(rows, recs):
                ty, ttl, hop, src, ep, mid, fl, rssi, node, lok, iok, expert = (row + [""] * 12)[:12]
                if "Dissector bug" in expert or "Malformed" in expert:
                    bugs += 1
                want = (TYPE_NUM.get(rec["type"]), rec["ttl"], rec["hop"], int(rec["pseudo"], 16), rec["epoch"],
                        rec["msg_id"], rec["flags"], rec["rssi"], rec.get("node", ""),
                        bool(rec["link_ok"]), bool(rec["id_ok"]))
                got = (int(ty), int(ttl), int(hop), int(src, 16), int(ep), mid.replace(":", ""),
                       int(fl, 16), int(rssi), node, lok in ("1", "True"), iok in ("1", "True"))
                bad += got != want
            ok(bad == 0, f"{ds.name}: every decoded field matches the JSON line ({bad} mismatches)")
            ok(bugs == 0, f"{ds.name}: no dissector bugs or malformed packets")


def follow_test():
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "live.jsonl"
        src.write_text(sample_line())                      # already there: skipped without --from-start
        out = io.BytesIO()
        stop = threading.Event()
        th = threading.Thread(target=lambda: gm_pcap.follow(str(src), out, poll_s=0.02, stop=stop), daemon=True)
        th.start()
        time.sleep(0.2)
        with open(src, "a") as f:
            f.write(sample_line(t=1795052680.0))
            f.flush()
            half = sample_line(t=1795052681.0)
            f.write(half[:50]); f.flush()
            time.sleep(0.2)
            n_mid = len(read_pcap(out.getvalue()))
            f.write(half[50:]); f.flush()
        time.sleep(0.3)
        pk = read_pcap(out.getvalue())
        stop.set()
        th.join(timeout=2)
    ok(n_mid == 1, "--follow: new line streamed; half-written line waits")
    ok(len(pk) == 2 and abs(pk[1][0] - 1795052681.0) < 1e-6, "--follow: completed line streamed")


def main():
    unit_tests()
    tshark = tshark_path()
    dataset_tests(tshark)
    follow_test()
    for good, name in results:
        print(f"{'PASS' if good else 'FAIL'}  {name}")
    if not tshark:
        print("NOTE  tshark not found: dissector checks skipped")
    failed = sum(not g for g, _ in results)
    print(f"\n{len(results) - failed}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
