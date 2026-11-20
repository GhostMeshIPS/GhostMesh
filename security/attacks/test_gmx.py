#!/usr/bin/env python3
"""Tests for security/attacks/gmx.py (attacker X library, decision 18). No hardware needed.

    python security/attacks/test_gmx.py

1. Crypto matches the spec's test vectors and, when gcc is available, the firmware's own gm_crypto.c
   on random inputs (pseudonym, MAC, link_tag).
2. Frames: parse/serialize round-trip on every real frame in ips/datasets, fields match the JSON log,
   link_tag re-signing, CTRL TIME parsing.
3. Keys: a throwaway keygen run (temp dir) -> load_keys(keys_X.h) -> fingerprint matches the roster.
4. MeshClock from TIME beacons, paced() rate and cap, LabelLog rows loadable by ips/ingest.read_labeled.
5. The X firmware source and platformio.ini: X build excludes node/watchtower mains and keys; node and
   watchtower builds exclude src/attacker/ (the raw-transmit command).
"""
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
FW = REPO / "firmware"
sys.path.insert(0, str(HERE))
import gmx  # noqa: E402

results = []
def ok(cond, name):
    results.append((bool(cond), name))


def find_cc():
    cc = os.environ.get("GM_CC") or shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if not cc and os.name == "nt" and Path(r"C:\msys64\ucrt64\bin\gcc.exe").exists():
        cc = r"C:\msys64\ucrt64\bin\gcc.exe"
    return cc


def c_arr(b):
    return "{" + ",".join(str(x) for x in b) + "}"


def test_vectors():
    ps = bytes(range(32))
    ok(gmx.pseudonym(ps, 0x0102) == 0xAC341587, "pseudonym test vector (ac341587)")
    ok(gmx.mac_str(gmx.mac_for(ps, 0x0102)) == "6a:a7:07:ca:0e:dd", "MAC test vector (6a:a7:07:ca:0e:dd)")
    ok(gmx.link_tag(bytes(range(0x20, 0x40)), bytes(range(240))).hex() == "152ee8ad612ca586",
       "link_tag test vector (152ee8ad612ca586)")
    m = gmx.mac_for(os.urandom(32), 7)
    ok(m[0] & 0x03 == 0x02, "derived MACs are locally administered unicast")


def test_against_c():
    cc = find_cc()
    if not cc:
        print("NOTE  no C compiler: firmware cross-check skipped")
        return
    rnd = random.Random(1)
    cases = []
    for _ in range(40):
        cases.append((bytes(rnd.getrandbits(8) for _ in range(32)), rnd.getrandbits(16),
                      bytes(rnd.getrandbits(8) for _ in range(32)), bytes(rnd.getrandbits(8) for _ in range(240))))
    lines = ['#include <stdio.h>', '#include <string.h>', '#include "gm_crypto.h"', "int main(void){"]
    for i, (ps, ep, net, fr) in enumerate(cases):
        lines += [f"{{ const uint8_t ps[32]={c_arr(ps)}; const uint8_t net[32]={c_arr(net)}; const uint8_t fr[240]={c_arr(fr)};",
                  "  uint8_t p[4], m[6], t[8]; rt_frame_t f; memcpy(&f, fr, 240);",
                  f"  gm_pseudonym(ps, {ep}, p); gm_mac(ps, {ep}, m); gm_link_tag(net, &f, t);",
                  "  for(int i=0;i<4;i++)printf(\"%02x\",p[i]); printf(\" \");",
                  "  for(int i=0;i<6;i++)printf(\"%02x\",m[i]); printf(\" \");",
                  "  for(int i=0;i<8;i++)printf(\"%02x\",t[i]); printf(\"\\n\"); }"]
    lines.append("return 0; }")
    lib, cr = FW / "lib" / "monocypher", FW / "src" / "crypto"
    env = dict(os.environ)
    env["PATH"] = str(Path(cc).parent) + os.pathsep + env.get("PATH", "")
    with tempfile.TemporaryDirectory() as d:
        c = Path(d) / "x.c"; c.write_text("\n".join(lines), encoding="utf-8")
        exe = Path(d) / ("x.exe" if os.name == "nt" else "x")
        r = subprocess.run([cc, "-std=c99", "-O1", "-I", str(cr), "-I", str(FW / "src" / "routing"), "-I", str(lib),
                            str(c), str(cr / "gm_crypto.c"), str(cr / "gm_ratchet.c"), str(lib / "monocypher.c"),
                            str(lib / "monocypher-ed25519.c"), "-o", str(exe)], env=env, capture_output=True, text=True)
        if r.returncode != 0:
            ok(False, f"firmware cross-check compiled ({r.stderr[:200]})")
            return
        out = subprocess.run([str(exe)], env=env, capture_output=True, text=True).stdout.split("\n")
    bad = 0
    for (ps, ep, net, fr), line in zip(cases, out):
        want = f"{gmx.pseudonym(ps, ep):08x} {gmx.mac_for(ps, ep).hex()} {gmx.link_tag(net, fr).hex()}"
        bad += line.strip() != want
    ok(bad == 0, f"pseudonym, MAC and link_tag match gm_crypto.c on 40 random cases ({bad} mismatches)")


def test_frames():
    n = bad = times = 0
    for ds in sorted((REPO / "ips" / "datasets").glob("*.jsonl")):
        if ds.name.endswith(".labels.jsonl"):
            continue
        for line in open(ds, encoding="utf-8"):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "raw" not in rec:
                continue
            raw = bytes.fromhex(rec["raw"])
            f = gmx.Frame.parse(raw)
            n += 1
            same = (f.to_bytes() == raw and f.type_name == rec["type"] and f.ttl == rec["ttl"] and f.hop == rec["hop"]
                    and f"{f.src_pseudo:08x}" == rec["pseudo"] and f.msg_id.hex() == rec["msg_id"]
                    and f.epoch == rec["epoch"] and f.flags == rec["flags"])
            bad += not same
            t = f.ctrl_time_ms()
            if t is not None:
                times += 1
                bad += not (1.7e12 < t < 1.9e12)
    ok(n > 4000 and bad == 0, f"{n} recorded frames parse, re-serialize and match their JSON ({bad} bad)")
    ok(times > 0, f"CTRL TIME beacons parsed from recordings ({times})")

    net = os.urandom(32)
    f = gmx.random_data_frame(net, 0x11223344, 500, ttl=3, hop=2)
    ok(f.link_ok(net), "random_data_frame has a valid link_tag")
    ok(len(f.to_bytes()) == 240 and f.ttl + f.hop == 5, "random_data_frame keeps ttl + hop")
    f.hop = 0
    ok(not f.link_ok(net), "editing a field breaks link_tag")
    f.sign(net)
    ok(f.link_ok(net), "sign() repairs link_tag after an edit")
    ok(not f.link_ok(os.urandom(32)), "link_tag fails under another network key")


def test_keys():
    with tempfile.TemporaryDirectory() as d:
        out, roster = Path(d) / "keys", Path(d) / "roster.json"
        r = subprocess.run([sys.executable, str(REPO / "security" / "keygen.py"), "--out", str(out),
                            "--roster", str(roster)], capture_output=True, text=True)
        if r.returncode != 0:
            ok(False, f"keygen ran in a temp dir ({r.stderr[:200]})")
            return
        k = gmx.load_keys(out / "keys_X.h")
        ok(k.name == "X" and k.node_id == 6, "load_keys reads X's name and ID")
        import hashlib
        fp = hashlib.blake2b(b"GM-FP" + k.network_key, digest_size=4).hexdigest()
        ok(f"{fp[:4]}-{fp[4:]}" in roster.read_text(), "X's network key matches the roster fingerprint")
        try:
            gmx.load_keys(out / "keys_W.h")
            ok(False, "load_keys refuses the watchtower header")
        except ValueError:
            ok(True, "load_keys refuses the watchtower header")


def test_clock_pacing_labels():
    radio = gmx.MockRadio()
    ok(not radio.clock.synced, "clock unknown before a TIME beacon")
    issued = int(time.time() * 1000) + 5000                 # mesh clock 5 s ahead of this laptop
    rest = bytearray(os.urandom(210))
    rest[24] = gmx.CTRL_TIME
    rest[25:33] = issued.to_bytes(8, "big")
    beacon = gmx.Frame(gmx.CTRL, 0, os.urandom(8), 6, 1, 0x01020304, 0, 1, b"\0" * 8, bytes(rest))
    radio.inject(beacon.to_bytes())
    ok(radio.clock.synced and abs(radio.clock.offset_ms - 5000) < 200, "TIME beacon sets the mesh clock offset")
    ok(radio.clock.epoch() == (int(radio.clock.now_ms() // 60000) & 0xFFFF), "epoch from the mesh clock")
    ok(radio.heard.get_nowait().frame.ver_type == gmx.CTRL, "heard frames are queued")

    net = os.urandom(32)
    n = gmx.paced(radio, lambda: gmx.random_data_frame(net, 1, 2), rate_hz=50, duration_s=0.5)
    ts = [t for t, _ in radio.tx_log]
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    ok(n == 25 and len(radio.tx_log) == 25, f"paced: 50/s for 0.5 s sends 25 frames ({n})")
    ok(gaps and 15 < sum(gaps) / len(gaps) < 25, f"paced: mean gap ~20 ms ({sum(gaps) / max(1, len(gaps)):.1f})")
    try:
        gmx.paced(radio, lambda: b"\0" * 240, rate_hz=150, duration_s=0.1)
        ok(False, "paced refuses rates above 100/s (16e)")
    except ValueError:
        ok(True, "paced refuses rates above 100/s (16e)")

    with tempfile.TemporaryDirectory() as d:
        src = REPO / "ips" / "datasets" / "2026-11-18_normal_01.jsonl"
        log = Path(d) / "run.jsonl"
        shutil.copy(src, log)
        frames = [json.loads(l) for l in open(src, encoding="utf-8") if '"raw"' in l]
        frames = [f for f in frames if f["t"] > 1e9]
        a, b = frames[100]["t"], frames[200]["t"]
        labels = gmx.LabelLog(Path(d) / "run.labels.jsonl", radio.clock)
        row = labels.add("flood", a, b, node="A", variant="test")
        ok(set(row) == {"label", "node", "start", "end", "variant"}, "label row has the agreed fields")
        try:
            labels.add("jamming", a, b)
            ok(False, "LabelLog refuses labels the IPS doesn't know")
        except ValueError:
            ok(True, "LabelLog refuses labels the IPS doesn't know")
        with labels.run("replay", variant="ctx"):
            time.sleep(0.05)
        rows = [json.loads(l) for l in open(Path(d) / "run.labels.jsonl")]
        ok(len(rows) == 2 and rows[1]["end"] - rows[1]["start"] >= 0.04, "labels.run() writes start/end on the mesh clock")
        try:
            sys.path.insert(0, str(REPO / "ips"))
            cwd = os.getcwd(); os.chdir(REPO / "ips")
            import ingest
            df = ingest.read_labeled(str(log))
            os.chdir(cwd)
            want = sum(1 for f in frames if a <= f["t"] <= b and f.get("node") in ("A", "?"))
            got = int((df["label"] == "flood").sum())
            ok(got == want and got > 0, f"ips/ingest.read_labeled applies the labels ({got} flood rows)")
        except ImportError as e:
            print(f"NOTE  ips/ingest not importable ({e}); read_labeled check skipped")


def test_firmware_config():
    ini = (FW / "platformio.ini").read_text(encoding="utf-8")
    envs = dict(re.findall(r"^\[(env(?::\w+)?)\]\n(.*?)(?=^\[|\Z)", ini, re.S | re.M))
    base_filter = re.search(r"build_src_filter\s*=\s*(.*)", envs["env"]).group(1)
    ok("-<attacker/>" in base_filter, "node builds (A-D) exclude src/attacker/")
    w = re.search(r"build_src_filter\s*=\s*(.*)", envs["env:W"]).group(1)
    ok("-<attacker/>" in w, "watchtower build excludes src/attacker/")
    x = envs.get("env:X", "")
    xf = re.search(r"build_src_filter\s*=\s*(.*)", x)
    ok(xf and all(s in xf.group(1) for s in ("-<main.cpp>", "-<node_serial.cpp>", "-<watchtower/>", "-<node/board_keys.c>")),
       "X build excludes the node and watchtower mains and board keys")
    ok("GM_KEYS_FILE" not in x, "X build compiles in no keys")
    src = (FW / "src" / "attacker" / "main_x.cpp").read_text(encoding="utf-8")
    ok("keys_" not in src.replace("keys_X.h", "") and "GM_NETWORK_KEY" not in src, "main_x.cpp references no key material")
    ok(src.count("radio_send(") == 1 and '"tx"' in src, "X transmits only on the tx command")
    longest = len('{"cmd":"tx","hex":"' + "0" * 480 + '"}')
    ok(longest < 511, f"tx command line ({longest} chars) fits serial_if's 512-byte line buffer")


def main():
    test_vectors()
    test_against_c()
    test_frames()
    test_keys()
    test_clock_pacing_labels()
    test_firmware_config()
    for good, name in results:
        print(f"{'PASS' if good else 'FAIL'}  {name}")
    failed = sum(not g for g, _ in results)
    print(f"\n{len(results) - failed}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
