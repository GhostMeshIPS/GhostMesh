#!/usr/bin/env python3
"""Tests for security/attacks/attacks.py and run.py, against MockRadio and a small simulated mesh.

    python security/attacks/test_attacks.py

A fake mesh (nodes A, B, C with their own pseudo_secrets, real pseudonym/MAC/link_tag derivation and
fixed RSSIs) feeds frames into MockRadio, so every attack sees realistic traffic. Checks each variant's
frames against decision 20: rates, identities, link_tag validity, replay ages, victim tracking across a
rotation, forged hops, and that sessions write the right label rows.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import attacks  # noqa: E402
import gmx  # noqa: E402
import run  # noqa: E402

results = []
def ok(cond, name):
    results.append((bool(cond), name))


NET = os.urandom(32)
KEYS = gmx.XKeys("X", 6, NET, os.urandom(32), os.urandom(32), os.urandom(32))
NODES = {"A": (os.urandom(32), -50), "B": (os.urandom(32), -68), "C": (os.urandom(32), -84)}


class Mesh:
    """Injects DATA frames from A, B, C into a MockRadio, ~30 frames/s, on the radio's mesh clock."""

    def __init__(self, radio):
        self.radio, self.stop = radio, threading.Event()
        self.t = threading.Thread(target=self.loop, daemon=True)

    def frame(self, name, hop=1):
        ps, rssi = NODES[name]
        ep = self.radio.clock.epoch()
        f = gmx.random_data_frame(NET, gmx.pseudonym(ps, ep), ep, ttl=gmx.DEFAULT_TTL - hop, hop=hop)
        return f, gmx.mac_str(gmx.mac_for(ps, ep)), rssi

    def loop(self):
        i = 0
        while not self.stop.is_set():
            name = "ABC"[i % 3]
            f, mac, rssi = self.frame(name)
            self.radio.inject(f.to_bytes(), mac=mac, rssi=rssi + (i % 3) - 1)
            i += 1
            time.sleep(0.033)

    def __enter__(self):
        self.t.start(); time.sleep(0.4); return self

    def __exit__(self, *e):
        self.stop.set(); self.t.join(1)


def new_ctx():
    r = gmx.MockRadio()
    r.clock.assume_laptop_clock()
    return r, attacks.AttackContext(r, KEYS)


def frames_of(radio):
    return [gmx.Frame.parse(raw) for _, raw in radio.tx_log]


def test_floods():
    r, ctx = new_ctx()
    n = attacks.ATTACKS[("flood", "loud")](ctx, 1.0)
    fs = frames_of(r)
    ep = r.clock.epoch()
    xp = gmx.pseudonym(KEYS.pseudo_secret, ep)
    ok(75 <= n <= 81, f"flood/loud: ~80 frames in 1 s ({n})")
    ok(all(f.ver_type == gmx.DATA and f.link_ok(NET) and f.src_pseudo == xp and f.ttl + f.hop == 5 for f in fs),
       "flood/loud: valid DATA as X, ttl + hop = 5")
    ok(r.mac == gmx.mac_str(gmx.mac_for(KEYS.pseudo_secret, ep)), "flood/loud: X uses its own derived MAC")
    ok(len({f.hop for f in fs}) > 1, "flood/loud: hop padding varies like a real originator")
    ok(len({f.msg_id for f in fs}) == len(fs), "flood/loud: fresh msg_id on every frame")

    for variant, rate in (("slow", 15), ("low_slow", 8)):
        r, ctx = new_ctx()
        n = attacks.ATTACKS[("flood", variant)](ctx, 1.0)
        ok(abs(n - rate) <= 1, f"flood/{variant}: {rate}/s ({n})")

    r, ctx = new_ctx()
    n = attacks.ATTACKS[("flood", "outsider")](ctx, 1.0)
    fs = frames_of(r)
    ok(45 <= n <= 51 and not any(f.link_ok(NET) for f in fs), f"flood/outsider: ~50/s, every link_tag invalid ({n})")
    mac = gmx.mac_bytes(r.mac)
    ok(mac[0] & 0x03 == 0x02 and r.mac != gmx.mac_str(gmx.mac_for(KEYS.pseudo_secret, r.clock.epoch())),
       "flood/outsider: random locally administered MAC, not X's")
    ok(len({f.src_pseudo for f in fs}) == 1, "flood/outsider: one random pseudonym for the run")

    r, ctx = new_ctx()
    macs = []
    real = r.set_mac
    r.set_mac = lambda m: (macs.append(m), real(m))[1]
    n = attacks.ATTACKS[("flood", "cycling")](ctx, 1.0)
    fs = frames_of(r)
    ok(45 <= n <= 51 and all(f.link_ok(NET) for f in fs), f"flood/cycling: ~50/s, valid link_tag ({n})")
    ok(len({f.src_pseudo for f in fs}) >= 9 and len(macs) >= 9, f"flood/cycling: new identity every 5 frames "
       f"({len({f.src_pseudo for f in fs})} pseudonyms, {len(macs)} MACs)")

    r, ctx = new_ctx()
    n = attacks.ATTACKS[("flood", "ctrl_forgery")](ctx, 1.0)
    fs = frames_of(r)
    subs = [f.rest[24] for f in fs]
    now = r.clock.now_ms()
    ok(18 <= n <= 21 and all(f.ver_type == gmx.CTRL and f.link_ok(NET) for f in fs), f"flood/ctrl_forgery: ~20/s valid CTRL ({n})")
    ok(set(subs) == {gmx.CTRL_TIME, gmx.CTRL_BLOCK}, "flood/ctrl_forgery: alternates TIME and BLOCK")
    ok(all(int.from_bytes(f.rest[25:33], "big") > now - 2000 for f in fs), "flood/ctrl_forgery: fresh issued_at (not skipped as old)")


def test_replay():
    r, ctx = new_ctx()
    now = gmx.MeshClock.laptop_ms()
    old = []
    for i in range(400):                       # frames heard 40 s .. 0 s ago, 10/s
        t = now - 40000 + i * 100
        f = gmx.random_data_frame(NET, 0xA0A0A0A0, r.clock.epoch())
        r.inject(f.to_bytes(), laptop_ms=t)
        old.append((t, f.to_bytes()))
    n = attacks.ATTACKS[("replay", "age_30s")](ctx, 1.0)
    sent = [raw for _, raw in r.tx_log]
    stamp = {raw: t for t, raw in old}
    ages = [(sent_t - stamp[raw]) / 1000 for sent_t, raw in r.tx_log if raw in stamp]
    ok(4 <= n <= 5, f"replay/age_30s: 5/s ({n})")
    ok(len(ages) == len(sent), "replay: frames resent byte-for-byte unchanged")
    ok(ages and all(28 <= a <= 32.5 for a in ages), f"replay/age_30s: each frame ~30 s old ({[round(a, 1) for a in ages]})")
    ok(len(set(sent)) == len(sent), "replay: no frame replayed twice")
    r2, ctx2 = new_ctx()
    n2 = attacks.ATTACKS[("replay", "age_90s")](ctx2, 0.6)
    ok(n2 == 0, "replay: sends nothing when no frame is old enough yet")


def test_spoof():
    for variant, copy_mac in (("pseudo", False), ("pseudo_mac", True)):
        r, ctx = new_ctx()
        fn = attacks.spoof(copy_mac=copy_mac, settle_s=0.5, min_frames=3)     # test mesh is fast: short settle
        with Mesh(r) as mesh:
            ep0 = r.clock.epoch()
            out = {}
            th = threading.Thread(target=lambda: out.setdefault("n", fn(ctx, 2.4)))
            th.start()
            time.sleep(1.1)
            r.clock.offset_ms += 60000             # rotation: every node's pseudonym and MAC change
            th.join()
        ep1 = ep0 + 1
        fs = frames_of(r)
        a0 = gmx.pseudonym(NODES["A"][0], ep0)
        a1 = gmx.pseudonym(NODES["A"][0], ep1)
        before = [f for f in fs if f.epoch == ep0]
        after = [f for f in fs if f.epoch == ep1]
        ok(before and all(f.src_pseudo == a0 for f in before), f"spoof/{variant}: picks the strongest neighbour (A)")
        ok(after and all(f.src_pseudo == a1 for f in after), f"spoof/{variant}: re-finds A by RSSI after rotation")
        gap = [t for t, raw in r.tx_log if gmx.Frame.parse(raw).epoch == ep1]
        ok(gap and gap[0] - [t for t, raw in r.tx_log if gmx.Frame.parse(raw).epoch == ep0][-1] >= 450,
           f"spoof/{variant}: waits the settle time after a rotation before spoofing again")
        ok(all(f.link_ok(NET) for f in fs), f"spoof/{variant}: valid link_tag (insider)")
        want_mac = gmx.mac_str(gmx.mac_for(NODES["A"][0], ep1)) if copy_mac else gmx.mac_str(gmx.mac_for(KEYS.pseudo_secret, ep1))
        ok(r.mac == want_mac, f"spoof/{variant}: radio MAC is {'the victim' if copy_mac else 'X'}'s")
    r, ctx = new_ctx()
    ctx.victim_hint = gmx.pseudonym(NODES["C"][0], r.clock.epoch())
    with Mesh(r):
        attacks.ATTACKS[("spoof", "pseudo")](ctx, 0.6)
    fs = frames_of(r)
    ok(fs and all(f.src_pseudo == ctx.victim_hint for f in fs), "spoof: --victim picks the named pseudonym")


def test_routing():
    for variant, fix in (("hop0", False), ("hop0_ttlfix", True)):
        r, ctx = new_ctx()
        with Mesh(r):
            n = attacks.ATTACKS[("routing", variant)](ctx, 1.0)
        fs = frames_of(r)
        xp = gmx.pseudonym(KEYS.pseudo_secret, r.clock.epoch())
        ok(n >= 20, f"routing/{variant}: relays what it hears ({n})")
        ok(all(f.hop == 0 and f.src_pseudo == xp and f.link_ok(NET) for f in fs), f"routing/{variant}: hop 0, as X, valid link_tag")
        ok(all(f.ttl == (5 if fix else 3) for f in fs), f"routing/{variant}: ttl {'raised to 5' if fix else 'decremented (4 -> 3)'}")
        ok(len({f.msg_id for f in fs}) == len(fs), f"routing/{variant}: each msg_id relayed once")
        ok(r.mac == gmx.mac_str(gmx.mac_for(KEYS.pseudo_secret, r.clock.epoch())), f"routing/{variant}: as X's own MAC")


def test_sessions():
    with tempfile.TemporaryDirectory() as d:
        for name, want in (("flood", ["loud", "slow", "outsider", "low_slow"]),
                           ("extras", ["cycling", "ctrl_forgery", "slow"]),
                           ("mixed", ["pseudo", "hop0_ttlfix", "age_90s", "slow"])):
            r, ctx = new_ctx()
            path = Path(d) / f"{name}.labels.jsonl"
            labels = gmx.LabelLog(path, r.clock)
            t0 = time.time()
            run.run_session(ctx, labels, name, scale=0.004)
            rows = [json.loads(l) for l in open(path)]
            ok([x["variant"] for x in rows] == want, f"session {name}: label rows in order ({[x['variant'] for x in rows]})")
            ok(all(x["label"] in gmx.LABELS and x["node"] == "X" for x in rows), f"session {name}: valid labels")
            ok(all(a["end"] <= b["start"] for a, b in zip(rows, rows[1:])), f"session {name}: runs don't overlap")
            ok(rows and rows[0]["start"] >= t0 + 300 * 0.004 - 0.05, f"session {name}: normal traffic before the first attack")

        r, ctx = new_ctx()
        stop_at = time.time() + 0.3
        threading.Timer(0.3, ctx.stop.set).start()
        path = Path(d) / "stop.labels.jsonl"
        run.run_variant(ctx, gmx.LabelLog(path, r.clock), "flood", "loud", 10)
        rows = [json.loads(l) for l in open(path)]
        ok(len(rows) == 1 and rows[0]["end"] - stop_at < 0.5, "stopping mid-attack still writes the label row")

        out = subprocess.run([sys.executable, str(HERE / "run.py"), "--mock", "--labels", str(Path(d) / "cli.labels.jsonl"),
                              "attack", "flood", "slow", "--secs", "0.5"], capture_output=True, text=True)
        rows = [json.loads(l) for l in open(Path(d) / "cli.labels.jsonl")]
        ok(out.returncode == 0 and rows[0]["variant"] == "slow", "run.py --mock attack works end to end")
        out = subprocess.run([sys.executable, str(HERE / "run.py"), "--mock", "list"], capture_output=True, text=True)
        ok(out.returncode == 0 and out.stdout.count("\n") >= 14, "run.py list shows every attack and session")
        out = subprocess.run([sys.executable, str(HERE / "run.py"), "--mock", "attack", "flood", "loud"],
                             capture_output=True, text=True)
        ok(out.returncode == 2 and "--labels" in out.stderr, "run.py refuses to attack without a labels file")


def test_specs_cover_readme():
    readme = (HERE / "README.md").read_text(encoding="utf-8")
    listed = set()
    for label, variant in attacks.ATTACKS:
        if f"| {label} | `{variant}` |" in readme:
            listed.add((label, variant))
    ok(listed == set(attacks.ATTACKS), f"every implemented attack is in the README spec table "
       f"({sorted(set(attacks.ATTACKS) - listed)} missing)")


def main():
    test_floods()
    test_replay()
    test_spoof()
    test_routing()
    test_sessions()
    test_specs_cover_readme()
    for good, name in results:
        print(f"{'PASS' if good else 'FAIL'}  {name}")
    failed = sum(not g for g, _ in results)
    print(f"\n{len(results) - failed}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
