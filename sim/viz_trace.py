"""
viz_trace.py - replays real experiment runs with full logging, for the Manim clips (viz_scenes.py).

    python3 sim/viz_trace.py               # build every clip -> sim/out/viz/<clip>.json
    python3 sim/viz_trace.py flood k       # just these

Clips 1-5 rerun the exact RunConfig (same experiment, settings, seed) from sim/run.py and check
that the rerun's summary matches the stored sim/out/<experiment>/<run_id>.jsonl exactly before
using it. The sim is deterministic, so a match means it's the same run. Clip 6 (selfheal) is a
scenario: same code, settings and mesh as a 30-node run, with hand-picked sends and one relay
unplugged, since no experiment unplugs nodes.
"""
import json
import math
import struct
import sys
from collections import deque
from dataclasses import replace
from pathlib import Path

from bindings import RtFrame, load
from config import OUT_DIR, experiments
from engine import Sim

VIZ_DIR = OUT_DIR / "viz"
TYPE_DATA = 1
EV_SEND = 2


class TraceSim(Sim):
    """Sim that records every transmission and reception. sends = [(t_ms, src, dst)] replaces the
    run's traffic when given; down = {node: t_ms} unplugs a node (it stops sending and hearing).
    With neither, it is exactly the experiment run (only extra logging)."""

    def __init__(self, cfg, sends=None, down=None, **kw):
        self._sends, self.down = sends, dict(down or {})
        self.frames, self.rx = [], []
        self.data_ids, self.ack_ids = {}, {}         # msg_id hex -> message index
        super().__init__(cfg, record_events=True, **kw)

    def _schedule_traffic(self):
        if self._sends is None:
            return super()._schedule_traffic()
        for idx, (t, src, dst) in enumerate(self._sends):
            self._push(t, EV_SEND, (src, dst, idx))

    def _is_down(self, i):
        return i in self.down and self.now >= self.down[i]

    def _on_timer(self, i, token, version):
        if not self._is_down(i):
            super()._on_timer(i, token, version)

    def _on_tx(self, i, frame):
        if self._is_down(i):
            return
        before = self.transmissions
        super()._on_tx(i, frame)
        if self.transmissions == before:             # deferred by carrier sense, comes back later
            return
        ct = bytes(RtFrame.from_buffer_copy(frame).ciphertext)
        _, _, _, _, typ, ln = struct.unpack(">IIIIBB", ct[:18])
        body, mid = ct[18:18 + ln], frame[2:10].hex()
        if typ == TYPE_DATA:
            idx, kind = int(body[1:8]), "data"
            self.data_ids.setdefault(mid, idx)
        else:
            idx, kind = self.data_ids.get(body[:8].hex()), "ack"
            self.ack_ids.setdefault(mid, idx)
        self.frames.append({"t0": round(self.now, 3), "t1": round(self.now + self.cfg.channel.airtime_ms, 3),
                            "node": i, "msg": idx, "kind": kind, "id": mid, "ttl": frame[10], "hop": frame[11]})

    def _on_rx_end(self, j, rec, frame, i):
        if self._is_down(j):
            self.active[j].remove(rec)
            return
        lost = rec[1]
        super()._on_rx_end(j, rec, frame, i)
        self.rx.append({"t": round(self.now, 3), "frm": i, "to": j, "id": frame[2:10].hex(), "ok": not lost})

    # ---- after the run ----

    def events(self):
        ids = {**{k: (v, "data") for k, v in self.data_ids.items()}, **{k: (v, "ack") for k, v in self.ack_ids.items()}}
        out = []
        for e in self.events_out:
            msg, kind = ids.get(e.get("msg"), (None, None))
            out.append({"t": e["t"], "node": e["node"] - 1, "ev": e["ev"], "msg": msg, "kind": kind})
        return out

    def messages(self):
        """Per message: who, when, attempts, and the time span its frames (DATA + ACK) cover."""
        ev = self.events()
        attempts, span = {}, {}
        for f in self.frames:
            if f["msg"] is None:
                continue
            if f["kind"] == "data" and f["node"] == self.dest[f["msg"]][0]:
                attempts.setdefault(f["msg"], [])
                if f["id"] not in attempts[f["msg"]]:
                    attempts[f["msg"]].append(f["id"])
            a, b = span.get(f["msg"], (f["t0"], f["t1"]))
            span[f["msg"]] = (min(a, f["t0"]), max(b, f["t1"]))
        acked = {}
        for e in ev:
            if e["ev"] == "ACK_MATCHED" and e["msg"] is not None and e["node"] == self.dest[e["msg"]][0]:
                acked.setdefault(e["msg"], e["t"])
        out = {}
        for idx, t in self.sent.items():
            src, dst = self.dest[idx]
            out[idx] = {"src": src, "dst": dst, "sent": t, "delivered": self.delivered.get(idx),
                        "acked": acked.get(idx), "attempts": attempts.get(idx, []),
                        "span": span.get(idx, (t, t)), "hops": hops(self.adj, src).get(dst)}
        return out

    def trace(self, t_a, t_b, **extra) -> dict:
        """Everything a clip needs, cut to the sim-time window [t_a, t_b]."""
        msgs = self.messages()
        return {
            "n": self.n, "pos": self.pos,
            "edges": sorted((a, b) for a in range(self.n) for b in self.adj[a] if a < b),
            "radio_range": self.cfg.topology.radio_range, "airtime_ms": self.cfg.channel.airtime_ms,
            "window": [t_a, t_b], "down": self.down,
            "frames": [f for f in self.frames if f["t1"] >= t_a and f["t0"] <= t_b],
            "rx": [r for r in self.rx if t_a <= r["t"] <= t_b + 50],
            "events": [e for e in self.events() if t_a <= e["t"] <= t_b],
            "messages": {k: v for k, v in msgs.items() if v["span"][1] >= t_a and v["sent"] <= t_b},
            "summary": self.summary(), **extra,
        }


# ---- helpers ----------------------------------------------------------------------

def hops(adj, a, skip=None):
    dist, q = {a: 0}, deque([a])
    while q:
        u = q.popleft()
        for v in adj[u]:
            if v not in dist and v != skip:
                dist[v] = dist[u] + 1
                q.append(v)
    return dist


def find_run(experiment, seed, **match):
    """The RunConfig sim/run.py used, e.g. find_run('k_sweep', 3, k=1, bitrate_kbps=1000)."""
    for cfg in experiments()[experiment]:
        if cfg.seed != seed:
            continue
        flat = {**vars(cfg.topology), **vars(cfg.channel), **vars(cfg.traffic), **vars(cfg.routing)}
        if all(flat[k] == v for k, v in match.items()):
            return cfg
    raise KeyError(f"no {experiment} run with seed {seed} and {match}")


def stored(cfg):
    """(config line, summary line) sim/run.py wrote for this run."""
    lines = cfg.out_path.read_text().splitlines()
    return json.loads(lines[0]), json.loads(lines[-1])


_LIB = None
_OLD_LOG_NAMES = {"23": "ROUTE_SCOPED", "24": "ROUTE_STALE"}


def replay(cfg) -> TraceSim:
    """Reruns one experiment run with full logging; refuses if the summary isn't identical."""
    global _LIB
    _LIB = _LIB or load()
    sim = TraceSim(cfg, lib=_LIB)
    got = sim.run()
    conf, want = stored(cfg)
    # runs stored before shim.c named the v2 log events list them by number
    want["log_counts"] = {_OLD_LOG_NAMES.get(k, k): v for k, v in want["log_counts"].items()}
    diff = [k for k in want if k != "wall_s" and want[k] != got.get(k)]
    if diff:
        raise RuntimeError(f"{cfg.experiment} {cfg.run_id}: rerun differs from stored run in {diff}")
    sim.run_id, sim.commit = cfg.run_id, conf.get("commit")
    return sim


def overlap(sim, idx, msgs):
    # frames from other messages inside this message's span
    a, b = msgs[idx]["span"]
    return sum(1 for f in sim.frames if f["msg"] != idx and f["t1"] > a and f["t0"] < b)


def mean_of(experiment, key, **match):
    """Average of a summary field over all 10 seeds of one setting (the number sim-results.md quotes)."""
    vals = []
    for cfg in experiments()[experiment]:
        flat = {**vars(cfg.topology), **vars(cfg.channel), **vars(cfg.traffic), **vars(cfg.routing)}
        if all(flat[k] == v for k, v in match.items()):
            vals.append(stored(cfg)[1][key])
    return sum(vals) / len(vals)


def source(sim, experiment, seed, **match):
    return {"experiment": experiment, "seed": seed, "settings": match, "run_id": sim.run_id,
            "commit": sim.commit, "verified": True}


def phase_times(m, frames):
    """Key moments of one message: sent, delivered, first ACK transmission, ACK back at A."""
    ack_tx = [f["t0"] for f in frames if f["msg"] == m["idx"] and f["kind"] == "ack"]
    return {"sent": m["sent"], "delivered": m["delivered"], "ack_start": min(ack_tx) if ack_tx else None,
            "acked": m["acked"], "end": m["span"][1]}


def focus(tr, idx):
    m = dict(tr["messages"][idx], idx=idx)
    tr["focus"] = idx
    tr["phases"] = phase_times(m, tr["frames"])
    return tr


# ---- clips ------------------------------------------------------------------------

def clip_flood():
    """1. One message across a 30-node scaling run, DATA out and ACK back, nothing else on air."""
    best = None
    for seed in range(10):
        sim = replay(find_run("scaling", seed, n_nodes=30))
        msgs = sim.messages()
        for idx, m in msgs.items():
            if not (m["acked"] and len(m["attempts"]) == 1):
                continue
            key = (overlap(sim, idx, msgs) == 0, m["hops"], -m["span"][1] + m["span"][0])
            if best is None or key > best[0]:
                best = (key, seed, idx, sim)
    _, seed, idx, sim = best
    m = sim.messages()[idx]
    tr = focus(sim.trace(m["sent"] - 20, m["span"][1] + 20), idx)
    tr["source"] = source(sim, "scaling", seed, n_nodes=30)
    tr["headline"] = {"delivery": mean_of("scaling", "delivery_ratio", n_nodes=30),
                      "tx_per_delivered": mean_of("scaling", "tx_per_delivered", n_nodes=30)}
    return {"clip": "flood", "panels": [tr]}


def _pair_clip(experiment, setting, bad, good, base, bad_ok, prefer_hops=True):
    """Same seed, same message, two settings. bad_ok(m) says the message struggled in the bad run."""
    best = None
    for seed in range(10):
        sb = replay(find_run(experiment, seed, **base, **{setting: bad}))
        sg = replay(find_run(experiment, seed, **base, **{setting: good}))
        mb, mg = sb.messages(), sg.messages()
        for idx in mb:
            if idx not in mg or not bad_ok(mb[idx]):
                continue
            if not (mg[idx]["acked"] and len(mg[idx]["attempts"]) == 1):
                continue
            quiet = -(overlap(sb, idx, mb) + overlap(sg, idx, mg))
            key = (quiet, mg[idx]["hops"] if prefer_hops else 0)
            if best is None or key > best[0]:
                best = (key, seed, idx, sb, sg)
    _, seed, idx, sb, sg = best
    mb, mg = sb.messages()[idx], sg.messages()[idx]
    # window: the good run's full DATA + ACK, and the bad run's first attempt
    first_b = [f for f in sb.frames if f["msg"] == idx and f["id"] == mb["attempts"][0]]
    t_a = mg["sent"] - 20
    t_b = max(mg["span"][1], max(f["t1"] for f in first_b) if first_b else 0) + 20
    panels = []
    for sim, val in ((sb, bad), (sg, good)):
        tr = focus(sim.trace(t_a, t_b), idx)
        tr["source"] = source(sim, experiment, seed, **base, **{setting: val})
        tr["label"] = f"{setting} = {val}"
        tr["headline"] = {"delivery": mean_of(experiment, "delivery_ratio", **base, **{setting: val}),
                          "tx_per_delivered": mean_of(experiment, "tx_per_delivered", **base, **{setting: val})}
        panels.append(tr)
    return panels


def clip_ttl():
    """2. ttl_sweep, 50 nodes: a message TTL 5 can't get across, TTL 16 can (first try)."""
    panels = _pair_clip("ttl_sweep", "default_ttl", 5, 16, {"n_nodes": 50},
                        bad_ok=lambda m: m["delivered"] is None)
    return {"clip": "ttl", "panels": panels}


def clip_k():
    """3. k_sweep, 50 nodes, 1000 kbps: k = 1's first attempt never reaches C (coverage hole), k = 2's does."""
    def hole(m):
        # the first DATA attempt never reached C (it got there on a retry, or never)
        return m["delivered"] is None or m["delivered"] - m["sent"] > 900
    panels = _pair_clip("k_sweep", "k", 1, 2, {"n_nodes": 50, "bitrate_kbps": 1000}, bad_ok=hole)
    return {"clip": "k", "panels": panels}


def clip_load(win=1500.0):
    """4. capacity, 30 nodes, 8 msg/s: the same traffic at 1000 vs 300 kbps, everything on air."""
    best = None
    for seed in range(10):
        fast = replay(find_run("capacity", seed, bitrate_kbps=1000, avg_rate_mps=8))
        slow = replay(find_run("capacity", seed, bitrate_kbps=300, avg_rate_mps=8))
        sends = sorted(slow.sent.values())
        for t in sends:
            if t < 5000 or t + win > 115000:
                continue
            n = sum(1 for u in sends if t <= u < t + win)
            if best is None or n > best[0]:
                best = (n, seed, t, fast, slow)
    _, seed, t, fast, slow = best
    panels = []
    for sim, kbps in ((fast, 1000), (slow, 300)):
        tr = sim.trace(t - 10, t + win)
        tr["focus"] = None
        msgs = tr["messages"]
        tr["window_stats"] = {"sent": sum(1 for m in msgs.values() if t - 10 <= m["sent"] <= t + win),
                              "collisions": sum(1 for r in tr["rx"] if not r["ok"] and r["t"] <= t + win)}
        tr["source"] = source(sim, "capacity", seed, bitrate_kbps=kbps, avg_rate_mps=8)
        tr["label"] = f"{kbps} kbps"
        tr["headline"] = {"delivery": mean_of("capacity", "delivery_ratio", bitrate_kbps=kbps, avg_rate_mps=8),
                          "tx_per_delivered": mean_of("capacity", "tx_per_delivered", bitrate_kbps=kbps, avg_rate_mps=8)}
        panels.append(tr)
    return {"clip": "load", "panels": panels}


def clip_v2():
    """5. v2_compare, 50 nodes, 5 conversations: a message v2 scoped, next to the same message in v1."""
    best = None
    base = {"n_nodes": 50, "conversations": 5}
    for seed in range(10):
        s1 = replay(find_run("v2_compare", seed, **base, route_learning=0))
        s2 = replay(find_run("v2_compare", seed, **base, route_learning=1))
        m1, m2 = s1.messages(), s2.messages()
        scoped = {e["msg"] for e in s2.events() if e["ev"] == "ROUTE_SCOPED" and e["kind"] == "data"}
        for idx in m2:
            if idx not in scoped or idx not in m1 or (m2[idx]["hops"] or 0) < 3:
                continue
            if not all(m[idx]["acked"] and len(m[idx]["attempts"]) == 1 for m in (m1, m2)):
                continue
            n1 = len({f["node"] for f in s1.frames if f["msg"] == idx})
            n2 = len({f["node"] for f in s2.frames if f["msg"] == idx})
            quiet = overlap(s1, idx, m1) + overlap(s2, idx, m2) == 0
            key = (quiet, n1 - n2, m2[idx]["hops"])
            if best is None or key > best[0]:
                best = (key, seed, idx, s1, s2)
    _, seed, idx, s1, s2 = best
    m1, m2 = s1.messages()[idx], s2.messages()[idx]
    t_a = min(m1["sent"], m2["sent"]) - 20
    t_b = max(m1["span"][1], m2["span"][1]) + 20
    panels = []
    for sim, rl, name in ((s1, 0, "v1 flooding (deployed)"), (s2, 1, "v2 route learning (not deployed)")):
        tr = focus(sim.trace(t_a, t_b), idx)
        tr["source"] = source(sim, "v2_compare", seed, **base, route_learning=rl)
        tr["label"] = name
        tr["headline"] = {"delivery": mean_of("v2_compare", "delivery_ratio", **base, route_learning=rl),
                          "tx_per_delivered": mean_of("v2_compare", "tx_per_delivered", **base, route_learning=rl)}
        panels.append(tr)
    return {"clip": "v2", "panels": panels}


def _selfheal_try(cfg, a, c):
    """Message 1 A -> C with nothing broken; then unplug the relay message 1 leaned on most
    (on a shortest path, but not a cut node) and send message 2. None if message 1 was messy."""
    probe = Sim(cfg)
    first = TraceSim(cfg, sends=[(100.0, a, c)])
    first.run()
    m = first.messages()[0]
    if not (m["acked"] and len(m["attempts"]) == 1):
        return None
    da, dc = hops(probe.adj, a), hops(probe.adj, c)
    used = {f["node"] for f in first.frames if f["kind"] == "data"}
    cands = [v for v in range(probe.n) if v not in (a, c) and v in used and da[v] + dc[v] == da[c]
             and c in hops(probe.adj, a, skip=v)]
    if not cands:
        return None
    x = max(cands, key=lambda v: len(probe.adj[v]))
    # unplug X only once message 1 (DATA and ACK) is completely over, then send message 2
    t_down = math.ceil((max(f["t1"] for f in first.frames) + 100) / 100) * 100
    sim = TraceSim(cfg, sends=[(100.0, a, c), (t_down + 300.0, a, c)], down={x: t_down})
    sim.run()
    return sim, x, t_down


def clip_selfheal():
    """6. Scenario: same code, settings and meshes as the 30-node scaling runs. A sends C a
    message, the relay it used most is unplugged, A sends again. Picks the seed / pair where
    message 1 is clean; message 2's outcome is whatever the routing does."""
    best = None
    for seed in range(10):
        cfg = find_run("scaling", seed, n_nodes=30)
        cfg = replace(cfg, traffic=replace(cfg.traffic, duration_s=4.0, drain_s=20.0))
        probe = Sim(cfg)
        pairs = [(math.dist(probe.pos[a], probe.pos[b]), a, b) for a in range(probe.n)
                 for b, h in hops(probe.adj, a).items() if 6 <= h <= 9 and a < b]
        for _, a, c in sorted(pairs, reverse=True)[:3]:
            got = _selfheal_try(cfg, a, c)
            if not got:
                continue
            sim, x, t_down = got
            m2 = sim.messages()[1]
            key = (m2["delivered"] is not None, hops(probe.adj, a)[c])
            if best is None or key > best[0]:
                best = (key, seed, sim, x, t_down)
            break
    _, seed, sim, x, t_down = best
    msgs = sim.messages()
    panels = []
    for idx in (0, 1):
        m = msgs[idx]
        tr = focus(sim.trace(m["sent"] - 20, m["span"][1] + 20), idx)
        tr["source"] = {"experiment": "scenario", "seed": seed, "mesh_from": f"scaling, 30 nodes, seed {seed}",
                        "settings": {"unplugged": x, "at_ms": t_down}, "verified": False}
        panels.append(tr)
    return {"clip": "selfheal", "x": x, "t_down": t_down, "panels": panels}


CLIPS = {"flood": clip_flood, "ttl": clip_ttl, "k": clip_k, "load": clip_load, "v2": clip_v2, "selfheal": clip_selfheal}


def build(name: str) -> dict:
    VIZ_DIR.mkdir(parents=True, exist_ok=True)
    clip = CLIPS[name]()
    (VIZ_DIR / f"{name}.json").write_text(json.dumps(clip))
    return json.loads(json.dumps(clip))              # same shape as get() (string keys)


def get(name: str) -> dict:
    """Loads a clip, building it first if it isn't there yet. Message keys become ints again."""
    path = VIZ_DIR / f"{name}.json"
    clip = json.loads(path.read_text()) if path.exists() else build(name)
    for p in clip["panels"]:
        p["messages"] = {int(k): v for k, v in p["messages"].items()}
        p["down"] = {int(k): v for k, v in p["down"].items()}
    return clip


def describe(clip) -> str:
    out = [clip["clip"]]
    for p in clip["panels"]:
        s = p["source"]
        f = p.get("focus")
        m = p["messages"].get(f) if f is not None else None
        line = f"  {p.get('label', '')}: {s['experiment']} seed {s.get('seed', '-')} {s.get('settings')}"
        line += f" run {s.get('run_id', '-')} @ {s.get('commit', '-')}" + (" (summary matches)" if s["verified"] else "")
        if m:
            nodes = len({fr["node"] for fr in p["frames"] if fr["msg"] == f})
            line += (f"\n    message {f}: {m['src']}->{m['dst']}, {m['hops']} hops, attempts {len(m['attempts'])}, "
                     f"delivered {'no' if m['delivered'] is None else round(m['delivered'] - m['sent'])} ms, "
                     f"{nodes} nodes transmitted")
        out.append(line)
    return "\n".join(out)


if __name__ == "__main__":
    for nm in sys.argv[1:] or list(CLIPS):
        build(nm)
        print(describe(get(nm)))
