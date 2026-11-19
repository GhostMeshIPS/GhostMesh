"""
engine.py - discrete-event GhostMesh simulator that drives the real routing.c.

    from engine import Sim
    summary = Sim(cfg).run()                          # random topology from cfg.topology
    summary = Sim(cfg, edges=[(0, 1), (1, 2)]).run()  # your own topology (0-based node indices)

Only routing is real. Crypto is a stand-in (fake link_tag, inner header packed in clear),
since the sim measures forwarding, not encryption. Metrics follow PROTOCOL.md §13.

Radio model (all switchable in ChannelConfig):
  - airtime per frame = preamble + (240 + overhead) bytes at the bit rate
  - collisions: a reception is lost if another frame overlaps it at that receiver,
    or if the receiver is transmitting at the same time (half duplex)
  - carrier sense: a node waits for the channel it hears to go quiet, plus a random backoff
  - base_loss: random extra loss
The virtual watchtower (optional log) sits at the centre and hears every transmission in
range, without collisions.
"""
import ctypes
import hashlib
import heapq
import json
import math
import random
import struct
import time
from ctypes import c_uint8, c_void_p

from bindings import (RtFrame, RtPlatform, STATUS_DELIVERED, STATUS_FAILED, STATUS_SENT,
                      TRANSMIT, NOW_MS, RANDOM, IS_SYNCED, T_START, T_CANCEL, LINK_OK, LINK_TAG,
                      ENCRYPT, DECRYPT, BLOCKED, KEYS, CTRL, PSEUDO, EPOCH, DELIVER, NOTIFY, LOG,
                      load, log_names)
from config import RunConfig, to_rt_config

T0_MS = 1_700_000_000_000          # mesh clock (Unix ms) at sim time 0
NET_KEY = b"ghostmesh-sim-network-key"
BACKOFF_MS = (0.05, 0.67)          # carrier-sense backoff range: ~DIFS + up to 31 x 20 us slots (802.11b)
FRAME_TYPES = {1: "DATA", 2: "HELLO", 3: "CTRL", 4: "KEYS"}

# event kinds. at the same instant lower runs first: a reception that ends exactly when a
# node starts transmitting finishes cleanly first. seq keeps same-kind events in order
EV_RX_END, EV_TIMER, EV_SEND, EV_TX = 0, 1, 2, 3


def _tag(frame: bytes) -> bytes:
    # fake link_tag: keyed hash over everything except the tag (bytes 22-29), like §9.4
    return hashlib.blake2b(frame[:22] + frame[30:], key=NET_KEY, digest_size=8).digest()


class Sim:
    def __init__(self, cfg: RunConfig, lib=None, edges=None, positions=None,
                 record_events: bool = False, watchtower: bool = False):
        self.cfg = cfg
        self.lib = lib or load()
        self.rng = random.Random(cfg.seed)
        self.names = log_names(self.lib)
        self.record_events = record_events
        self.events_out = []
        self.watchtower_out = [] if watchtower else None
        self.error = None

        # ---- topology ----
        if edges is not None:
            n = 1 + max(max(a, b) for a, b in edges)
            self.pos = positions or [(i / max(n - 1, 1), 0.5) for i in range(n)]
            self.adj = [set() for _ in range(n)]
            for a, b in edges:
                self.adj[a].add(b)
                self.adj[b].add(a)
        else:
            self.pos, self.adj = self._random_topology()
        self.n = len(self.adj)

        # distances are scaled so the edge of radio range sits at rssi_weak
        ch = cfg.channel
        edge_m = 10 ** ((ch.rssi_at_1m - cfg.routing.rssi_weak) / (10 * ch.path_loss_exp))
        self.m_per_unit = edge_m / cfg.topology.radio_range

        # ---- event queue + clock ----
        self.now = 0.0
        self.queue = []
        self.seq = 0
        self.timer_ver = {}                      # (node, token) -> current version

        # ---- radio state ----
        self.tx_until = [0.0] * self.n           # node is transmitting until
        self.busy_until = [0.0] * self.n         # node hears the channel busy until
        self.active = [[] for _ in range(self.n)]  # receptions in progress: [end, corrupted]
        self.macs = [bytes([0x02, 0, 0, 0, (i + 1) >> 8, (i + 1) & 0xFF]) for i in range(self.n)]

        # ---- metrics (§13) ----
        self.sent = {}           # msg index -> send time
        self.dest = {}           # msg index -> (src, dst)
        self.handles = {}        # (src node, handle) -> msg index
        self.delivered = {}      # msg index -> first delivery time
        self.acked, self.failed = set(), set()
        self.rejected = 0
        self.dup_deliveries = 0
        self.transmissions = 0
        self.collisions = 0
        self.random_losses = 0
        self.deferrals = 0
        self.log_counts = {}

        # ---- nodes ----
        self._build_platform()
        size = self.lib.sim_node_size()
        self.node_bufs = [ctypes.create_string_buffer(size) for _ in range(self.n)]
        self.node_ptrs = [ctypes.cast(b, c_void_p) for b in self.node_bufs]
        for i in range(self.n):
            rc = to_rt_config(cfg.routing, i + 1)
            self.lib.rt_init(self.node_ptrs[i], ctypes.byref(rc), ctypes.byref(self.platform), c_void_p(i + 1))

        self._schedule_traffic()

    # ---- topology ----------------------------------------------------------------

    def _random_topology(self):
        topo = self.cfg.topology
        r = topo.radio_range
        for _ in range(1000):
            pos = [(self.rng.random(), self.rng.random()) for _ in range(topo.n_nodes)]
            adj = [set() for _ in range(topo.n_nodes)]
            for a in range(topo.n_nodes):
                for b in range(a + 1, topo.n_nodes):
                    if math.dist(pos[a], pos[b]) <= r:
                        adj[a].add(b)
                        adj[b].add(a)
            if not topo.require_connected or self._connected(adj):
                return pos, adj
        raise RuntimeError("couldn't draw a connected topology; raise target_avg_degree")

    @staticmethod
    def _connected(adj) -> bool:
        seen, stack = {0}, [0]
        while stack:
            for nb in adj[stack.pop()]:
                if nb not in seen:
                    seen.add(nb)
                    stack.append(nb)
        return len(seen) == len(adj)

    def _rssi(self, a: int, b_pos) -> int:
        # log-distance path loss + per-reception noise, clamped to int8
        ch = self.cfg.channel
        d_m = max(math.dist(self.pos[a], b_pos) * self.m_per_unit, 1.0)
        rssi = ch.rssi_at_1m - 10 * ch.path_loss_exp * math.log10(d_m) + self.rng.gauss(0, ch.rssi_noise_db)
        return max(-127, min(0, round(rssi)))

    # ---- events ------------------------------------------------------------------

    def _push(self, t: float, kind: int, data) -> None:
        self.seq += 1
        heapq.heappush(self.queue, (t, kind, self.seq, data))

    def _schedule_traffic(self) -> None:
        # every laptop send for the whole run, decided up front from the seed
        tr = self.cfg.traffic
        dur = tr.duration_s * 1000
        times = []
        if tr.pattern == "bursty":
            on, period = tr.burst_on_s * 1000, (tr.burst_on_s + tr.burst_off_s) * 1000
            start = -self.rng.uniform(0, period)                 # random phase per seed
            while start < dur:
                t, we = max(start, 0.0), min(start + on, dur)
                while True:
                    t += self.rng.expovariate(tr.burst_rate_mps) * 1000
                    if t >= we:
                        break
                    times.append(t)
                start += period
        else:
            t = 0.0
            while True:
                t += self.rng.expovariate(tr.avg_rate_mps) * 1000
                if t >= dur:
                    break
                times.append(t)
        for idx, t in enumerate(times):
            src, dst = self.rng.sample(range(self.n), 2)
            self._push(t, EV_SEND, (src, dst, idx))

    def run(self) -> dict:
        """Runs until traffic + drain time is over. Returns the §13 summary."""
        wall = time.time()
        t_end = (self.cfg.traffic.duration_s + self.cfg.traffic.drain_s) * 1000
        while self.queue:
            t, kind, _, data = heapq.heappop(self.queue)
            if t > t_end:
                break
            self.now = t
            if kind == EV_SEND:
                self._on_send(*data)
            elif kind == EV_TX:
                self._on_tx(*data)
            elif kind == EV_RX_END:
                self._on_rx_end(*data)
            else:
                self._on_timer(*data)
            if self.error:
                raise RuntimeError(f"callback failed at t={self.now:.1f} ms") from self.error
        self.now = t_end
        return self.summary(time.time() - wall)

    def _on_send(self, src: int, dst: int, idx: int) -> None:
        # laptop send: the body starts with the message index so delivery can be matched back
        size = max(8, self.cfg.traffic.msg_bytes)
        text = f"m{idx:07d}".encode().ljust(size, b".")
        buf = (c_uint8 * len(text)).from_buffer_copy(text)
        handle = self.lib.rt_send(self.node_ptrs[src], dst + 1, buf, len(text))
        if handle:
            self.sent[idx] = self.now
            self.dest[idx] = (src, dst)
            self.handles[(src, handle)] = idx
        else:
            self.rejected += 1

    def _on_timer(self, i: int, token: int, version: int) -> None:
        if self.timer_ver.get((i, token)) == version:         # skip cancelled / restarted timers
            self.lib.rt_on_timer(self.node_ptrs[i], token)

    # ---- radio -------------------------------------------------------------------

    def _on_tx(self, i: int, frame: bytes) -> None:
        ch = self.cfg.channel
        # carrier sense: channel busy where this node is, so wait it out plus a random backoff
        if ch.carrier_sense and self.busy_until[i] > self.now:
            self.deferrals += 1
            self._push(self.busy_until[i] + self.rng.uniform(*BACKOFF_MS), EV_TX, (i, frame))
            return

        end = self.now + ch.airtime_ms
        self.transmissions += 1
        self.tx_until[i] = end
        self.busy_until[i] = max(self.busy_until[i], end)
        if ch.collisions:                                     # half duplex: can't hear while sending
            for rec in self.active[i]:
                rec[1] = True

        for j in self.adj[i]:
            self.busy_until[j] = max(self.busy_until[j], end)
            rec = [end, False]
            if ch.collisions:
                if self.tx_until[j] > self.now:
                    rec[1] = True
                for other in self.active[j]:                  # overlap destroys both
                    other[1] = True
                    rec[1] = True
            self.active[j].append(rec)
            self._push(end, EV_RX_END, (j, rec, frame, i))

        if self.watchtower_out is not None:
            self._watchtower_log(i, frame)

    def _on_rx_end(self, j: int, rec, frame: bytes, i: int) -> None:
        self.active[j].remove(rec)
        if rec[1]:
            self.collisions += 1
            return
        if self.cfg.channel.base_loss and self.rng.random() < self.cfg.channel.base_loss:
            self.random_losses += 1
            return
        f = RtFrame.from_buffer_copy(frame)
        mac = (c_uint8 * 6)(*self.macs[i])
        self.lib.rt_on_receive(self.node_ptrs[j], ctypes.byref(f), mac, self._rssi(i, self.pos[j]))

    def _watchtower_log(self, i: int, frame: bytes) -> None:
        # one line in ips/schema.py's watchtower format per transmission in range of the centre
        centre = (0.5, 0.5)
        if math.dist(self.pos[i], centre) > self.cfg.topology.radio_range:
            return
        self.watchtower_out.append({
            "t": round((T0_MS + self.now) / 1000, 3),
            "mac": ":".join(f"{b:02x}" for b in self.macs[i]),
            "pseudo": frame[12:16].hex(),                     # transmitter's pseudonym (§9.3)
            "type": FRAME_TYPES.get(frame[0], "DATA"),
            "msg_id": frame[2:10].hex(),
            "ttl": frame[10],
            "hop": frame[11],
            "rssi": self._rssi(i, centre),
            "len": 240,
            "link_ok": True,
            "node": f"N{i + 1}",
            "label": "normal",
        })

    # ---- platform callbacks ----------------------------------------------------------

    def _build_platform(self) -> None:
        # every callback is wrapped so a python exception stops the run instead of being swallowed
        def guard(fn, default=None):
            def wrapped(*args):
                try:
                    return fn(*args)
                except BaseException as e:      # noqa: BLE001 - re-raised after the event
                    if self.error is None:
                        self.error = e
                    return default
            return wrapped

        node = lambda ctx: ctx - 1             # ctx is node index + 1 (0 would arrive as None)

        def transmit(ctx, fp):
            self._push(self.now, EV_TX, (node(ctx), ctypes.string_at(fp, 240)))

        def timer_start(ctx, token, delay):
            key = (node(ctx), token)
            v = self.timer_ver.get(key, 0) + 1
            self.timer_ver[key] = v
            self._push(self.now + delay, EV_TIMER, (key[0], token, v))

        def timer_cancel(ctx, token):
            key = (node(ctx), token)
            self.timer_ver[key] = self.timer_ver.get(key, 0) + 1

        def link_ok(ctx, fp):
            b = ctypes.string_at(fp, 240)
            return _tag(b) == b[22:30]

        def link_tag(ctx, fp, out):
            ctypes.memmove(out, _tag(ctypes.string_at(fp, 240)), 8)

        def encrypt(ctx, ip, fp):
            inner = ip.contents
            if not 1 <= inner.recipient_id <= self.n:
                return False
            blob = struct.pack(">IIIIBB", inner.sender_id, inner.recipient_id, inner.timestamp,
                               inner.seq, inner.type, inner.len) + bytes(inner.body[:inner.len])
            ctypes.memmove(ctypes.addressof(fp.contents.ciphertext), blob.ljust(170, b"\0"), 170)
            return True

        def try_decrypt(ctx, fp, ip):
            ct = bytes(fp.contents.ciphertext)
            sender, recipient, ts, seq, typ, ln = struct.unpack(">IIIIBB", ct[:18])
            if recipient != ctx or ln > 152:                  # ctx == own node id
                return False
            out = ip.contents
            out.sender_id, out.recipient_id, out.timestamp, out.seq, out.type, out.len = sender, recipient, ts, seq, typ, ln
            ctypes.memmove(ctypes.addressof(out.body), ct[18:18 + ln], ln)
            return True

        def my_pseudonym(ctx, out):
            ep = self._epoch()
            ctypes.memmove(out, bytes([0xA0, (ctx >> 8) & 0xFF, ctx & 0xFF, ep & 0xFF]), 4)

        def deliver(ctx, ip):
            body = bytes(ip.contents.body[:ip.contents.len])
            idx = int(body[1:8])
            if idx in self.delivered:
                self.dup_deliveries += 1
            else:
                self.delivered[idx] = self.now

        def notify(ctx, handle, status):
            idx = self.handles.get((node(ctx), handle))
            if idx is None:
                return
            if status == STATUS_DELIVERED:
                self.acked.add(idx)
            elif status == STATUS_FAILED:
                self.failed.add(idx)

        def log(ctx, ev, fp):
            name = self.names.get(ev, str(ev))
            self.log_counts[name] = self.log_counts.get(name, 0) + 1
            if self.record_events:
                row = {"type": "event", "t": round(self.now, 3), "node": ctx, "ev": name}
                if fp:
                    b = ctypes.string_at(fp, 240)
                    row.update(msg=b[2:10].hex(), ttl=b[10], hop=b[11])
                self.events_out.append(row)

        cb = [
            TRANSMIT(guard(transmit)),
            NOW_MS(guard(lambda ctx: int(T0_MS + self.now) & 0xFFFFFFFF, 0)),
            RANDOM(guard(lambda ctx: self.rng.getrandbits(32), 0)),
            IS_SYNCED(guard(lambda ctx: True, True)),
            T_START(guard(timer_start)),
            T_CANCEL(guard(timer_cancel)),
            LINK_OK(guard(link_ok, False)),
            LINK_TAG(guard(link_tag)),
            ENCRYPT(guard(encrypt, False)),
            DECRYPT(guard(try_decrypt, False)),
            BLOCKED(guard(lambda ctx, fp, mac: False, False)),
            KEYS(guard(lambda ctx, fp: None)),
            CTRL(guard(lambda ctx, fp: True, False)),
            PSEUDO(guard(my_pseudonym)),
            EPOCH(guard(lambda ctx: self._epoch(), 0)),
            DELIVER(guard(deliver)),
            NOTIFY(guard(notify)),
            LOG(guard(log)),
        ]
        self._callbacks = cb                                  # keep alive: C holds these pointers
        self.platform = RtPlatform(*cb)

    def _epoch(self) -> int:
        return int((T0_MS + self.now) // 60000) & 0xFFFF

    # ---- results (§13) ------------------------------------------------------------------

    def summary(self, wall_s: float = 0.0) -> dict:
        sent, delivered = len(self.sent), len(self.delivered)
        lat = sorted(self.delivered[i] - self.sent[i] for i in self.delivered if i in self.sent)

        def pct(p):
            return round(lat[min(len(lat) - 1, max(0, math.ceil(p * len(lat)) - 1))], 2) if lat else None

        edges = sum(len(a) for a in self.adj) // 2
        return {
            "type": "summary",
            "run_id": self.cfg.run_id,
            "experiment": self.cfg.experiment,
            "seed": self.cfg.seed,
            "nodes": self.n,
            "edges": edges,
            "avg_degree": round(2 * edges / self.n, 2),
            "sent": sent,
            "rejected": self.rejected,
            "delivered": delivered,
            "delivery_ratio": round(delivered / sent, 4) if sent else None,
            "acked": len(self.acked),
            "failed": len(self.failed),
            "latency_ms_median": pct(0.5),
            "latency_ms_p95": pct(0.95),
            "transmissions": self.transmissions,
            "tx_per_delivered": round(self.transmissions / delivered, 2) if delivered else None,
            "collisions": self.collisions,
            "random_losses": self.random_losses,
            "deferrals": self.deferrals,
            "dup_deliveries": self.dup_deliveries,
            "log_counts": self.log_counts,
            "wall_s": round(wall_s, 2),
        }


def run_config(cfg: RunConfig, lib=None, events: bool = False, watchtower: bool = False,
               commit: str = None) -> dict:
    """Runs one config and writes cfg.out_path: config line, event lines (optional), summary line.
    The watchtower log (optional) goes next to it as <run_id>.watchtower.jsonl."""
    sim = Sim(cfg, lib=lib, record_events=events, watchtower=watchtower)
    summary = sim.run()

    cfg.out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg.out_path, "w") as f:
        f.write(json.dumps({"type": "config", "run_id": cfg.run_id, "commit": commit, **cfg.to_dict()}) + "\n")
        for row in sim.events_out:
            f.write(json.dumps(row) + "\n")
        f.write(json.dumps(summary) + "\n")
    if watchtower:
        with open(cfg.out_path.with_suffix(".watchtower.jsonl"), "w") as f:
            for row in sim.watchtower_out:
                f.write(json.dumps(row) + "\n")
    return summary
