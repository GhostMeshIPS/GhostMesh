"""Fake watchtower logs that behave like the real mesh (until Rashad's sim / real captures arrive).

What it models (numbers from PROTOCOL.md and Jose's security/notes-for-hannan.md):
  * Topology A-B, B-C, A-D, D-C, plus attacker X sitting near A and B. The watchtower W hears
    every transmission.
  * Managed flooding: each node relays a new message once, after a 10-50 ms jitter, with
    ttl-1 / hop+1 and its OWN pseudonym + MAC (pseudo = transmitter). HELLOs go one hop only.
  * Hop padding: the originator starts at hop 0, 1 or 2 (ttl lowered to match), so a low hop
    no longer means "this is the sender".
  * Chat: conversations with quiet and chatty spells. Each DATA gets an ACK (also sent as type
    DATA, 0-400 ms after it arrives). No ACK -> retry with a NEW msg_id after 1 / 2 / 4 s.
  * KEYS frames from every node about every 10 s; a signed CTRL time beacon from W every 10 s.
  * Every node swaps MAC + pseudonym on each Unix minute, with a short outage (~0.3 s).
  * Relays accept at most ~20 new msg_ids per second from one transmitter (flood hardening).
Attacks: flood (any rate), routing abuse (fast HELLOs with a fake TTL), replay (X re-sends frames
it overheard 2+ minutes earlier). Harmless event that must NOT be flagged: node B unplugged.

Relayed copies of an attacker's frames are labelled "normal": the relay isn't attacking, and
the IPS has to learn to blame the originator, not the nodes that pass its traffic along.
"""
import hashlib
import json
import random
from collections import defaultdict

random.seed(42)          # same "random" output each run, which makes debugging easier

START_T = 1731264000.0   # fake Unix timestamp for t=0 (a whole minute, like a real epoch start)
EPOCH = 60               # every node changes pseudonym AND MAC on each Unix minute boundary
ROTATION_GAP = 0.3       # seconds of silence after each boundary (changing MAC restarts Wi-Fi)

DEFAULT_TTL = 16         # Rashad's sim value (PROTOCOL.md 12, includes +2 for hop padding); hardware still TBD
HELLO_PERIOD = 2.0       # HELLO beacons ~every 2 s (0.5 Hz), never relayed
JITTER = 0.2             # +/- wobble on each HELLO interval
KEYS_PERIOD = 10.0       # each node floods its next-epoch key ~6 times a minute
BEACON_PERIOD = 10.0     # watchtower's signed TIME beacon
RELAY_JITTER = (0.010, 0.050)   # relays wait 10-50 ms before rebroadcasting
ACK_DELAY = (0.0, 0.4)          # ACK sent 0-400 ms after the DATA arrives
RETRY_BACKOFF = [1, 2, 4]       # seconds between attempts (first send + 3 retries)
ACK_LOSS = 0.05                 # chance an ACK gets lost and the sender retries
INSERT_LIMIT = 20               # new msg_ids/s a relay accepts from one transmitter

# Who can hear whom (radio links). W is the watchtower: it hears everything, relays nothing.
TOPOLOGY = {
    "A": {"B", "D", "X", "W"},
    "B": {"A", "C", "X", "W"},
    "C": {"B", "D", "W"},
    "D": {"A", "C", "W"},
    "X": {"A", "B", "W"},
    "W": {"A", "B", "C", "D"},
}
# Average signal strength of each board at the watchtower (dBm): closer = nearer zero
RSSI = {"A": -48, "B": -60, "C": -67, "D": -75, "X": -55, "W": -40}
NODES = ["A", "B", "C", "D"]                 # our boards
CONVERSATIONS = [("A", "C"), ("B", "D")]     # who chats with whom (A-C must go via B or D)

ATTACKER = "X"           # the attacker board: a keyed insider that behaves normally between attacks
FLOOD_RATE = 30          # packets per second (a normal node originates well under 1/s)
SLOW_FLOOD_RATE = 8      # under the rule's threshold of 15
ROUTING_RATE = 5         # fake HELLOs per second (normal: 0.5/s)
ROUTING_FAKE_TTL = 10    # honest HELLOs use TTL 1
REPLAY_RATE = 2          # replayed frames per second
REPLAY_AGE = (120, 170)  # replayed frames were captured this many seconds earlier
SPOOF_RATE = 2           # messages per second X sends while pretending to be a victim


def identity(node, t):
    """This node's pseudonym and MAC during the epoch containing time t.

    A simplified copy of Jose's scheme (PROTOCOL.md 9.3): both come from a hash of the
    node's secret and the epoch number, so they change every minute and look random to
    an outsider. Here the "secret" is just the node letter (fine for fake data).
    """
    epoch = int(t // EPOCH)
    h = hashlib.blake2b(f"{node}-{epoch}".encode(), digest_size=10).digest()
    pseudo = h[:4].hex()
    mac = bytearray(h[4:10])
    mac[0] = (mac[0] & 0xFC) | 0x02          # "locally administered" MAC, like the real boards
    return pseudo, ":".join(f"{b:02x}" for b in mac)


def new_msg_id():
    """8 random bytes, like the real frame's msg_id. Uses `random` so the seed controls it."""
    return f"{random.getrandbits(64):016x}"


def make_packet(t, node, ptype, ttl, hop, msg_id, label="normal", pseudo=None, mac=None, node_tag=None):
    """One watchtower log line. pseudo/mac/node_tag override the honest values (used by replays)."""
    real_pseudo, real_mac = identity(node, t)
    return {
        "t": round(t, 3),
        "mac": mac or real_mac,              # rotates every minute...
        "pseudo": pseudo or real_pseudo,     # ...and so does this
        "node": node_tag or node,            # added by the watchtower; does NOT rotate
        "type": ptype,
        "msg_id": msg_id,
        "ttl": ttl,
        "hop": hop,
        "rssi": round(RSSI[node] + random.gauss(0, 2)),
        "len": 240,
        "link_ok": True,
        "label": label,
    }


def in_rotation_gap(t):
    return (t % EPOCH) < ROTATION_GAP


class Mesh:
    """Generates one session's packets, as the watchtower would log them."""

    def __init__(self, duration):
        self.duration = duration
        self.packets = []
        self.down = []                        # (node, start, end): unplugged during that time
        self.jam_keys = []                    # (node, start, end): its KEYS frames are jammed
        self.accepted = defaultdict(int)      # (relay, transmitter, second) -> new msg_ids accepted

    def is_down(self, node, t):
        return any(n == node and s <= t - START_T < e for n, s, e in self.down)

    def keys_jammed(self, node, t):
        """A jammer that reacts to frame type wipes out this node's KEYS frames (O18), nothing else."""
        return any(n == node and s <= t - START_T < e for n, s, e in self.jam_keys)

    def flood(self, t0, origin, ptype, label="normal", pad=True, as_node=None, copy_mac=False):
        """Send one message from `origin` and let the mesh relay it.
        as_node: the origin transmits WEARING that node's identity (spoofing): its pseudonym, so the
        watchtower tags it as that node; and its MAC too if copy_mac, else the origin's own MAC.
        Returns {node: time it first heard the message} (used to time ACKs)."""
        if self.is_down(origin, t0):
            return {}
        if in_rotation_gap(t0):
            t0 += ROTATION_GAP                # the radio is restarting: send right after
        p = random.choice((0, 1, 2)) if pad else 0     # hop padding (Jose, PROTOCOL.md 9.9)
        msg_id = new_msg_id()
        heard = {origin: t0}
        queue = [(t0, origin, DEFAULT_TTL - p, p)]
        while queue:
            queue.sort()
            t, tx, ttl, hop = queue.pop(0)
            if in_rotation_gap(t):
                continue                      # this transmission is lost in the outage
            disguise = {}
            if tx == origin and as_node:
                fake_pseudo, fake_mac = identity(as_node, t)
                disguise = dict(pseudo=fake_pseudo, node_tag=as_node, mac=fake_mac if copy_mac else None)
            self.packets.append(make_packet(t, tx, ptype, ttl, hop, msg_id,
                                            label if tx == origin else "normal", **disguise))
            if ttl == 0:
                continue                      # out of hops: nobody relays it further
            for nb in sorted(TOPOLOGY[tx]):   # sorted: same order every run (sets aren't ordered)
                if nb == "W" or nb in heard or self.is_down(nb, t):
                    continue
                key = (nb, tx, int(t))
                if self.accepted[key] >= INSERT_LIMIT:
                    continue                  # relay's per-transmitter limit: dropped, not relayed
                self.accepted[key] += 1
                heard[nb] = t
                queue.append((t + random.uniform(*RELAY_JITTER), nb, ttl - 1, hop + 1))
        return heard

    def send_message(self, t, sender, recipient, attempt=0):
        """A chat message, its ACK, and retries (each with a NEW msg_id) if the ACK doesn't come."""
        heard = self.flood(t, sender, "DATA")
        if recipient in heard and random.random() > ACK_LOSS:
            self.flood(heard[recipient] + random.uniform(*ACK_DELAY), recipient, "DATA")  # ACK looks like DATA
        elif attempt < len(RETRY_BACKOFF):
            self.send_message(t + RETRY_BACKOFF[attempt], sender, recipient, attempt + 1)

    # ------------------------------------------------------------ normal traffic
    def normal_traffic(self):
        end = START_T + self.duration
        for node in NODES + [ATTACKER]:
            t = START_T + random.uniform(0, HELLO_PERIOD)           # HELLO: one hop, not relayed
            while t < end:
                if not self.is_down(node, t) and not in_rotation_gap(t):
                    self.packets.append(make_packet(t, node, "HELLO", 1, 0, new_msg_id()))
                t += HELLO_PERIOD + random.uniform(-JITTER, JITTER)
            t = START_T + random.uniform(0, KEYS_PERIOD)            # KEYS: flooded like DATA
            while t < end:
                if not self.keys_jammed(node, t):
                    self.flood(t, node, "KEYS")
                t += KEYS_PERIOD + random.uniform(-1, 1)
        t = START_T + random.uniform(0, BEACON_PERIOD)              # watchtower TIME beacon
        while t < end:
            self.flood(t, "W", "CTRL", pad=False)
            t += BEACON_PERIOD
        for a, b in CONVERSATIONS:                                  # chat: quiet and chatty spells
            t = START_T + random.uniform(0, 10)
            while t < end:
                spell_end = t + random.uniform(20, 60)
                mean_gap = 3 if random.random() < 0.4 else 25       # chatty: a message every ~3 s
                while t < min(spell_end, end):
                    sender, recipient = (a, b) if random.random() < 0.5 else (b, a)
                    self.send_message(t, sender, recipient)
                    t += random.expovariate(1 / mean_gap)

    # ------------------------------------------------------------ attacks
    def flood_attack(self, rate, start, end):
        """X originates DATA at `rate`/s. It's an insider (valid link_tag), so relays pass it on."""
        t = START_T + start
        while t < START_T + end:
            self.flood(t, ATTACKER, "DATA", label="flood")
            t += 1 / rate

    def routing_attack(self, start, end, rate=ROUTING_RATE):
        """X beacons HELLOs far too often with a fake TTL, to look like a great neighbour.
        (Placeholder until Jose's task 11 defines the real forgery: lying about hop counts.)"""
        t = START_T + start
        while t < START_T + end:
            self.packets.append(make_packet(t, ATTACKER, "HELLO", ROUTING_FAKE_TTL, 0,
                                            new_msg_id(), label="routing"))
            t += 1 / rate

    def spoof_attack(self, victim, start, end, copy_mac=False, rate=SPOOF_RATE):
        """X sends messages wearing `victim`'s identity (insider only: it needs the network key).
        The watchtower tags them as the victim, so one "node" suddenly has two signal levels,
        and two MACs unless X copied the victim's MAC too. Relays pass them on as usual."""
        t = START_T + start
        while t < START_T + end:
            self.flood(t, ATTACKER, "DATA", label="spoof", as_node=victim, copy_mac=copy_mac)
            t += 1 / rate

    def replay_attack(self, start, end, rate=REPLAY_RATE):
        """X re-sends frames it overheard 2-3 minutes earlier, unchanged.

        Unchanged means same msg_id, type, ttl, hop and the ORIGINAL transmitter's pseudonym.
        But they come out of X's radio, so the MAC and signal strength are X's. That pseudonym
        is from an epoch long gone, so the watchtower can't match it to a node: node = "?".
        Relays drop them (their 180 s msg_id cache / epoch check), so they aren't relayed.
        """
        overheard = [p for p in self.packets
                     if p["node"] in TOPOLOGY[ATTACKER] and p["type"] in ("DATA", "KEYS")]
        t = START_T + start
        while t < START_T + end:
            lo, hi = t - REPLAY_AGE[1], t - REPLAY_AGE[0]
            choices = [p for p in overheard if lo <= p["t"] <= hi]
            if choices:
                old = random.choice(choices)
                _, x_mac = identity(ATTACKER, t)
                self.packets.append(make_packet(t, ATTACKER, old["type"], old["ttl"], old["hop"],
                                                old["msg_id"], label="replay", pseudo=old["pseudo"],
                                                mac=x_mac, node_tag="?"))
            t += 1 / rate


def make_session(seed, duration, floods=(), routing=(), replays=(), unplug_b=None, x_off=False, spoofs=(),
                 jam_keys=()):
    """One labelled session. Times are seconds into the session.
    floods = [(rate, start, end), ...]; routing / replays = [(start, end), ...];
    spoofs = [(victim, start, end, copy_mac), ...];
    jam_keys = [(node, start, end), ...]: that node's KEYS frames never get through (labels stay
    "normal": the node itself isn't misbehaving; live.py's missing-KEYS check alerts on it);
    unplug_b = (start, end) when node B is switched off (harmless, must not be flagged);
    x_off = attacker board powered off the whole time (no traffic, no relaying)."""
    random.seed(seed)
    mesh = Mesh(duration)
    if x_off:
        mesh.down.append((ATTACKER, 0, duration))
    mesh.jam_keys.extend(jam_keys)
    if unplug_b:
        mesh.down.append(("B", *unplug_b))
    mesh.normal_traffic()
    for rate, start, end in floods:
        mesh.flood_attack(rate, start, end)
    for start, end in routing:
        mesh.routing_attack(start, end)
    for victim, start, end, copy_mac in spoofs:
        mesh.spoof_attack(victim, start, end, copy_mac)
    for start, end in replays:                # after normal traffic: it replays what it overheard
        mesh.replay_attack(start, end)
    return sorted(mesh.packets, key=lambda p: p["t"])


def write_jsonl(packets, path):
    with open(path, "w") as f:
        for p in packets:
            f.write(json.dumps(p) + "\n")


if __name__ == "__main__":
    sessions = {
        # Clean traffic (incl. B unplugged for 40 s): what the Isolation Forest learns as "normal".
        # X powered OFF (Jose's request), so the anomaly model never learns the attacker's habits as normal.
        "normal_session1.jsonl":    dict(seed=42, duration=300, unplug_b=(150, 190), x_off=True),
        # Same normal traffic + one loud or one slow flood
        "flood_session1.jsonl":     dict(seed=42, duration=300, unplug_b=(150, 190),
                                         floods=[(FLOOD_RATE, 120, 150)]),
        "slowflood_session1.jsonl": dict(seed=42, duration=300, unplug_b=(150, 190),
                                         floods=[(SLOW_FLOOD_RATE, 120, 150)]),
        # Random Forest training: floods at several rates, routing, replay, B unplugged
        "train_session.jsonl":      dict(seed=42, duration=600,
                                         floods=[(30, 40, 60), (20, 100, 120), (10, 160, 180), (5, 220, 240)],
                                         routing=[(300, 330)], replays=[(420, 450)], unplug_b=(480, 520),
                                         # spoof A (own MAC, 7 dB louder) and C (copied MAC, 12 dB louder)
                                         spoofs=[("A", 360, 390, False), ("C", 540, 570, True)]),
        # Unseen test: different seed and timings, a flood rate (8/s) not in training, and a spoof of
        # B, whose usual signal is only 5 dB from X's (harder than the 7 and 12 dB seen in training)
        "test_session.jsonl":       dict(seed=7, duration=300,
                                         routing=[(60, 90)], unplug_b=(100, 140),
                                         floods=[(SLOW_FLOOD_RATE, 150, 180)], replays=[(230, 260)],
                                         spoofs=[("B", 265, 295, False)],
                                         jam_keys=[("C", 170, 260)]),       # C's KEYS jammed for 90 s
    }
    for path, kw in sessions.items():
        packets = make_session(**kw)
        write_jsonl(packets, path)
        print(f"{path:26} {len(packets):6} packets")
