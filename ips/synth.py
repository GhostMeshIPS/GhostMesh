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
Attacks follow Jose's specs (security/attacks/README.md, decision 20): flood (loud 80/s, slow 15/s,
low_slow 8/s, an outsider without the network key, `cycling` through fake identities, forged CTRL
frames), routing abuse (X relays claiming hop 0, sometimes with TTL fixed to hide it), replay (X
re-sends frames it heard 30 / 90 / 240 s earlier) and spoofing. X is a passthrough board (decision 18):
SILENT between attacks, no KEYS, no relaying. Harmless event that must NOT be flagged: node B unplugged.

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

DEFAULT_TTL = 5          # hardware value (Yunus, Nov 19): 3 real hops + 2 for hop padding
HELLO_ENABLED = False    # honest HELLOs are OFF on the real boards (hello_interval_ms = 0, Yunus, Nov 19),
                         # so normal traffic has none (a HELLO on the real mesh would itself be odd)
HELLO_PERIOD = 2.0       # if turned on: HELLO beacons ~every 2 s (0.5 Hz), never relayed
JITTER = 0.2             # +/- wobble on each HELLO interval
KEYS_PERIOD = 15.0       # each node floods its next-epoch key ~4 times a minute (real boards, Nov 18)
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

ATTACKER = "X"           # the attacker board: a keyed insider, SILENT between attacks (decision 18)
# Attack rates from Jose's spec table (decision 20). A normal node originates well under 1 packet/s.
FLOOD_RATE = 80          # `loud`
SLOW_FLOOD_RATE = 15     # `slow`: under the relays' 20/s limit, exactly at the rule's edge (> 15)
LOW_SLOW_RATE = 8        # `low_slow`: below the rule's threshold
OUTSIDER_RATE = 50       # `outsider`: frames per second from a radio without the network key
CYCLING_RATE = 50        # `cycling`: keyed frames under a new random pseudonym + MAC...
CYCLING_PER_ID = 5       # ...every 5 frames
CTRL_FORGERY_RATE = 20   # `ctrl_forgery`: CTRL frames with bad signatures, as X
REPLAY_RATE = 5          # replayed frames per second
REPLAY_SLACK = 2.0       # a replay of age A re-sends frames heard between A and A + 2 s ago
SPOOF_RATE = 5           # messages per second X sends while pretending to be a victim
X_RELAY_DELAY = (0.005, 0.030)   # routing attack: laptop script latency before X's forged copy


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


def random_la_mac():
    """A random locally administered MAC, like the boards' (what X's scripts pick for fake identities)."""
    b = [random.getrandbits(8) for _ in range(6)]
    b[0] = (b[0] & 0xFC) | 0x02
    return ":".join(f"{x:02x}" for x in b)


def new_msg_id():
    """8 random bytes, like the real frame's msg_id. Uses `random` so the seed controls it."""
    return f"{random.getrandbits(64):016x}"


def make_packet(t, node, ptype, ttl, hop, msg_id, label="normal", pseudo=None, mac=None, node_tag=None):
    """One watchtower log line. pseudo/mac/node_tag override the honest values (used by replays)."""
    real_pseudo, real_mac = identity(node, t)
    tag = node_tag or node
    # The watchtower's id_ok check: does the MAC on air match the MAC derived for the node whose
    # pseudonym this is? False for "?" frames and for a spoofer using its own MAC.
    id_ok = tag != "?" and (mac or real_mac) == identity(tag, t)[1]
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
        "id_ok": id_ok,
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
        self.forging = []                     # (start, end): X forges the hop count on everything it relays
        self.accepted = defaultdict(int)      # (relay, transmitter, second) -> new msg_ids accepted

    def is_down(self, node, t):
        return any(n == node and s <= t - START_T < e for n, s, e in self.down)

    def forging_hops(self, t):
        return any(s <= t - START_T < e for s, e in self.forging)

    def keys_jammed(self, node, t):
        """A jammer that reacts to frame type wipes out this node's KEYS frames (O18), nothing else."""
        return any(n == node and s <= t - START_T < e for n, s, e in self.jam_keys)

    def flood(self, t0, origin, ptype, label="normal", pad=True, as_node=None, copy_mac=False, fake=None):
        """Send one message from `origin` and let the mesh relay it.
        as_node: the origin transmits WEARING that node's identity (spoofing): its pseudonym, so the
        watchtower tags it as that node; and its MAC too if copy_mac, else the origin's own MAC.
        fake: dict(pseudo=, mac=, node_tag=) the origin uses instead (the `cycling` flood).
        X never relays (passthrough firmware); during a routing attack it sends one forged copy.
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
            elif tx == origin and fake:
                disguise = dict(fake)
            lab = label if tx == origin else "normal"
            self.packets.append(make_packet(t, tx, ptype, ttl, hop, msg_id, lab, **disguise))
            if ATTACKER in TOPOLOGY[tx] and ATTACKER not in heard and tx != ATTACKER:
                heard[ATTACKER] = t           # X overhears it (it never relays it honestly)
                if ptype in ("DATA", "KEYS") and self.forging_hops(t) and not self.is_down(ATTACKER, t):
                    self.forge_relay(t, ptype, ttl, msg_id)
            if ttl == 0:
                continue                      # out of hops: nobody relays it further
            for nb in sorted(TOPOLOGY[tx]):   # sorted: same order every run (sets aren't ordered)
                if nb in ("W", ATTACKER) or nb in heard or self.is_down(nb, t):
                    continue
                # relays limit new msg_ids per transmitter PSEUDONYM: a fake one starts a fresh count
                key = (nb, disguise.get("pseudo") or tx, int(t))
                if self.accepted[key] >= INSERT_LIMIT:
                    continue                  # relay's per-transmitter limit: dropped, not relayed
                self.accepted[key] += 1
                heard[nb] = t
                queue.append((t + random.uniform(*RELAY_JITTER), nb, ttl - 1, hop + 1))
        return heard

    def forge_relay(self, t, ptype, ttl, msg_id):
        """Routing abuse (`hop0` / `hop0_ttlfix`, security/attacks/attacks.py): X re-sends a frame it
        just heard, as itself, claiming hop 0 ("I'm right next to the sender, route through me").
        Half the time TTL is just decremented (ttl + hop no longer adds up to 5), half the time it is
        raised to DEFAULT_TTL to hide that (only the hop going DOWN for that msg_id gives it away).
        Nodes have already seen the msg_id, so nobody relays X's copy further."""
        fix_ttl = random.random() < 0.5
        if not fix_ttl and ttl == 0:
            return                            # the script skips frames it can't decrement
        t_x = t + random.uniform(*X_RELAY_DELAY)
        self.packets.append(make_packet(t_x, ATTACKER, ptype, DEFAULT_TTL if fix_ttl else ttl - 1, 0,
                                        msg_id, "routing"))

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
        for node in NODES:                                          # X stays silent (decision 18)
            t = START_T + random.uniform(0, HELLO_PERIOD)           # HELLO: one hop, not relayed
            while HELLO_ENABLED and t < end:
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

    def outsider_flood(self, start, end, rate=OUTSIDER_RATE):
        """A radio WITHOUT the network key spams frames. It can't compute a valid link_tag or a real
        pseudonym, so W sees link_ok = false from an unknown radio ("?"), and the first relay drops
        them (never relayed). One random MAC for the whole run (`outsider`, decision 20)."""
        mac = random_la_mac()
        pseudo = f"{random.getrandbits(32):08x}"
        t = START_T + start
        while t < START_T + end:
            pkt = make_packet(t, ATTACKER, "DATA", DEFAULT_TTL, 0, new_msg_id(), label="flood",
                              pseudo=pseudo, mac=mac, node_tag="?")
            pkt["link_ok"] = False
            self.packets.append(pkt)
            t += 1 / rate

    def cycling_flood(self, start, end, rate=CYCLING_RATE):
        """`cycling`: X floods with the network key (valid link_tag, so relays pass it on) under a new
        random pseudonym + MAC every CYCLING_PER_ID frames, to dodge per-sender limits. W can't match
        those pseudonyms: every frame is "?" but with link_ok true."""
        t, n, fake = START_T + start, 0, None
        while t < START_T + end:
            if n % CYCLING_PER_ID == 0:
                fake = dict(pseudo=f"{random.getrandbits(32):08x}", mac=random_la_mac(), node_tag="?")
            self.flood(t, ATTACKER, "DATA", label="flood", fake=fake)
            n += 1
            t += 1 / rate

    def ctrl_forgery(self, start, end, rate=CTRL_FORGERY_RATE):
        """`ctrl_forgery`: X sends CTRL TIME/BLOCK frames as itself with bad signatures. Nodes reject
        them (signature check), so they're not relayed. CTRL uses TTL 7, hop 0, like W's."""
        t = START_T + start
        while t < START_T + end:
            self.packets.append(make_packet(t, ATTACKER, "CTRL", 7, 0, new_msg_id(), "flood"))
            t += 1 / rate

    def spoof_attack(self, victim, start, end, copy_mac=False, rate=SPOOF_RATE):
        """X sends messages wearing `victim`'s identity (insider only: it needs the network key).
        The watchtower tags them as the victim; with X's own MAC (`pseudo`) id_ok is False, with the
        victim's MAC copied (`pseudo_mac`) only the signal strength differs. Relays pass them on."""
        t = START_T + start
        while t < START_T + end:
            self.flood(t, ATTACKER, "DATA", label="spoof", as_node=victim, copy_mac=copy_mac)
            t += 1 / rate

    def replay_attack(self, start, end, age, rate=REPLAY_RATE):
        """X re-sends, unchanged, DATA/KEYS frames it overheard `age` seconds earlier (30 / 90 / 240 s).

        Unchanged means same msg_id, type, ttl, hop and the ORIGINAL transmitter's pseudonym, but from
        X's radio: X's own MAC and signal strength. W knows pseudonyms for the current epoch and the
        ones either side, so a recent replay (30 s) is tagged as the original node with id_ok False
        (wrong MAC); an old one (240 s) matches nobody: "?" (its link_tag is still valid).
        Relays drop them (seen-cache / msg_id cache / epoch check), so they aren't relayed.
        """
        overheard = [p for p in self.packets
                     if p["node"] in NODES and p["node"] in TOPOLOGY[ATTACKER]
                     and p["type"] in ("DATA", "KEYS") and p["label"] == "normal"]
        used = set()
        t = START_T + start
        while t < START_T + end:
            lo, hi = t - age - REPLAY_SLACK, t - age
            choices = [p for p in overheard if lo <= p["t"] <= hi and p["msg_id"] not in used]
            if choices:
                old = random.choice(choices)
                used.add(old["msg_id"])
                recent = int(t // EPOCH) - int(old["t"] // EPOCH) <= 1
                _, x_mac = identity(ATTACKER, t)
                self.packets.append(make_packet(t, ATTACKER, old["type"], old["ttl"], old["hop"],
                                                old["msg_id"], label="replay", pseudo=old["pseudo"],
                                                mac=x_mac, node_tag=old["node"] if recent else "?"))
            t += 1 / rate


def make_session(seed, duration, floods=(), routing=(), replays=(), unplug_b=None, x_off=False, spoofs=(),
                 jam_keys=(), outsider=(), cycling=(), ctrl_forgery=()):
    """One labelled session. Times are seconds into the session.
    floods = [(rate, start, end), ...]; routing / cycling / ctrl_forgery = [(start, end), ...];
    replays = [(start, end, age), ...];
    outsider = [(rate, start, end), ...]: flood from a radio without the network key;
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
    mesh.forging.extend(routing)              # before normal traffic: X forges hops on what it relays
    if unplug_b:
        mesh.down.append(("B", *unplug_b))
    mesh.normal_traffic()
    for rate, start, end in floods:
        mesh.flood_attack(rate, start, end)
    for rate, start, end in outsider:
        mesh.outsider_flood(start, end, rate)
    for victim, start, end, copy_mac in spoofs:
        mesh.spoof_attack(victim, start, end, copy_mac)
    for start, end in cycling:
        mesh.cycling_flood(start, end)
    for start, end in ctrl_forgery:
        mesh.ctrl_forgery(start, end)
    for start, end, age in replays:           # after everything else: it replays what it overheard
        mesh.replay_attack(start, end, age)
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
        # Random Forest training: every attack family from decision 20, B unplugged
        "train_session.jsonl":      dict(seed=42, duration=600,
                                         floods=[(FLOOD_RATE, 40, 60), (SLOW_FLOOD_RATE, 100, 120),
                                                 (5, 220, 240)],
                                         cycling=[(160, 180)], ctrl_forgery=[(455, 470)],
                                         outsider=[(OUTSIDER_RATE, 255, 285)],   # no network key
                                         routing=[(300, 330)], unplug_b=(480, 520),
                                         replays=[(420, 445, 30), (575, 595, 240)],
                                         # spoof A (own MAC, 7 dB louder) and C (copied MAC, 12 dB louder)
                                         spoofs=[("A", 360, 390, False), ("C", 540, 570, True)]),
        # Unseen test: different seed and timings, a flood rate (8/s, `low_slow`) and a replay age (90 s)
        # not in training, and a spoof of B, whose usual signal is only 5 dB from X's (harder than the
        # 7 and 12 dB seen in training)
        "test_session.jsonl":       dict(seed=7, duration=360,
                                         routing=[(60, 90)], unplug_b=(100, 140),
                                         floods=[(LOW_SLOW_RATE, 150, 180)], replays=[(230, 260, 90)],
                                         spoofs=[("B", 265, 295, False)],
                                         jam_keys=[("C", 170, 260)],        # C's KEYS jammed for 90 s
                                         outsider=[(OUTSIDER_RATE, 195, 220)],
                                         cycling=[(305, 325)], ctrl_forgery=[(335, 350)]),
    }
    for path, kw in sessions.items():
        packets = make_session(**kw)
        write_jsonl(packets, path)
        print(f"{path:26} {len(packets):6} packets")
