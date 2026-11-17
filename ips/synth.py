import hashlib
import json
import random

random.seed(42)          # same "random" output each run, which makes debugging easier

DURATION = 300           # seconds of simulated traffic
HELLO_PERIOD = 2.0       # nodes beacon every ~2 s
JITTER = 0.2             # +/- random wobble on each beacon interval
START_T = 1731264000.0   # fake Unix timestamp for t=0 (a whole minute, like a real epoch start)
EPOCH = 60               # every node changes pseudonym AND MAC on each Unix minute boundary

# Each real node and its average signal strength at the watchtower (dBm).
NODES = {
    "A": -48,   # close
    "B": -60,
    "C": -67,
    "D": -75,   # far
}

# Attacker board: node "X" (the watchtower knows it like any keyed insider).
ATTACKER = "X"
ATTACKER_RSSI = -55
FLOOD_START, FLOOD_END = 120, 150   # seconds into the session
FLOOD_RATE = 30                     # packets per second (normal node: ~0.5/s)
SLOW_FLOOD_RATE = 8                 # under the rule's threshold of 15, but still ~16x normal

# Routing abuse: extra HELLOs with a fake TTL so the attacker looks like a great neighbour
ROUTING_RATE = 5                    # HELLOs per second (normal: ~0.5/s)
ROUTING_FAKE_TTL = 10               # honest HELLOs use TTL 1
ATTACK_LEN = 30                     # seconds each attack lasts in the train/test sessions


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


def make_packet(t, node, rssi_mean, ptype="HELLO", ttl=1, label="normal"):
    """Build one log line (as a dict) in the watchtower schema."""
    pseudo, mac = identity(node, t)
    return {
        "t": round(t, 3),
        "mac": mac,                # rotates every minute...
        "pseudo": pseudo,          # ...and so does this
        "node": node,              # added by the watchtower; does NOT rotate
        "type": ptype,
        # 8 random bytes, like the real frame's msg_id. Uses `random` (not uuid) so the seed
        # controls it too: same seed -> byte-identical files.
        "msg_id": f"{random.getrandbits(64):016x}",
        "ttl": ttl,   # HELLOs use 1 (direct neighbours only); DATA can travel further
        "hop": 0,     # heard straight from the sender, not relayed
        "rssi": round(rssi_mean + random.gauss(0, 2)),
        "len": 240,
        "link_ok": True,
        "label": label,
    }


def simulate():
    packets = []
    for node, rssi_mean in NODES.items():
        t = random.uniform(0, HELLO_PERIOD)          # random start so nodes aren't in sync
        while t < DURATION:
            packets.append(make_packet(START_T + t, node, rssi_mean))
            t += HELLO_PERIOD + random.uniform(-JITTER, JITTER)
    return sorted(packets, key=lambda p: p["t"])     # interleave nodes by time


def simulate_flood(rate=FLOOD_RATE, start=FLOOD_START, end=FLOOD_END):
    """Attacker spams DATA packets at `rate` per second between `start` and `end`."""
    packets = []
    t = start
    while t < end:
        packets.append(make_packet(START_T + t, ATTACKER, ATTACKER_RSSI,
                                   ptype="DATA", ttl=4, label="flood"))
        t += 1 / rate                                # 30/s -> 0.033 s gaps, 8/s -> 0.125 s
    return packets


def simulate_routing(start, end, rate=ROUTING_RATE):
    """Attacker spams HELLOs with a fake TTL between `start` and `end`.
    Each packet looks like a normal HELLO, so only the rate and TTL give it away."""
    packets = []
    t = start
    while t < end:
        packets.append(make_packet(START_T + t, ATTACKER, ATTACKER_RSSI,
                                   ptype="HELLO", ttl=ROUTING_FAKE_TTL, label="routing"))
        t += 1 / rate                                # 5/s -> 0.2 s gaps
    return packets


def make_session(seed, flood_rate, flood_start, routing_start):
    """One full labeled session: normal traffic + one flood + one routing attack.
    A different seed gives different random noise, so sessions are truly separate."""
    random.seed(seed)
    packets = (simulate()
               + simulate_flood(rate=flood_rate, start=flood_start, end=flood_start + ATTACK_LEN)
               + simulate_routing(start=routing_start, end=routing_start + ATTACK_LEN))
    return sorted(packets, key=lambda p: p["t"])


def write_jsonl(packets, path):
    with open(path, "w") as f:
        for p in packets:
            f.write(json.dumps(p) + "\n")


if __name__ == "__main__":
    normal = simulate()                              # call once, reuse below
    write_jsonl(normal, "normal_session1.jsonl")     # clean file: no attacks (for Step 7)

    attack = sorted(normal + simulate_flood(), key=lambda p: p["t"])  # mix flood into normal traffic
    write_jsonl(attack, "flood_session1.jsonl")

    # Same normal traffic + a quieter flood that stays under the rule's threshold.
    # Label stays "flood": same attack, just slower.
    slow = sorted(normal + simulate_flood(rate=SLOW_FLOOD_RATE), key=lambda p: p["t"])
    write_jsonl(slow, "slowflood_session1.jsonl")

    print(f"normal_session1.jsonl:    {len(normal)} packets")
    print(f"flood_session1.jsonl:     {len(attack)} packets")
    print(f"slowflood_session1.jsonl: {len(slow)} packets")

    # --- Step 9: two separate labeled sessions for the Random Forest ---
    # Train: seed 42, LOUD flood early, routing late
    train = make_session(seed=42, flood_rate=FLOOD_RATE, flood_start=60, routing_start=180)
    write_jsonl(train, "train_session.jsonl")
    # Test: seed 7, SLOW flood late, routing early -> different noise, timing and rate
    test = make_session(seed=7, flood_rate=SLOW_FLOOD_RATE, flood_start=200, routing_start=90)
    write_jsonl(test, "test_session.jsonl")

    print(f"train_session.jsonl:      {len(train)} packets")
    print(f"test_session.jsonl:       {len(test)} packets")
