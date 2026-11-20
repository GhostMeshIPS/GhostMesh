"""The ONLY file that knows the watchtower's JSON format.

If the firmware team renames a field or adds a packet type, edit this file and
nothing else. Every other file uses the internal names on the left of FIELD_MAP.
"""
import json

# internal name -> name in the watchtower's JSON line
# (identical today; change the right-hand side if the firmware renames a field)
FIELD_MAP = {
    "t": "t",              # timestamp, seconds (float)
    "mac": "mac",          # transmitter's MAC (rotates every 60 s)
    "pseudo": "pseudo",    # TRANSMITTER's pseudonym, i.e. the last hop, not the originator (rotates every 60 s)
    "type": "type",        # DATA / ACK / HELLO / RREQ / RREP / BLOCK
    "msg_id": "msg_id",
    "ttl": "ttl",
    "hop": "hop",
    "rssi": "rssi",        # signal strength at the watchtower, dBm
    "len": "len",          # frame length, always 240
    "link_ok": "link_ok",  # did the network link_tag check pass?
}

# Which Python type each field must have (used to clean up each line)
FIELD_TYPES = {
    "t": float, "mac": str, "pseudo": str, "type": str, "msg_id": str,
    "ttl": int, "hop": int, "rssi": int, "len": int, "link_ok": bool,
}

# Cleartext frame types, decided Nov 17 (routing.h RT_FRAME_*, project-breakdown 4.1 / 4.7 #8d).
# An unknown type makes parse_line drop the packet.
#   DATA   messages AND their ACKs (the real DATA/ACK type is hidden inside the encryption)
#   HELLO  one-hop "I'm here" beacon
#   CTRL   signed by the watchtower: TIME beacons and BLOCKs (BLOCK is no longer its own type)
#   KEYS   each node's next-epoch key, flooded ~every 10 s
PACKET_TYPES = {"DATA", "HELLO", "CTRL", "KEYS"}

# Optional fields: kept when present, never required (older logs and the sim may not have them).
# node: the REAL node behind the transmitter, worked out by the watchtower from its pseudonym
#       secrets. "A"-"D" = our nodes, "X" = attacker board, "W" = watchtower itself,
#       "?" = a pseudonym that matches no real node (an outsider, or a forged identity).
#       Unlike mac/pseudo it does NOT rotate, so the IPS can follow a node across rotations.
# id_ok: the watchtower checked that the frame's MAC is the one derived from the same secret as its
#        pseudonym (False for "?" and for a radio using someone's pseudonym from its own MAC).
OPTIONAL_TYPES = {"node": str, "id_ok": bool}
MIN_MESH_TIME = 1e9      # before W's clock is set, its `t` is seconds since boot (< 1e9): drop those lines
NODE_IDS = {"A", "B", "C", "D", "W", "X"}
UNKNOWN_NODE = "?"
WATCHTOWER = "W"
ATTACKER = "X"             # the attack board: silent between attacks, never sends KEYS (decision 18)
KEYS_NODES = {"A", "B", "C", "D"}   # boards that must keep sending KEYS (the missing-KEYS check)
# The IPS's name for every "?" frame that still carries a VALID link_tag: someone with the network
# key hiding behind pseudonyms that match no node (the `cycling` flood swaps pseudonym + MAC every
# 5 frames, decision 20; old replays). Grouped into one identity, or each fake one looks tiny.
UNKNOWN_INSIDER = "?insider"

# Only present in synthetic / labeled data; live watchtower data has no label
LABEL_FIELD = "label"
LABELS = {"normal", "flood", "replay", "spoof", "routing"}


def parse_line(line):
    """One raw line (str or bytes) -> a clean packet dict, or None if it's unusable.

    Serial ports produce junk (boot messages, half lines), so a bad line is
    skipped instead of crashing the IPS. Extra unknown fields are ignored.
    """
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
    line = line.strip()
    if not line.startswith("{"):
        return None                                   # not JSON (e.g. a firmware debug print)
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None                                   # half a line, corrupted bytes, ...

    pkt = {}
    for name, json_name in FIELD_MAP.items():
        if json_name not in raw:
            return None                               # missing a required field
        value = raw[json_name]
        try:
            if FIELD_TYPES[name] is bool and isinstance(value, str):
                pkt[name] = value.lower() == "true"         # bool("false") would be True!
            else:
                pkt[name] = FIELD_TYPES[name](value)        # e.g. "4" -> 4
        except (TypeError, ValueError):
            return None

    if pkt["type"] not in PACKET_TYPES:
        return None
    if pkt["t"] < MIN_MESH_TIME:
        return None                                   # W's clock isn't set yet: t is boot time (PROTOCOL 10.1 D5)
    for name, cast in OPTIONAL_TYPES.items():         # optional: keep if present and valid
        if raw.get(name) is not None:
            value = raw[name]
            try:
                pkt[name] = (value.lower() == "true" if cast is bool and isinstance(value, str)
                             else cast(value))
            except (TypeError, ValueError):
                pass                                  # a bad optional field doesn't sink the packet
    if LABEL_FIELD in raw:                            # keep ground truth when it exists
        pkt["label"] = raw[LABEL_FIELD]
    return pkt


def _target(node, pseudo, mac, pair_only):
    """Who a block/unblock is aimed at (Jose's format, design decision 8b).

    Known node ("A".."X"): just name it. The watchtower works out that node's pseudonym + MAC
    for every epoch and re-issues the BLOCK each minute, so the block survives rotation.
    Unknown node, or pair_only=True: name the exact (pseudo, mac) seen on air. Nodes drop
    frames matching BOTH, so a spoofer using a victim's pseudonym from its own MAC is blocked
    without cutting off the victim (open issue O9). This kind lasts until the next rotation.
    """
    if node in NODE_IDS and not pair_only:
        return {"node": node}
    return {"node": UNKNOWN_NODE, "pseudo": pseudo, "mac": mac}


def make_block_cmd(node, reason, until, pseudo="", mac="", pair_only=False):
    """The command the IPS sends to the watchtower, which signs and broadcasts it.
    e.g. {"cmd":"block","node":"X","reason":"flood","until":1731264300.0}"""
    return {"cmd": "block", **_target(node, pseudo, mac, pair_only),
            "reason": reason, "until": round(until, 3)}


def make_unblock_cmd(node, pseudo="", mac="", pair_only=False):
    """Lift a block early (operator clicked Unblock). Blocks also expire on their own via `until`.
    PROVISIONAL: Jose proposes unblocking by a `block_id` the watchtower echoes back; the exact
    format is Yunus's call (PROTOCOL.md serial section). Until then we name the same target."""
    return {"cmd": "unblock", **_target(node, pseudo, mac, pair_only)}


def make_set_time_cmd(unix_s):
    """Start (or restart) the watchtower's mesh clock. W beacons this time to every node, and
    BLOCKs fail with clock_not_set until it has one (PROTOCOL.md 10.4)."""
    return {"cmd": "set_time", "unix_ms": int(unix_s * 1000)}


def parse_event(line):
    """A watchtower EVENT line ({"ev": ...}: block_sent, warning, error, clock_set, ...) -> dict,
    or None if the line is a frame line, junk, or not JSON. (PROTOCOL.md 10.1 D3)"""
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None
    return raw if isinstance(raw, dict) and "ev" in raw else None


def needs_clock(event):
    """True if W is telling us its clock is lost (after a reset): re-send set_time."""
    return event.get("ev") in ("warning", "error") and event.get("reason") == "clock_not_set"


def encode_cmd(cmd):
    """Dict -> one line of bytes, ready to write to the serial port."""
    return (json.dumps(cmd) + "\n").encode("utf-8")
