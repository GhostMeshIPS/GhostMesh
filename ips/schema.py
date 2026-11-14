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
    "pseudo": "pseudo",    # sender pseudonym (rotates every 60 s)
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

PACKET_TYPES = {"DATA", "ACK", "HELLO", "RREQ", "RREP", "BLOCK"}

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
    if LABEL_FIELD in raw:                            # keep ground truth when it exists
        pkt["label"] = raw[LABEL_FIELD]
    return pkt


def make_block_cmd(mac, pseudo, reason, until):
    """The command the IPS sends to the watchtower, which signs and broadcasts it."""
    return {"cmd": "block", "mac": mac, "pseudo": pseudo,
            "reason": reason, "until": round(until, 3)}


def make_unblock_cmd(mac):
    """Lift a block early (operator clicked Unblock). Blocks also expire on their own via `until`."""
    return {"cmd": "unblock", "mac": mac}


def encode_cmd(cmd):
    """Dict -> one line of bytes, ready to write to the serial port."""
    return (json.dumps(cmd) + "\n").encode("utf-8")
