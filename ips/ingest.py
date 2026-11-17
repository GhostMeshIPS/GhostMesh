"""Where packets come from. Two sources, same output (a stream of packet dicts):

    replay(path)       a .jsonl log played back in (sped-up) real time  -> works today
    serial_stream(ser) the live watchtower over USB serial              -> when hardware is ready

Everything downstream (live.py, dashboard) can't tell the difference.
"""
import time
import pandas as pd
from schema import parse_line

BAUD = 921600   # watchtower serial speed


def read_file(path):
    """Whole log at once as a DataFrame (for training / offline analysis)."""
    with open(path) as f:
        packets = [p for p in (parse_line(line) for line in f) if p is not None]
    return pd.DataFrame(packets)


def read_labeled(path):
    """A recorded session plus its ground truth (datasets/README.md), as a DataFrame with `label`.

    Labels come from `<name>.labels.jsonl` next to the log: one row per attack run,
    {"label": "flood", "node": "X", "start": ..., "end": ...}. Packets from that node (or tagged
    "?") inside [start, end] get the label; everything else is "normal". No labels file = all normal.
    """
    import json
    import os
    df = read_file(path)
    df["label"] = "normal"
    labels_path = path[:-len(".jsonl")] + ".labels.jsonl"
    if os.path.exists(labels_path):
        with open(labels_path) as f:
            for row in (json.loads(line) for line in f if line.strip()):
                who = df["node"].isin([row.get("node", "X"), "?"]) if "node" in df else True
                in_time = df["t"].between(row["start"], row["end"])
                df.loc[who & in_time, "label"] = row["label"]
    return df


def replay(path, speed=1.0):
    """Yield packets from a log file, sleeping between them like a live feed.

    speed=10 plays 10x faster (a 300 s session takes 30 s). speed=0 means no sleeping.
    Each packet gets rx_t: the log's timeline shifted so the session starts NOW
    (and squeezed by `speed`), so the dashboard shows real clock times.
    """
    prev_t = first_t = start_wall = None
    with open(path) as f:
        for line in f:
            pkt = parse_line(line)
            if pkt is None:
                continue
            if first_t is None:
                first_t, start_wall = pkt["t"], time.time()
            if prev_t is not None and speed > 0:
                # wait the real gap between packets, scaled; cap it so one big gap can't freeze us
                time.sleep(min(max(pkt["t"] - prev_t, 0) / speed, 2.0))
            prev_t = pkt["t"]
            pkt["rx_t"] = start_wall + (pkt["t"] - first_t) / (speed if speed > 0 else 1)
            yield pkt


def open_serial(port):
    """Open the watchtower's USB serial port, e.g. /dev/tty.usbserial-0001 on a Mac."""
    import serial                                   # pyserial; imported here so replay works without it
    return serial.Serial(port, BAUD, timeout=1)


def serial_stream(ser):
    """Yield packets from the live watchtower, forever. Junk lines are skipped."""
    while True:
        line = ser.readline()                       # waits up to timeout=1 s for a full line
        if not line:
            continue                                # timeout, nothing heard: keep waiting
        pkt = parse_line(line)
        if pkt is not None:
            # The ESP32 has no real-time clock (its t is likely "seconds since boot"),
            # so stamp the laptop's real time on arrival.
            pkt["rx_t"] = time.time()
            yield pkt


if __name__ == "__main__":
    # Quick check: replay the first 10 packets of the test session as fast as possible
    for i, pkt in enumerate(replay("test_session.jsonl", speed=0)):
        print(pkt)
        if i == 9:
            break
    df = read_file("test_session.jsonl")
    print(f"\nread_file: {len(df)} packets, columns: {list(df.columns)}")
