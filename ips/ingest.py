"""Where packets come from. Two sources, same output (a stream of packet dicts):

    replay(path)       a .jsonl log played back in (sped-up) real time  -> works today
    serial_stream(ser) the live watchtower over USB serial              -> when hardware is ready

Everything downstream (live.py, dashboard) can't tell the difference.
"""
import time
import pandas as pd
from schema import encode_cmd, make_set_time_cmd, needs_clock, parse_event, parse_line

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
    """Open the watchtower's USB serial port, e.g. /dev/cu.usbmodem1101 on a Mac.

    DTR and RTS are set LOW before opening: toggling them is how the ESP32's USB port resets the
    board, and a reset wipes W's clock (PROTOCOL.md 10.1 D2). It can still reset on some drivers,
    which is why serial_stream re-sends the time whenever W says it lost it.
    """
    import serial                                   # pyserial; imported here so replay works without it
    ser = serial.Serial()
    ser.port, ser.baudrate, ser.timeout = port, BAUD, 1     # baud is ignored on the S3's native USB
    ser.dtr = False
    ser.rts = False
    ser.open()
    return ser


def serial_stream(ser, on_event=None):
    """Yield packets from the live watchtower, forever.

    The watchtower prints two kinds of line (PROTOCOL.md 10.1 D3):
      frame lines (one per packet heard)    -> yielded as packet dicts
      event lines {"ev": ...}               -> passed to on_event(event), e.g. block_sent / errors
    The laptop is the mesh's clock source: we send set_time on connect and again whenever W
    reports clock_not_set (it lost its clock in a reset). Without it W sends no TIME beacons and
    refuses BLOCKs. Frame lines from before the clock is set are dropped by parse_line.
    """
    last_sync = 0.0

    def sync_clock():
        nonlocal last_sync
        if time.time() - last_sync > 2:             # W nags every 5 s: don't answer the same nag twice
            ser.write(encode_cmd(make_set_time_cmd(time.time())))
            last_sync = time.time()

    sync_clock()                                    # start the mesh clock right away
    while True:
        line = ser.readline()                       # waits up to timeout=1 s for a full line
        if not line:
            continue                                # timeout, nothing heard: keep waiting
        event = parse_event(line)
        if event is not None:
            if needs_clock(event):
                sync_clock()
            if on_event:
                on_event(event)
            continue
        pkt = parse_line(line)
        if pkt is not None:
            pkt["rx_t"] = time.time()               # laptop arrival time (for display)
            yield pkt


if __name__ == "__main__":
    # Quick check: replay the first 10 packets of the test session as fast as possible
    for i, pkt in enumerate(replay("test_session.jsonl", speed=0)):
        print(pkt)
        if i == 9:
            break
    df = read_file("test_session.jsonl")
    print(f"\nread_file: {len(df)} packets, columns: {list(df.columns)}")
