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
    {"label": "flood", "node": "X", "start": ..., "end": ..., "variant": "loud"} (decision 19).
    Inside [start, end] these packets get the label:
      * tagged with that node (normally "X") or "?",
      * id_ok False under ANY letter: X's replays and `pseudo` spoofs carry the copied node's
        pseudonym, so W tags them "A"/"B"/..., but from X's MAC, so id_ok is False.
    Everything else is "normal". No labels file = all normal. `variant` is kept for per-variant results.
    Known gap: a `pseudo_mac` spoof copies the victim's MAC as well, so its frames look exactly like the
    victim's in the log (id_ok True) and stay "normal" here; only the signal strength tells them apart.
    """
    import json
    import os
    df = read_file(path)
    df["label"] = "normal"
    df["variant"] = ""
    labels_path = path[:-len(".jsonl")] + ".labels.jsonl"
    if os.path.exists(labels_path):
        with open(labels_path) as f:
            for row in (json.loads(line) for line in f if line.strip()):
                if "node" in df:
                    who = df["node"].isin([row.get("node", "X"), "?"])
                    if "id_ok" in df:
                        who |= df["id_ok"] == False                    # noqa: E712 (NaN = unknown, not False)
                else:
                    who = True
                in_time = df["t"].between(row["start"], row["end"])
                df.loc[who & in_time, "label"] = row["label"]
                df.loc[who & in_time, "variant"] = row.get("variant", "")
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


def serial_stream(ser, on_event=None, on_line=None):
    """Yield packets from the live watchtower, forever.

    The watchtower prints two kinds of line (PROTOCOL.md 10.1 D3):
      frame lines (one per packet heard)    -> yielded as packet dicts
      event lines {"ev": ...}               -> passed to on_event(event), e.g. block_sent / errors
    The laptop is the mesh's clock source: we send set_time on connect and again whenever W
    reports clock_not_set (it lost its clock in a reset). Without it W sends no TIME beacons and
    refuses BLOCKs. Frame lines from before the clock is set are dropped by parse_line.
    on_line(text) gets every JSON line exactly as W sent it (live.py --log saves them).
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
        if on_line and line.lstrip().startswith(b"{"):
            on_line(line.decode("utf-8", "replace").strip())
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


def watchtower_stream(port, on_event=None, on_connect=None, retry_s=2.0, on_line=None):
    """serial_stream that survives the USB cable being wiggled or unplugged.

    If the port disappears, we close it, wait, and reopen it (forever), instead of crashing
    mid-demo. on_connect(ser, first) runs after every (re)connect, so the caller can swap in
    the new port and re-send anything W may have forgotten. Reopening the port can reset W
    (PROTOCOL.md 10.1 D2); serial_stream then re-sends the clock as usual.
    pyserial's errors are a kind of OSError, so OSError catches all of them.
    """
    first = True
    while True:
        try:
            ser = open_serial(port)
        except OSError as err:
            print(f"  [watchtower] can't open {port} ({err}); retrying in {retry_s:.0f} s")
            time.sleep(retry_s)
            continue
        if not first:
            print(f"  [watchtower] reconnected to {port}")
        if on_connect:
            on_connect(ser, first)
        first = False
        try:
            yield from serial_stream(ser, on_event, on_line)
        except OSError as err:
            print(f"  [watchtower] connection lost ({err}); reconnecting...")
            try:
                ser.close()
            except OSError:
                pass
            time.sleep(retry_s)


if __name__ == "__main__":
    # Quick check: replay the first 10 packets of the test session as fast as possible
    for i, pkt in enumerate(replay("test_session.jsonl", speed=0)):
        print(pkt)
        if i == 9:
            break
    df = read_file("test_session.jsonl")
    print(f"\nread_file: {len(df)} packets, columns: {list(df.columns)}")
