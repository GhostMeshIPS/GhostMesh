"""Live hop viewer for filming: shows each message's path through the mesh, from W's log.

W hears every transmission and tags it with the board that sent it ("node"). A relay re-sends the
frame with the same msg_id, so grouping W's log by msg_id shows the path a message took:

    16:58:03  msg a10e309e   A  ->  B +37 ms  ->  D +45 ms  ->  C +64 ms      (4 transmissions)

W itself can't read the messages (encrypted, no destination on the outside), so this shows the path,
not who it's for or what it says: delivery shows on the receiver's chat client / OLED. An ACK is a
DATA frame too, so the reply shows up as its own path in the other direction.

Run W with a log, then this in a second terminal (it follows the file as it grows):
    python tools/chat_client.py --port COM5 --sync --log ips/data/raw/film.jsonl
    python tools/hop_view.py ips/data/raw/film.jsonl

Options: --only A (only paths that start at A), --replay (read the whole file once, don't follow).
"""
import argparse
import json
import os
import time

QUIET_S = 0.4            # a message's path is printed once no copy of it is heard for this long
COLORS = {"A": "\033[96m", "B": "\033[93m", "C": "\033[92m", "D": "\033[95m", "X": "\033[91m"}
RESET = "\033[0m"


def paint(node, color):
    return f"{COLORS.get(node, '')}{node}{RESET}" if color else node


def show(msg_id, frames, color, only):
    frames.sort(key=lambda f: f["t"])
    first = frames[0]
    if only and first["node"] != only:
        return
    seen, hops = set(), []
    for f in frames:
        if f["node"] in seen:
            continue                      # a board re-sending the same frame (retry) adds nothing
        seen.add(f["node"])
        hops.append(f)
    path = f"  {paint(first['node'], color)}"
    for f in hops[1:]:
        path += f"  ->  {paint(f['node'], color)} +{(f['t'] - first['t']) * 1000:.0f} ms"
    stamp = time.strftime("%H:%M:%S", time.localtime(first["t"]))
    print(f"{stamp}  msg {msg_id[:8]} {path}      ({len(frames)} transmissions)", flush=True)


def frames_from(line):
    try:
        ev = json.loads(line)
    except ValueError:
        return None
    if ev.get("type") != "DATA" or "msg_id" not in ev or "t" not in ev:
        return None
    if ev.get("t", 0) < 1e9:
        return None                       # W's clock not set yet
    ev.setdefault("node", "?")
    return ev


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", help="W's --log file (JSON lines)")
    ap.add_argument("--only", help="only show paths that start at this board, e.g. A")
    ap.add_argument("--replay", action="store_true", help="read the whole file once instead of following it")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args()
    color = not a.no_color
    if color and os.name == "nt":
        os.system("")                     # turn on ANSI colours in the Windows console
    only = a.only.upper() if a.only else None

    open_msgs = {}                        # msg_id -> (last heard wall time, [frames])

    def flush(now, force=False):
        for mid in [m for m, (last, _) in open_msgs.items() if force or now - last >= QUIET_S]:
            show(mid, open_msgs.pop(mid)[1], color, only)

    if a.replay:
        last_t = None
        for line in open(a.log, encoding="utf-8"):
            f = frames_from(line)
            if not f:
                continue
            if last_t is not None:
                flush(f["t"])             # in replay, the log's own clock decides what's "quiet"
            last_t = f["t"]
            open_msgs.setdefault(f["msg_id"], [0, []])
            open_msgs[f["msg_id"]][0] = f["t"]
            open_msgs[f["msg_id"]][1].append(f)
        flush(0, force=True)
        return

    while not os.path.exists(a.log):
        print(f"waiting for {a.log} (start W's chat client with --log)...", flush=True)
        time.sleep(2)
    with open(a.log, encoding="utf-8") as fh:
        fh.seek(0, os.SEEK_END)           # only new traffic
        print(f"watching {a.log} - send a message from A", flush=True)
        buf = ""
        while True:
            chunk = fh.readline()
            if not chunk:
                flush(time.time())
                time.sleep(0.05)
                continue
            buf += chunk
            if not buf.endswith("\n"):
                continue                  # half-written line, wait for the rest
            line, buf = buf, ""
            f = frames_from(line)
            if f:
                entry = open_msgs.setdefault(f["msg_id"], [0, []])
                entry[0] = time.time()
                entry[1].append(f)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
