# Recording the attack datasets: runbook

Step by step, for whoever has the boards. It produces the labelled recordings the IPS trains and is tested on
(decisions 19 and 20). One laptop runs everything. Allow about 2 hours for all six sessions, setup included.
Background: [`README.md`](README.md) (attack specs), [`ips/datasets/README.md`](../../ips/datasets/README.md) (file naming).

## Part 1: Setup (once, ~15 min)

**1. Latest code and Python packages.**

```
git pull
pip install pyserial
```

**2. X's key file.** `firmware/config/keys/keys_X.h` must exist on this laptop (it was made by
`security/keygen.py` along with the other boards' keys). The X board itself holds no keys; the laptop scripts
use this file. It's secret and gitignored: never commit it.

**3. Flash X** (once): `cd firmware` then `pio run -e X -t upload`. X needs no keys file to build.
**Never flash this build onto A–D or W**: its `tx` command sends anything it's given.

**4. Put the boards out.**
- A, B, C, D on power banks, with the metal shielding between A and C (as for the multi-hop demo).
- W plugged into the laptop.
- X plugged into the laptop, placed where it can hear at least B and W.

**5. Find the COM ports.**

```
python -m serial.tools.list_ports
```

Unplug and replug a board to see which port is which. Below, **COM5 = W** and **COM7 = X**: use your real ones.

**6. Start the mesh clock.**

```
python tools/chat_client.py --port COM5 --sync
```

Wait ~20 s so A–D sync from W's TIME beacons, then Ctrl+C. (W keeps its clock while it stays powered.)

**7. Check X.** With W still powered:

```
python security/attacks/xctl.py --port COM7 status
python security/attacks/xctl.py --port COM7 sniff --secs 20
python security/attacks/xctl.py --port COM7 clock
```

- `status` answers with `"name":"X"`.
- `sniff` shows frames scrolling with **`link ok`**. `BAD link_tag` on everything means `keys_X.h` is from a
  different keygen run than the boards: get the right one.
- `clock` prints the mesh time and epoch.

**8. Normal traffic.** The nodes must be sending their usual automatic messages (`/auto`, as in the Nov 18
recording). Without it there's nothing to replay, spoof or relay.

## Part 2: Record one session (~15 min each)

Two terminals.

**Terminal 1: record the watchtower.** Today's date, the session type, and `_01`:

```
python tools/chat_client.py --port COM5 --sync --log ips/datasets/2026-11-20_flood_01.jsonl
```

**Terminal 2: run the attacks.** Same name, ending in `.labels.jsonl`:

```
python security/attacks/run.py --port COM7 --laptop-clock --labels ips/datasets/2026-11-20_flood_01.labels.jsonl session flood
```

Terminal 2 runs the whole plan by itself and prints what it's doing:

| It prints | Meaning |
|---|---|
| `normal traffic first: 270 s left (X silent)` | 5 min of normal traffic, X sends nothing |
| `ATTACK flood/loud for 120 s` | an attack is running |
| `normal gap` | 1 min of normal traffic between attacks |
| `normal tail` | last minute of normal traffic, then it exits |

**When terminal 2 exits, press Ctrl+C in terminal 1.** The session is done.

`--laptop-clock` is correct because this laptop set W's clock. If X runs on a different laptop than W, leave
it out: the script then learns the mesh clock from W's TIME beacons.

**While recording:**
- Don't touch W's USB cable and don't open W's port in any other program. On Windows, opening the port resets
  W and wipes its clock. If terminal 1 shows a `boot` or `clock_not_set` line mid-session, redo the session as `_02`.
- The IPS can't run live at the same time (the chat client holds W's port). The IPS is run on the files afterwards.

## Part 3: The six sessions, in this order

Change the session word at the end of the terminal 2 command, and the file names in both terminals.

| # | Session | Files | Notes |
|---|---|---|---|
| 1 | `flood` | `..._flood_01` | Easiest; checks everything works |
| 2 | `routing` | `..._routing_01` | |
| 3 | `spoof` | `..._spoof_01` | X pretends to be its strongest neighbour, so put X next to the board it should impersonate (or add `--victim <pseudonym>`). After each 60 s key rotation it pauses ~10 s to find the victim again: that's expected |
| 4 | `replay` | `..._replay_01` | The 5 min of normal traffic at the start fills X's capture buffer |
| 5 | `extras` | `..._extras_01` | **Needs a free hand.** When terminal 2 prints `>>> OPERATOR`: unplug W; a minute later, press a node's reset button; two minutes after that, plug W back in. Type each step into terminal 1 as `/mark W unplugged`, `/mark node rebooted`, `/mark W back` |
| 6 | `mixed` | `..._mixed_01` | The **held-out test set**: tell Hannan never to train on it |

## Part 4: Check each recording (~1 min)

**1. Turn it into a capture:**

```
python security/gm_pcap.py ips/datasets/2026-11-20_flood_01.jsonl
```

**2. Open the `.pcap` in Wireshark** with the dissector:

```
"C:\Program Files\Wireshark\Wireshark.exe" -X lua_script:security/ghostmesh.lua ips/datasets/2026-11-20_flood_01.pcap
```

Filter `ghostmesh.cap.node == "X"`: X's frames should come in bursts with quiet gaps between them. For the
outsider flood, filter `!ghostmesh.cap.link_ok`. No X frames at all means W didn't hear X: move X closer and redo.

**3. Check the labels load:**

```
python -c "import sys; sys.path.insert(0,'ips'); import ingest; print(ingest.read_labeled('ips/datasets/2026-11-20_flood_01.jsonl')['label'].value_counts())"
```

It should list `normal` and the session's attack label (`flood`, `replay`, ...).

## Part 5: Hand off

1. In `ips/datasets/README.md`, add one row per recording to the **Recordings** table (date, boards, length,
   which attacks, anything that went wrong), like the existing rows.
2. Commit the `.jsonl` and `.labels.jsonl` files (not the `.pcap`s, and never `keys_X.h`), then push.
3. Tell Hannan the recordings are up and that `mixed` is the test set.

## If something breaks

| Problem | Fix |
|---|---|
| `no TIME beacon` | W isn't running or its clock isn't set: run step 6 again |
| `xctl.py` hangs or `status` times out | Wrong COM port, or X isn't flashed with the X build |
| `BAD link_tag` on every frame | `keys_X.h` doesn't match the boards' keygen run |
| No X frames in the recording | X too far from W, or X's port was wrong |
| Spoof never prints a victim | Normal traffic too quiet: check the nodes' auto messages |
| W reset mid-session (`boot` / `clock_not_set`) | Redo the session as `_02` |
| Anything else mid-session | Ctrl+C both terminals, redo as `_02`. Stopping still writes the label for the running attack |
| Want to try without boards | `python security/attacks/run.py --mock --scale 0.05 --labels test.labels.jsonl session flood` |
