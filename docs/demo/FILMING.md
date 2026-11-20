# Filming the hardware demos

Two hardware shots for the 3-minute video. Everything else (privacy, replay/spoof, the sim) is voiceover
over screen recordings.

| Shot | Length in the cut | What it proves |
|---|---|---|
| **Demo 1:** A → C over the mesh, then B unplugged | ~35 s | Encrypted multi-hop with no router; losing a relay costs nothing |
| **Demo 2:** X floods the mesh, the IPS blocks it | ~40 s | The AI watchtower catches an insider and the boards drop it |

Both shots are checked on the laptop before filming: `python firmware/test/node/run_node_tests.py`
runs the real node + watchtower code through each shot (tests "Demo 1" and "Demo 2"), and the Demo 2
watchtower log, fed to `ips/live.py`, gets X blocked ~2 s after the flood starts (93% sure, no other node
touched). Neither has run on the boards yet: do one dry run of each before the real takes.

All commands are PowerShell from the repo root. `COMa`, `COMw`, `COMx` = the ports of A, W and X
(`pio device list`).

## 1. Flash (once)

One board plugged in at a time, always name the port (auto-detect once put A's keys on D).

```powershell
cd firmware
pio run -e A -t upload --upload-port COMx      # then B, C, D, W the same way
pio run -e X -t upload --upload-port COMx      # attacker passthrough: no keys inside, never on a demo node
cd ..
```

Good flash: `Hash of data verified` → `Hard resetting`. Stuck at `Connecting...`: hold BOOT, tap RST,
release BOOT, upload again.

Each node once, plugged in, so B/C/D stay quiet (it's saved in flash):

```powershell
python tools/chat_client.py --port COMx
/auto off
```

## 2. Table layout

```
              B
            /   \
   A ===[shield]=== C          A and C can't hear each other: metal pan upright
            \   /              close to C, facing A. Not touching any board.
              D
        W (centre, nothing in front of it)        X (near A/B/D, off camera until demo 2)
```

- B and D wall/power-bank powered. A on the laptop (it's the chat client). C on a power bank, OLED to camera.
- Tape labels A B C D W X on every board.
- **Check the shield:** with the mesh running and X unplugged, A's and C's OLED line 3 (`hear N best ..`)
  should show **3** (B, D and W), not 4. A 4 means A and C hear each other: move them further apart.

## 3. One session for both shots

W stays on the IPS for the whole session (it sets W's clock, so the mesh runs from it). Three terminals:

```powershell
# 1: dashboard
cd ips; .venv\Scripts\activate; streamlit run dashboard.py
# 2: IPS on the watchtower, wait for "[watchtower] clock_set"
cd ips; .venv\Scripts\activate; python live.py --port COMw
# 3: A's chat client
python tools/chat_client.py --port COMa
```

Every OLED should show `SYNC` within ~30 s. Leave it **2 minutes** before any attack (the IPS learns
normal first). Film demo 1 during that time.

Start OBS (screen) + the phone camera (boards). **Clap on camera at the start of every take** to line
the two up in the edit.

## 4. Demo 1: multi-hop, then unplug B

In A's chat client (terminal 3):

```
C: meet at 9
```

| On camera | Expected |
|---|---|
| A | LED blue; OLED last-send line `>C vv #1` (vv = delivered) |
| B and D | LED blinks blue (relaying) |
| C | LED green; OLED shows `<A: meet at 9` |

Then the self-healing part, same take:

```
/auto C 1
```

A now sends to C every second. Let ~10 s run, **pull B's power on camera**, let ~10 s more run, then
`/auto off`.

| On camera | Expected |
|---|---|
| A's OLED bottom line | `auto>C/1s okN x0`: `ok` keeps climbing after B is gone, `x` stays 0 |
| D | was already blinking blue before B was pulled, keeps going |

Voiceover line: the mesh floods every message over every path, so there's no reroute to wait for:
D was already carrying it.

Plug B back in after the take (it resyncs from W in ~10 s).

## 5. Demo 2: flood, then BLOCK

Dashboard on screen, **Auto-block on**, camera on A, B and D. X plugged into the laptop
(it's silent until told to send). Terminal 4:

```powershell
pip install pyserial                       # once
python security/attacks/xctl.py --port COMx clock    # should print the mesh epoch (X hears W)
python security/attacks/run.py --port COMx --laptop-clock --labels ips/datasets/2026-11-20_demo_flood_01.labels.jsonl attack flood loud --secs 60
```

`flood loud` = 80 frames/s of random undecryptable DATA as X's real insider identity (valid link_tag,
X's own pseudonym + MAC, follows the epoch).

| Time | Dashboard | Boards |
|---|---|---|
| 0–2 s | X's packet rate spikes (~70/s vs ~1–4 normal) | A, B, D blink blue fast: they relay X's frames (each capped at ~20 new/s per sender) |
| ~2–3 s | **BLOCK X flood (~93%)** + plain-English explanation; terminal 2 shows `[watchtower] block_sent` | |
| ~3–6 s | | BLOCK lands: A, B, D flash **red** (dropping X at the first hop), blue blinking stops |
| rest | | Send `C: still here` from A: still delivered while X keeps flooding |

The run stops by itself after 60 s. The block lasts 60 s and survives X's minute rotation (W re-issues it).
To retake: wait for the block to expire (or **Unblock** on the dashboard), then run the command again.

## 6. If something goes wrong

| Problem | Fix |
|---|---|
| Node OLED stuck on `NO SYNC` | It can't hear W or a synced neighbour: move it closer, check W shows `clock_set` |
| C shows A's message but `hear` says 3 boards | Shield not doing its job: more distance between A and C |
| `x` climbs on A after B is pulled | D can't reach A or C: move D, re-check `hear` |
| `xctl.py clock` hangs | X can't hear W's beacons: move X closer to W |
| No BLOCK on the dashboard | Waited less than 2 min before attacking, or Auto-block is off (then click **Confirm BLOCK**) |
| BLOCK on dashboard but no `block_sent` | Read the `[watchtower] error reason=...` line just above |
| Opening a port reset W | `live.py` re-sends the clock by itself; wait for `clock_set` again |

**Don't film replay or spoof yet.** A replayed frame carries the victim's pseudonym, so the IPS can block
the real node (fix pending in `ips/live.py`: block only the pseudonym+MAC pair when `id_ok` is false).
They go in the voiceover only.

## After

Ctrl+C everywhere. Send Hannan `ips/data/raw/*` and the `.labels.jsonl` file (real attack data).
