# IPS demo runbook

The exact steps to run the IPS live for the demo, and what to do when something goes wrong.
All commands run from `GhostMesh/ips/`.

## The day before

```bash
git pull
source .venv/bin/activate
pip install -r requirements-lock.txt
python3 synth.py && python3 detect.py      # rebuild data + models
```

Check the end of the `detect.py` output: **Random Forest false alarms 0.0%** on real hardware.

Optional LLM explanations: open the Ollama app, run `ollama pull llama3.2:3b` once.

Rehearse once without hardware: `python3 live.py --file test_session.jsonl --speed 5` with the dashboard open.

## Setup (about 5 minutes)

1. **Boards:** A, B, C, D on power banks. **X stays off** until the attack segment.
2. **Find W's port:** run `ls /dev/cu.*`, plug W into the laptop, run it again. The new entry is W
   (something like `/dev/cu.usbserial-XXXX`).
   Close anything else using that port (Arduino or PlatformIO serial monitor): only one program can open it.
3. **Ollama** (optional): open the app.
4. **Terminal 1, dashboard:**
   ```bash
   cd GhostMesh/ips && source .venv/bin/activate
   streamlit run dashboard.py
   ```
5. **Terminal 2, IPS:**
   ```bash
   cd GhostMesh/ips && source .venv/bin/activate
   python3 live.py --port /dev/cu.usbserial-XXXX
   ```
   To also record the demo as a dataset, add `--log datasets/<date>_mixed_02.jsonl`.
   Within a few seconds you should see `[watchtower] clock_set`. That means W took our time and the
   mesh can sync. (Only if D doubles as W: add `--trusted D`.)
6. **Check the dashboard:** A–D show up as normal and **Auto-block** is on.
7. **Wait 2 minutes of normal traffic before any attack.** The IPS learns each node's usual signal
   level and KEYS rhythm first. Attacking too early weakens spoof and missing-KEYS detection.

## During the demo

| Segment | What to do | What should happen |
|---|---|---|
| Normal mesh | Chat between nodes | No alerts |
| Flood / replay / routing | Start the attack on X (commands below) | Within ~2–5 s: **BLOCK** on the dashboard, `[watchtower] block_sent` in Terminal 2, then a plain-English explanation |
| Spoof | X pretends to be a node | **ALERT only** ("a radio using Node B's identity"). We don't block the real victim |
| Operator mode (optional) | Turn **Auto-block** off, attack again | Alert waits for a click: press **Confirm BLOCK** |
| Ask the watchtower | Type a question in the sidebar chat | Answer from live state (needs Ollama) |

Blocks lift by themselves after 60 s. An attacker that keeps going is blocked again.

**Attack commands** (Terminal 3, X's port; `--laptop-clock` because this laptop set W's clock;
`security/attacks/README.md` has the full list). Run from the repo root:

```bash
python security/attacks/run.py --port <X port> --laptop-clock --labels ips/data/demo.labels.jsonl attack flood loud --secs 30
python security/attacks/run.py --port <X port> --laptop-clock --labels ips/data/demo.labels.jsonl attack routing hop0 --secs 30
python security/attacks/run.py --port <X port> --laptop-clock --labels ips/data/demo.labels.jsonl attack spoof pseudo --secs 30
python security/attacks/run.py --port <X port> --laptop-clock --labels ips/data/demo.labels.jsonl attack replay age_30s --secs 30
```

The replay needs X to have heard at least 30 s of normal traffic first. `flood cycling` gives an **ALERT only**
on "Unknown keyed radio": it changes identity every 5 frames, so there's nothing a BLOCK could name.

## If something goes wrong

| Problem | Fix |
|---|---|
| Terminal 2 says `can't open ... retrying` | Wrong port or cable out. Check `ls /dev/cu.*`; close other serial monitors. It keeps retrying by itself |
| USB cable wiggled / W rebooted | Do nothing: the IPS reconnects, re-sets W's clock and re-sends active blocks (`re-sent N active block(s)`) |
| No `clock_set`, only `clock_not_set` warnings | Unplug and replug W; restart `live.py` |
| BLOCK shows but no `block_sent` | Read the `[watchtower] error reason=...` line just above (`clock_not_set`, `unknown_node`, `block_table_full`) |
| Explanations are plain template sentences | Ollama isn't running. Harmless: detection and blocking don't use the LLM |
| Dashboard empty or frozen | Refresh the browser tab; check Terminal 2 is still running |
| An alert on a node that did nothing | Click **Unblock** / **Dismiss** on the dashboard; blocks expire after 60 s anyway |
| Hardware fails completely | **Backup:** replay the real Nov 20 attack recording: `python3 live.py --file datasets/2026-11-20_mixed_01.jsonl --speed 2` (spoof, routing, replay, slow flood from the real X; the dashboard shows it as a replay). `test_session.jsonl` is the synthetic one |

## After

`Ctrl+C` in both terminals. Live logs in `data/` are private and auto-delete (6 h).
