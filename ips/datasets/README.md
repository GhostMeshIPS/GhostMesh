# IPS datasets

Recorded watchtower sessions, kept in git (unlike `ips/data/`, which holds private live logs that
auto-delete). Use these to train and test the IPS on real traffic.

## Naming

```
YYYY-MM-DD_<type>_<nn>.jsonl          the watchtower log, one JSON line per packet
YYYY-MM-DD_<type>_<nn>.labels.jsonl   ground truth for attack runs (Jose's attack scripts)
```

`<type>`: `normal`, `unplugB`, `flood`, `slowflood`, `replay`, `spoof`, `routing`, or `mixed`.
Example: `2026-11-18_flood_01.jsonl` + `2026-11-18_flood_01.labels.jsonl`.

Keep **one full session aside for testing only**: never train on it.

## Log lines

The watchtower log schema (see `ips/schema.py`, and PROTOCOL.md section 11), plus the optional
`node` field (`A`-`D`, `X`, `W`, or `?`).

## Labels file (confirmed by Jose, Nov 19: decision 19)

One JSON line per attack run, with times on the same Unix clock as the log:

```json
{"label": "flood", "node": "X", "start": 1731264120.0, "end": 1731264150.0, "variant": "loud"}
```

- `label`: `flood`, `replay`, `spoof` or `routing`.
- `node`: the attacking board (normally `X`). Packets tagged `?` in that time span are also
  counted as the attack (replayed and forged frames often can't be matched to a node).
- `variant` (optional): which version of the attack, e.g. `loud`, `slow`, `outsider`, `age_90s`,
  `mac_copied`. Training uses `label`; `variant` is for per-variant results. The IPS ignores it.
- Everything not covered by a label row is `normal`, including relays passing the attack along.
- The attack scripts write this file themselves (`security/attacks/gmx.py`, `LabelLog`).

Load a labelled recording with `ingest.read_labeled("datasets/<name>.jsonl")`.

## Recordings

| File | Date | Boards | Length | Contents | Notes |
|---|---|---|---|---|---|
| `2026-11-17_mixed_01.jsonl` | Nov 17, 21:24–21:44 EST | W + A, B, C (D off, no X) | ~20 min, 2614 lines | Normal traffic, then B unplugged (no backup path), a `/block C` + unblock, a W outage, and C moved to a weak link. **No attacks.** | Bench test 2, `docs/results/hardware-bench-2026-11-17.md` §5 has the timeline. Drop lines with `t < 1e9` (first 155, W's clock not set yet). `{"ev":"mark"}` lines are ground-truth notes. 2 frames carry C's factory MAC (a firmware bug, not an attack). Not in `detect.py`'s training list, since the block and W outage aren't normal traffic |
| `2026-11-18_normal_01.jsonl` | Nov 18, 20:44–21:06 EST | W + A, B, C (D off, no X) | ~18 min, 2291 lines | Normal traffic only, auto messages every 20 s | Pre-merge smoke test, `docs/results/hardware-smoke-2026-11-18.md`. Used by `detect.py` as real normal traffic. Contains W's `airtime_avg_us` readings (mean 3178 µs per send) |
