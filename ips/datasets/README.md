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

**How `detect.py` uses them:** the Random Forest trains on the synthetic session plus every Nov 20 recording
except `2026-11-20_mixed_01` (the held-out test set). Nov 17 and Nov 18 are false-alarm checks only (the
Isolation Forest also learns "normal" from Nov 18).

## Recordings

| File | Date | Boards | Length | Contents | Notes |
|---|---|---|---|---|---|
| `2026-11-17_mixed_01.jsonl` | Nov 17, 21:24–21:44 EST | W + A, B, C (D off, no X) | ~20 min, 2614 lines | Normal traffic, then B unplugged (no backup path), a `/block C` + unblock, a W outage, and C moved to a weak link. **No attacks.** | Bench test 2, `docs/results/hardware-bench-2026-11-17.md` §5 has the timeline. Drop lines with `t < 1e9` (first 155, W's clock not set yet). `{"ev":"mark"}` lines are ground-truth notes. 2 frames carry C's factory MAC (a firmware bug, not an attack). Not in `detect.py`'s training list, since the block and W outage aren't normal traffic |
| `2026-11-18_normal_01.jsonl` | Nov 18, 20:44–21:06 EST | W + A, B, C (D off, no X) | ~18 min, 2291 lines | Normal traffic only, auto messages every 20 s | Pre-merge smoke test, `docs/results/hardware-smoke-2026-11-18.md`. Used by `detect.py` as real normal traffic. Contains W's `airtime_avg_us` readings (mean 3178 µs per send) |
| `2026-11-20_normal_01.jsonl` | Nov 20, 18:01–18:09 EST | W + B, C, D (**A off**, X off) | ~8 min, 5702 lines | Normal traffic only, no attacks. | Recorded with `tools/record_all.py`. **Not the usual traffic mix:** B, C and D were still sending to A every 2 s (left over from an RSSI test) and A was unpowered, so their messages went undelivered and retried. W never hears A in this file. Fine as X-off traffic; don't use it as A's baseline. |
| `2026-11-20_unplugB_01.jsonl` | Nov 20, 18:29–18:36 EST | W + A, B, C, D (no X) | ~6 min, 5700 lines | Self-healing test: A sends C one message per second; B unplugged then plugged back in, 5 times. **No attacks** | PROTOCOL.md §13 reroute trials, results in `docs/results/hardware-measurements-2026-11-20.md`. 10 `mark` lines (`trial N: B unplugged` / `B back in`) are ground truth for when B was off. RSSI gate −85 dBm on A and C (forced multi-hop). A node going silent and coming back is normal, not an attack |
| `2026-11-20_flood_01.jsonl` | Nov 20, 19:30–19:36 EST | W + B, C, D + X (A not heard) | ~6 min, 13.4k lines | Normal traffic, then flood/loud for 80 s. | Session stopped early (X serial error, fixed in `gmx.py`); the 80 s attack is labelled and good. Use `flood_02` for the full flood set |
| `2026-11-20_flood_02.jsonl` | Nov 20, 19:45–19:51 EST | W + A, B, C, D + X | ~7 min, 17.5k lines | Flood: loud, slow, outsider, low_slow (48 s each) | `record_all --scale 0.4`. X at 73 frames/s in `loud`; `outsider` frames show as node `?`, `id_ok=false` |
| `2026-11-20_routing_02.jsonl` | Nov 20, 19:53–19:57 EST | W + A, B, C, D + X | ~4 min, 4.0k lines | Routing: hop0, hop0_ttlfix (48 s each) | Forged hop counts from X, ~4 frames/s |
| `2026-11-20_spoof_01.jsonl` | Nov 20, 19:58–20:02 EST | W + A, B, C, D + X | ~4 min, 5.4k lines | Spoof of A: pseudo, pseudo_mac (48 s each) | `pseudo`: `id_ok=false`. **`pseudo_mac`: `id_ok=true`**, only A's rate (≈3×) and signal (X at −30 dBm vs. the real A at −62) give it away. `read_labeled` now labels both: `id_ok=false` frames, and in spoof rows frames ≥ 10 dB off the node's usual signal (219 + 190 frames) |
| `2026-11-20_replay_01.jsonl` | Nov 20, 20:02–20:08 EST | W + A, B, C, D + X | ~6 min, 5.3k lines | Replay: age_30s, age_90s, age_240s (48 s each) | ~5 replayed frames/s, `id_ok=false` |
| `2026-11-20_mixed_01.jsonl` | Nov 20, 20:11–20:18 EST | W + A, B, C, D + X | ~6 min, 9.4k lines | spoof/pseudo, routing/hop0_ttlfix, replay/age_90s, flood/slow | **Held-out TEST set: never train on it.** `extras` (cycling, CTRL forgery, W outage) was not recorded |
