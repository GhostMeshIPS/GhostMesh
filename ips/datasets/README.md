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

## Labels file (PROPOSED: Jose to confirm)

One JSON line per attack run, with times on the same Unix clock as the log:

```json
{"label": "flood", "node": "X", "start": 1731264120.0, "end": 1731264150.0}
```

- `label`: `flood`, `replay`, `spoof` or `routing`.
- `node`: the attacking board (normally `X`). Packets tagged `?` in that time span are also
  counted as the attack (replayed and forged frames often can't be matched to a node).
- Everything not covered by a label row is `normal`, including relays passing the attack along.

Load a labelled recording with `ingest.read_labeled("datasets/<name>.jsonl")`.
