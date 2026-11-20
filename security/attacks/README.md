# Attacker X (decision 18)

X is a radio passthrough. Its firmware (`firmware/src/attacker/main_x.cpp`, `pio run -e X`) holds **no keys**
and never transmits on its own: it prints every frame it hears and sends whatever 240-byte frame the laptop
gives it. Everything an insider can do runs here, in Python, with X's keys from `firmware/config/keys/keys_X.h`.

| File | What it is |
|---|---|
| `gmx.py` | Shared library: keys, crypto (same formulas as `gm_crypto`), frame build/parse, mesh clock from TIME beacons, `XRadio` (serial link to X), `MockRadio`, `paced()` sending, `LabelLog` ground truth |
| `xctl.py` | Bring-up: `status`, `sniff`, `clock`, `set-mac`, `own-mac`. No attacks |
| `test_gmx.py` | Tests, no hardware needed: `python security/attacks/test_gmx.py` |

## First run on hardware

1. Flash X: `cd firmware && pio run -e X -t upload` (X doesn't need a keys file).
2. Start the mesh as usual (W on the IPS laptop with its clock set, nodes on power banks).
3. On the attack laptop:

```
python security/attacks/xctl.py --port COM7 status
python security/attacks/xctl.py --port COM7 sniff --secs 20     # frames + "link ok" if keys_X.h is present
python security/attacks/xctl.py --port COM7 clock               # mesh time and epoch from W's TIME beacons
```

## Attack specs (decision 20)

"As X" means X's own per-epoch pseudonym and derived MAC (the script calls `set_mac` at every epoch
boundary), so the watchtower tags the frames `X` with `id_ok=true`: a real insider. Every frame an insider
sends carries a valid `link_tag`. All runs are 2 minutes unless noted.

| Label | Variant | What X sends | Rate | Expected outcome |
|---|---|---|---|---|
| flood | `loud` | Random undecryptable DATA, as X | 80/s | Rate spike; relays drop everything above ~20 new `msg_id`s/s (10g); BLOCK |
| flood | `slow` | Same | 15/s | Under the insertion limit, so every relay re-floods it (amplification). Exactly at the IPS rule's edge (> 15/window): rules vs. ML |
| flood | `outsider` | Random frames, bad `link_tag`, random pseudonym, one random locally administered MAC | 50/s | `node "?"`, `link_ok=false`, dropped at the first hop; BLOCK can't stop the airtime |
| flood | `low_slow` | Random DATA, as X | 8/s | Below the rule threshold: does the ML still see it? (16f residual) |
| flood | `cycling` | Random DATA with a new random pseudonym + MAC every 5 frames | 50/s | Dodges per-sender limits (10b/10g residual); watchtower sees many `?` identities |
| flood | `ctrl_forgery` | CTRL TIME/BLOCK frames with bad signatures and fresh `issued_at`, as X | 20/s | Verify failures; X loses its own verify budget only, genuine TIME/BLOCK still checked (16d) |
| replay | `age_30s` | Every frame heard 30 s earlier (DATA + KEYS), resent unchanged, sampled to 5/s | 5/s | Dropped by the 60 s seen-cache; watchtower tags the original node with `id_ok=false` |
| replay | `age_90s` | Same, 90 s old | 5/s | Dropped by the 180 s `msg_id` cache |
| replay | `age_240s` | Same, 240 s old | 5/s | Dropped by the ±1 epoch window |
| spoof | `pseudo` | Random DATA under the victim's current pseudonym, X's own MAC | 5/s | MAC ≠ pseudonym (`id_ok=false`), second RSSI cluster; alert only (O9) |
| spoof | `pseudo_mac` | Same, and X sets its MAC to the victim's | 5/s | Full spoof: only RSSI separates it; alert only, operator decides (O9) |
| routing | `hop0` | Relays every DATA/KEYS frame it hears, as X, claiming hop 0, TTL decremented normally | as heard (≤ 100/s) | `ttl + hop ≠ 5`; hop goes down for the same `msg_id`; BLOCK |
| routing | `hop0_ttlfix` | Same, with TTL raised so `ttl + hop = 5` | as heard | Sum check passes; only "hop went down for the same `msg_id`" catches it |

**Spoof victim:** the strongest non-X transmitter (or a pseudonym the operator names at the start). After each
rotation the script re-acquires it as the new pseudonym whose RSSI is closest to the victim's last RSSI,
which also demonstrates O3 (RSSI tracking across rotation) on hardware.

**Watchtower outage** (operator steps, during a `slow` flood): unplug W for 3 min, reboot one node while W is
down, replug W. Expected: blocks lapse within ~2 min (16c), the IPS is blind, the rebooted node stays mute until
W is back (16b). Mark each step with `/mark` in the chat client; the labels row covers only the flood.

**Sessions** (`ips/datasets/<date>_<type>_<nn>.jsonl` + `.labels.jsonl`):

| Session | Contents |
|---|---|
| `flood` | 5 min normal, then `loud`, `slow`, `outsider`, `low_slow`, each 2 min with 1 min normal between |
| `replay` | 5 min normal (fills the capture buffer), then `age_30s`, `age_90s`, `age_240s` |
| `spoof` | 5 min normal, then `pseudo`, `pseudo_mac` |
| `routing` | 5 min normal, then `hop0`, `hop0_ttlfix` |
| `extras` | 5 min normal, then `cycling`, `ctrl_forgery`, then the watchtower outage during a `slow` flood |
| `mixed` | **Held-out test set, never trained on:** one variant of each core attack in a different order, shorter gaps |

X stays silent during every normal segment.

## Rules for attack scripts

- Floods stay at or below **100 frames/s** (`paced()` refuses more without `allow_fast=True`): above
  ~120/s the watchtower's log can't keep up and the IPS lags (decision 16e).
- Every run writes its ground truth with `LabelLog` next to the recording, on the mesh clock:
  `{"label": "flood", "node": "X", "start": ..., "end": ..., "variant": "loud"}`.
  `label` is one of `flood`, `replay`, `spoof`, `routing` (what the IPS knows); details go in `variant`.
- X stays silent between attacks, so normal recordings contain no X traffic (16f).
- Never flash the X build onto a demo node: its `tx` command sends anything it is given.
