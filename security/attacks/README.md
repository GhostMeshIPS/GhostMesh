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

## Rules for attack scripts

- Floods stay at or below **100 frames/s** (`paced()` refuses more without `allow_fast=True`): above
  ~120/s the watchtower's log can't keep up and the IPS lags (decision 16e).
- Every run writes its ground truth with `LabelLog` next to the recording, on the mesh clock:
  `{"label": "flood", "node": "X", "start": ..., "end": ..., "variant": "loud"}`.
  `label` is one of `flood`, `replay`, `spoof`, `routing` (what the IPS knows); details go in `variant`.
- X stays silent between attacks, so normal recordings contain no X traffic (16f).
- Never flash the X build onto a demo node: its `tx` command sends anything it is given.
