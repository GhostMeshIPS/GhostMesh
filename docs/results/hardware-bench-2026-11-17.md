# Hardware bench results, Tue Nov 17

Owner: Yunus (Comp E). First runs of the full stack (Rashad's routing + Jose's crypto + the node /
watchtower firmware) on real ESP32-S3 Super Mini boards. Firmware: branch `firmware-node-integration`.

**Short version:** everything in the protocol works on hardware: encryption, ACKs, relaying with
k-suppression, key ratchet, pseudonym + MAC rotation, sync from signed TIME beacons, BLOCK/unblock.
One privacy bug to chase (C sent with its factory MAC, §4.1) and D needs debugging.

---

## 1. Setups

| Run | Boards | Clock | Duration | Data |
|---|---|---|---|---|
| **Run 1** (afternoon) | A, B, C, D on one table, all on the laptop | laptop `set_time` (bench-only) | ~15 min | serial output only |
| **Run 2** (evening) | W on the laptop; A, B, C on power banks, up to ~4 m apart; D not working | W's signed TIME beacon (the real path) | 21 min | `ips/data/raw/hw_run1.jsonl` (watchtower log, §5) |

Both runs at minimum TX power (`qdbm` 8 = 2 dBm), MAC rotation on, ESP-NOW channel 1. In run 2 each
node sent an automatic test message every 20 s (`/auto`): A→C, B→D, C→A, D→B.

---

## 2. For Rashad (routing)

| Measurement | Value | Notes |
|---|---|---|
| **Send-to-callback per 240-byte frame** | **3279 µs, measured** (time from `esp_now_send` to the send-done callback; `airtime_avg_us` in `/status`) | This is what the board can measure. Includes channel access (DIFS + backoff) and driver/callback delay on top of the on-air time. Nov 18 smoke: 3151–3199 µs. Sets the per-board send ceiling (~305 frames/s) |
| **Pure on-air time** | **~2.46 ms, calculated (not measured)** | Derived, not timed: 283 B (240 payload + 802.11 + ESP-NOW headers) at the **measured** 1 Mbps (8 µs/B = 2264 µs) + 192 µs preamble. The board has no second radio to time a frame on the air; only the rate (below) is measured, and at a fixed rate + fixed size the on-air time is fixed. To measure it directly would need a sniffer/SDR with µs timestamps. Your ~3 ms estimate holds, so the 10–50 ms jitter window with k = 2–3 is fine |
| **PHY rate** | **1 Mbps, every frame** (`rate 0`, `sig_mode 0` on all 2504 logged frames) | ESP-NOW doesn't adapt its rate: weak links lose frames, they don't slow down |
| Max frames/s per transmitter | ~305 (1 / 3.28 ms) | Rough mesh ceiling with flooding: ~305 / (2·N) messages/s, ≈ 38/s at N = 4, about half that with collisions. Worth confirming with the attacker flood |
| **k-suppression on hardware** | Run 1, per board after ~10 min: `relayed` 150–200, `dup` ~240, **`cancelled` 15–33** | Relays are being cancelled after k copies |
| Relaying | Run 2 baseline: **84%** of `msg_id`s heard from 2+ transmitters | Everyone in range of everyone, so mostly redundant relays (expected without topology control) |
| Retries / failure | Unreachable recipient → 3 retries → `failed`, as specified | B → D (D offline) showed up as ~2× B's normal DATA rate |
| Channel load | ~127 frames/min with 3 nodes + W ≈ 0.7% airtime ≈ 4 kbit/s | Far from capacity |
| Signal on one table, min power | −52 to −65 dBm between all boards; −67 to −85 dBm at ~4 m | Everyone hears everyone, so forcing multi-hop needs the MAC allowlist (rotation off), not an RSSI gate |

**Open for you** (also in §4.7 of the planning doc):
- **First-beacon bug:** `rt_on_receive` checks the epoch window before CTRL. An unsynced node's
  epoch is 0, so every TIME beacon is dropped as `bad_epoch` and the mesh never syncs from W. The
  workaround in `gm_node_rx` takes the first beacon directly but can't relay it, so sync spreads one
  hop per beacon (10 s/hop). Fix: skip the epoch check for CTRL TIME while `!is_synced()`.
- **`rt_originate()`** so frames a node creates itself (KEYS, CTRL) go into your seen-caches.
- Integration test you can run: `python firmware/test/node/run_node_tests.py` (34 checks: real
  routing + crypto + watchtower, several nodes in one process; needs gcc + pynacl).

---

## 3. For Jose (security)

| Measurement | Value |
|---|---|
| **MAC rotation cost** (decision 2a) | **5.4–5.7 ms** per epoch (Wi-Fi + ESP-NOW restart), 4 boards × ~15 epochs, no `set_mac_failed`. Rotation stays on |
| Key ratchet | Run 1: ~12 epoch changes, every message delivered + ACKed. KEYS ~6/min per board (run 2 baseline: 5.1–6.4/min) |
| Network key | `bad_link_tag` 0 on every board in both runs (0 of 2504 frames at W) |
| **Resync after reboot** | Run 1: rebooted board reloaded `gm_state` from NVS, resynced, first message delivered. Run 2: **B's first frame 7.1 s** after being plugged back in |
| **BLOCK on hardware** | Before the block A/B relayed **5/5** of C's DATA; **during the block 0/12**; after unblock **4/4**. W sent the block twice in 38 s (initial + re-issue at the epoch change) |
| Watchtower loss | Nodes kept messaging with W unplugged; picked W's beacons back up when it returned |
| `id_ok` (MAC matches pseudonym) | 4 of 2349 frames false, see §4.1 |

Your Nov 17 notes are all in the firmware: CTRL budget counts **failed** verifies only (regression
test: 0/6 → 6/6 for a BLOCK 200 ms after a beacon, 2 hops from W); W spaces CTRL frames ≥ 3 s apart;
non-240-byte frames dropped first; log lines carry `raw`, `flags`, `epoch`, `rx_us`, `rate`,
`sig_mode`, `mcs`, `node`, `id_ok`. **`noise_floor` isn't available on the ESP32-S3** (its receive
metadata has no noise-floor field; only the original ESP32 and the S2 do).

Bench-only: nodes accept `set_time` over serial so they can be tested without W. It will be
disabled in the demo build.

### 4.1 Finding: C transmitted with its factory MAC
Of the 4 `id_ok: false` frames:
- **2 at an epoch boundary** (0.1 s into the new epoch, frame carries the previous epoch): a frame
  queued just before the MAC change went out just after it. A harmless race, but the IPS should not
  treat a lone mismatch right at a boundary as spoofing.
- **2 from C mid-epoch with MAC `3c:0f:02:e3:ba:d8`**: no locally-administered bit, so it's C's
  **factory MAC**. That defeats MAC rotation for that period.
  **Update Nov 18: root cause found** (it was not stale firmware on C): frames relayed in the ~100 ms after a
  node takes its first beacon go out before its MAC switches. See `hardware-smoke-2026-11-18.md` §3.1.

---

## 5. For Hannan (IPS): the dataset

**File:** `ips/data/raw/hw_run1.jsonl` on Yunus's laptop (the folder is gitignored; ask him for the
file). 2614 lines: 2504 watchtower frame lines + 110 events. Every frame line has the full schema plus
`node`, `id_ok`, `epoch`, `flags`, `rx_us`, `rate`, `sig_mode`, `mcs` and `raw`.

**Before using it:**
- **Drop lines with `t < 1e9`** (the first 155). W had just rebooted and its clock wasn't set, so they
  carry local time and every `node` is `?`.
- `{"ev":"mark",...}` lines are ground-truth notes from the laptop (laptop clock, unix seconds).

**Timeline (EST):**

| From | To | Label | What happened |
|---|---|---|---|
| 21:24:23 | 21:35:07 | normal | A, B, C on power banks, auto messages every 20 s; D off |
| 21:35:07 | 21:37:28 | node loss | B unplugged |
| 21:37:28 | 21:37:58 | recovery | B plugged back in (first frame 7.1 s later) |
| 21:37:58 | 21:38:36 | blocked | W blocked node C (`/block C`), then unblock |
| 21:38:59 | ~21:41 | W outage | W unplugged, then restarted (new `clock_set`) |
| 21:41:18 | 21:44:43 | normal, weak link | C moved further away (RSSI at W −79 → −85 dBm) |

**Things that will look odd:**
- **B sends ~11 DATA/min vs ~6 for A and C:** B's auto target is D, which was offline, so every
  message is retried 3 times. Normal behaviour for an unreachable peer, not an attack.
- D and X never appear; X was never powered.
- 4 `id_ok: false` frames (§4.1): 2 boundary races and 2 from C's factory MAC (a firmware bug, not an attack).
- Traffic dips to ~55 frames/min during the B unplug and the W outage.

Baseline rates (normal period, originated per minute): A 6.1 DATA + 6.4 KEYS, B 11.1 DATA + 6.0 KEYS,
C 6.4 DATA + 5.1 KEYS, W 6.1 CTRL (TIME beacons). ~127 frames/min total at W, including relays.

---

## 6. Tooling notes

- **Opening the serial port reset the board.** The default pyserial open toggles DTR/RTS, which
  reboots an S3 on native USB. This wiped W's clock every time the client was restarted. Fixed in
  `tools/chat_client.py` (opens with DTR/RTS low). **Update Nov 18: this does not stop the reset on
  Windows**, see `hardware-smoke-2026-11-18.md` §3.2. **Hannan:**
  `ips/ingest.py` line 69 opens with `serial.Serial(port, BAUD, timeout=1)`, which will do the same
  to W and wipe its clock. Open it the way the chat client now does:
  `s = serial.Serial(); s.port = port; s.baudrate = BAUD; s.timeout = 1; s.dtr = False; s.rts = False; s.open()`.
- Logging: `python tools/chat_client.py --port COMx --sync --log ips/data/raw/<name>.jsonl`; `/mark <note>`
  adds a ground-truth line.
- No baud limit: the S3 uses native USB.

## 7. Next

- Debug D; reflash C and recheck MAC behaviour (§4.1).
- 3 boards in a line with the allowlist (rotation off) for A → B → C (G1) and unplug-B reroute (G2).
- Attacker firmware (X), then labelled attack runs for the IPS and a flood test for real capacity.
