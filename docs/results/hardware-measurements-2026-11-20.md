# Hardware measurements, 2026-11-20

Made with `tools/record_all.py`. Boards: A-D ESP32-S3 Super Mini, W and X ESP32-WROOM-32E.

## Reroute time (PROTOCOL.md section 13)

A sends C one message per second; B is unplugged; time until C shows the first message A sent after.
Measured at: A, via C's end-to-end ACK (includes the ACK's trip back: an upper bound).

| Trial | Reroute time | Sent | Lost |
|---|---|---|---|
| 1 | 3.19 s | 143 | 0 |
| 2 | 0.71 s | 23 | 0 |
| 3 | 0.97 s | 35 | 0 |
| 4 | 0.74 s | 28 | 0 |
| 5 | 4.28 s | 32 | 0 |

**Median 0.97 s, max 4.28 s** over 5 trials; 0 messages lost in total.

## Delivery rate, A -> C (results table, G1)

47/50 delivered (**94.0%**), 3 reported failed at A. Counted by: ACK back at A (a message whose ACK was lost counts as not delivered: a lower bound).

## Crypto benchmark on the S3 (results table)

```
{"ev": "bench", "runs": 1000, "peer": "B", "enc_ms": 3245, "dec_ms": 9529, "enc_us": 3245, "dec_us": 9529}
```

## Reading these numbers

- **Reroute time** is timed at A from C's end-to-end ACK, so each value includes the ACK's trip back
  (tens of ms): an upper bound. Target ≤ 10 s (G2): met. The 3–4 s trials (1 and 5) are most likely a
  message that needed one retry (backoff 1 s, then 2 s). No message was lost in any trial. 5 trials, not
  the 10 that section 13 asks for (time).
- **Delivery** is counted from ACKs back at A, so a message that reached C but whose ACK was lost counts as
  failed: 94% is a lower bound. Target ≥ 95% (G1): just short, within that uncertainty.
- **Crypto** (`bench`, 1000 runs, A's peer B): `enc_us` / `dec_us` are per operation. **Encrypt 3.2 ms,
  trial-decrypt 9.5 ms**, so 12.7 ms per message: the < 5 ms target is missed. Trial-decrypt is ~3x the
  3.2 ms airtime of a frame, so under heavy load a board runs out of CPU before it runs out of airtime
  (~100 frames/s). Fine at demo traffic; worth a line in limitations.

## Forcing multi-hop indoors (RSSI tests, `rssi_C.jsonl`)

Boards already run at minimum TX power (2 dBm). C's log of A's messages (`python tools/rssi_summary.py
docs/results/rssi_C.jsonl`), medians:

| Setup | A→C RSSI |
|---|---|
| Same room, 1.5 m, nothing between | −70 dBm |
| + 2 metal pans | −70 dBm |
| + pans and water bottles | −73 dBm |
| Same room, 3–4 m | −74 dBm |
| **Different room** | **−86 dBm** |
| Different room, closer to the wall | −81 dBm |

Shielding on a table buys ~3 dB; a wall buys ~12 dB, but A and C still hear each other (sensitivity
≈ −94 dBm). So the demo uses the **RSSI gate at −85 dBm on A and C only**: through-wall A–C frames
(−88 to −96) are dropped, the relays B and D (−76 to −82 at A) are kept. With the gate on, every C→A
message still arrived, all of them through B or D. Margin is ~3 dB on the weakest relay link.

## Rows for `ips/datasets/README.md` (Recordings table)

| File | Date | Boards | Length | Contents | Notes |
|---|---|---|---|---|---|
| `2026-11-20_unplugB_01.jsonl` | 2026-11-20 | W + A, B, C, D | 5690 lines | Reroute trials: B unplugged and replugged, `mark` lines at each |  |
