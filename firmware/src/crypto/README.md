# `gm_crypto`: GhostMesh security layer (stages 14a + 14b)

Owner: Jose (Network #2). Spec: [`PROTOCOL.md` §9](../../../PROTOCOL.md). Portable C99, no ESP headers
(same rule as `routing.c`), built on [Monocypher 4.0.2](../../lib/monocypher/README.md).

| File | What | Spec |
|---|---|---|
| `gm_crypto.c` | `link_tag`, pseudonym/MAC, inner-header codec, encrypt / trial-decrypt, CTRL sign/verify, root/chain/message-key formulas | §9.3–9.6, §9.8 |
| `gm_ratchet.c` | mesh clock, epoch DH ratchet, KEYS/RESYNC frames, alerts, persistence | §9.2, §9.6 |

## Tests

```bash
python firmware/test/run_crypto_tests.py
```

Needs gcc (MSYS2 ucrt64 on Windows; set `GM_CC` to use another compiler) and `pip install pynacl cryptography`.
Builds with `-Wall -Wextra -pedantic -Werror` and runs two C programs:
- `test_crypto` (14a): frames, encryption and signatures.
- `test_ratchet` (14b): simulates 3 nodes over many epochs, covering clock slew, DH progression, forward
  secrecy, a thief with stolen state being locked out, one-way loss, splits and convergence, fork + RESYNC,
  RESYNC replay, a powered-off peer, reboot gaps, persistence, the ±1 epoch window and own-echo.

It then re-derives every formula independently in Python (PyNaCl/libsodium, cryptography) and checks the bytes.
**131/131 pass.** Of 18 deliberate code mutations, 16 are caught. The other two can't be caught by any test:
the reserved-pseudonym rehash (needs a 1-in-2³¹ hash output), and the `my_next_sk` wipe, which the next line
overwrites anyway.

## Wiring it into firmware (for Yunus)

```c
#include "keys_A.h"   /* from security/keygen.py, picked per board by a build flag (4 boards: D also includes keys_W.h) */
gm_init(&g, GM_NODE_ID, GM_NETWORK_KEY, GM_PSEUDO_SECRET, GM_X25519_SK, GM_WATCHTOWER_PK, rng_fn, NULL);  /* rng: esp_fill_random */
for (int i = 0; i < GM_PEER_COUNT; i++) gm_add_peer(&g, GM_PEERS[i].id, GM_PEERS[i].pk);
char fp[10]; gm_fingerprint(g.x_pk, fp); /* print at boot; must match firmware/config/roster.json */
if (nvs has "gm_state") gm_state_import(&g, blob, GM_STATE_BYTES);    /* ~1.5 KB */

/* every ~100 ms */
gm_events_t ev;
gm_tick(&g, esp_timer_get_time() / 1000, &ev);
if (ev.keys_due)      { gm_keys_build(&g, region); flood a ver_type=KEYS frame with it; }
if (ev.state_changed) { gm_state_export(&g, blob, sizeof blob); nvs write "gm_state"; }
if (ev.no_beacon)     serial {"ev":"no_beacon","secs":30}
if (ev.no_dh_mask)    serial {"ev":"no_dh","peer":...}  (one per set bit = peer slot)
if (ev.resync_mask)   serial {"ev":"resync","peer":...}

/* received, link_tag OK, not blocked */
KEYS frame -> gm_keys_receive(&g, f->ciphertext);
CTRL TIME  -> gm_ctrl_verify(&g, f->ciphertext, ...) then gm_clock_on_beacon(&g, issued_at_ms, local_ms);
```
Notes:
- **The 170-byte "region"** for KEYS and CTRL frames is the `ciphertext` field (bytes 54–223). When building one,
  fill `nonce` and `aead_tag` with random bytes so the frame looks like DATA on the air (PROTOCOL §9.6, §9.8).
- `my_pseudonym` / `current_epoch` callbacks: `gm_pseudonym(g.pseudo_secret, gm_wire_epoch(g.cur_epoch), out)` and
  `gm_wire_epoch(g.cur_epoch)`. The MAC for the epoch is `gm_mac(...)`; change it at each `ev.epoch_changed`.
- Until `gm_tick` reports `synced_now`, there are no keys: queue laptop sends (decision 2c).

## Changes needed in routing (for Rashad)

1. **Encryption order:** the AEAD authenticates `ver_type`, `flags`, `msg_id` and `epoch`, so `build_and_send`
   fills them **before** `encrypt()`: NEW_MSG → those 4 fields → BHD → `encrypt()` → `ttl`/`hop`/`src_pseudo`/`next_hop`
   → `link_tag` last.
2. **Cleartext type is always DATA**, ACKs included. The real type is `rt_inner_t.type`.
3. **`RT_BODY_MAX` 153 → 152.**
4. **`encrypt` should return `bool`.** It fails on an unknown recipient, a bad length, or before the first sync.
5. **`link_tag_valid()`** = `gm_link_tag_ok`.
6. **Freshness in `handle_data`:** drop DATA with `|now − timestamp| > 5 s`, log `RT_LOG_REPLAY_STALE`, send no ACK.
7. **KEYS and CTRL types:** flood them like DATA, but hand KEYS to `gm_keys_receive` and CTRL to the CTRL path.
   Relay CTRL **only after** it verifies (decision 8d / O8).
8. **Own frames:** keep caching your own `msg_id` at send time. `gm_keys_receive` also ignores its own KEYS as a
   backstop, but the seen-cache is the first defense.
