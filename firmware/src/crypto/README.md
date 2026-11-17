# `gm_crypto`: GhostMesh security primitives (stage 14a)

Owner: Jose (Network #2). Spec: [`PROTOCOL.md` §9](../../../PROTOCOL.md). Portable C99, no ESP headers
(same rule as `routing.c`), built on [Monocypher 4.0.2](../../lib/monocypher/README.md).

| Function | Spec |
|---|---|
| `gm_link_tag`, `gm_link_tag_ok` (constant time) | §9.4 |
| `gm_pseudonym`, `gm_mac` | §9.3 |
| `gm_root_key`, `gm_chain_start`, `gm_message_key`, `gm_peer_message_key` | §9.6 |
| `gm_inner_pack` / `gm_inner_unpack` | §9.5 |
| `gm_encrypt`, `gm_try_decrypt`, `gm_ad` | §9.6 |
| `gm_ctrl_sign`, `gm_ctrl_verify` | §9.8 |

**Stage 14a vs. 14b:** today `gm_peer_message_key()` derives the epoch's key straight from the static root key
(the RESYNC formula), so there is **no forward secrecy yet**. Stage 14b adds the epoch ratchet, KEYS/RESYNC and the
mesh clock behind that same function; callers don't change.

## Tests

```bash
python firmware/test/run_crypto_tests.py
```

Needs gcc (MSYS2 ucrt64 on Windows; set `GM_CC` to use another compiler) and `pip install pynacl cryptography`.
It builds with `-Wall -Wextra -pedantic -Werror` and runs 40 C checks. It then re-implements every formula
independently in Python (hashlib, PyNaCl/libsodium, cryptography) and checks the C output byte for byte (16 checks).
Six deliberate code mutations were each caught by at least one test. **Not tested:** the pseudonym rehash
for reserved values, which needs a 1-in-2³¹ hash output to trigger.

## Wiring into `rt_platform_t` (for Yunus)

The platform `ctx` is firmware-owned, so the adapters live in firmware. Each one is a one-liner:

```c
static bool p_try_decrypt(void *ctx, const rt_frame_t *f, rt_inner_t *out) { return gm_try_decrypt(&((fw_t *)ctx)->gm, f, out); }
static void p_encrypt(void *ctx, const rt_inner_t *in, rt_frame_t *f)      { gm_encrypt(&((fw_t *)ctx)->gm, in, f); /* see note 4 */ }
static void p_link_tag(void *ctx, const rt_frame_t *f, uint8_t out[8])     { gm_link_tag(((fw_t *)ctx)->gm.network_key, f, out); }
static void p_pseudonym(void *ctx, uint8_t out[4]) { fw_t *w = ctx; gm_pseudonym(w->gm.pseudo_secret, w->epoch, out); }
```
`gm_rng_fn` on the board: wrap `esp_fill_random()` (Wi-Fi must be on for true randomness).

## Changes needed in routing (for Rashad)

1. **Encryption order** (decision 14): the AEAD authenticates `ver_type`, `flags`, `msg_id` and `epoch`, so
   `build_and_send` must fill them **before** calling `encrypt()`:
   NEW_MSG → fill those 4 fields → BHD → `encrypt()` → fill `ttl`/`hop_count`/`src_pseudo`/`next_hop` → `link_tag` last.
2. **Cleartext type is always DATA** (decision 5): set `ver_type = RT_TYPE_DATA` for ACKs too. The real type is
   `rt_inner_t.type`.
3. **`RT_BODY_MAX` 153 → 152** (decision 5). `gm_inner_pack` already rejects 153.
4. **`encrypt` should return `bool`.** `gm_encrypt` fails on an unknown recipient or a bad length. With the
   current `void` callback, routing can't tell, and would transmit a frame with stale ciphertext.
5. **`link_tag_valid()`** becomes: `compute_link_tag()` + constant-time compare (or call `gm_link_tag_ok`).
6. **Freshness in `handle_data`** (decision 14): drop DATA with `|now − timestamp| > 5 s`, add
   `RT_LOG_REPLAY_STALE`, and send no ACK (§9.7). `try_decrypt` does not check time.
