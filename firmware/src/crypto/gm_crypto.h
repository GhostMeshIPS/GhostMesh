/*
 * gm_crypto.h - GhostMesh security primitives (Network #2), stage 14a.
 *
 * Portable C99: no ESP32 headers, so the same code runs in firmware, host
 * tests and the sim. Spec: PROTOCOL.md §9. Decisions: security/design-decisions.md.
 *
 * Stage 14a (gm_crypto.c): link_tag, pseudonym/MAC derivation, inner-header codec,
 * end-to-end encrypt / trial-decrypt, CTRL sign/verify.
 * Stage 14b (gm_ratchet.c): mesh clock, epoch DH ratchet, KEYS/RESYNC frames,
 * persistence. Message keys come from gm_peer_message_keys().
 *
 * All multi-byte wire fields are big-endian (decision 3).
 */
#ifndef GHOSTMESH_GM_CRYPTO_H
#define GHOSTMESH_GM_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "routing.h"   /* rt_frame_t, rt_inner_t, RT_TYPE_*, RT_MAX_PEERS */

/* ---- Sizes (PROTOCOL §9) ---------------------------------------------- */
#define GM_KEY_BYTES        32
#define GM_PSEUDO_BYTES     4
#define GM_MAC_BYTES        6
#define GM_LINK_TAG_BYTES   8
#define GM_INNER_BYTES      170   /* == sizeof rt_frame_t.ciphertext */
#define GM_INNER_HDR_BYTES  18
#define GM_BODY_MAX         152   /* decision 5: not 153 */
#define GM_ACK_BODY_BYTES   8     /* acked attempt's msg_id */
#define GM_AD_BYTES         12    /* ver_type | flags | msg_id | epoch */
#define GM_MAX_PEERS        RT_MAX_PEERS
#define GM_SIG_BYTES        64

/* CTRL subtypes (decision 8d). Values TBD with the team; keep in one place. */
enum { GM_CTRL_TIME = 1, GM_CTRL_BLOCK = 2 };
#define GM_CTRL_HDR_BYTES   9     /* subtype(1) | issued_at_ms(8) */
#define GM_CTRL_BLOCK_PAYLOAD_BYTES 37  /* block_id(4) until_ms(8) reason(1) 2 x [pseudo(4) mac(6) epoch(2)] */

/* ---- Platform hook ------------------------------------------------------
 * Fill `out` with `n` cryptographically random bytes (firmware: esp_fill_random
 * with the radio on; host tests: deterministic or OS RNG). */
typedef void (*gm_rng_fn)(void *ctx, uint8_t *out, size_t n);

/* ---- Stage 14b parameters (PROTOCOL §9.2, §9.6, §12) ---------------------- */
#define GM_EPOCH_MS               60000u
#define GM_KEYS_INTERVAL_MS       10000u
#define GM_BEACON_TIMEOUT_MS      30000u
#define GM_SLEW_WINDOW_MS         5000u
#define GM_SLEW_MAX_MS            1000     /* smaller forward corrections are slewed */
#define GM_MAX_CATCHUP_EPOCHS     10       /* longer gaps -> RESYNC */
#define GM_NO_DH_EPOCHS           3
#define GM_RESYNC_SILENT_EPOCHS   2
#define GM_RESYNC_MIN_GAP_EPOCHS  5
#define GM_RESYNC_REPEATS         3        /* RESYNC frames sent per resync */
#define GM_KEYS_SLOTS             8
enum { GM_KEYS_NORMAL = 0, GM_KEYS_RESYNC = 1 };

/* ---- State --------------------------------------------------------------- */
typedef struct {                       /* epoch ratchet, per peer (decision 6a) */
    uint8_t  ck_cur[GM_KEY_BYTES];     /* main chain key for the current epoch */
    uint8_t  ck_prev[GM_KEY_BYTES];    /* for frames from the previous epoch */
    uint8_t  ck_alt[GM_KEY_BYTES];     /* the other version (DH vs hash-only) */
    bool     has_prev, has_alt, main_is_dh, alt_is_dh;
    uint8_t  peer_next_pk[GM_KEY_BYTES];  /* peer's key for the next epoch */
    bool     has_peer_next, peer_confirmed, no_dh_alerted;
    uint32_t last_verified, last_dh, last_resync;   /* absolute epochs, 0 = never */
    uint8_t  resync_nonces[4][8];
    uint8_t  resync_nonce_i;
} gm_ratchet_peer_t;

typedef struct {
    bool     used;
    uint32_t node_id;                  /* real node ID */
    uint8_t  pk[GM_KEY_BYTES];         /* peer's static X25519 public key */
    uint8_t  root[GM_KEY_BYTES];       /* decision 6a: root[me, peer] */
    gm_ratchet_peer_t r;
} gm_peer_t;

typedef struct {
    uint32_t   node_id;
    uint8_t    network_key[GM_KEY_BYTES];
    uint8_t    pseudo_secret[GM_KEY_BYTES];
    uint8_t    x_sk[GM_KEY_BYTES];     /* own static X25519 secret */
    uint8_t    x_pk[GM_KEY_BYTES];
    uint8_t    watchtower_pk[GM_KEY_BYTES]; /* Ed25519 public key */
    gm_peer_t  peers[GM_MAX_PEERS];
    int        last_peer;              /* trial-decryption hint: try this one first */
    gm_rng_fn  rng;
    void      *rng_ctx;

    /* Mesh clock (decisions 2b, 8c, 10c): mesh_ms = local_ms + offset (+ slew in progress) */
    bool       synced;
    int64_t    offset_ms;
    int64_t    slew_total_ms;
    uint64_t   slew_start_local;
    uint64_t   last_beacon_ms;
    uint64_t   last_beacon_local;
    bool       no_beacon_alerted;

    /* Ratchet, node-wide */
    bool       have_chain, imported, dirty;
    uint32_t   cur_epoch;              /* absolute: floor(unix_ms / 60000) */
    uint8_t    my_next_sk[GM_KEY_BYTES];  /* r(cur+1), announced in KEYS */
    uint8_t    my_next_pk[GM_KEY_BYTES];
    uint64_t   next_keys_local;
    uint8_t    resync_mask;            /* peers (by slot bit) we are resyncing */
    uint8_t    resync_sends_left;
    uint32_t   unverified_heard;       /* epoch an unverifiable KEYS frame was last heard */
} gm_crypto_t;

typedef struct {                       /* what gm_tick() asks firmware to do */
    bool    synced_now;                /* first beacon accepted this tick */
    bool    epoch_changed;
    bool    keys_due;                  /* build + flood a KEYS frame (gm_keys_build) */
    bool    state_changed;             /* save gm_state_export() to NVS */
    bool    no_beacon;                 /* serial event no_beacon (decision 10f) */
    uint8_t no_dh_mask;                /* serial event no_dh, per peer slot (10e) */
    uint8_t resync_mask;               /* serial event resync, per peer slot (10d) */
} gm_events_t;

/* ---- Setup --------------------------------------------------------------- */

/* Copies the keys in and derives this node's X25519 public key. */
void gm_init(gm_crypto_t *c, uint32_t node_id,
             const uint8_t network_key[32], const uint8_t pseudo_secret[32],
             const uint8_t x25519_sk[32], const uint8_t watchtower_pk[32],
             gm_rng_fn rng, void *rng_ctx);

/* Adds a peer and derives root[me, peer]. Returns false if the table is full or the
 * X25519 result is all-zero (low-order public key). */
bool gm_add_peer(gm_crypto_t *c, uint32_t peer_id, const uint8_t peer_pk[32]);

/* Wipes every secret in `c`. */
void gm_wipe(gm_crypto_t *c);

/* ---- Pseudonyms and MACs (decision 3) ------------------------------------ */
void gm_pseudonym(const uint8_t pseudo_secret[32], uint16_t epoch, uint8_t out[4]);
void gm_mac(const uint8_t pseudo_secret[32], uint16_t epoch, uint8_t out[6]);

/* ---- link_tag (decision 4) ---------------------------------------------- */
void gm_link_tag(const uint8_t network_key[32], const rt_frame_t *f, uint8_t out[8]);
bool gm_link_tag_ok(const uint8_t network_key[32], const rt_frame_t *f);   /* constant time */

/* ---- Keys (decision 6a) -------------------------------------------------- */
/* root = BLAKE2b(32, "GM-ROOT" || X25519(sk, peer_pk) || pk_lo || pk_hi). False on all-zero DH. */
bool gm_root_key(const uint8_t my_sk[32], const uint8_t my_pk[32],
                 const uint8_t peer_pk[32], uint8_t root[32]);
/* ck[e] = BLAKE2b(key=root, 32, "GM-RESYNC" || e) */
void gm_chain_start(const uint8_t root[32], uint16_t epoch, uint8_t ck[32]);
/* mk = BLAKE2b(key=ck, 32, "GM-MSG") */
void gm_message_key(const uint8_t ck[32], uint8_t mk[32]);
/* ck[e+1] = BLAKE2b(key=ck[e], 32, "GM-CHAIN" || (e+1)_be16 [|| dh]); dh may be NULL (hash-only). */
void gm_chain_step(const uint8_t ck[32], uint16_t next_epoch, const uint8_t *dh, uint8_t out[32]);

/* Message keys to try for a frame with this wire epoch (stage 14b ratchet):
 * current epoch -> main [+ alternate]; previous -> prev; next -> its candidates.
 * Returns how many keys were written (0..2); index 0 is the one to encrypt with. */
int  gm_peer_message_keys(const gm_crypto_t *c, int peer_slot, uint16_t wire_epoch, uint8_t mk[2][32]);

/* ---- Mesh clock (decisions 2b, 8c, 10c) ------------------------------------ */
/* local_ms: any monotonic millisecond counter (esp_timer_get_time()/1000). */
uint64_t gm_clock_now(const gm_crypto_t *c, uint64_t local_ms);
/* Apply an already-verified TIME beacon. Never moves the clock backward; corrections
 * < 1 s are slewed over 5 s, larger ones jump. Returns false if not newer than the last. */
bool     gm_clock_on_beacon(gm_crypto_t *c, uint64_t issued_at_ms, uint64_t local_ms);
uint16_t gm_wire_epoch(uint32_t abs_epoch);

/* ---- Epoch ratchet driver (decisions 6a, 10d, 10e, 10f) --------------------- */
/* Call every ~100 ms. Steps epochs, schedules KEYS, raises alerts. */
void gm_tick(gm_crypto_t *c, uint64_t local_ms, gm_events_t *ev);
/* Builds the next KEYS frame (normal or RESYNC) into the 170-byte region. */
bool gm_keys_build(gm_crypto_t *c, uint8_t region[GM_INNER_BYTES]);
/* Processes a received KEYS region. True if at least one slot verified. */
bool gm_keys_receive(gm_crypto_t *c, const uint8_t region[GM_INNER_BYTES]);

/* ---- Persistence (decision 14b) ------------------------------------------- */
#define GM_STATE_BYTES 1517
/* Fixed-size, versioned blob for NVS. Returns bytes written (GM_STATE_BYTES) or 0. */
size_t gm_state_export(const gm_crypto_t *c, uint8_t *buf, size_t cap);
/* Restore after gm_init + gm_add_peer (peers matched by node_id). Clock stays unsynced. */
bool   gm_state_import(gm_crypto_t *c, const uint8_t *buf, size_t len);

/* ---- Inner header (decision 5) ------------------------------------------- */
/* Big-endian pack into exactly 170 bytes, zero-padded. False if len is out of range. */
bool gm_inner_pack(const rt_inner_t *in, uint8_t out[GM_INNER_BYTES]);
bool gm_inner_unpack(const uint8_t buf[GM_INNER_BYTES], rt_inner_t *out);

/* ---- End-to-end encryption (decisions 6b, 6c) ---------------------------- */
/* Associated data: frame[0:10] || frame[20:22]. */
void gm_ad(const rt_frame_t *f, uint8_t ad[GM_AD_BYTES]);

/* Encrypts `in` for in->recipient_id into f->nonce / f->ciphertext / f->aead_tag.
 * PRECONDITION: f->ver_type, f->flags, f->msg_id and f->epoch are already filled
 * (they are authenticated as AD). Returns false if the recipient is unknown or
 * the inner header is invalid. */
bool gm_encrypt(gm_crypto_t *c, const rt_inner_t *in, rt_frame_t *f);

/* Trial-decrypts with every peer's key for the frame's epoch. True only if the
 * frame is for this node: AEAD verifies, recipient_id == me, sender_id == the peer
 * whose key worked, type is DATA/ACK and len fits. Freshness and seq checks are
 * routing's job (handle_data). */
bool gm_try_decrypt(gm_crypto_t *c, const rt_frame_t *f, rt_inner_t *out);

/* ---- Signed CTRL frames (decision 8) ------------------------------------- */
/* Payload length for a subtype, or -1 if unknown. */
int  gm_ctrl_payload_len(uint8_t subtype);
/* Writes subtype | issued_at_ms | payload | sig into region[0..], random-fills the
 * rest of the 170-byte region. sk is Monocypher's 64-byte Ed25519 secret key.
 * Returns false if payload_len doesn't match the subtype. */
bool gm_ctrl_sign(gm_crypto_t *c, const uint8_t ed_sk[64], uint8_t subtype,
                  uint64_t issued_at_ms, const uint8_t *payload, size_t payload_len,
                  uint8_t region[GM_INNER_BYTES]);
/* Verifies a CTRL region against the watchtower's public key. On success fills
 * subtype / issued_at_ms and points *payload into the region. */
bool gm_ctrl_verify(const gm_crypto_t *c, const uint8_t region[GM_INNER_BYTES],
                    uint8_t *subtype, uint64_t *issued_at_ms,
                    const uint8_t **payload, size_t *payload_len);

/* ---- Big-endian helpers ---------------------------------------------------- */
uint16_t gm_get_be16(const uint8_t *p);
void     gm_put_be16(uint8_t *p, uint16_t v);
uint32_t gm_get_be32(const uint8_t *p);
void     gm_put_be32(uint8_t *p, uint32_t v);
uint64_t gm_get_be64(const uint8_t *p);
void     gm_put_be64(uint8_t *p, uint64_t v);

#endif /* GHOSTMESH_GM_CRYPTO_H */
