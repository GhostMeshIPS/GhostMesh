/*
 * gm_crypto.h - GhostMesh security primitives (Network #2), stage 14a.
 *
 * Portable C99: no ESP32 headers, so the same code runs in firmware, host
 * tests and the sim. Spec: PROTOCOL.md §9. Decisions: security/design-decisions.md.
 *
 * Stage 14a (this file): link_tag, pseudonym/MAC derivation, inner-header codec,
 * end-to-end encrypt / trial-decrypt, CTRL sign/verify.
 * Stage 14b (next): epoch ratchet, KEYS/RESYNC frames, mesh clock. It plugs in at
 * gm_peer_message_key(); nothing else here should need to change.
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

/* ---- State --------------------------------------------------------------- */
typedef struct {
    bool     used;
    uint32_t node_id;                  /* real node ID */
    uint8_t  pk[GM_KEY_BYTES];         /* peer's static X25519 public key */
    uint8_t  root[GM_KEY_BYTES];       /* decision 6a: root[me, peer] */
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
} gm_crypto_t;

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
/* The seam for stage 14b. Today: mk for `epoch` from the chain-start formula
 * (no forward secrecy yet). 14b: look up the ratchet's ck for that epoch. */
bool gm_peer_message_key(const gm_crypto_t *c, int peer_slot, uint16_t epoch, uint8_t mk[32]);

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
