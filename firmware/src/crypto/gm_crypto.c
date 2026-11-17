/*
 * gm_crypto.c - GhostMesh security primitives (Network #2), stage 14a.
 * Spec: PROTOCOL.md §9. Every formula here has a matching Python version in
 * firmware/test/run_crypto_tests.py, which cross-checks the bytes.
 */
#include "gm_crypto.h"

#include <string.h>

#include "monocypher.h"
#include "monocypher-ed25519.h"

/* The frame layout this file assumes (PROTOCOL §9.4). */
typedef char gm_assert_frame_size[(sizeof(rt_frame_t) == 240) ? 1 : -1];
typedef char gm_assert_ct_size[(sizeof(((rt_frame_t *)0)->ciphertext) == GM_INNER_BYTES) ? 1 : -1];
typedef char gm_assert_body_fits[(RT_BODY_MAX >= GM_BODY_MAX) ? 1 : -1];

/* ---- Big-endian helpers ------------------------------------------------- */

uint16_t gm_get_be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
void gm_put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

uint32_t gm_get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
void gm_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

uint64_t gm_get_be64(const uint8_t *p)
{
    return ((uint64_t)gm_get_be32(p) << 32) | gm_get_be32(p + 4);
}
void gm_put_be64(uint8_t *p, uint64_t v)
{
    gm_put_be32(p, (uint32_t)(v >> 32)); gm_put_be32(p + 4, (uint32_t)v);
}

/* ---- Key fingerprints ----------------------------------------------------- */

void gm_fingerprint(const uint8_t key[32], char out[10])
{
    static const char hexd[] = "0123456789abcdef";
    uint8_t msg[5 + 32], h[4];
    memcpy(msg, "GM-FP", 5);
    memcpy(msg + 5, key, 32);
    crypto_blake2b(h, 4, msg, sizeof msg);
    for (int i = 0, o = 0; i < 4; i++) {
        if (i == 2) out[o++] = '-';
        out[o++] = hexd[h[i] >> 4];
        out[o++] = hexd[h[i] & 15];
    }
    out[9] = '\0';
}

/* ---- Small internals ------------------------------------------------------ */

static bool all_zero(const uint8_t *p, size_t n)       /* constant time */
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

static bool equal_ct(const uint8_t *a, const uint8_t *b, size_t n)   /* constant time */
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= (uint8_t)(a[i] ^ b[i]);
    return acc == 0;
}

static int find_peer(const gm_crypto_t *c, uint32_t node_id)
{
    for (int i = 0; i < GM_MAX_PEERS; i++)
        if (c->peers[i].used && c->peers[i].node_id == node_id) return i;
    return -1;
}

/* ---- Setup ------------------------------------------------------------------ */

void gm_init(gm_crypto_t *c, uint32_t node_id,
             const uint8_t network_key[32], const uint8_t pseudo_secret[32],
             const uint8_t x25519_sk[32], const uint8_t watchtower_pk[32],
             gm_rng_fn rng, void *rng_ctx)
{
    memset(c, 0, sizeof *c);
    c->node_id = node_id;
    memcpy(c->network_key, network_key, 32);
    memcpy(c->pseudo_secret, pseudo_secret, 32);
    memcpy(c->x_sk, x25519_sk, 32);
    crypto_x25519_public_key(c->x_pk, c->x_sk);
    memcpy(c->watchtower_pk, watchtower_pk, 32);
    c->rng = rng;
    c->rng_ctx = rng_ctx;
}

bool gm_add_peer(gm_crypto_t *c, uint32_t peer_id, const uint8_t peer_pk[32])
{
    int slot = find_peer(c, peer_id);
    if (slot < 0) {
        for (int i = 0; i < GM_MAX_PEERS && slot < 0; i++)
            if (!c->peers[i].used) slot = i;
    }
    if (slot < 0) return false;

    gm_peer_t *p = &c->peers[slot];
    if (!gm_root_key(c->x_sk, c->x_pk, peer_pk, p->root)) return false;
    p->used = true;
    p->node_id = peer_id;
    memcpy(p->pk, peer_pk, 32);
    return true;
}

void gm_wipe(gm_crypto_t *c) { crypto_wipe(c, sizeof *c); }

/* ---- Pseudonyms and MACs (decision 3) ---------------------------------------- */

void gm_pseudonym(const uint8_t pseudo_secret[32], uint16_t epoch, uint8_t out[4])
{
    uint8_t msg[12];
    memcpy(msg, "GM-PSEUDO", 9);
    gm_put_be16(msg + 9, epoch);
    size_t len = 11;
    for (uint8_t counter = 0;; counter++) {
        if (counter > 0) { msg[11] = counter; len = 12; }   /* rehash: "… || 0x01", "… || 0x02", … */
        crypto_blake2b_keyed(out, 4, pseudo_secret, 32, msg, len);
        uint32_t v = gm_get_be32(out);
        if (v != 0x00000000u && v != 0xFFFFFFFFu) return;  /* reserved values */
    }
}

void gm_mac(const uint8_t pseudo_secret[32], uint16_t epoch, uint8_t out[6])
{
    uint8_t msg[8];
    memcpy(msg, "GM-MAC", 6);
    gm_put_be16(msg + 6, epoch);
    crypto_blake2b_keyed(out, 6, pseudo_secret, 32, msg, sizeof msg);
    out[0] = (uint8_t)((out[0] & 0xFC) | 0x02);   /* locally administered, unicast */
}

/* ---- link_tag (decision 4) ----------------------------------------------------- */

void gm_link_tag(const uint8_t network_key[32], const rt_frame_t *f, uint8_t out[8])
{
    const uint8_t *b = (const uint8_t *)f;
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, 8, network_key, 32);
    crypto_blake2b_update(&ctx, (const uint8_t *)"GM-LINK", 7);
    crypto_blake2b_update(&ctx, b, 22);            /* ver_type .. epoch */
    crypto_blake2b_update(&ctx, b + 30, 210);      /* nonce .. aead_tag (skips link_tag) */
    crypto_blake2b_final(&ctx, out);
}

bool gm_link_tag_ok(const uint8_t network_key[32], const rt_frame_t *f)
{
    uint8_t want[8];
    gm_link_tag(network_key, f, want);
    bool ok = equal_ct(want, f->link_tag, 8);
    crypto_wipe(want, sizeof want);
    return ok;
}

/* ---- Keys (decision 6a) ----------------------------------------------------------- */

bool gm_root_key(const uint8_t my_sk[32], const uint8_t my_pk[32],
                 const uint8_t peer_pk[32], uint8_t root[32])
{
    uint8_t ss[32];
    crypto_x25519(ss, my_sk, peer_pk);
    if (all_zero(ss, 32)) { crypto_wipe(ss, 32); return false; }   /* low-order point */

    const uint8_t *lo = my_pk, *hi = peer_pk;
    if (memcmp(my_pk, peer_pk, 32) > 0) { lo = peer_pk; hi = my_pk; }

    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, (const uint8_t *)"GM-ROOT", 7);
    crypto_blake2b_update(&ctx, ss, 32);
    crypto_blake2b_update(&ctx, lo, 32);
    crypto_blake2b_update(&ctx, hi, 32);
    crypto_blake2b_final(&ctx, root);
    crypto_wipe(ss, 32);
    return true;
}

void gm_chain_start(const uint8_t root[32], uint16_t epoch, uint8_t ck[32])
{
    uint8_t msg[11];
    memcpy(msg, "GM-RESYNC", 9);
    gm_put_be16(msg + 9, epoch);
    crypto_blake2b_keyed(ck, 32, root, 32, msg, sizeof msg);
}

void gm_message_key(const uint8_t ck[32], uint8_t mk[32])
{
    crypto_blake2b_keyed(mk, 32, ck, 32, (const uint8_t *)"GM-MSG", 6);
}

void gm_chain_step(const uint8_t ck[32], uint16_t next_epoch, const uint8_t *dh, uint8_t out[32])
{
    uint8_t lbl[10];
    memcpy(lbl, "GM-CHAIN", 8);
    gm_put_be16(lbl + 8, next_epoch);
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, 32, ck, 32);
    crypto_blake2b_update(&ctx, lbl, sizeof lbl);
    if (dh) crypto_blake2b_update(&ctx, dh, 32);
    crypto_blake2b_final(&ctx, out);
}

/* gm_peer_message_keys() lives in gm_ratchet.c with the rest of the ratchet. */

/* ---- Inner header (decision 5) ----------------------------------------------------- */

static bool inner_len_ok(uint8_t type, uint8_t len)
{
    if (type == RT_TYPE_DATA) return len <= GM_BODY_MAX;
    if (type == RT_TYPE_ACK)  return len == GM_ACK_BODY_BYTES;
    return false;
}

bool gm_inner_pack(const rt_inner_t *in, uint8_t out[GM_INNER_BYTES])
{
    if (!inner_len_ok(in->type, in->len)) return false;
    memset(out, 0, GM_INNER_BYTES);
    gm_put_be32(out + 0,  in->sender_id);
    gm_put_be32(out + 4,  in->recipient_id);
    gm_put_be32(out + 8,  in->timestamp);
    gm_put_be32(out + 12, in->seq);
    out[16] = in->type;
    out[17] = in->len;
    memcpy(out + GM_INNER_HDR_BYTES, in->body, in->len);
    return true;
}

bool gm_inner_unpack(const uint8_t buf[GM_INNER_BYTES], rt_inner_t *out)
{
    uint8_t type = buf[16], len = buf[17];
    if (!inner_len_ok(type, len)) return false;
    memset(out, 0, sizeof *out);
    out->sender_id    = gm_get_be32(buf + 0);
    out->recipient_id = gm_get_be32(buf + 4);
    out->timestamp    = gm_get_be32(buf + 8);
    out->seq          = gm_get_be32(buf + 12);
    out->type         = type;
    out->len          = len;
    memcpy(out->body, buf + GM_INNER_HDR_BYTES, len);
    return true;
}

/* ---- End-to-end encryption (decisions 6b, 6c) ---------------------------------------- */

void gm_ad(const rt_frame_t *f, uint8_t ad[GM_AD_BYTES])
{
    const uint8_t *b = (const uint8_t *)f;
    memcpy(ad, b, 10);           /* ver_type, flags, msg_id */
    memcpy(ad + 10, b + 20, 2);  /* epoch */
}

bool gm_encrypt(gm_crypto_t *c, const rt_inner_t *in, rt_frame_t *f)
{
    int slot = find_peer(c, in->recipient_id);
    if (slot < 0) return false;

    uint8_t pt[GM_INNER_BYTES], mks[2][32], ad[GM_AD_BYTES];
    if (!gm_inner_pack(in, pt)) return false;
    if (gm_peer_message_keys(c, slot, gm_get_be16(f->epoch), mks) < 1) { crypto_wipe(pt, sizeof pt); return false; }
    uint8_t *mk = mks[0];                            /* main key: what the peer expects */

    c->rng(c->rng_ctx, f->nonce, sizeof f->nonce);   /* random 24-byte nonce */
    gm_ad(f, ad);
    crypto_aead_lock(f->ciphertext, f->aead_tag, mk, f->nonce, ad, sizeof ad, pt, sizeof pt);

    crypto_wipe(pt, sizeof pt);
    crypto_wipe(mks, sizeof mks);
    return true;
}

/* Implemented in gm_ratchet.c: "the DH version wins" when a frame verifies under the alternate. */
void gm_ratchet_note_key_used(gm_crypto_t *c, int peer_slot, uint16_t wire_epoch, int key_index);

bool gm_try_decrypt(gm_crypto_t *c, const rt_frame_t *f, rt_inner_t *out)
{
    uint8_t ad[GM_AD_BYTES], mks[2][32], pt[GM_INNER_BYTES];
    uint16_t epoch = gm_get_be16(f->epoch);
    gm_ad(f, ad);

    int start = (c->last_peer >= 0 && c->last_peer < GM_MAX_PEERS) ? c->last_peer : 0;
    bool ok = false, done = false;
    for (int n = 0; n < GM_MAX_PEERS && !done; n++) {
        int i = (start + n) % GM_MAX_PEERS;
        if (!c->peers[i].used) continue;
        int nk = gm_peer_message_keys(c, i, epoch, mks);
        for (int k = 0; k < nk && !done; k++) {
            if (crypto_aead_unlock(pt, f->aead_tag, mks[k], f->nonce, ad, sizeof ad,
                                   f->ciphertext, sizeof f->ciphertext) != 0) continue;
            done = true;   /* a frame authenticates under at most one key; stop here */

            /* Authentic. Now it must really be for us, from that peer (decision 5). */
            rt_inner_t tmp;
            if (gm_inner_unpack(pt, &tmp) &&
                tmp.recipient_id == c->node_id &&
                tmp.sender_id == c->peers[i].node_id) {
                *out = tmp;
                c->last_peer = i;
                gm_ratchet_note_key_used(c, i, epoch, k);
                ok = true;
            }
            crypto_wipe(&tmp, sizeof tmp);
        }
    }
    crypto_wipe(mks, sizeof mks);
    crypto_wipe(pt, sizeof pt);
    return ok;
}

/* ---- Signed CTRL frames (decision 8) --------------------------------------------------- */

int gm_ctrl_payload_len(uint8_t subtype)
{
    switch (subtype) {
    case GM_CTRL_TIME:  return 0;
    case GM_CTRL_BLOCK: return GM_CTRL_BLOCK_PAYLOAD_BYTES;
    default:            return -1;
    }
}

/* Signed message = "GM-CTRL" || subtype || issued_at_ms || payload */
static size_t ctrl_message(const uint8_t *region, size_t body_len, uint8_t *msg)
{
    memcpy(msg, "GM-CTRL", 7);
    memcpy(msg + 7, region, body_len);
    return 7 + body_len;
}

bool gm_ctrl_sign(gm_crypto_t *c, const uint8_t ed_sk[64], uint8_t subtype,
                  uint64_t issued_at_ms, const uint8_t *payload, size_t payload_len,
                  uint8_t region[GM_INNER_BYTES])
{
    int want = gm_ctrl_payload_len(subtype);
    if (want < 0 || (size_t)want != payload_len) return false;
    size_t body = GM_CTRL_HDR_BYTES + payload_len;

    c->rng(c->rng_ctx, region, GM_INNER_BYTES);        /* random filler everywhere */
    region[0] = subtype;
    gm_put_be64(region + 1, issued_at_ms);
    if (payload_len) memcpy(region + GM_CTRL_HDR_BYTES, payload, payload_len);

    uint8_t msg[7 + GM_CTRL_HDR_BYTES + GM_CTRL_BLOCK_PAYLOAD_BYTES];
    size_t mlen = ctrl_message(region, body, msg);
    crypto_ed25519_sign(region + body, ed_sk, msg, mlen);
    return true;
}

bool gm_ctrl_verify(const gm_crypto_t *c, const uint8_t region[GM_INNER_BYTES],
                    uint8_t *subtype, uint64_t *issued_at_ms,
                    const uint8_t **payload, size_t *payload_len)
{
    int plen = gm_ctrl_payload_len(region[0]);
    if (plen < 0) return false;
    size_t body = GM_CTRL_HDR_BYTES + (size_t)plen;

    uint8_t msg[7 + GM_CTRL_HDR_BYTES + GM_CTRL_BLOCK_PAYLOAD_BYTES];
    size_t mlen = ctrl_message(region, body, msg);
    if (crypto_ed25519_check(region + body, c->watchtower_pk, msg, mlen) != 0) return false;

    *subtype = region[0];
    *issued_at_ms = gm_get_be64(region + 1);
    *payload = region + GM_CTRL_HDR_BYTES;
    *payload_len = (size_t)plen;
    return true;
}
