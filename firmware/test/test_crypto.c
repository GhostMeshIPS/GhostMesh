/*
 * test_crypto.c - host tests for firmware/src/crypto/gm_crypto (stage 14a).
 * Run through firmware/test/run_crypto_tests.py, which compiles this file and
 * cross-checks the "VEC" lines against an independent Python implementation.
 *
 * Output: "PASS name" / "FAIL name" per check, "VEC name hex" for cross-checks,
 * then "SUMMARY passed failed". Exit code = number of failures.
 */
#include <stdio.h>
#include <string.h>

#include "gm_crypto.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

static int passed, failed;

static void check(bool ok, const char *name)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) passed++; else failed++;
}

static void vec(const char *name, const void *data, size_t n)
{
    const uint8_t *b = data;
    printf("VEC %s ", name);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

/* Deterministic test RNG (NOT for firmware). */
static void test_rng(void *ctx, uint8_t *out, size_t n)
{
    uint32_t *s = ctx;
    for (size_t i = 0; i < n; i++) { *s = *s * 1103515245u + 12345u; out[i] = (uint8_t)(*s >> 16); }
}

static void fill(uint8_t *p, size_t n, uint8_t start)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(start + i);
}

/* Node IDs and keys used throughout (the Python runner uses the same patterns). */
enum { ID_A = 1, ID_B = 2, ID_C = 3 };
static uint8_t NET[32], PS_A[32], PS_B[32], PS_C[32], SK_A[32], SK_B[32], SK_C[32], WT_SEED[32];
static uint8_t WT_SK[64], WT_PK[32];
static gm_crypto_t A, B, C;
static uint32_t rngA = 1, rngB = 2, rngC = 3;

static void setup(void)
{
    fill(NET, 32, 0x20); fill(PS_A, 32, 0x00); fill(PS_B, 32, 0x30); fill(PS_C, 32, 0x60);
    fill(SK_A, 32, 0x10); fill(SK_B, 32, 0x40); fill(SK_C, 32, 0x70); fill(WT_SEED, 32, 0xA0);
    uint8_t seed[32];
    memcpy(seed, WT_SEED, 32);
    crypto_ed25519_key_pair(WT_SK, WT_PK, seed);        /* wipes seed */

    gm_init(&A, ID_A, NET, PS_A, SK_A, WT_PK, test_rng, &rngA);
    gm_init(&B, ID_B, NET, PS_B, SK_B, WT_PK, test_rng, &rngB);
    gm_init(&C, ID_C, NET, PS_C, SK_C, WT_PK, test_rng, &rngC);
    check(gm_add_peer(&A, ID_B, B.x_pk) && gm_add_peer(&A, ID_C, C.x_pk), "setup: A adds peers");
    check(gm_add_peer(&B, ID_A, A.x_pk) && gm_add_peer(&B, ID_C, C.x_pk), "setup: B adds peers");
    check(gm_add_peer(&C, ID_A, A.x_pk) && gm_add_peer(&C, ID_B, B.x_pk), "setup: C adds peers");

    /* Stage 14b: keys exist only after the first time beacon. Sync everyone into the
     * absolute epoch whose wire value is 0x0102; a fresh chain there equals the
     * chain-start formula, which the Python cross-check recomputes. */
    uint64_t t = (uint64_t)0x01B00102u * GM_EPOCH_MS + 1000u;
    gm_events_t ev;
    gm_crypto_t *all[3] = { &A, &B, &C };
    for (int i = 0; i < 3; i++) { gm_clock_on_beacon(all[i], t, 0); gm_tick(all[i], 0, &ev); }
    check(A.have_chain && gm_wire_epoch(A.cur_epoch) == 0x0102, "setup: nodes synced to epoch 0x0102");
}

/* Builds the header fields routing fills BEFORE encrypt() (AD precondition). */
static void header(rt_frame_t *f, uint8_t msg_id_seed, uint16_t epoch)
{
    memset(f, 0, sizeof *f);
    f->ver_type = RT_TYPE_DATA;          /* always DATA in cleartext (decision 5) */
    f->flags = 0;
    fill(f->msg_id, 8, msg_id_seed);
    gm_put_be16(f->epoch, epoch);
}

static void finish(rt_frame_t *f, const uint8_t pseudo_secret[32], uint16_t epoch)
{
    f->ttl = 5; f->hop_count = 0;
    gm_pseudonym(pseudo_secret, epoch, f->src_pseudo);
    gm_link_tag(NET, f, f->link_tag);    /* last */
}

static rt_inner_t data_msg(uint32_t from, uint32_t to, const char *text, uint32_t seq)
{
    rt_inner_t in;
    memset(&in, 0, sizeof in);
    in.sender_id = from; in.recipient_id = to; in.timestamp = 123456789u; in.seq = seq;
    in.type = RT_TYPE_DATA; in.len = (uint8_t)strlen(text);
    memcpy(in.body, text, in.len);
    return in;
}

static void test_vectors(void)
{
    uint8_t out[8];
    uint8_t ps[32]; fill(ps, 32, 0x00);
    gm_pseudonym(ps, 0x0102, out);
    check(memcmp(out, "\xac\x34\x15\x87", 4) == 0, "vector: pseudonym (decision 3)");
    uint8_t mac[6];
    gm_mac(ps, 0x0102, mac);
    check(memcmp(mac, "\x6a\xa7\x07\xca\x0e\xdd", 6) == 0, "vector: MAC (decision 3)");
    int good_bits = 0;
    for (int e = 0; e < 256; e++) { gm_mac(ps, (uint16_t)e, mac); good_bits += (mac[0] & 0x03) == 0x02; }
    check(good_bits == 256, "MAC is locally administered + unicast (256 epochs)");
    /* Untested branch: pseudonym rehash for reserved values 0x00000000 / 0xFFFFFFFF.
     * Triggering it needs a ~1-in-2^31 hash output; the Python reference mirrors it. */

    rt_frame_t f; uint8_t *b = (uint8_t *)&f;
    for (int i = 0; i < 240; i++) b[i] = (uint8_t)i;
    uint8_t k[32]; fill(k, 32, 0x20);
    gm_link_tag(k, &f, out);
    check(memcmp(out, "\x15\x2e\xe8\xad\x61\x2c\xa5\x86", 8) == 0, "vector: link_tag (decision 4)");
}

static void test_link_tag(void)
{
    rt_frame_t f; uint8_t *b = (uint8_t *)&f;
    for (int i = 0; i < 240; i++) b[i] = (uint8_t)(i * 3);
    gm_link_tag(NET, &f, f.link_tag);
    check(gm_link_tag_ok(NET, &f), "link_tag: valid frame passes");

    int caught = 0;
    for (int i = 0; i < 240; i++) {
        rt_frame_t t = f; ((uint8_t *)&t)[i] ^= 0x01;
        caught += !gm_link_tag_ok(NET, &t);
    }
    check(caught == 240, "link_tag: flipping ANY single byte (header, tag, body) fails");

    uint8_t other[32]; fill(other, 32, 0x21);
    check(!gm_link_tag_ok(other, &f), "link_tag: wrong network key fails");
}

static void test_keys(void)
{
    check(memcmp(A.peers[1].root, C.peers[0].root, 32) == 0, "root[A,C] == root[C,A]");
    check(memcmp(A.peers[1].root, A.peers[0].root, 32) != 0, "root[A,C] != root[A,B]");
    uint8_t zero_pk[32] = {0};
    gm_crypto_t T = A;
    check(!gm_add_peer(&T, 99, zero_pk), "low-order (all-zero) public key rejected");

    uint8_t mks[2][32];
    check(gm_peer_message_keys(&A, 1, 0x0102, mks) == 1, "one message key for a fresh pair");
    vec("root_AC", A.peers[1].root, 32);
    vec("mk_AC_0102", mks[0], 32);
}

static void test_e2e(void)
{
    rt_frame_t f;
    header(&f, 0x50, 0x0102);
    rt_inner_t in = data_msg(ID_A, ID_C, "meet at 9", 7);
    check(gm_encrypt(&A, &in, &f), "encrypt A->C");
    finish(&f, PS_A, 0x0102);
    vec("frame_AC", &f, sizeof f);

    rt_inner_t out;
    bool okC = gm_try_decrypt(&C, &f, &out);
    check(okC && out.sender_id == ID_A && out.recipient_id == ID_C && out.seq == 7 &&
          out.len == 9 && memcmp(out.body, "meet at 9", 9) == 0 && out.type == RT_TYPE_DATA &&
          out.timestamp == 123456789u, "C decrypts A's message with all fields intact");
    check(!gm_try_decrypt(&B, &f, &out), "relay B cannot decrypt A->C");
    check(!gm_try_decrypt(&A, &f, &out), "A rejects its own frame reflected back (sender check)");

    /* Authentic under key[A,C] but addressed to B: only the recipient check catches it. */
    {
        rt_frame_t g; header(&g, 0x58, 0x0102);
        rt_inner_t wrong = data_msg(ID_C, ID_B, "not for A", 1);
        uint8_t pt[GM_INNER_BYTES], mks[2][32], adb[GM_AD_BYTES];
        uint8_t *mk = mks[0];
        gm_inner_pack(&wrong, pt);
        gm_peer_message_keys(&C, 0, 0x0102, mks);        /* C's slot 0 = peer A */
        fill(g.nonce, 24, 0x33);
        gm_ad(&g, adb);
        crypto_aead_lock(g.ciphertext, g.aead_tag, mk, g.nonce, adb, sizeof adb, pt, sizeof pt);
        check(!gm_try_decrypt(&A, &g, &out), "frame authentic under key[A,C] but addressed to B is rejected (recipient check)");

        /* Authentic under key[A,C], addressed to A, but claiming to come from B. */
        rt_inner_t forged = data_msg(ID_B, ID_A, "i am B", 1);
        gm_inner_pack(&forged, pt);
        header(&g, 0x59, 0x0102);
        fill(g.nonce, 24, 0x34);
        gm_ad(&g, adb);
        crypto_aead_lock(g.ciphertext, g.aead_tag, mk, g.nonce, adb, sizeof adb, pt, sizeof pt);
        check(!gm_try_decrypt(&A, &g, &out), "C cannot pass off a message as B's (sender check)");
    }

    /* Relays rewrite these fields; decryption must not depend on them. */
    rt_frame_t r = f;
    r.ttl = 4; r.hop_count = 1; fill(r.src_pseudo, 4, 0x99); fill(r.next_hop, 4, 0x77);
    gm_link_tag(NET, &r, r.link_tag);
    check(gm_try_decrypt(&C, &r, &out), "still decrypts after relay rewrites ttl/hop/src_pseudo/next_hop/link_tag");

    /* Every authenticated byte: AD fields, nonce, ciphertext, tag. */
    int caught = 0, total = 0;
    for (int i = 0; i < 240; i++) {
        bool in_ad = (i < 10) || (i == 20 || i == 21);
        bool in_aead = (i >= 30);
        if (!in_ad && !in_aead) continue;
        rt_frame_t t = f; ((uint8_t *)&t)[i] ^= 0x01;
        total++; caught += !gm_try_decrypt(&C, &t, &out);
    }
    check(caught == total, "flipping any AD/nonce/ciphertext/tag byte breaks decryption");

    /* Different epoch -> different key and AD. */
    rt_frame_t e = f; gm_put_be16(e.epoch, 0x0103);
    check(!gm_try_decrypt(&C, &e, &out), "re-dated epoch fails");

    /* Two encryptions of the same message differ (fresh nonce). */
    rt_frame_t f2; header(&f2, 0x50, 0x0102);
    gm_encrypt(&A, &in, &f2);
    check(memcmp(f.nonce, f2.nonce, 24) != 0 && memcmp(f.ciphertext, f2.ciphertext, 170) != 0,
          "fresh random nonce per encryption");
}

static void test_ack_and_limits(void)
{
    rt_frame_t f; header(&f, 0x60, 0x0102);
    rt_inner_t ack; memset(&ack, 0, sizeof ack);
    ack.sender_id = ID_C; ack.recipient_id = ID_A; ack.seq = 7; ack.type = RT_TYPE_ACK; ack.len = 8;
    fill(ack.body, 8, 0x50);
    check(gm_encrypt(&C, &ack, &f), "encrypt ACK C->A");
    check(f.ver_type == RT_TYPE_DATA, "ACK frame's cleartext type stays DATA");
    rt_inner_t out;
    check(gm_try_decrypt(&A, &f, &out) && out.type == RT_TYPE_ACK && out.len == 8, "A decrypts ACK");

    rt_inner_t bad = ack; bad.len = 7;
    check(!gm_encrypt(&C, &bad, &f), "ACK with len != 8 rejected");
    rt_inner_t big = data_msg(ID_A, ID_C, "", 1); big.len = GM_BODY_MAX + 1;
    check(!gm_encrypt(&A, &big, &f), "DATA longer than 152 bytes rejected");
    rt_inner_t max = data_msg(ID_A, ID_C, "", 1); max.len = GM_BODY_MAX; memset(max.body, 'x', GM_BODY_MAX);
    header(&f, 0x61, 0x0102);
    check(gm_encrypt(&A, &max, &f) && gm_try_decrypt(&C, &f, &out) && out.len == GM_BODY_MAX,
          "152-byte DATA round-trips");
    rt_inner_t weird = data_msg(ID_A, ID_C, "x", 1); weird.type = 9;
    check(!gm_encrypt(&A, &weird, &f), "unknown inner type rejected");
    rt_inner_t nobody = data_msg(ID_A, 42, "x", 1);
    check(!gm_encrypt(&A, &nobody, &f), "unknown recipient rejected");
}

static void test_ctrl(void)
{
    uint8_t region[GM_INNER_BYTES], st; uint64_t at; const uint8_t *pl; size_t plen;
    check(gm_ctrl_sign(&A, WT_SK, GM_CTRL_TIME, 1731264000123ull, NULL, 0, region), "sign TIME");
    check(gm_ctrl_verify(&C, region, &st, &at, &pl, &plen) && st == GM_CTRL_TIME &&
          at == 1731264000123ull && plen == 0, "verify TIME");

    uint8_t block[GM_CTRL_BLOCK_PAYLOAD_BYTES]; fill(block, sizeof block, 0xB0);
    check(gm_ctrl_sign(&A, WT_SK, GM_CTRL_BLOCK, 1731264000456ull, block, sizeof block, region), "sign BLOCK");
    vec("ctrl_block", region, GM_INNER_BYTES);
    check(gm_ctrl_verify(&C, region, &st, &at, &pl, &plen) && st == GM_CTRL_BLOCK &&
          plen == sizeof block && memcmp(pl, block, plen) == 0, "verify BLOCK");

    int signed_len = GM_CTRL_HDR_BYTES + GM_CTRL_BLOCK_PAYLOAD_BYTES + GM_SIG_BYTES;
    int caught = 0;
    for (int i = 0; i < signed_len; i++) {
        uint8_t t[GM_INNER_BYTES]; memcpy(t, region, sizeof t); t[i] ^= 0x01;
        caught += !gm_ctrl_verify(&C, t, &st, &at, &pl, &plen);
    }
    check(caught == signed_len, "flipping any signed byte or signature byte fails");

    uint8_t t[GM_INNER_BYTES]; memcpy(t, region, sizeof t); t[GM_INNER_BYTES - 1] ^= 0x01;
    check(gm_ctrl_verify(&C, t, &st, &at, &pl, &plen), "random filler after the signature is not signed");

    gm_crypto_t X = C; fill(X.watchtower_pk, 32, 0x55);
    check(!gm_ctrl_verify(&X, region, &st, &at, &pl, &plen), "wrong watchtower key fails");
    check(!gm_ctrl_sign(&A, WT_SK, GM_CTRL_BLOCK, 1, block, 5, region), "BLOCK with wrong payload length refused");
    memcpy(t, region, sizeof t); t[0] = 0x7F;
    check(!gm_ctrl_verify(&C, t, &st, &at, &pl, &plen), "unknown subtype refused");
}

static void test_wipe(void)
{
    gm_crypto_t T = A;
    gm_wipe(&T);
    uint8_t acc = 0; const uint8_t *p = (const uint8_t *)&T;
    for (size_t i = 0; i < sizeof T; i++) acc |= p[i];
    check(acc == 0, "gm_wipe clears all state");
}

int main(void)
{
    setup();
    test_vectors();
    test_link_tag();
    test_keys();
    test_e2e();
    test_ack_and_limits();
    test_ctrl();
    test_wipe();
    printf("SUMMARY %d %d\n", passed, failed);
    return failed;
}
