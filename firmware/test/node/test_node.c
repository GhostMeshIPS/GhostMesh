/*
 * test_node.c - laptop integration test: Rashad's routing + Jose's crypto + Yunus's node glue,
 * several nodes in one process, real keys from security/keygen.py, a fake radio and a virtual clock.
 *
 * Run:  python firmware/test/node/run_node_tests.py
 *
 * This is the same gm_node.c the boards run; only gm_hw_t is fake.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gm_node.h"

/* one wrapper per board, from board_keys.c compiled with different names */
const gm_node_keys_t *keys_A(void);
const gm_node_keys_t *keys_B(void);
const gm_node_keys_t *keys_C(void);
const uint8_t *wt_sk(void);
const uint8_t *wt_network_key(void);

#define MAXN       4
#define MAX_AIR    2048
#define MAX_EVENTS 4096
#define UNIX_BASE  1763400000000ULL     /* Nov 2025-ish, any value works */

typedef struct {
    gm_node_t node;
    int       idx;
    uint64_t  boot_at;      /* virtual ms when this board "powered on" */
    uint8_t   mac[6];
    uint64_t  rng;
    bool      alive;
} simnode_t;

typedef struct { uint8_t frame[240]; uint8_t mac[6]; int from; uint64_t at; } air_t;

static simnode_t N[MAXN];
static int       NN;
static bool      LINK[MAXN + 1][MAXN + 1];   /* index MAXN = watchtower */
static uint64_t  T;                          /* virtual ms since sim start */
static air_t     AIR[MAX_AIR];
static int       NAIR;
static char      EV[MAX_EVENTS][256];
static int       NEV;
static bool      PRINT;
static int       g_pass, g_fail;
static uint64_t  wt_rng = 0x1234567;

#define CHECK(c, msg) do { if (c) g_pass++; else { g_fail++; printf("  FAIL line %d: %s\n", __LINE__, msg); } } while (0)

/* ---- fake hardware ------------------------------------------------------- */
static uint64_t xs(uint64_t *s) { uint64_t x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return *s = x; }

static void air_send(int from, const uint8_t *mac, const uint8_t frame[240])
{
    if (NAIR >= MAX_AIR) { printf("  air overflow\n"); return; }
    air_t *a = &AIR[NAIR++];
    memcpy(a->frame, frame, 240);
    memcpy(a->mac, mac, 6);
    a->from = from;
    a->at = T + 3;                            /* ~airtime */
}

static void hw_transmit(void *ctx, const uint8_t f[240]) { simnode_t *s = ctx; air_send(s->idx, s->mac, f); }
static uint64_t hw_local_ms(void *ctx) { return T - ((simnode_t *)ctx)->boot_at; }
static void hw_rng(void *ctx, uint8_t *out, size_t n)
{
    simnode_t *s = ctx;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)xs(&s->rng);
}
static void hw_emit(void *ctx, const char *json)
{
    simnode_t *s = ctx;
    if (PRINT) printf("  [%7.3fs] %c %s\n", T / 1000.0, s->node.keys.name, json);
    if (NEV < MAX_EVENTS) snprintf(EV[NEV++], sizeof EV[0], "%c|%s", s->node.keys.name, json);
}
static uint32_t hw_set_mac(void *ctx, const uint8_t mac[6]) { memcpy(((simnode_t *)ctx)->mac, mac, 6); return 1500; }

static int count_ev(char who, const char *needle)
{
    int c = 0;
    for (int i = 0; i < NEV; i++) if ((who == '*' || EV[i][0] == who) && strstr(EV[i], needle)) c++;
    return c;
}

/* ---- watchtower (test stand-in): signs TIME beacons with keys_W.h -------- */
static gm_crypto_t WT;

static void wt_rng_fn(void *ctx, uint8_t *out, size_t n) { (void)ctx; for (size_t i = 0; i < n; i++) out[i] = (uint8_t)xs(&wt_rng); }

static void wt_send_ctrl(uint8_t subtype, const uint8_t *payload, size_t plen)
{
    uint64_t unix_now = UNIX_BASE + T;
    rt_frame_t f;
    memset(&f, 0, sizeof f);
    if (!gm_ctrl_sign(&WT, wt_sk(), subtype, unix_now, payload, plen, f.ciphertext)) { printf("  sign failed\n"); return; }
    f.ver_type = RT_FRAME_CTRL;
    wt_rng_fn(NULL, f.msg_id, 8);
    f.ttl = 5;
    wt_rng_fn(NULL, f.src_pseudo, 4);
    gm_put_be16(f.epoch, gm_wire_epoch((uint32_t)(unix_now / 60000)));
    wt_rng_fn(NULL, f.nonce, 24);
    wt_rng_fn(NULL, f.aead_tag, 16);
    gm_link_tag(wt_network_key(), &f, f.link_tag);
    uint8_t mac[6] = {0x02, 0x57, 0, 0, 0, 0x57};
    air_send(MAXN, mac, (const uint8_t *)&f);
}

/* ---- sim driver ----------------------------------------------------------- */
static void sim_reset(void)
{
    memset(N, 0, sizeof N);
    memset(LINK, 0, sizeof LINK);
    NN = 0; NAIR = 0; NEV = 0; T = 0;
}

static simnode_t *add_node(const gm_node_keys_t *k, uint64_t boot_at, uint64_t seed)
{
    simnode_t *s = &N[NN];
    s->idx = NN++;
    s->boot_at = boot_at;
    s->rng = seed;
    s->alive = true;
    uint8_t m[6] = {0x02, 0, 0, 0, 0, (uint8_t)k->name};
    memcpy(s->mac, m, 6);
    gm_hw_t hw = { s, hw_transmit, hw_local_ms, hw_rng, hw_emit, hw_set_mac, NULL, NULL };
    T = boot_at;
    gm_node_init(&s->node, k, &hw, NULL, 0);
    return s;
}

static void link_(int a, int b) { LINK[a][b] = LINK[b][a] = true; }

static void run(uint64_t ms, int beacon_every_ms)
{
    for (uint64_t t = 0; t < ms; t++) {
        T++;
        if (beacon_every_ms && T % (uint64_t)beacon_every_ms == 0) wt_send_ctrl(GM_CTRL_TIME, NULL, 0);
        int i = 0;
        while (i < NAIR) {
            if (AIR[i].at > T) { i++; continue; }
            air_t a = AIR[i];
            AIR[i] = AIR[--NAIR];
            for (int j = 0; j < NN; j++)
                if (j != a.from && N[j].alive && LINK[a.from][j])
                    gm_node_rx(&N[j].node, a.frame, a.mac, (int8_t)(-45 - (int)(xs(&wt_rng) % 30)));
        }
        for (int j = 0; j < NN; j++) if (N[j].alive) gm_node_poll(&N[j].node);
    }
}

/* ---- tests ---------------------------------------------------------------- */

static void test_two_boards_debug_clock(void)
{
    printf("Test 1: A + B, clock set by debug command (tonight's first hardware test)\n");
    sim_reset();
    simnode_t *a = add_node(keys_A(), 0, 11);
    simnode_t *b = add_node(keys_B(), 700, 22);      /* B boots 0.7 s later */
    link_(0, 1);
    run(1000, 0);

    gm_node_send(&a->node, 'B', "early", 5);         /* before sync: must queue */
    CHECK(count_ev('A', "\"ev\":\"queued\"") == 1, "send before sync is queued");
    run(500, 0);
    CHECK(count_ev('*', "\"ev\":\"tx\"") == 0 && a->node.st.tx_frames == 0, "nothing transmitted before sync");

    gm_node_debug_set_time(&a->node, UNIX_BASE + T);
    gm_node_debug_set_time(&b->node, UNIX_BASE + T + 40);   /* laptops never agree exactly */
    run(3000, 0);
    CHECK(count_ev('A', "\"ev\":\"synced\"") == 1 && count_ev('B', "\"ev\":\"synced\"") == 1, "both synced");
    CHECK(count_ev('B', "\"ev\":\"rx\",\"from\":\"A\",\"text\":\"early\"") == 1, "queued message delivered after sync");
    CHECK(count_ev('A', "\"ev\":\"delivered\",\"to\":\"B\"") == 1, "A got the ACK (double check)");

    /* chat across 4 epoch boundaries: keys ratchet every 60 s */
    int sent = 0;
    char msg[32];
    for (int i = 0; i < 24; i++) {
        int len = snprintf(msg, sizeof msg, "msg %d", i);
        gm_node_send(i % 2 ? &b->node : &a->node, i % 2 ? 'A' : 'B', msg, (size_t)len);
        sent++;
        run(10000, 0);
    }
    int got = count_ev('*', "\"ev\":\"rx\"") - 1;
    printf("  over %.0f s: %d/%d delivered, A sent %lu KEYS, B sent %lu KEYS\n",
           T / 1000.0, got, sent,
           (unsigned long)a->node.st.keys_sent, (unsigned long)b->node.st.keys_sent);
    CHECK(got == sent, "every message delivered across epoch changes");
    CHECK(count_ev('*', "\"ev\":\"failed\"") == 0, "no failed sends");
    CHECK(a->node.st.keys_sent >= 10 && b->node.st.keys_sent >= 10, "KEYS flooded every ~10 s");
    CHECK(count_ev('*', "no_dh") == 0, "DH ratchet steps happened (no no_dh alert)");
    CHECK(count_ev('*', "bad_link_tag") == 0, "no link_tag failures (same network key)");
    CHECK(count_ev('*', "\"ev\":\"epoch\"") >= 8, "both boards rotated pseudonym/MAC each epoch");
    CHECK(count_ev('*', "no_beacon") == 2, "no_beacon alert (expected: no watchtower in this test)");
}

static void test_line_with_watchtower(void)
{
    printf("Test 2: W -> A - B - C line, signed TIME beacons, A -> C through B\n");
    sim_reset();
    simnode_t *a = add_node(keys_A(), 0, 101);
    simnode_t *b = add_node(keys_B(), 300, 202);
    simnode_t *c = add_node(keys_C(), 600, 303);
    link_(0, 1); link_(1, 2);          /* A and C can't hear each other */
    LINK[MAXN][0] = true;              /* watchtower only reaches A: beacons must be relayed */
    run(1000, 0);
    run(45000, 10000);   /* with the workaround, sync spreads one hop per beacon (10 s) */
    CHECK(a->node.c.synced && b->node.c.synced && c->node.c.synced, "beacon reached every hop, all synced");
    CHECK(b->node.st.beacons_ok >= 2, "B verified signed beacons");

    gm_node_send(&a->node, 'C', "meet at 9", 9);
    run(5000, 10000);
    CHECK(count_ev('C', "\"from\":\"A\",\"text\":\"meet at 9\"") == 1, "C got A's message (2 hops)");
    CHECK(count_ev('A', "\"ev\":\"delivered\",\"to\":\"C\"") == 1, "A got C's ACK back through B");
    CHECK(count_ev('B', "\"ev\":\"rx\"") == 0, "B relayed but could not read it");

    int before = count_ev('C', "\"ev\":\"rx\"");
    for (int i = 0; i < 10; i++) { gm_node_send(&c->node, 'A', "pong", 4); gm_node_send(&a->node, 'C', "ping", 4); run(12000, 10000); }
    CHECK(count_ev('C', "\"ev\":\"rx\"") - before == 10 && count_ev('A', "text\":\"pong") == 10,
          "10 round trips over 2 minutes of epoch changes");
    CHECK(count_ev('*', "\"ev\":\"failed\"") == 0, "no failed sends");
    CHECK(count_ev('*', "no_beacon") == 0, "no missing-beacon alerts");
}

static void test_outsider(void)
{
    printf("Test 3: frame with a wrong network key is dropped\n");
    sim_reset();
    simnode_t *a = add_node(keys_A(), 0, 5);
    run(10, 0);
    gm_node_debug_set_time(&a->node, UNIX_BASE);
    run(200, 0);
    uint8_t junk[240];
    memset(junk, 0x41, sizeof junk);
    junk[0] = RT_FRAME_DATA;
    uint8_t mac[6] = {0x02, 0xBA, 0xD0, 0, 0, 1};
    gm_node_rx(&a->node, junk, mac, -50);
    CHECK(a->node.st.log_counts[RT_LOG_BAD_LINK_TAG] == 1, "bad_link_tag counted");
}

int main(int argc, char **argv)
{
    PRINT = argc > 1 && !strcmp(argv[1], "-v");
    gm_init(&WT, 5, wt_network_key(), wt_network_key(), wt_network_key(), wt_network_key(), wt_rng_fn, NULL);
    test_two_boards_debug_clock();
    test_line_with_watchtower();
    test_outsider();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
