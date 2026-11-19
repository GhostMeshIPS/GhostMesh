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
#include "gm_watch.h"

/* one wrapper per board, from board_keys.c compiled with different names */
const gm_node_keys_t *keys_A(void);
const gm_node_keys_t *keys_B(void);
const gm_node_keys_t *keys_C(void);
const gm_watch_keys_t *keys_W(void);

#define MAXN       4
#define MAX_AIR    2048
#define MAX_EVENTS 8192
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
static char      EV[MAX_EVENTS][1024];
static int       NEV;
static bool      PRINT;
static int       g_pass, g_fail;
static uint64_t  wt_rng = 0x1234567;   /* RSSI noise */

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

static bool g_factory_mac_on_air;   /* set if any node ever transmits under a non-rotated (factory) MAC */
static void hw_transmit(void *ctx, const uint8_t f[240])
{
    simnode_t *s = ctx;
    /* A rotated epoch MAC is locally administered (bit 0x02 of octet 0); a real Espressif factory
     * MAC is globally administered (bit clear). A node must never put a frame on the air under a
     * factory MAC: that defeats rotation and links the board across epochs (first-sync race). */
    if (s->idx < MAXN && !(s->mac[0] & 0x02)) g_factory_mac_on_air = true;
    air_send(s->idx, s->mac, f);
}
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
static void hw_emit_w(void *ctx, const char *json)
{
    (void)ctx;
    if (PRINT) printf("  [%7.3fs] W %s\n", T / 1000.0, json);
    if (NEV < MAX_EVENTS) snprintf(EV[NEV++], sizeof EV[0], "W|%s", json);
}
static uint32_t hw_set_mac(void *ctx, const uint8_t mac[6]) { memcpy(((simnode_t *)ctx)->mac, mac, 6); return 1500; }

static int count_ev(char who, const char *needle)
{
    int c = 0;
    for (int i = 0; i < NEV; i++) if ((who == '*' || EV[i][0] == who) && strstr(EV[i], needle)) c++;
    return c;
}

/* ---- watchtower: the real gm_watch.c, fed by keys_W.h ----------------------- */
static gm_watch_t WATCH;
static bool       W_ON;
static simnode_t  WNODE;          /* hw context for W (idx MAXN) */

static void start_watchtower(bool link_to_all)
{
    memset(&WNODE, 0, sizeof WNODE);
    WNODE.idx = MAXN;
    WNODE.rng = 0x5151;
    uint8_t m[6] = {0x02, 0x57, 0, 0, 0, 0x57};
    memcpy(WNODE.mac, m, 6);
    gm_hw_t hw = { &WNODE, hw_transmit, hw_local_ms, hw_rng, hw_emit_w, NULL, NULL, NULL };
    gm_watch_init(&WATCH, keys_W(), &hw);
    gm_watch_set_time(&WATCH, UNIX_BASE + T);
    W_ON = true;
    for (int i = 0; i < NN && link_to_all; i++) LINK[MAXN][i] = LINK[i][MAXN] = true;
}

/* ---- sim driver ----------------------------------------------------------- */
static void sim_reset(void)
{
    memset(N, 0, sizeof N);
    memset(LINK, 0, sizeof LINK);
    NN = 0; NAIR = 0; NEV = 0; T = 0; W_ON = false;
    g_factory_mac_on_air = false;
}

static simnode_t *add_node(const gm_node_keys_t *k, uint64_t boot_at, uint64_t seed)
{
    simnode_t *s = &N[NN];
    s->idx = NN++;
    s->boot_at = boot_at;
    s->rng = seed;
    s->alive = true;
    /* Boot under a factory-style (globally administered) MAC, like a real board before it rotates,
     * so any pre-rotation transmit is caught by hw_transmit's factory-MAC check. */
    uint8_t m[6] = {0x3c, 0x0f, 0x02, 0xe3, 0xbb, (uint8_t)k->name};
    memcpy(s->mac, m, 6);
    gm_hw_t hw = { s, hw_transmit, hw_local_ms, hw_rng, hw_emit, hw_set_mac, NULL, NULL };
    T = boot_at;
    gm_node_init(&s->node, k, &hw, NULL, 0);
    return s;
}

static void link_(int a, int b) { LINK[a][b] = LINK[b][a] = true; }

static void run(uint64_t ms)
{
    for (uint64_t t = 0; t < ms; t++) {
        T++;
        if (W_ON) gm_watch_poll(&WATCH);
        int i = 0;
        while (i < NAIR) {
            if (AIR[i].at > T) { i++; continue; }
            air_t a = AIR[i];
            AIR[i] = AIR[--NAIR];
            for (int j = 0; j < NN; j++)
                if (j != a.from && N[j].alive && LINK[a.from][j])
                    gm_node_rx(&N[j].node, a.frame, a.mac, (int8_t)(-45 - (int)(xs(&wt_rng) % 30)));
            if (W_ON && a.from != MAXN && LINK[a.from][MAXN]) gm_watch_rx(&WATCH, a.frame, a.mac, -50, NULL);
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
    run(1000);

    gm_node_send(&a->node, 'B', "early", 5);         /* before sync: must queue */
    CHECK(count_ev('A', "\"ev\":\"queued\"") == 1, "send before sync is queued");
    run(500);
    CHECK(count_ev('*', "\"ev\":\"tx\"") == 0 && a->node.st.tx_frames == 0, "nothing transmitted before sync");

    gm_node_debug_set_time(&a->node, UNIX_BASE + T);
    gm_node_debug_set_time(&b->node, UNIX_BASE + T + 40);   /* laptops never agree exactly */
    run(3000);
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
        run(10000);
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

    /* crypto benchmark command: runs and reports on a synced node with a peer (µs numbers are only
     * meaningful on hardware; the host's virtual clock doesn't tick inside the loop). */
    gm_node_bench(&a->node, 50);
    CHECK(count_ev('A', "\"ev\":\"bench\"") == 1, "bench ran and reported");
    CHECK(count_ev('A', "\"reason\":\"not_ready\"") == 0 && count_ev('A', "\"reason\":\"no_peer\"") == 0,
          "bench found the node ready with a peer");
}

static void test_line_with_watchtower(void)
{
    printf("Test 2: W -> A - B - C line, signed TIME beacons, A -> C through B\n");
    sim_reset();
    simnode_t *a = add_node(keys_A(), 0, 101);
    simnode_t *b = add_node(keys_B(), 300, 202);
    simnode_t *c = add_node(keys_C(), 600, 303);
    link_(0, 1); link_(1, 2);          /* A and C can't hear each other */
    run(1000);
    start_watchtower(false);
    LINK[MAXN][0] = LINK[0][MAXN] = true;   /* watchtower only reaches A: beacons must be relayed */
    run(45000);   /* with the workaround, sync spreads one hop per beacon (10 s) */
    CHECK(a->node.c.synced && b->node.c.synced && c->node.c.synced, "beacon reached every hop, all synced");
    CHECK(b->node.st.beacons_ok >= 2, "B verified signed beacons");

    gm_node_send(&a->node, 'C', "meet at 9", 9);
    run(5000);
    CHECK(count_ev('C', "\"from\":\"A\",\"text\":\"meet at 9\"") == 1, "C got A's message (2 hops)");
    CHECK(count_ev('A', "\"ev\":\"delivered\",\"to\":\"C\"") == 1, "A got C's ACK back through B");
    CHECK(count_ev('B', "\"ev\":\"rx\"") == 0, "B relayed but could not read it");

    int before = count_ev('C', "\"ev\":\"rx\"");
    for (int i = 0; i < 10; i++) { gm_node_send(&c->node, 'A', "pong", 4); gm_node_send(&a->node, 'C', "ping", 4); run(12000); }
    CHECK(count_ev('C', "\"ev\":\"rx\"") - before == 10 && count_ev('A', "text\":\"pong") == 10,
          "10 round trips over 2 minutes of epoch changes");
    CHECK(count_ev('*', "\"ev\":\"failed\"") == 0, "no failed sends");
    CHECK(count_ev('*', "no_beacon") == 0, "no missing-beacon alerts");
}

/* Regression for the Nov 18 first-sync race (hardware-smoke-2026-11-18.md §3.1): when a node takes
 * its first beacon, its clock syncs immediately but the radio MAC used to switch only on the next
 * ~100 ms tick, so a frame relayed in that window went out under the board's factory MAC. Here W
 * reaches only A, so sync spreads hop by hop (A, then B, then C), and cross traffic runs the whole
 * time, maximising the chance a node relays something right after syncing. No node may ever
 * transmit under its factory MAC. */
static void test_first_sync_no_factory_mac(void)
{
    printf("Test 2b: first-sync MAC race - no factory MAC ever reaches the air\n");
    sim_reset();
    simnode_t *a = add_node(keys_A(), 0, 4001);
    simnode_t *b = add_node(keys_B(), 250, 4002);
    simnode_t *c = add_node(keys_C(), 500, 4003);
    link_(0, 1); link_(1, 2);
    run(1000);
    start_watchtower(false);
    LINK[MAXN][0] = LINK[0][MAXN] = true;    /* W -> A only: B and C sync from relayed beacons */

    /* keep DATA moving while sync spreads, so a node may need to relay just after it syncs */
    for (int i = 0; i < 12; i++) {
        gm_node_send(&a->node, 'C', "x", 1);
        gm_node_send(&c->node, 'A', "y", 1);
        run(5000);
    }
    CHECK(a->node.c.synced && b->node.c.synced && c->node.c.synced, "all three nodes synced");
    CHECK(count_ev('*', "\"ev\":\"synced\"") == 3, "each node emitted synced exactly once");
    CHECK(count_ev('*', "\"ev\":\"epoch\"") > 0, "MAC/pseudonym rotated (boot MAC was replaced)");
    CHECK(!g_factory_mac_on_air, "no node ever transmitted under its factory MAC");
}

static void test_watchtower_log_and_block(void)
{
    printf("Test 4: W hears A, B, C: tags real nodes, BLOCK C survives an epoch change, unblock\n");
    sim_reset();
    simnode_t *a = add_node(keys_A(), 0, 7);
    simnode_t *b = add_node(keys_B(), 100, 8);
    simnode_t *c = add_node(keys_C(), 200, 9);
    link_(0, 1); link_(1, 2); link_(0, 2);
    run(500);
    start_watchtower(true);
    run(25000);
    CHECK(a->node.c.synced && b->node.c.synced && c->node.c.synced, "all synced from W");
    CHECK(count_ev('W', "\"node\":\"A\",\"id_ok\":true") > 0 && count_ev('W', "\"node\":\"C\",\"id_ok\":true") > 0,
          "W tags log lines with the real node + matching MAC");
    CHECK(count_ev('W', "\"node\":\"?\"") == 0, "no unknown transmitters");
    CHECK(count_ev('W', "\"type\":\"KEYS\"") > 0 && count_ev('W', "\"link_ok\":true") > 0, "W logs KEYS frames, link_ok");
    CHECK(count_ev('W', "\"raw\":\"") > 0 && count_ev('W', "\"flags\":") > 0, "log lines carry raw + flags");

    gm_watch_block(&WATCH, 'C', NULL, NULL, "flood", gm_watch_now(&WATCH) + 150000);
    run(3000);
    CHECK(count_ev('A', "\"ev\":\"block\"") == 1 && count_ev('B', "\"ev\":\"block\"") == 1, "A and B applied the signed BLOCK");
    uint64_t next_minute = 60000 - (gm_watch_now(&WATCH) % 60000) + 2000;
    run(next_minute);                                   /* cross an epoch: C has a new pseudonym + MAC */
    CHECK(count_ev('W', "\"blocks_reissued\":1") >= 1, "W re-issued the block for the new epoch");
    gm_node_send(&c->node, 'A', "let me in", 9);
    run(10000);
    CHECK(count_ev('A', "text\":\"let me in") == 0, "blocked C can't reach A after rotation");
    CHECK(a->node.st.log_counts[RT_LOG_BLOCKED] > 0, "A counted blocked frames");

    gm_watch_unblock(&WATCH, 'C', NULL, NULL);
    run(3000);
    CHECK(count_ev('A', "\"ev\":\"unblock\"") == 1, "A applied the unblock");
    gm_node_send(&c->node, 'A', "sorry", 5);
    run(10000);
    CHECK(count_ev('A', "text\":\"sorry") == 1, "C reaches A again after unblock");
}

static void test_outsider(void)
{
    printf("Test 3: frame with a wrong network key is dropped\n");
    sim_reset();
    simnode_t *a = add_node(keys_A(), 0, 5);
    run(10);
    gm_node_debug_set_time(&a->node, UNIX_BASE);
    run(200);
    uint8_t junk[240];
    memset(junk, 0x41, sizeof junk);
    junk[0] = RT_FRAME_DATA;
    uint8_t mac[6] = {0x02, 0xBA, 0xD0, 0, 0, 1};
    gm_node_rx(&a->node, junk, mac, -50);
    CHECK(a->node.st.log_counts[RT_LOG_BAD_LINK_TAG] == 1, "bad_link_tag counted");
}

static void test_block_two_hops_after_beacon(void)
{
    printf("Test 5: W - A - B line, BLOCK requested right after a TIME beacon still reaches B (Jose, HIGH)\n");
    int ok = 0, tries = 0;
    for (int round = 0; round < 6; round++) {
        sim_reset();
        simnode_t *a = add_node(keys_A(), 0, 40 + (uint64_t)round);
        simnode_t *b = add_node(keys_B(), 100, 80 + (uint64_t)round);
        add_node(keys_C(), 200, 120 + (uint64_t)round);
        link_(0, 1); link_(1, 2);
        run(300);
        start_watchtower(false);
        LINK[MAXN][0] = LINK[0][MAXN] = true;          /* W reaches only A; B is 2 hops away */
        run(35000);
        if (!b->node.c.synced) continue;
        /* wait for the next beacon, then ask for a BLOCK 200 ms later */
        uint32_t beacons = WATCH.beacons_sent;
        while (WATCH.beacons_sent == beacons) run(10);
        run(200);
        int before = count_ev('B', "\"ev\":\"block\"");
        gm_watch_block(&WATCH, 'C', NULL, NULL, "flood", gm_watch_now(&WATCH) + 120000);
        run(8000);
        tries++;
        ok += count_ev('B', "\"ev\":\"block\"") > before;
        (void)a;
    }
    printf("  B applied the BLOCK in %d/%d rounds\n", ok, tries);
    CHECK(tries == 6 && ok == tries, "BLOCK always reaches the 2-hop node");
    CHECK(count_ev('W', "block_queued") >= 1 && count_ev('W', "block_sent") >= 1, "W queued, then sent after the CTRL gap");
}

int main(int argc, char **argv)
{
    PRINT = argc > 1 && !strcmp(argv[1], "-v");
    test_two_boards_debug_clock();
    test_line_with_watchtower();
    test_first_sync_no_factory_mac();
    test_outsider();
    test_watchtower_log_and_block();
    test_block_two_hops_after_beacon();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
