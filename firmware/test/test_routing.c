/*
 * test_routing.c - host tests for routing.c (v1 managed flooding).
 *
 *   gcc -std=c11 -Wall -Wextra -I firmware/src/routing firmware/src/routing/routing.c \
 *       firmware/test/test_routing.c -o /tmp/test_routing && /tmp/test_routing
 *
 *   /tmp/test_routing       every check, PASS/FAIL by name
 *   /tmp/test_routing -v    plus a timestamped trace of what every node did
 *
 * A tiny fake network: nodes, radio links, a millisecond clock and a timer
 * queue. Crypto is a stand-in (no real security), just enough to exercise the
 * routing decisions: the inner header is packed in clear inside `ciphertext`
 * and "decrypts" only for its recipient.
 */
#include "routing.h"

#include <stdio.h>
#include <string.h>

/* ---- Fake world ---------------------------------------------------------- */

#define MAX_NODES  6
#define MAX_TIMERS 256

typedef struct {
    uint32_t   id;
    rt_node_t  node;
    uint8_t    mac[6];
    bool       synced;
    int        delivered;
    int        sent, acked, failed;            // notify() counts
    int        tx;                             // transmissions
    int        keys_seen;
    int        log[64];
} tnode_t;

typedef struct { bool used; int node; uint32_t token; uint32_t due; } ttimer_t;

static tnode_t  nodes[MAX_NODES];
static int      n_nodes;
static bool     link_up[MAX_NODES][MAX_NODES];
static ttimer_t timers[MAX_TIMERS];
static uint32_t clock_ms;
static uint32_t rng = 12345;
static uint16_t epoch_now = 100;
static uint8_t  blocked_mac[6];
static bool     block_on;
static bool   (*drop_fn)(int from, int to, const rt_frame_t *f);

static int idx_of(void *ctx) { return (int)((tnode_t *)ctx - nodes); }

/* ---- Trace output (-v) ------------------------------------------------- */

#define T0 1000000u                                     // clock value when each test's world starts
static bool verbose;

static const char *EV[] = {
    [RT_LOG_BAD_LINK_TAG] = "BAD_LINK_TAG",     [RT_LOG_BAD_EPOCH] = "BAD_EPOCH",
    [RT_LOG_BAD_TYPE] = "BAD_TYPE",             [RT_LOG_BLOCKED] = "BLOCKED",
    [RT_LOG_RATE_LIMITED] = "RATE_LIMITED",     [RT_LOG_DUPLICATE] = "DUPLICATE",
    [RT_LOG_DUP_COUNTED] = "DUP_COUNTED",       [RT_LOG_RELAY_CANCELLED] = "RELAY_CANCELLED",
    [RT_LOG_TTL_EXPIRED] = "TTL_EXPIRED",       [RT_LOG_CTRL_UNVERIFIED] = "CTRL_UNVERIFIED",
    [RT_LOG_REPLAY_STALE] = "REPLAY_STALE",     [RT_LOG_NOT_SYNCED] = "NOT_SYNCED",
    [RT_LOG_RELAY_SCHEDULED] = "RELAY_SCHEDULED", [RT_LOG_TX] = "TX",
    [RT_LOG_DELIVERED] = "DELIVERED",           [RT_LOG_REACK] = "REACK",
    [RT_LOG_ACK_MATCHED] = "ACK_MATCHED",       [RT_LOG_ACK_UNMATCHED] = "ACK_UNMATCHED",
    [RT_LOG_HELLO] = "HELLO",                   [RT_LOG_TOO_LONG] = "TOO_LONG",
    [RT_LOG_ENCRYPT_FAILED] = "ENCRYPT_FAILED", [RT_LOG_SEND_FAILED] = "SEND_FAILED",
};

static char letter(int i) { return (char)('A' + i); }

// "      t=+   12 ms  B  " prefix for one trace line
static void trace_prefix(int i) { printf("      t=+%6u ms  %c  ", (unsigned)(clock_ms - T0), letter(i)); }

/* ---- Fake crypto: keyed checksum for link_tag, clear packing for "encryption" ---- */

static void fake_tag(const rt_frame_t *f, uint8_t out[8])
{
    const uint8_t *b = (const uint8_t *)f;
    uint64_t h = 1469598103934665603ull ^ 0x4E45544B4559ull;    // "NETKEY"
    for (int i = 0; i < 240; i++) {
        if (i >= 22 && i < 30) continue;                         // skip the tag itself
        h = (h ^ b[i]) * 1099511628211ull;
    }
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(h >> (8 * i));
}

static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static uint32_t get32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

static void pack(const rt_inner_t *in, uint8_t ct[170])
{
    memset(ct, 0, 170);
    put32(ct, in->sender_id); put32(ct + 4, in->recipient_id);
    put32(ct + 8, in->timestamp); put32(ct + 12, in->seq);
    ct[16] = in->type; ct[17] = in->len;
    memcpy(ct + 18, in->body, in->len);
}

/* ---- Platform callbacks ---------------------------------------------------- */

static uint32_t cb_random(void *ctx) { (void)ctx; rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; }
static uint32_t cb_now(void *ctx)    { (void)ctx; return clock_ms; }
static bool     cb_synced(void *ctx) { return ((tnode_t *)ctx)->synced; }

static void cb_transmit(void *ctx, const rt_frame_t *f)
{
    int from = idx_of(ctx);
    nodes[from].tx++;
    rt_frame_t copy = *f;                                        // the radio delivers a copy
    for (int to = 0; to < n_nodes; to++) {
        if (!link_up[from][to]) continue;
        if (drop_fn && drop_fn(from, to, &copy)) continue;
        rt_on_receive(&nodes[to].node, &copy, nodes[from].mac, -60);
    }
}

static void cb_timer_start(void *ctx, uint32_t token, uint32_t delay)
{
    int n = idx_of(ctx), free_i = -1;
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (timers[i].used && timers[i].node == n && timers[i].token == token) { timers[i].due = clock_ms + delay; return; }
        if (!timers[i].used && free_i < 0) free_i = i;
    }
    timers[free_i] = (ttimer_t){ true, n, token, clock_ms + delay };
}

static void cb_timer_cancel(void *ctx, uint32_t token)
{
    int n = idx_of(ctx);
    for (int i = 0; i < MAX_TIMERS; i++)
        if (timers[i].used && timers[i].node == n && timers[i].token == token) timers[i].used = false;
}

static bool cb_link_ok(void *ctx, const rt_frame_t *f) { (void)ctx; uint8_t t[8]; fake_tag(f, t); return memcmp(t, f->link_tag, 8) == 0; }
static void cb_link_tag(void *ctx, const rt_frame_t *f, uint8_t out[8]) { (void)ctx; fake_tag(f, out); }

static bool cb_encrypt(void *ctx, const rt_inner_t *in, rt_frame_t *f) { (void)ctx; pack(in, f->ciphertext); return true; }

static bool cb_decrypt(void *ctx, const rt_frame_t *f, rt_inner_t *out)
{
    const uint8_t *ct = f->ciphertext;
    if (get32(ct + 4) != ((tnode_t *)ctx)->id) return false;    // not for us
    memset(out, 0, sizeof *out);
    out->sender_id = get32(ct); out->recipient_id = get32(ct + 4);
    out->timestamp = get32(ct + 8); out->seq = get32(ct + 12);
    out->type = ct[16]; out->len = ct[17];
    memcpy(out->body, ct + 18, out->len);
    return true;
}

static bool cb_blocked(void *ctx, const rt_frame_t *f, const uint8_t mac[6]) { (void)ctx; (void)f; return block_on && memcmp(mac, blocked_mac, 6) == 0; }
static void cb_keys(void *ctx, const rt_frame_t *f) { (void)f; ((tnode_t *)ctx)->keys_seen++; }
// 0x01 = "signature ok". like gm_node, a verified TIME beacon (subtype RT_CTRL_TIME = 1) syncs the node
static bool cb_ctrl(void *ctx, const rt_frame_t *f)
{
    if (f->ciphertext[0] != 0x01) return false;
    ((tnode_t *)ctx)->synced = true;
    return true;
}

static void cb_pseudo(void *ctx, uint8_t out[4]) { out[0] = 0xA0; out[1] = (uint8_t)((tnode_t *)ctx)->id; out[2] = (uint8_t)epoch_now; out[3] = 0; }
static uint16_t cb_epoch(void *ctx) { (void)ctx; return epoch_now; }

static void cb_deliver(void *ctx, const rt_inner_t *m)
{
    ((tnode_t *)ctx)->delivered++;
    if (verbose) { trace_prefix(idx_of(ctx)); printf("-> laptop: \"%.*s\" from %c\n", m->len, (const char *)m->body, letter((int)m->sender_id - 1)); }
}
static void cb_notify(void *ctx, uint32_t h, rt_status_t s)
{
    (void)h; tnode_t *t = ctx;
    if (s == RT_STATUS_SENT) t->sent++; else if (s == RT_STATUS_DELIVERED) t->acked++; else t->failed++;
    if (verbose) {
        trace_prefix(idx_of(ctx));
        printf("-> laptop: %s\n", s == RT_STATUS_SENT ? "sent (single check)" : s == RT_STATUS_DELIVERED ? "delivered (double check)" : "FAILED");
    }
}
static void cb_log(void *ctx, rt_log_t ev, const rt_frame_t *f)
{
    ((tnode_t *)ctx)->log[ev]++;
    if (!verbose) return;
    trace_prefix(idx_of(ctx));
    printf("%-16s", EV[ev] ? EV[ev] : "?");
    if (f) printf("  msg %02x%02x%02x%02x  ttl %u  hop %u", f->msg_id[0], f->msg_id[1], f->msg_id[2], f->msg_id[7], f->ttl, f->hop_count);
    printf("\n");
}

static const rt_platform_t P = {
    cb_transmit, cb_now, cb_random, cb_synced,
    cb_timer_start, cb_timer_cancel,
    cb_link_ok, cb_link_tag, cb_encrypt, cb_decrypt,
    cb_blocked, cb_keys, cb_ctrl,
    cb_pseudo, cb_epoch,
    cb_deliver, cb_notify, cb_log,
};

/* ---- World setup + clock ------------------------------------------------- */

static void world(int count, rt_config_t *override)
{
    memset(nodes, 0, sizeof nodes);
    memset(link_up, 0, sizeof link_up);
    memset(timers, 0, sizeof timers);
    clock_ms = 1000000; epoch_now = 100; block_on = false; drop_fn = NULL; rng = 12345;
    n_nodes = count;
    for (int i = 0; i < count; i++) {
        tnode_t *t = &nodes[i];
        t->id = (uint32_t)(i + 1);
        t->synced = true;
        t->mac[0] = 0x02; t->mac[5] = (uint8_t)(i + 1);
        rt_config_t cfg;
        if (override) { cfg = *override; cfg.node_id = t->id; } else rt_default_config(&cfg, t->id);
        rt_init(&t->node, &cfg, &P, t);
    }
}

static void connect(int a, int b) { link_up[a][b] = link_up[b][a] = true; }

// runs every timer due up to clock_ms + ms, in time order
static void run(uint32_t ms)
{
    uint32_t end = clock_ms + ms;
    for (;;) {
        int best = -1;
        for (int i = 0; i < MAX_TIMERS; i++)
            if (timers[i].used && (int32_t)(timers[i].due - end) <= 0 &&
                (best < 0 || (int32_t)(timers[i].due - timers[best].due) < 0)) best = i;
        if (best < 0) break;
        ttimer_t t = timers[best];
        timers[best].used = false;
        if ((int32_t)(t.due - clock_ms) > 0) clock_ms = t.due;
        rt_on_timer(&nodes[t.node].node, t.token);
    }
    clock_ms = end;
}

// a hand-built frame from node `from_i`, for injecting straight into one node
static rt_frame_t make_frame(int from_i, uint8_t ver_type, uint8_t id_seed, uint8_t ttl, uint16_t epoch)
{
    rt_frame_t f;
    memset(&f, 0, sizeof f);
    f.ver_type = ver_type;
    f.msg_id[0] = 0x77; f.msg_id[7] = id_seed;
    f.ttl = ttl;
    f.src_pseudo[0] = 0xA0; f.src_pseudo[1] = (uint8_t)nodes[from_i].id;
    f.epoch[0] = (uint8_t)(epoch >> 8); f.epoch[1] = (uint8_t)epoch;
    fake_tag(&f, f.link_tag);
    return f;
}

// a DATA frame from `from_i` to `to_i` with a chosen timestamp
static rt_frame_t make_data(int from_i, int to_i, uint8_t id_seed, uint32_t ts)
{
    rt_frame_t f = make_frame(from_i, RT_FRAME_DATA, id_seed, 3, epoch_now);
    rt_inner_t in;
    memset(&in, 0, sizeof in);
    in.sender_id = nodes[from_i].id; in.recipient_id = nodes[to_i].id;
    in.timestamp = ts; in.seq = 42; in.type = RT_TYPE_DATA; in.len = 2;
    in.body[0] = 'h'; in.body[1] = 'i';
    pack(&in, f.ciphertext);
    fake_tag(&f, f.link_tag);
    return f;
}

static void inject(int to_i, const rt_frame_t *f, int from_i)
{
    rt_on_receive(&nodes[to_i].node, f, nodes[from_i].mac, -60);
}

/* ---- Tiny test framework ------------------------------------------------- */

static int pass, fail;
#define CHECK(cond, name) do {                                                   \
        if (cond) { pass++; printf("    PASS  %s\n", name); }                    \
        else      { fail++; printf("    FAIL  %s  (line %d)\n", name, __LINE__); } \
    } while (0)

// runs one test with a header saying what it checks, then its own pass/fail count
#define RUN(fn, what) do {                                                       \
        int p0 = pass, f0 = fail;                                                \
        printf("\n== %s\n   %s\n", #fn, what);                                   \
        fn();                                                                    \
        printf("   -> %d passed, %d failed\n", pass - p0, fail - f0);           \
    } while (0)

static const uint8_t HI[] = "meet at 9";

/* ---- Tests ---------------------------------------------------------------- */

static void test_line_delivery(void)
{
    world(3, NULL); connect(0, 1); connect(1, 2);               // A - B - C
    uint32_t h = rt_send(&nodes[0].node, 3, HI, 9);
    run(10000);
    CHECK(h != 0,                       "line: send accepted");
    CHECK(nodes[0].sent == 1,           "line: laptop told 'sent' once");
    CHECK(nodes[2].delivered == 1,      "line: C delivers exactly once");
    CHECK(nodes[0].acked == 1,          "line: A gets the ACK (✓✓)");
    CHECK(nodes[0].failed == 0,         "line: no failure reported");
    CHECK(nodes[0].log[RT_LOG_DUPLICATE] >= 1, "line: A drops the echo of its own DATA");
    for (int i = 0; i < 3; i++)
        CHECK(nodes[i].tx <= 2,         "line: each node sends at most DATA-or-relay + ACK-or-relay");
    CHECK(nodes[0].tx + nodes[1].tx + nodes[2].tx == 6, "line: 6 transmissions total (3 per direction)");
}

static void test_diamond(void)
{
    world(4, NULL); connect(0, 1); connect(0, 3); connect(1, 2); connect(3, 2);  // A-B-C and A-D-C
    rt_send(&nodes[0].node, 3, HI, 9);
    run(10000);
    CHECK(nodes[2].delivered == 1,      "diamond: C delivers once even with two copies");
    CHECK(nodes[0].acked == 1,          "diamond: A gets the ACK");
    for (int i = 0; i < 4; i++) CHECK(nodes[i].tx <= 2, "diamond: nobody relays the same frame twice");
}

static void test_duplicate_and_k(void)
{
    world(2, NULL);                                             // k = 2
    rt_frame_t f = make_frame(0, RT_FRAME_DATA, 1, 3, epoch_now);
    inject(1, &f, 0);
    CHECK(nodes[1].log[RT_LOG_RELAY_SCHEDULED] == 1, "k: first copy schedules a relay");
    inject(1, &f, 0);
    CHECK(nodes[1].log[RT_LOG_DUP_COUNTED] == 1,     "k: second copy only counts (1 < k)");
    inject(1, &f, 0);
    CHECK(nodes[1].log[RT_LOG_RELAY_CANCELLED] == 1, "k: third copy reaches k and cancels");
    run(1000);
    CHECK(nodes[1].tx == 0,                          "k: cancelled relay is never sent");
    inject(1, &f, 0);
    CHECK(nodes[1].log[RT_LOG_DUPLICATE] == 1,       "k: later copies are plain duplicates");
}

static void test_relay_fires(void)
{
    world(2, NULL);
    rt_frame_t f = make_frame(0, RT_FRAME_DATA, 2, 3, epoch_now);
    inject(1, &f, 0);
    run(9);
    CHECK(nodes[1].tx == 0,  "relay: nothing before jitter_min (10 ms)");
    run(50);
    CHECK(nodes[1].tx == 1,  "relay: sent once within the jitter window");
}

static void test_ttl_zero(void)
{
    world(2, NULL);
    rt_frame_t f = make_frame(0, RT_FRAME_DATA, 3, 0, epoch_now);
    inject(1, &f, 0);
    run(1000);
    CHECK(nodes[1].log[RT_LOG_TTL_EXPIRED] == 1, "ttl: ttl 0 is logged");
    CHECK(nodes[1].tx == 0,                      "ttl: ttl 0 is not relayed");
}

static void test_bad_link_tag(void)
{
    world(2, NULL);
    rt_frame_t f = make_frame(0, RT_FRAME_DATA, 4, 3, epoch_now);
    f.ttl = 9;                                                  // tampered after the tag was set
    inject(1, &f, 0);
    CHECK(nodes[1].log[RT_LOG_BAD_LINK_TAG] == 1,    "link_tag: tampered frame dropped");
    CHECK(nodes[1].log[RT_LOG_RELAY_SCHEDULED] == 0, "link_tag: tampered frame not relayed");
}

static void test_epoch_window(void)
{
    world(2, NULL);
    rt_frame_t prev = make_frame(0, RT_FRAME_DATA, 5, 3, (uint16_t)(epoch_now - 1));
    rt_frame_t next = make_frame(0, RT_FRAME_DATA, 6, 3, (uint16_t)(epoch_now + 1));
    rt_frame_t far  = make_frame(0, RT_FRAME_DATA, 7, 3, (uint16_t)(epoch_now + 2));
    inject(1, &prev, 0); inject(1, &next, 0); inject(1, &far, 0);
    CHECK(nodes[1].log[RT_LOG_RELAY_SCHEDULED] == 2, "epoch: previous and next accepted");
    CHECK(nodes[1].log[RT_LOG_BAD_EPOCH] == 1,       "epoch: +2 dropped");

    epoch_now = 0;                                              // wrap: 0xFFFF is the previous epoch
    rt_frame_t wrap = make_frame(0, RT_FRAME_DATA, 8, 3, 0xFFFF);
    inject(1, &wrap, 0);
    CHECK(nodes[1].log[RT_LOG_RELAY_SCHEDULED] == 3, "epoch: wrap-around handled");
}

static int acks_dropped;
static bool drop_first_ack(int from, int to, const rt_frame_t *f)
{
    (void)to;
    if (from == 2 && f->ciphertext[16] == RT_TYPE_ACK && acks_dropped == 0) { acks_dropped++; return true; }
    return false;
}

static void test_lost_ack_retry(void)
{
    world(3, NULL); connect(0, 1); connect(1, 2);
    acks_dropped = 0; drop_fn = drop_first_ack;                 // C's first ACK never leaves C
    rt_send(&nodes[0].node, 3, HI, 9);
    run(15000);
    CHECK(acks_dropped == 1,                     "lost ACK: first ACK was dropped");
    CHECK(nodes[2].delivered == 1,               "lost ACK: C still delivers only once");
    CHECK(nodes[2].log[RT_LOG_REACK] == 1,       "lost ACK: C re-ACKs the retry");
    CHECK(nodes[0].acked == 1 && nodes[0].failed == 0, "lost ACK: A ends up delivered");
    CHECK(nodes[0].sent == 1,                    "lost ACK: retry doesn't re-notify 'sent'");
}

static void test_all_retries_fail(void)
{
    world(1, NULL);                                             // A alone, nobody to hear it
    rt_send(&nodes[0].node, 3, HI, 9);
    run(10900);
    CHECK(nodes[0].failed == 0,  "fail: not failed before the last wait ends");
    run(200);
    CHECK(nodes[0].tx == 4,      "fail: 1 send + 3 retries");
    CHECK(nodes[0].failed == 1,  "fail: laptop told 'failed' after 1+2+4+4 s");
}

static void test_stale_and_fresh(void)
{
    world(2, NULL);
    rt_frame_t stale = make_data(0, 1, 9, clock_ms - 10000);
    inject(1, &stale, 0);
    run(1000);
    CHECK(nodes[1].log[RT_LOG_REPLAY_STALE] == 1, "stale: 10 s old DATA logged");
    CHECK(nodes[1].delivered == 0,                "stale: not delivered");
    CHECK(nodes[1].log[RT_LOG_TX] == 1,           "stale: no ACK sent (only the relay)");

    rt_frame_t fresh = make_data(0, 1, 10, clock_ms - 2000);
    inject(1, &fresh, 0);
    run(1000);
    CHECK(nodes[1].delivered == 1,                "fresh: 2 s old DATA delivered");
}

static void test_send_limits(void)
{
    world(2, NULL);
    uint8_t big[RT_BODY_MAX + 1];
    memset(big, 'x', sizeof big);
    CHECK(rt_send(&nodes[0].node, 2, big, RT_BODY_MAX + 1) == 0, "send: 153 bytes rejected");
    CHECK(nodes[0].log[RT_LOG_TOO_LONG] == 1,                    "send: TOO_LONG logged");
    CHECK(rt_send(&nodes[0].node, 2, big, RT_BODY_MAX) != 0,     "send: 152 bytes accepted");
}

static void test_presync(void)
{
    world(2, NULL);
    nodes[1].synced = false;
    rt_frame_t f = make_frame(0, RT_FRAME_DATA, 11, 3, epoch_now);
    inject(1, &f, 0);
    run(1000);
    CHECK(nodes[1].tx == 0,                              "presync: no relay before sync");
    CHECK(nodes[1].log[RT_LOG_NOT_SYNCED] == 1,          "presync: NOT_SYNCED logged");
    CHECK(rt_send(&nodes[1].node, 1, HI, 9) == 0,        "presync: laptop send rejected");
}

static void test_rate_limit(void)
{
    rt_config_t cfg;
    rt_default_config(&cfg, 0);
    cfg.insert_limit_per_s = 3;
    world(2, &cfg);
    for (uint8_t i = 0; i < 5; i++) { rt_frame_t f = make_frame(0, RT_FRAME_DATA, (uint8_t)(20 + i), 3, epoch_now); inject(1, &f, 0); }
    CHECK(nodes[1].log[RT_LOG_RELAY_SCHEDULED] == 3, "rate: first 3 new msg_ids accepted");
    CHECK(nodes[1].log[RT_LOG_RATE_LIMITED] == 2,    "rate: next 2 limited");
    run(1000);
    rt_frame_t later = make_frame(0, RT_FRAME_DATA, 30, 3, epoch_now);
    inject(1, &later, 0);
    CHECK(nodes[1].log[RT_LOG_RELAY_SCHEDULED] == 4, "rate: allowed again in the next second");
}

static void test_blocked(void)
{
    world(2, NULL);
    memcpy(blocked_mac, nodes[0].mac, 6); block_on = true;
    rt_frame_t f = make_frame(0, RT_FRAME_DATA, 12, 3, epoch_now);
    inject(1, &f, 0);
    CHECK(nodes[1].log[RT_LOG_BLOCKED] == 1,         "block: blocked transmitter dropped");
    CHECK(nodes[1].log[RT_LOG_RELAY_SCHEDULED] == 0, "block: never relayed");
}

static void test_ctrl_keys_hello(void)
{
    world(2, NULL);
    rt_frame_t bad = make_frame(0, RT_FRAME_CTRL, 13, 3, epoch_now);
    inject(1, &bad, 0);
    CHECK(nodes[1].log[RT_LOG_CTRL_UNVERIFIED] == 1, "ctrl: unverified CTRL not relayed");

    rt_frame_t good = make_frame(0, RT_FRAME_CTRL, 14, 3, epoch_now);
    good.ciphertext[0] = 0x01; cb_link_tag(NULL, &good, good.link_tag);
    inject(1, &good, 0);
    CHECK(nodes[1].log[RT_LOG_RELAY_SCHEDULED] == 1, "ctrl: verified CTRL relayed");

    rt_frame_t keys = make_frame(0, RT_FRAME_KEYS, 15, 3, epoch_now);
    inject(1, &keys, 0);
    CHECK(nodes[1].keys_seen == 1,                   "keys: handed to the key layer");
    CHECK(nodes[1].log[RT_LOG_RELAY_SCHEDULED] == 2, "keys: flooded like DATA");

    rt_frame_t hello = make_frame(0, RT_FRAME_HELLO, 16, 1, epoch_now);
    inject(1, &hello, 0);
    CHECK(nodes[1].log[RT_LOG_HELLO] == 1,           "hello: ignored in v1");
    CHECK(nodes[1].log[RT_LOG_RELAY_SCHEDULED] == 2, "hello: not relayed");
}

static void test_unsynced_time_beacon(void)
{
    // the Nov 17 bug: an unsynced node's epoch is 0, so its first TIME beacon was dropped as bad_epoch
    world(2, NULL);
    nodes[1].synced = false;
    rt_frame_t beacon = make_frame(0, RT_FRAME_CTRL, 40, 3, (uint16_t)(epoch_now + 500));
    beacon.ciphertext[0] = RT_CTRL_TIME; cb_link_tag(NULL, &beacon, beacon.link_tag);
    inject(1, &beacon, 0);
    CHECK(nodes[1].log[RT_LOG_BAD_EPOCH] == 0,  "unsynced: TIME beacon not dropped as bad_epoch");
    CHECK(nodes[1].synced,                      "unsynced: beacon verified, node now synced");
    run(1000);
    CHECK(nodes[1].tx == 0,                     "unsynced: syncing beacon is not relayed (old identity)");
    CHECK(nodes[1].log[RT_LOG_NOT_SYNCED] == 1, "unsynced: NOT_SYNCED logged for that relay");

    // only TIME is exempt: a BLOCK (subtype 2) outside the window is still dropped while unsynced
    world(2, NULL);
    nodes[1].synced = false;
    rt_frame_t block = make_frame(0, RT_FRAME_CTRL, 41, 3, (uint16_t)(epoch_now + 500));
    block.ciphertext[0] = 2; cb_link_tag(NULL, &block, block.link_tag);
    inject(1, &block, 0);
    CHECK(nodes[1].log[RT_LOG_BAD_EPOCH] == 1,  "unsynced: non-TIME CTRL still epoch-checked");

    // and only while unsynced: a synced node drops a TIME beacon outside the window
    nodes[1].synced = true;
    rt_frame_t late = make_frame(0, RT_FRAME_CTRL, 42, 3, (uint16_t)(epoch_now + 500));
    late.ciphertext[0] = RT_CTRL_TIME; cb_link_tag(NULL, &late, late.link_tag);
    inject(1, &late, 0);
    CHECK(nodes[1].log[RT_LOG_BAD_EPOCH] == 2,  "synced: TIME beacon outside the window dropped");

    // the next beacon, arriving after sync and inside the window, is relayed normally
    rt_frame_t next = make_frame(0, RT_FRAME_CTRL, 43, 3, epoch_now);
    next.ciphertext[0] = RT_CTRL_TIME; cb_link_tag(NULL, &next, next.link_tag);
    inject(1, &next, 0);
    run(1000);
    CHECK(nodes[1].tx == 1,                     "synced: next beacon relayed");
}

static void test_long_cache(void)
{
    world(2, NULL);
    rt_frame_t f = make_frame(0, RT_FRAME_DATA, 17, 3, epoch_now);
    inject(1, &f, 0);
    run(90000);                                                 // past the 60 s seen-cache
    inject(1, &f, 0);
    CHECK(nodes[1].log[RT_LOG_DUPLICATE] == 1,       "long cache: 90 s replay still caught");
    CHECK(nodes[1].log[RT_LOG_RELAY_SCHEDULED] == 1, "long cache: replay not relayed");
}

static void test_hop_padding(void)
{
    world(2, NULL); connect(0, 1);
    int seen[3] = {0, 0, 0}, bad = 0;
    for (int i = 0; i < 30; i++) {                              // 30 sends in 45 s, inside the 60 s cache
        rt_send(&nodes[0].node, 2, HI, 9);
        run(1500);
    }
    // checked through the copies B relayed: hop_count + ttl must stay default_ttl
    for (int i = 0; i < RT_CACHE_SIZE; i++) {
        rt_cache_entry_t *e = &nodes[1].node.cache[i];
        if (!e->used || e->pending.ver_type == 0) continue;
        uint8_t hop0 = (uint8_t)(e->pending.hop_count - 1);    // undo B's relay step
        if (hop0 <= 2) seen[hop0]++;
        if (e->pending.hop_count + e->pending.ttl != nodes[0].node.cfg.default_ttl) bad++;
    }
    CHECK(bad == 0,                           "padding: hop_count + ttl == default_ttl");
    CHECK(seen[0] && seen[1] && seen[2],      "padding: pads of 0, 1 and 2 all occur");
}

int main(int argc, char **argv)
{
    verbose = argc > 1 && strcmp(argv[1], "-v") == 0;

    RUN(test_line_delivery,    "A - B - C in a line. A sends to C: delivered once, ACK back, echo ignored.");
    RUN(test_diamond,          "A-B-C and A-D-C. C hears two copies but delivers once.");
    RUN(test_duplicate_and_k,  "One frame injected 3x into a node: schedule, count, cancel at k = 2.");
    RUN(test_relay_fires,      "A scheduled relay goes out once, inside the 10-50 ms jitter window.");
    RUN(test_ttl_zero,         "A frame arriving with ttl 0 is logged and not relayed.");
    RUN(test_bad_link_tag,     "A frame edited after its link_tag was set is dropped.");
    RUN(test_epoch_window,     "Epochs -1/0/+1 accepted, +2 dropped, 65535 -> 0 wrap handled.");
    RUN(test_lost_ack_retry,   "C's first ACK is lost: A retries, C re-ACKs without delivering twice.");
    RUN(test_all_retries_fail, "Nobody can hear A: 1 send + 3 retries, then 'failed' after 1+2+4+4 s.");
    RUN(test_stale_and_fresh,  "DATA 10 s old is dropped with no ACK; 2 s old is delivered.");
    RUN(test_send_limits,      "Laptop messages: 153 bytes rejected, 152 accepted.");
    RUN(test_presync,          "Before the clock syncs: no relaying and no laptop sends.");
    RUN(test_rate_limit,       "One transmitter limited to 3 new msg_ids/s (lowered for the test).");
    RUN(test_blocked,          "Frames from a blocked MAC are dropped and never relayed.");
    RUN(test_ctrl_keys_hello,  "CTRL relayed only if verified; KEYS handed over and flooded; HELLO ignored.");
    RUN(test_unsynced_time_beacon, "Unsynced node takes its first TIME beacon (epoch 0 bug), doesn't relay it.");
    RUN(test_long_cache,       "A replay 90 s later (past the 60 s cache) is still caught.");
    RUN(test_hop_padding,      "Originators pad hop_count by 0-2 and keep hop_count + ttl constant.");

    printf("\n%d checks: %d passed, %d failed\n", pass + fail, pass, fail);
    if (!verbose) printf("(run with -v to see what every node did)\n");
    return fail ? 1 : 0;
}
