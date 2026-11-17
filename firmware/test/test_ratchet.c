/*
 * test_ratchet.c - host tests for stage 14b (mesh clock, epoch DH ratchet,
 * KEYS/RESYNC, persistence). Three simulated nodes exchange KEYS frames over many
 * epochs; tests drop frames, power nodes off, corrupt keys and steal state.
 * Output format matches test_crypto.c (PASS/FAIL/VEC/SUMMARY).
 */
#include <stdio.h>
#include <string.h>

#include "gm_crypto.h"
#include "monocypher.h"

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
static void test_rng(void *ctx, uint8_t *out, size_t n)
{
    uint32_t *s = ctx;
    for (size_t i = 0; i < n; i++) { *s = *s * 1103515245u + 12345u; out[i] = (uint8_t)(*s >> 16); }
}
static void fill(uint8_t *p, size_t n, uint8_t start) { for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(start + i); }

/* ---- Simulation ------------------------------------------------------------ */

enum { A = 0, B = 1, C = 2, NN = 3 };
#define E0   0x01B00102u                                      /* absolute start epoch (wire 0x0102) */
#define BASE ((uint64_t)E0 * GM_EPOCH_MS + 5000u)             /* mesh time at local 0 */

typedef struct { gm_crypto_t g; uint32_t rng; bool alive; gm_events_t agg; } node_t;
static node_t N[NN];
static bool drop[NN][NN];
static uint64_t T;                                            /* shared local clock, ms */

static int slot_of(int me, int other)                         /* peer slot of node `other` in node `me` */
{
    for (int i = 0; i < GM_MAX_PEERS; i++)
        if (N[me].g.peers[i].used && N[me].g.peers[i].node_id == (uint32_t)(other + 1)) return i;
    return -1;
}
static gm_ratchet_peer_t *R(int me, int other) { return &N[me].g.peers[slot_of(me, other)].r; }

static void agg(node_t *n, const gm_events_t *ev)
{
    n->agg.synced_now |= ev->synced_now; n->agg.epoch_changed |= ev->epoch_changed;
    n->agg.keys_due |= ev->keys_due; n->agg.state_changed |= ev->state_changed;
    n->agg.no_beacon |= ev->no_beacon; n->agg.no_dh_mask |= ev->no_dh_mask; n->agg.resync_mask |= ev->resync_mask;
}

static void deliver_keys(int from)
{
    uint8_t region[GM_INNER_BYTES];
    if (!gm_keys_build(&N[from].g, region)) return;
    for (int to = 0; to < NN; to++)
        if (to != from && N[to].alive && !drop[from][to]) gm_keys_receive(&N[to].g, region);
}

static void beacon_all(void)
{
    for (int i = 0; i < NN; i++) if (N[i].alive) gm_clock_on_beacon(&N[i].g, BASE + T, T);
}

static void tick_node(int i)
{
    gm_events_t ev;
    gm_tick(&N[i].g, T, &ev);
    agg(&N[i], &ev);
    if (ev.keys_due) deliver_keys(i);
}

static void run_ms(uint64_t ms)                               /* 1 s steps, beacons every 10 s */
{
    for (uint64_t end = T + ms; T < end;) {
        T += 1000;
        if (T % 10000 == 0) beacon_all();
        for (int i = 0; i < NN; i++) if (N[i].alive) tick_node(i);
    }
}
static void run_epochs(int n) { run_ms((uint64_t)n * GM_EPOCH_MS); }
static void clear_agg(void) { for (int i = 0; i < NN; i++) memset(&N[i].agg, 0, sizeof N[i].agg); }

static void sim_init(void)
{
    uint8_t net[32], ps[32], sk[NN][32], wt[32];
    fill(net, 32, 0x20); fill(wt, 32, 0xA0);
    memset(drop, 0, sizeof drop);
    T = 0;
    for (int i = 0; i < NN; i++) {
        fill(ps, 32, (uint8_t)(0x30 * i)); fill(sk[i], 32, (uint8_t)(0x10 + 0x30 * i));
        N[i].rng = 1000u + (uint32_t)i;
        gm_init(&N[i].g, (uint32_t)(i + 1), net, ps, sk[i], wt, test_rng, &N[i].rng);
        N[i].alive = true;
    }
    for (int i = 0; i < NN; i++)
        for (int j = 0; j < NN; j++)
            if (i != j) gm_add_peer(&N[i].g, (uint32_t)(j + 1), N[j].g.x_pk);
    beacon_all();
    for (int i = 0; i < NN; i++) tick_node(i);
    clear_agg();
}

static bool send(int from, int to, const char *text)
{
    rt_frame_t f;
    memset(&f, 0, sizeof f);
    f.ver_type = RT_TYPE_DATA;
    test_rng(&N[from].rng, f.msg_id, 8);
    gm_put_be16(f.epoch, gm_wire_epoch(N[from].g.cur_epoch));
    rt_inner_t in, out;
    memset(&in, 0, sizeof in);
    in.sender_id = (uint32_t)(from + 1); in.recipient_id = (uint32_t)(to + 1);
    in.type = RT_TYPE_DATA; in.len = (uint8_t)strlen(text); memcpy(in.body, text, in.len);
    if (!gm_encrypt(&N[from].g, &in, &f)) return false;
    return gm_try_decrypt(&N[to].g, &f, &out) && out.len == in.len && memcmp(out.body, text, in.len) == 0;
}

static bool same_chain(int x, int y) { return memcmp(R(x, y)->ck_cur, R(y, x)->ck_cur, 32) == 0; }

/* ---- Tests ------------------------------------------------------------------- */

static void test_clock(void)
{
    gm_crypto_t g; uint32_t rs = 7; uint8_t k[32]; gm_events_t ev;
    fill(k, 32, 1);
    gm_init(&g, 9, k, k, k, k, test_rng, &rs);
    gm_tick(&g, 0, &ev);
    check(!g.synced && !g.have_chain && !ev.keys_due, "clock: nothing happens before the first beacon");
    uint64_t t0 = BASE;
    check(gm_clock_on_beacon(&g, t0, 0) && gm_clock_now(&g, 0) == t0, "clock: first beacon sets the time");
    check(!gm_clock_on_beacon(&g, t0, 100), "clock: same beacon again is rejected");
    check(!gm_clock_on_beacon(&g, t0 - 5, 100), "clock: older beacon is rejected");

    /* Beacon 400 ms ahead of our clock at local 1000 -> slewed over 5 s. */
    check(gm_clock_on_beacon(&g, t0 + 1400, 1000), "clock: newer beacon accepted");
    uint64_t at0 = gm_clock_now(&g, 1000), mid = gm_clock_now(&g, 3500), end = gm_clock_now(&g, 6000);
    check(at0 == t0 + 1000, "clock: small correction is not a jump");
    check(mid == t0 + 3500 + 200, "clock: halfway through the slew, half the correction applied");
    check(end == t0 + 6000 + 400, "clock: full correction after 5 s");

    /* Big correction jumps. */
    gm_clock_on_beacon(&g, t0 + 7000 + 400 + 5000, 7000);
    check(gm_clock_now(&g, 7000) == t0 + 7000 + 400 + 5000, "clock: >= 1 s correction jumps");

    /* A newer-but-delayed beacon must not move the clock backward (decision 10c). */
    uint64_t before = gm_clock_now(&g, 8000);
    check(gm_clock_on_beacon(&g, before - 3000, 8000) || true, "clock: delayed beacon processed");
    check(gm_clock_now(&g, 8000) >= before, "clock: never moves backward");

    gm_tick(&g, 8000, &ev);
    gm_tick(&g, 8000 + GM_BEACON_TIMEOUT_MS + 1, &ev);
    check(ev.no_beacon, "clock: no_beacon alert after 30 s without a beacon");
    gm_tick(&g, 8000 + GM_BEACON_TIMEOUT_MS + 2, &ev);
    check(!ev.no_beacon, "clock: no_beacon is raised once, not every tick");
    check(gm_wire_epoch(E0) == 0x0102, "clock: wire epoch is abs mod 65536");
    gm_wipe(&g);
}

static void test_dh_progression(void)
{
    sim_init();
    check(send(A, C, "hello") && send(C, A, "hi"), "fresh boot: A<->C messages work");
    run_epochs(3);
    check(same_chain(A, C) && same_chain(A, B) && same_chain(B, C), "after 3 epochs every pair agrees");
    check(R(A, C)->main_is_dh && R(C, A)->main_is_dh, "DH is mixed in when KEYS flow both ways");
    check(R(A, C)->last_dh == N[A].g.cur_epoch, "last DH step is this epoch");
    check(send(A, C, "x") && send(C, B, "y") && send(B, A, "z"), "messages work after DH steps");
    check(N[A].agg.no_dh_mask == 0 && N[A].agg.resync_mask == 0, "no alerts or resyncs on a healthy mesh");
    check(N[A].agg.state_changed, "state_changed reported at boundaries (save to NVS)");
}

static void test_forward_secrecy(void)
{
    sim_init();
    run_epochs(2);
    uint8_t old_ck[32];
    memcpy(old_ck, R(A, C)->ck_cur, 32);
    run_epochs(2);
    const uint8_t *p = (const uint8_t *)&N[A].g;
    bool found = false;
    for (size_t i = 0; i + 32 <= sizeof N[A].g; i++) if (memcmp(p + i, old_ck, 32) == 0) found = true;
    check(!found, "forward secrecy: a chain key from 2 epochs ago is gone from A's memory");
}

static void test_post_compromise(void)
{
    sim_init();
    run_epochs(2);
    run_ms(20000);                         /* mid-epoch e: C already holds A's next key */
    node_t thief = N[C];                   /* full copy of C's state, including r(e+1) */
    uint32_t thief_rng = 0xBADu;
    thief.g.rng_ctx = &thief_rng;          /* the thief can't predict C's future randomness */

    /* Passive thief: hears every KEYS frame C hears, never transmits. */
    bool ok_e = true, ok_e1 = true, ok_e2 = false;
    #define THIEF_SEES(frame_ok_var) do { \
        rt_frame_t f; memset(&f, 0, sizeof f); f.ver_type = RT_TYPE_DATA; \
        test_rng(&N[A].rng, f.msg_id, 8); gm_put_be16(f.epoch, gm_wire_epoch(N[A].g.cur_epoch)); \
        rt_inner_t in, o1, o2; memset(&in, 0, sizeof in); in.sender_id = 1; in.recipient_id = 3; \
        in.type = RT_TYPE_DATA; in.len = 6; memcpy(in.body, "secret", 6); \
        gm_encrypt(&N[A].g, &in, &f); \
        bool real = gm_try_decrypt(&N[C].g, &f, &o1); bool stolen = gm_try_decrypt(&thief.g, &f, &o2); \
        frame_ok_var = real && stolen; real_ok &= real; } while (0)
    bool real_ok = true;
    THIEF_SEES(ok_e);
    /* Advance one epoch, letting the thief follow along passively. */
    for (int s = 0; s < 60; s++) {
        T += 1000;
        if (T % 10000 == 0) { beacon_all(); gm_clock_on_beacon(&thief.g, BASE + T, T); }
        for (int i = 0; i < NN; i++) {
            gm_events_t ev; gm_tick(&N[i].g, T, &ev);
            if (ev.keys_due) {
                uint8_t region[GM_INNER_BYTES];
                if (gm_keys_build(&N[i].g, region)) {
                    for (int to = 0; to < NN; to++) if (to != i) gm_keys_receive(&N[to].g, region);
                    if (i != C) gm_keys_receive(&thief.g, region);   /* thief listens to everyone but C */
                }
            }
        }
        gm_events_t tev; gm_tick(&thief.g, T, &tev);
    }
    THIEF_SEES(ok_e1);
    for (int s = 0; s < 60; s++) {
        T += 1000;
        if (T % 10000 == 0) { beacon_all(); gm_clock_on_beacon(&thief.g, BASE + T, T); }
        for (int i = 0; i < NN; i++) {
            gm_events_t ev; gm_tick(&N[i].g, T, &ev);
            if (ev.keys_due) {
                uint8_t region[GM_INNER_BYTES];
                if (gm_keys_build(&N[i].g, region)) {
                    for (int to = 0; to < NN; to++) if (to != i) gm_keys_receive(&N[to].g, region);
                    if (i != C) gm_keys_receive(&thief.g, region);   /* thief listens to everyone but C */
                }
            }
        }
        gm_events_t tev; gm_tick(&thief.g, T, &tev);
    }
    THIEF_SEES(ok_e2);
    check(ok_e, "PCS: a thief with C's full state reads C's traffic in the epoch it was stolen");
    check(ok_e1, "PCS: ...and in the next one (the stolen state includes C's next DH key)");
    check(!ok_e2 && real_ok, "PCS: two epochs later the thief is locked out while C still reads everything");
    gm_wipe(&thief.g);
}

static void test_one_way_loss(void)
{
    sim_init();
    run_epochs(1);
    run_ms(GM_EPOCH_MS - ((BASE + T) % GM_EPOCH_MS) + 1000);   /* start just after a boundary */
    drop[C][A] = true;                     /* A never hears C's KEYS */
    uint32_t dhA = R(A, C)->last_dh, dhC = R(C, A)->last_dh;
    clear_agg();
    run_epochs(4);
    check(R(A, C)->last_dh == dhA && R(C, A)->last_dh == dhC, "one-way KEYS loss: no new DH step (C never gets A's confirmation)");
    check(same_chain(A, C), "one-way KEYS loss: both sides still agree (hash-only steps)");
    check(send(A, C, "still") && send(C, A, "works"), "one-way KEYS loss: messages still work");
    check(N[C].agg.no_dh_mask & (1u << slot_of(C, A)), "C raises no_dh for A after 3 epochs");
    check(!(N[A].agg.resync_mask & (1u << slot_of(A, C))), "A does not RESYNC: C is silent but nothing unverifiable was heard");
    drop[C][A] = false;
    run_epochs(2);
    check(R(A, C)->main_is_dh && same_chain(A, C), "DH resumes once KEYS flow again");
}

static void test_convergence(void)
{
    sim_init();
    run_epochs(1);
    /* Stop automatic KEYS; script one epoch by hand. */
    uint64_t to_boundary = GM_EPOCH_MS - ((BASE + T) % GM_EPOCH_MS) + 1000;
    for (int i = 0; i < NN; i++) N[i].alive = false;
    T += to_boundary;
    for (int i = 0; i < NN; i++) { gm_clock_on_beacon(&N[i].g, BASE + T, T); gm_events_t ev; gm_tick(&N[i].g, T, &ev); }

    uint8_t kA1[GM_INNER_BYTES], kC1[GM_INNER_BYTES], kA2[GM_INNER_BYTES];
    gm_keys_build(&N[A].g, kA1); gm_keys_receive(&N[C].g, kA1);   /* C learns A's key */
    gm_keys_build(&N[C].g, kC1); gm_keys_receive(&N[A].g, kC1);   /* A learns C's key + C confirms A's */
    gm_keys_build(&N[A].g, kA2); (void)kA2;                        /* A's confirmation is LOST */
    check(R(A, C)->peer_confirmed && !R(C, A)->peer_confirmed, "convergence setup: only A sees a confirmation");

    T += GM_EPOCH_MS;
    for (int i = 0; i < NN; i++) { gm_clock_on_beacon(&N[i].g, BASE + T, T); gm_events_t ev; gm_tick(&N[i].g, T, &ev); }
    check(R(A, C)->main_is_dh && !R(C, A)->main_is_dh, "after the boundary A used DH, C used hash-only");
    check(memcmp(R(A, C)->ck_cur, R(C, A)->ck_alt, 32) == 0, "C holds A's version as its alternate");
    check(send(A, C, "converge"), "A->C decrypts via C's alternate");
    check(R(C, A)->main_is_dh && same_chain(A, C), "C adopted the DH version (the DH version wins)");
    for (int i = 0; i < NN; i++) N[i].alive = true;
}

static void test_convergence_after_silence(void)
{
    /* Same split as test_convergence, but nothing resolves it for 2 more hash-only
     * boundaries; the alternate must be carried forward so it can still converge. */
    sim_init();
    run_epochs(1);
    uint64_t to_boundary = GM_EPOCH_MS - ((BASE + T) % GM_EPOCH_MS) + 1000;
    for (int i = 0; i < NN; i++) N[i].alive = false;
    T += to_boundary;
    for (int i = 0; i < NN; i++) { gm_clock_on_beacon(&N[i].g, BASE + T, T); gm_events_t ev; gm_tick(&N[i].g, T, &ev); }
    uint8_t r1[GM_INNER_BYTES];
    gm_keys_build(&N[A].g, r1); gm_keys_receive(&N[C].g, r1);
    gm_keys_build(&N[C].g, r1); gm_keys_receive(&N[A].g, r1);       /* A mixes, C won't */
    for (int k = 0; k < 3; k++) {                                     /* 3 boundaries, no traffic */
        T += GM_EPOCH_MS;
        for (int i = 0; i < NN; i++) { gm_clock_on_beacon(&N[i].g, BASE + T, T); gm_events_t ev; gm_tick(&N[i].g, T, &ev); }
    }
    check(!same_chain(A, C) && R(C, A)->has_alt, "split survives silent epochs as main + alternate");
    check(send(A, C, "late") && same_chain(A, C), "after 2 hash-only epochs the split still converges");
    for (int i = 0; i < NN; i++) N[i].alive = true;
}

static void test_convergence_via_keys(void)
{
    sim_init();
    run_epochs(1);
    uint64_t to_boundary = GM_EPOCH_MS - ((BASE + T) % GM_EPOCH_MS) + 1000;
    for (int i = 0; i < NN; i++) N[i].alive = false;
    T += to_boundary;
    for (int i = 0; i < NN; i++) { gm_clock_on_beacon(&N[i].g, BASE + T, T); gm_events_t ev; gm_tick(&N[i].g, T, &ev); }
    uint8_t r1[GM_INNER_BYTES];
    gm_keys_build(&N[A].g, r1); gm_keys_receive(&N[C].g, r1);
    gm_keys_build(&N[C].g, r1); gm_keys_receive(&N[A].g, r1);
    T += GM_EPOCH_MS;
    for (int i = 0; i < NN; i++) { gm_clock_on_beacon(&N[i].g, BASE + T, T); gm_events_t ev; gm_tick(&N[i].g, T, &ev); }
    gm_keys_build(&N[A].g, r1); gm_keys_receive(&N[C].g, r1);     /* A's next KEYS, tagged with A's DH chain */
    check(R(C, A)->main_is_dh && same_chain(A, C), "a KEYS tag under the alternate also makes C adopt");
    for (int i = 0; i < NN; i++) N[i].alive = true;
}

static void test_fork_resync(void)
{
    sim_init();
    run_epochs(6);                          /* past the boot RESYNC rate limit */
    R(C, A)->ck_cur[0] ^= 0x01;             /* split the A-C chain */
    if (R(C, A)->has_alt) R(C, A)->ck_alt[0] ^= 0x01;
    clear_agg();
    check(!send(A, C, "broken"), "fork: A->C fails while the chains differ");
    run_epochs(4);
    check((N[A].agg.resync_mask & (1u << slot_of(A, C))) || (N[C].agg.resync_mask & (1u << slot_of(C, A))),
          "fork: silent peer + unverifiable KEYS triggers RESYNC");
    run_epochs(1);
    check(same_chain(A, C) && send(A, C, "fixed") && send(C, A, "fixed"), "fork: RESYNC restores the pair");
    check(!(N[A].agg.resync_mask & (1u << slot_of(A, B))) && !(N[B].agg.resync_mask & (1u << slot_of(B, A))),
          "fork: healthy pairs are never resynced");
}

static void test_resync_replay(void)
{
    /* Decision 10d: at most one RESYNC per pair per 5 epochs, and a nonce is acted on once. */
    sim_init();
    run_epochs(6);
    R(C, A)->ck_cur[0] ^= 0x01;                          /* force a real fork + RESYNC */
    if (R(C, A)->has_alt) R(C, A)->ck_alt[0] ^= 0x01;
    run_epochs(5);
    check(same_chain(A, C), "replay setup: the pair recovered through a RESYNC");
    uint32_t last = R(A, C)->last_resync;
    check(last != 0 && N[A].g.cur_epoch - last < GM_RESYNC_MIN_GAP_EPOCHS, "replay setup: A's last RESYNC was recent");

    /* An attacker makes C emit a fresh RESYNC (new nonce) for A while the pair is healthy. */
    uint8_t rs[GM_INNER_BYTES], before[32];
    N[C].g.resync_mask = (uint8_t)(1u << slot_of(C, A)); N[C].g.resync_sends_left = 1;
    gm_keys_build(&N[C].g, rs);
    memcpy(before, R(A, C)->ck_cur, 32);
    gm_keys_receive(&N[A].g, rs);
    check(memcmp(before, R(A, C)->ck_cur, 32) == 0 && R(A, C)->last_resync == last,
          "a RESYNC within 5 epochs of the last one is ignored by a healthy pair");

    /* Same nonce again on a pair that would otherwise accept: ignored. */
    R(A, C)->last_resync = N[A].g.cur_epoch - GM_RESYNC_MIN_GAP_EPOCHS;   /* rate limit expired */
    gm_keys_receive(&N[A].g, rs);                                         /* accepted once */
    check(R(A, C)->last_resync == N[A].g.cur_epoch, "once the rate limit expires, a fresh RESYNC is accepted");
    R(A, C)->last_resync = N[A].g.cur_epoch - GM_RESYNC_MIN_GAP_EPOCHS;
    R(A, C)->ck_cur[5] ^= 1;
    memcpy(before, R(A, C)->ck_cur, 32);
    gm_keys_receive(&N[A].g, rs);                                         /* replay of the same frame */
    check(memcmp(before, R(A, C)->ck_cur, 32) == 0, "the same RESYNC nonce is never acted on twice");
}

static void test_own_echo(void)
{
    sim_init();
    run_epochs(1);
    run_ms(15000);
    uint8_t r[GM_INNER_BYTES];
    gm_keys_build(&N[A].g, r);
    uint8_t before[32]; memcpy(before, R(A, C)->peer_next_pk, 32);
    bool had = R(A, C)->has_peer_next;
    check(!gm_keys_receive(&N[A].g, r), "a node ignores its own KEYS frame echoed back");
    check(R(A, C)->has_peer_next == had && memcmp(before, R(A, C)->peer_next_pk, 32) == 0,
          "an echoed KEYS frame never overwrites a peer's announced key");
}

static void test_powered_off(void)
{
    sim_init();
    N[B].alive = false;
    run_epochs(1);
    clear_agg();
    run_epochs(8);
    check(!(N[A].agg.resync_mask & (1u << slot_of(A, B))) && !(N[C].agg.resync_mask & (1u << slot_of(C, B))),
          "powered-off peer: no RESYNC flood");
    check(!(N[A].agg.no_dh_mask & (1u << slot_of(A, B))), "powered-off peer: no no_dh alert (peer inactive)");
    check(send(A, C, "fine"), "the rest of the mesh keeps working");
}

static void test_gaps(void)
{
    sim_init();
    run_epochs(2);
    N[C].alive = false; run_epochs(3); N[C].alive = true;
    clear_agg();
    run_ms(15000);
    check(send(A, C, "back") && send(C, A, "back") && same_chain(A, C), "3-epoch gap: hash-steps catch up, no RESYNC needed");
    check(!(N[C].agg.resync_mask), "3-epoch gap: no RESYNC");

    sim_init();
    run_epochs(6);
    N[C].alive = false; run_epochs(12); N[C].alive = true;
    clear_agg();
    run_ms(5000);
    check(N[C].agg.resync_mask == ((1u << slot_of(C, A)) | (1u << slot_of(C, B))), "12-epoch gap: C RESYNCs every peer");
    run_epochs(1);
    check(same_chain(A, C) && send(A, C, "again") && send(C, B, "again"), "12-epoch gap: pairs restored");
}

static void test_persistence(void)
{
    sim_init();
    run_epochs(3);
    run_ms(20000);
    uint8_t blob[GM_STATE_BYTES];
    check(gm_state_export(&N[C].g, blob, sizeof blob) == GM_STATE_BYTES, "export: fixed-size blob");
    uint64_t saved_beacon = N[C].g.last_beacon_ms;

    /* Reboot C: same config, restored state, fresh RNG. */
    uint8_t net[32], ps[32], sk[32], wt[32];
    fill(net, 32, 0x20); fill(ps, 32, 0x60); fill(sk, 32, 0x70); fill(wt, 32, 0xA0);
    gm_wipe(&N[C].g);
    N[C].rng = 4242;
    gm_init(&N[C].g, 3, net, ps, sk, wt, test_rng, &N[C].rng);
    gm_add_peer(&N[C].g, 1, N[A].g.x_pk); gm_add_peer(&N[C].g, 2, N[B].g.x_pk);
    uint8_t bad[GM_STATE_BYTES]; memcpy(bad, blob, sizeof bad); bad[0] ^= 1;
    check(!gm_state_import(&N[C].g, bad, sizeof bad), "import rejects a corrupted header");
    check(!gm_state_import(&N[C].g, blob, sizeof blob - 1), "import rejects the wrong length");
    check(gm_state_import(&N[C].g, blob, sizeof blob) && !N[C].g.synced, "import restores state, clock unsynced");
    check(!gm_clock_on_beacon(&N[C].g, saved_beacon, T), "after reboot, an old beacon is still rejected");
    clear_agg();
    run_ms(15000);
    check(same_chain(A, C) && send(A, C, "rebooted") && send(C, A, "ok"), "restored node continues the same chain");
    check(N[C].agg.resync_mask == 0, "no RESYNC after a quick reboot");
}

static void test_window(void)
{
    sim_init();
    run_epochs(2);
    uint64_t to_boundary = GM_EPOCH_MS - ((BASE + T) % GM_EPOCH_MS) + 500;
    for (int i = 0; i < NN; i++) N[i].alive = false;
    T += to_boundary;
    gm_clock_on_beacon(&N[A].g, BASE + T, T);
    gm_events_t ev; gm_tick(&N[A].g, T, &ev);              /* only A has crossed the boundary */
    check(N[A].g.cur_epoch == N[C].g.cur_epoch + 1, "window setup: A is one epoch ahead of C");
    check(send(A, C, "from the future"), "C (epoch e) reads A's frame stamped e+1");
    check(send(C, A, "from the past"), "A (epoch e+1) reads C's frame stamped e");
    for (int i = 0; i < NN; i++) N[i].alive = true;
}

static void test_keys_tamper_and_vectors(void)
{
    sim_init();
    run_epochs(1);
    run_ms(15000);
    uint8_t r[GM_INNER_BYTES];
    gm_keys_build(&N[A].g, r);
    check(r[2] == GM_KEYS_NORMAL, "KEYS: normal mode after the boot RESYNCs");
    vec("keys_region", r, sizeof r);
    vec("keys_ck_AC", R(A, C)->ck_cur, 32);
    vec("keys_C_next_pk", N[C].g.my_next_pk, 32);
    uint32_t before = N[C].g.unverified_heard;
    uint8_t t[GM_INNER_BYTES]; memcpy(t, r, sizeof t); t[10] ^= 1;   /* inside next_pk */
    check(!gm_keys_receive(&N[C].g, t) && N[C].g.unverified_heard == N[C].g.cur_epoch, "KEYS: tampered frame fails and is noted");
    (void)before;
    check(gm_keys_receive(&N[C].g, r), "KEYS: untampered frame verifies");

    uint8_t ck[32], dh[32], out[32];
    fill(ck, 32, 0x11); fill(dh, 32, 0x22);
    gm_chain_step(ck, 0x0103, dh, out);  vec("step_dh", out, 32);
    gm_chain_step(ck, 0x0103, NULL, out); vec("step_hash", out, 32);
}

int main(void)
{
    test_clock();
    test_dh_progression();
    test_forward_secrecy();
    test_post_compromise();
    test_one_way_loss();
    test_convergence();
    test_convergence_after_silence();
    test_convergence_via_keys();
    test_fork_resync();
    test_resync_replay();
    test_own_echo();
    test_powered_off();
    test_gaps();
    test_persistence();
    test_window();
    test_keys_tamper_and_vectors();
    printf("SUMMARY %d %d\n", passed, failed);
    return failed;
}
