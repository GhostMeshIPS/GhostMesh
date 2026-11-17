/*
 * gm_ratchet.c - GhostMesh stage 14b: mesh clock, epoch DH ratchet, KEYS/RESYNC,
 * persistence. Spec: PROTOCOL.md §9.2 and §9.6; decisions 2b, 6a, 8c, 10c-10f, 14b.
 *
 * Absolute epochs (floor(unix_ms / 60000)) are used internally; the 16-bit wire
 * epoch (abs mod 65536) is what goes in frames and in every KDF label.
 */
#include "gm_crypto.h"

#include <string.h>

#include "monocypher.h"

/* ---- Small internals ------------------------------------------------------ */

static bool eq_ct(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= (uint8_t)(a[i] ^ b[i]);
    return acc == 0;
}

static bool is_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

uint16_t gm_wire_epoch(uint32_t abs_epoch) { return (uint16_t)(abs_epoch & 0xFFFFu); }

static void conf_hash(const uint8_t pk[32], uint8_t out[4])
{
    uint8_t msg[7 + 32];
    memcpy(msg, "GM-CONF", 7);
    memcpy(msg + 7, pk, 32);
    crypto_blake2b(out, 4, msg, sizeof msg);
}

/* tag = BLAKE2b(key, 8, "GM-KEYS" || target || mode || [nonce] || next_pk || conf) */
static void keys_tag(const uint8_t key[32], const uint8_t *region, const uint8_t conf[4], uint8_t out[8])
{
    uint8_t mode = region[2];
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, 8, key, 32);
    crypto_blake2b_update(&ctx, (const uint8_t *)"GM-KEYS", 7);
    crypto_blake2b_update(&ctx, region, 3);                        /* target_epoch, mode */
    if (mode == GM_KEYS_RESYNC) crypto_blake2b_update(&ctx, region + 35, 8);   /* nonce */
    crypto_blake2b_update(&ctx, region + 3, 32);                   /* next_pk */
    crypto_blake2b_update(&ctx, conf, 4);
    crypto_blake2b_final(&ctx, out);
}

/* DH between my next-epoch key and the peer's announced one. False if unknown or low-order. */
static bool peer_dh(const gm_crypto_t *c, const gm_peer_t *p, uint8_t out[32])
{
    if (!p->r.has_peer_next) return false;
    crypto_x25519(out, c->my_next_sk, p->r.peer_next_pk);
    if (is_zero(out, 32)) { crypto_wipe(out, 32); return false; }
    return true;
}

static void new_my_next(gm_crypto_t *c)
{
    c->rng(c->rng_ctx, c->my_next_sk, 32);
    crypto_x25519_public_key(c->my_next_pk, c->my_next_sk);
}

static uint32_t abs_epoch_now(const gm_crypto_t *c, uint64_t local_ms)
{
    return (uint32_t)(gm_clock_now(c, local_ms) / GM_EPOCH_MS);
}

/* ---- Mesh clock --------------------------------------------------------------- */

uint64_t gm_clock_now(const gm_crypto_t *c, uint64_t local_ms)
{
    int64_t applied = 0;
    if (c->slew_total_ms != 0) {
        uint64_t elapsed = local_ms - c->slew_start_local;
        applied = (elapsed >= GM_SLEW_WINDOW_MS)
                ? c->slew_total_ms
                : c->slew_total_ms * (int64_t)elapsed / (int64_t)GM_SLEW_WINDOW_MS;
    }
    return (uint64_t)((int64_t)local_ms + c->offset_ms + applied);
}

bool gm_clock_on_beacon(gm_crypto_t *c, uint64_t issued_at_ms, uint64_t local_ms)
{
    if (issued_at_ms <= c->last_beacon_ms) return false;     /* not newer: replay or stale */

    if (!c->synced) {
        c->offset_ms = (int64_t)issued_at_ms - (int64_t)local_ms;
        c->slew_total_ms = 0;
        c->synced = true;
    } else {
        uint64_t now = gm_clock_now(c, local_ms);
        c->offset_ms = (int64_t)now - (int64_t)local_ms;     /* fold any slew in progress */
        c->slew_total_ms = 0;
        if (issued_at_ms > now) {                             /* never move backward */
            int64_t diff = (int64_t)(issued_at_ms - now);
            if (diff < GM_SLEW_MAX_MS) { c->slew_total_ms = diff; c->slew_start_local = local_ms; }
            else c->offset_ms += diff;
        }
    }
    c->last_beacon_ms = issued_at_ms;
    c->last_beacon_local = local_ms;
    c->no_beacon_alerted = false;
    return true;
}

/* ---- Ratchet ------------------------------------------------------------------- */

static void reset_pair(gm_peer_t *p, uint32_t abs_epoch)
{
    gm_chain_start(p->root, gm_wire_epoch(abs_epoch), p->r.ck_cur);
    crypto_wipe(p->r.ck_prev, 32);
    crypto_wipe(p->r.ck_alt, 32);
    p->r.has_prev = p->r.has_alt = p->r.main_is_dh = p->r.alt_is_dh = false;
}

static void start_resync(gm_crypto_t *c, int i, gm_events_t *ev)
{
    gm_peer_t *p = &c->peers[i];
    reset_pair(p, c->cur_epoch);
    p->r.last_resync = c->cur_epoch;
    p->r.last_verified = c->cur_epoch;        /* grace period before the next trigger */
    c->resync_mask |= (uint8_t)(1u << i);
    c->resync_sends_left = GM_RESYNC_REPEATS;
    c->dirty = true;
    if (ev) ev->resync_mask |= (uint8_t)(1u << i);
}

static void init_chain(gm_crypto_t *c, uint32_t e, gm_events_t *ev)
{
    c->cur_epoch = e;
    for (int i = 0; i < GM_MAX_PEERS; i++) {
        gm_peer_t *p = &c->peers[i];
        if (!p->used) continue;
        reset_pair(p, e);
        p->r.last_verified = e;
        p->r.last_dh = e;
    }
    new_my_next(c);
    c->have_chain = true;
    c->dirty = true;
    /* First boot (no saved state): tell every peer, in case it kept an older chain. */
    if (!c->imported)
        for (int i = 0; i < GM_MAX_PEERS; i++)
            if (c->peers[i].used) start_resync(c, i, ev);
}

/* One boundary step for one pair (decision 6a: chained DH + confirmation + alternate). */
static void step_pair(gm_crypto_t *c, gm_peer_t *p, uint32_t next_abs, bool allow_dh)
{
    uint16_t w = gm_wire_epoch(next_abs);
    uint8_t dh[32], H[32], D[32];
    bool can = allow_dh && peer_dh(c, p, dh);
    bool mix = can && p->r.peer_confirmed;

    gm_chain_step(p->r.ck_cur, w, NULL, H);
    if (can) gm_chain_step(p->r.ck_cur, w, dh, D);

    memcpy(p->r.ck_prev, p->r.ck_cur, 32);
    p->r.has_prev = true;
    if (mix) {
        memcpy(p->r.ck_cur, D, 32); memcpy(p->r.ck_alt, H, 32);
        p->r.main_is_dh = true; p->r.alt_is_dh = false; p->r.has_alt = true;
        p->r.last_dh = next_abs;
        p->r.no_dh_alerted = false;
    } else if (can) {
        memcpy(p->r.ck_cur, H, 32); memcpy(p->r.ck_alt, D, 32);
        p->r.main_is_dh = false; p->r.alt_is_dh = true; p->r.has_alt = true;
    } else {
        memcpy(p->r.ck_cur, H, 32);
        if (!p->r.has_alt) p->r.main_is_dh = false;
        else {
            /* main_is_dh / alt_is_dh now describe each branch's lineage since the split. */
            /* Keep an unresolved alternate alive through hash-only steps, so a split from
             * an earlier boundary can still converge later ("the DH version wins"). */
            uint8_t a[32];
            gm_chain_step(p->r.ck_alt, w, NULL, a);
            memcpy(p->r.ck_alt, a, 32);
            crypto_wipe(a, 32);
        }
    }
    p->r.has_peer_next = false;
    p->r.peer_confirmed = false;
    crypto_wipe(dh, 32); crypto_wipe(H, 32); crypto_wipe(D, 32);
}

static void advance(gm_crypto_t *c, uint32_t new_e, gm_events_t *ev)
{
    uint32_t gap = new_e - c->cur_epoch;
    if (gap > GM_MAX_CATCHUP_EPOCHS) {                 /* too long: restart every pair */
        c->cur_epoch = new_e;
        for (int i = 0; i < GM_MAX_PEERS; i++) {
            gm_peer_t *p = &c->peers[i];
            if (!p->used) continue;
            p->r.has_peer_next = p->r.peer_confirmed = false;
            p->r.last_dh = new_e;
            start_resync(c, i, ev);
        }
    } else {
        for (uint32_t s = 0; s < gap; s++) {
            uint32_t next = c->cur_epoch + 1;
            for (int i = 0; i < GM_MAX_PEERS; i++)
                if (c->peers[i].used) step_pair(c, &c->peers[i], next, s == 0);
            c->cur_epoch = next;
        }
        for (int i = 0; i < GM_MAX_PEERS; i++) {      /* missing-DH alert (decision 10e) */
            gm_peer_t *p = &c->peers[i];
            if (!p->used) continue;
            bool active = p->r.last_verified + 1 >= c->cur_epoch;
            if (active && c->cur_epoch - p->r.last_dh >= GM_NO_DH_EPOCHS && !p->r.no_dh_alerted) {
                p->r.no_dh_alerted = true;
                ev->no_dh_mask |= (uint8_t)(1u << i);
            }
        }
    }
    crypto_wipe(c->my_next_sk, 32);                    /* this epoch's DH key is spent */
    new_my_next(c);
    c->dirty = true;
    ev->epoch_changed = true;
}

void gm_tick(gm_crypto_t *c, uint64_t local_ms, gm_events_t *ev)
{
    memset(ev, 0, sizeof *ev);
    if (!c->synced) return;                            /* decision 2c: wait for the clock */

    uint32_t e = abs_epoch_now(c, local_ms);
    if (!c->have_chain) { init_chain(c, e, ev); ev->synced_now = true; }
    else if (e > c->cur_epoch) advance(c, e, ev);      /* clock never runs backward */

    /* RESYNC trigger (decision 14b): peer silent for 2 epochs AND unverifiable KEYS heard. */
    for (int i = 0; i < GM_MAX_PEERS; i++) {
        gm_peer_t *p = &c->peers[i];
        if (!p->used) continue;
        bool may = p->r.last_resync == 0 || c->cur_epoch - p->r.last_resync >= GM_RESYNC_MIN_GAP_EPOCHS;
        bool silent = c->cur_epoch >= p->r.last_verified + GM_RESYNC_SILENT_EPOCHS;
        bool forked = c->unverified_heard != 0 && c->unverified_heard + 1 >= c->cur_epoch;
        if (may && silent && forked) start_resync(c, i, ev);
    }

    if (local_ms >= c->next_keys_local) {              /* KEYS cadence */
        ev->keys_due = true;
        c->next_keys_local = local_ms + GM_KEYS_INTERVAL_MS;
    }
    if (local_ms - c->last_beacon_local > GM_BEACON_TIMEOUT_MS && !c->no_beacon_alerted) {
        c->no_beacon_alerted = true;                   /* decision 10f */
        ev->no_beacon = true;
    }
    ev->state_changed = c->dirty;
    c->dirty = false;
}

/* ---- Message keys (used by gm_encrypt / gm_try_decrypt) -------------------------- */

int gm_peer_message_keys(const gm_crypto_t *c, int peer_slot, uint16_t wire_epoch, uint8_t mk[2][32])
{
    if (!c->have_chain || peer_slot < 0 || peer_slot >= GM_MAX_PEERS) return 0;
    const gm_peer_t *p = &c->peers[peer_slot];
    if (!p->used) return 0;

    if (wire_epoch == gm_wire_epoch(c->cur_epoch)) {
        gm_message_key(p->r.ck_cur, mk[0]);
        if (!p->r.has_alt) return 1;
        gm_message_key(p->r.ck_alt, mk[1]);
        return 2;
    }
    if (wire_epoch == gm_wire_epoch(c->cur_epoch - 1)) {
        if (!p->r.has_prev) return 0;
        gm_message_key(p->r.ck_prev, mk[0]);
        return 1;
    }
    if (wire_epoch == gm_wire_epoch(c->cur_epoch + 1)) {   /* sender's clock is slightly ahead */
        uint8_t ck[32], dh[32];
        int n = 0;
        if (peer_dh(c, p, dh)) {
            gm_chain_step(p->r.ck_cur, wire_epoch, dh, ck);
            gm_message_key(ck, mk[n++]);
            crypto_wipe(dh, 32);
        }
        gm_chain_step(p->r.ck_cur, wire_epoch, NULL, ck);
        gm_message_key(ck, mk[n++]);
        crypto_wipe(ck, 32);
        return n;
    }
    return 0;   /* outside the ±1 window (decision 2c) */
}

void gm_ratchet_note_key_used(gm_crypto_t *c, int peer_slot, uint16_t wire_epoch, int key_index)
{
    gm_peer_t *p = &c->peers[peer_slot];
    if (wire_epoch != gm_wire_epoch(c->cur_epoch) || key_index != 1) return;
    if (p->r.has_alt && p->r.alt_is_dh && !p->r.main_is_dh) {   /* the DH version wins */
        uint8_t t[32];
        memcpy(t, p->r.ck_cur, 32); memcpy(p->r.ck_cur, p->r.ck_alt, 32); memcpy(p->r.ck_alt, t, 32);
        crypto_wipe(t, 32);
        p->r.main_is_dh = true; p->r.alt_is_dh = false;
        p->r.last_dh = c->cur_epoch;
        p->r.no_dh_alerted = false;
        c->dirty = true;
    }
}

/* ---- KEYS frames ------------------------------------------------------------------- */

#define KEYS_SLOTS_NORMAL 35
#define KEYS_SLOTS_RESYNC 43

bool gm_keys_build(gm_crypto_t *c, uint8_t region[GM_INNER_BYTES])
{
    if (!c->have_chain) return false;
    bool resync = c->resync_mask && c->resync_sends_left;
    c->rng(c->rng_ctx, region, GM_INNER_BYTES);            /* random filler + resync nonce */

    gm_put_be16(region, gm_wire_epoch(resync ? c->cur_epoch : c->cur_epoch + 1));
    region[2] = resync ? GM_KEYS_RESYNC : GM_KEYS_NORMAL;
    memcpy(region + 3, c->my_next_pk, 32);
    size_t off = resync ? KEYS_SLOTS_RESYNC : KEYS_SLOTS_NORMAL;

    uint8_t perm[GM_KEYS_SLOTS], rnd[GM_KEYS_SLOTS];       /* random slot order */
    for (int i = 0; i < GM_KEYS_SLOTS; i++) perm[i] = (uint8_t)i;
    c->rng(c->rng_ctx, rnd, sizeof rnd);
    for (int i = GM_KEYS_SLOTS - 1; i > 0; i--) {
        int j = rnd[i] % (i + 1);
        uint8_t t = perm[i]; perm[i] = perm[j]; perm[j] = t;
    }

    int s = 0;
    for (int i = 0; i < GM_MAX_PEERS && s < GM_KEYS_SLOTS; i++) {
        gm_peer_t *p = &c->peers[i];
        if (!p->used) continue;
        if (resync && !(c->resync_mask & (1u << i))) continue;
        uint8_t *slot = region + off + 12u * perm[s++];
        if (p->r.has_peer_next) conf_hash(p->r.peer_next_pk, slot + 8);   /* else stays random */
        keys_tag(resync ? p->root : p->r.ck_cur, region, slot + 8, slot);
    }
    if (resync && --c->resync_sends_left == 0) c->resync_mask = 0;
    return true;
}

static bool nonce_seen(const gm_peer_t *p, const uint8_t *nonce)
{
    for (int k = 0; k < 4; k++) if (memcmp(p->r.resync_nonces[k], nonce, 8) == 0) return true;
    return false;
}

static void accept_announcement(gm_crypto_t *c, gm_peer_t *p, const uint8_t *region, const uint8_t *conf)
{
    uint8_t mine[4];
    memcpy(p->r.peer_next_pk, region + 3, 32);
    p->r.has_peer_next = true;
    conf_hash(c->my_next_pk, mine);
    if (eq_ct(conf, mine, 4)) p->r.peer_confirmed = true;
    p->r.last_verified = c->cur_epoch;
}

bool gm_keys_receive(gm_crypto_t *c, const uint8_t region[GM_INNER_BYTES])
{
    if (!c->have_chain) return false;
    /* Our own frame echoed back: pair keys are symmetric, so its tags would verify and we'd
     * store our own key as the peer's. Routing's seen-cache should drop echoes; never rely on it. */
    if (eq_ct(region + 3, c->my_next_pk, 32)) return false;
    uint16_t target = gm_get_be16(region);
    uint8_t mode = region[2];
    bool matched[GM_MAX_PEERS] = {0}, any = false;
    uint8_t want[8];

    if (mode == GM_KEYS_NORMAL) {
        if (target != gm_wire_epoch(c->cur_epoch + 1)) return false;   /* not for our next epoch */
        for (int s = 0; s < GM_KEYS_SLOTS; s++) {
            const uint8_t *slot = region + KEYS_SLOTS_NORMAL + 12 * s;
            for (int i = 0; i < GM_MAX_PEERS; i++) {
                gm_peer_t *p = &c->peers[i];
                if (!p->used || matched[i]) continue;
                bool on_main = false, on_alt = false;
                keys_tag(p->r.ck_cur, region, slot + 8, want);
                on_main = eq_ct(want, slot, 8);
                if (!on_main && p->r.has_alt) { keys_tag(p->r.ck_alt, region, slot + 8, want); on_alt = eq_ct(want, slot, 8); }
                if (!on_main && !on_alt) continue;
                if (on_alt) gm_ratchet_note_key_used(c, i, gm_wire_epoch(c->cur_epoch), 1);
                accept_announcement(c, p, region, slot + 8);
                matched[i] = true; any = true;
                break;
            }
        }
        if (!any) c->unverified_heard = c->cur_epoch;   /* someone talks under a key we don't share */
        return any;
    }

    if (mode != GM_KEYS_RESYNC) return false;
    bool for_prev = target == gm_wire_epoch(c->cur_epoch - 1);
    if (target != gm_wire_epoch(c->cur_epoch) && !for_prev) return false;
    const uint8_t *nonce = region + 35;
    for (int s = 0; s < GM_KEYS_SLOTS; s++) {
        const uint8_t *slot = region + KEYS_SLOTS_RESYNC + 12 * s;
        for (int i = 0; i < GM_MAX_PEERS; i++) {
            gm_peer_t *p = &c->peers[i];
            if (!p->used || matched[i]) continue;
            keys_tag(p->root, region, slot + 8, want);
            if (!eq_ct(want, slot, 8)) continue;
            matched[i] = true;
            if (nonce_seen(p, nonce)) break;               /* replayed RESYNC (decision 10d) */
            bool same_epoch = p->r.last_resync == c->cur_epoch;   /* we already reset this epoch */
            bool rate_ok = p->r.last_resync == 0 || c->cur_epoch - p->r.last_resync >= GM_RESYNC_MIN_GAP_EPOCHS;
            /* A pair that is already silent is broken anyway: accept, or staggered boots deadlock.
             * A replayed RESYNC against a healthy (recently verified) pair stays rate-limited. */
            bool silent = c->cur_epoch >= p->r.last_verified + GM_RESYNC_SILENT_EPOCHS;
            if (!same_epoch && !rate_ok && !silent) break;  /* rate limit: max 1 per 5 epochs */
            if (!same_epoch) {
                reset_pair(p, for_prev ? c->cur_epoch - 1 : c->cur_epoch);
                if (for_prev) {
                    uint8_t t[32];
                    gm_chain_step(p->r.ck_cur, gm_wire_epoch(c->cur_epoch), NULL, t);
                    memcpy(p->r.ck_cur, t, 32); crypto_wipe(t, 32);
                }
                p->r.last_resync = c->cur_epoch;
                c->dirty = true;
            }
            memcpy(p->r.resync_nonces[p->r.resync_nonce_i], nonce, 8);
            p->r.resync_nonce_i = (uint8_t)((p->r.resync_nonce_i + 1) % 4);
            accept_announcement(c, p, region, slot + 8);
            any = true;
            break;
        }
    }
    return any;
}

/* ---- Persistence ---------------------------------------------------------------------- */

#define STATE_MAGIC "GMS1"
#define PEER_BYTES  (1 + 4 + 96 + 1 + 32 + 12 + 33)

static uint8_t pack_flags(const gm_ratchet_peer_t *r)
{
    return (uint8_t)(r->has_prev | r->has_alt << 1 | r->main_is_dh << 2 | r->alt_is_dh << 3 |
                     r->has_peer_next << 4 | r->peer_confirmed << 5 | r->no_dh_alerted << 6);
}

static void unpack_flags(gm_ratchet_peer_t *r, uint8_t f)
{
    r->has_prev = f & 1; r->has_alt = (f >> 1) & 1; r->main_is_dh = (f >> 2) & 1; r->alt_is_dh = (f >> 3) & 1;
    r->has_peer_next = (f >> 4) & 1; r->peer_confirmed = (f >> 5) & 1; r->no_dh_alerted = (f >> 6) & 1;
}

size_t gm_state_export(const gm_crypto_t *c, uint8_t *buf, size_t cap)
{
    if (cap < GM_STATE_BYTES || !c->have_chain) return 0;
    uint8_t *w = buf;
    memcpy(w, STATE_MAGIC, 4); w += 4;
    *w++ = 1;                                              /* format version */
    gm_put_be64(w, c->last_beacon_ms); w += 8;
    gm_put_be32(w, c->cur_epoch); w += 4;
    memcpy(w, c->my_next_sk, 32); w += 32;
    memcpy(w, c->my_next_pk, 32); w += 32;
    gm_put_be32(w, c->unverified_heard); w += 4;
    for (int i = 0; i < GM_MAX_PEERS; i++) {
        const gm_peer_t *p = &c->peers[i];
        *w++ = p->used;
        gm_put_be32(w, p->node_id); w += 4;
        memcpy(w, p->r.ck_cur, 32); memcpy(w + 32, p->r.ck_prev, 32); memcpy(w + 64, p->r.ck_alt, 32); w += 96;
        *w++ = pack_flags(&p->r);
        memcpy(w, p->r.peer_next_pk, 32); w += 32;
        gm_put_be32(w, p->r.last_verified); gm_put_be32(w + 4, p->r.last_dh); gm_put_be32(w + 8, p->r.last_resync); w += 12;
        memcpy(w, p->r.resync_nonces, 32); w += 32;
        *w++ = p->r.resync_nonce_i;
    }
    return (size_t)(w - buf);
}

bool gm_state_import(gm_crypto_t *c, const uint8_t *buf, size_t len)
{
    if (len != GM_STATE_BYTES || memcmp(buf, STATE_MAGIC, 4) != 0 || buf[4] != 1) return false;
    const uint8_t *r = buf + 5;
    c->last_beacon_ms = gm_get_be64(r); r += 8;
    c->cur_epoch = gm_get_be32(r); r += 4;
    memcpy(c->my_next_sk, r, 32); r += 32;
    memcpy(c->my_next_pk, r, 32); r += 32;
    c->unverified_heard = gm_get_be32(r); r += 4;
    for (int s = 0; s < GM_MAX_PEERS; s++, r += PEER_BYTES) {
        if (!r[0]) continue;
        uint32_t id = gm_get_be32(r + 1);
        for (int i = 0; i < GM_MAX_PEERS; i++) {           /* match to the configured peer */
            gm_peer_t *p = &c->peers[i];
            if (!p->used || p->node_id != id) continue;
            const uint8_t *q = r + 5;
            memcpy(p->r.ck_cur, q, 32); memcpy(p->r.ck_prev, q + 32, 32); memcpy(p->r.ck_alt, q + 64, 32); q += 96;
            unpack_flags(&p->r, *q++);
            memcpy(p->r.peer_next_pk, q, 32); q += 32;
            p->r.last_verified = gm_get_be32(q); p->r.last_dh = gm_get_be32(q + 4); p->r.last_resync = gm_get_be32(q + 8); q += 12;
            memcpy(p->r.resync_nonces, q, 32); q += 32;
            p->r.resync_nonce_i = (uint8_t)(*q % 4);
        }
    }
    c->have_chain = true;
    c->imported = true;
    c->synced = false;                                     /* wait for a beacon (decision 2c) */
    return true;
}
