/*
 * gm_node.c - see gm_node.h. Spec references: PROTOCOL.md §5 (routing), §9 (security), §10 (serial).
 */
#include "gm_node.h"

#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(rt_frame_t) == 240, "rt_frame_t must be exactly the 240-byte wire frame");

/* ------------------------------------------------------------------------ */
/* small helpers                                                             */
/* ------------------------------------------------------------------------ */

static uint64_t local_ms(gm_node_t *n) { return n->hw.local_ms(n->hw.ctx); }
static void emit(gm_node_t *n, const char *json) { n->hw.emit(n->hw.ctx, json); }
static void indicate(gm_node_t *n, int what) { if (n->hw.indicate) n->hw.indicate(n->hw.ctx, what); }

static const char *LOG_NAMES[] = {
    "bad_link_tag", "bad_epoch", "bad_type", "blocked", "rate_limited", "duplicate",
    "dup_counted", "relay_cancelled", "ttl_expired", "ctrl_unverified", "replay_stale",
    "not_synced", "relay_scheduled", "tx", "delivered", "reack", "ack_matched",
    "ack_unmatched", "hello", "too_long", "encrypt_failed", "send_failed", "peer_evicted",
};
_Static_assert(sizeof LOG_NAMES / sizeof LOG_NAMES[0] == GM_NODE_LOG_LAST + 1,
               "LOG_NAMES must match rt_log_t in routing.h (and GM_NODE_LOG_LAST in gm_node.h)");

const char *gm_node_log_name(rt_log_t e)
{
    return (unsigned)e <= GM_NODE_LOG_LAST ? LOG_NAMES[e] : "?";
}

/* Events that always reach the laptop; everything else only with verbose on. */
static bool log_is_important(rt_log_t e)
{
    switch (e) {
    case RT_LOG_BAD_LINK_TAG: case RT_LOG_BAD_EPOCH: case RT_LOG_BLOCKED:
    case RT_LOG_CTRL_UNVERIFIED: case RT_LOG_REPLAY_STALE: case RT_LOG_TOO_LONG:
    case RT_LOG_ENCRYPT_FAILED: case RT_LOG_RATE_LIMITED: case RT_LOG_PEER_EVICTED:
        return true;
    default:
        return false;
    }
}

char gm_node_peer_name(gm_node_t *n, uint32_t id)
{
    if (id == n->keys.node_id) return n->keys.name;
    for (int i = 0; i < n->keys.peer_count; i++)
        if (n->keys.peers[i].id == id) return n->keys.peers[i].name;
    return '?';
}

static uint32_t peer_id_by_name(gm_node_t *n, char name)
{
    for (int i = 0; i < n->keys.peer_count; i++)
        if (n->keys.peers[i].name == name) return n->keys.peers[i].id;
    return 0;
}

static void hex(const uint8_t *p, size_t len, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) { out[2 * i] = d[p[i] >> 4]; out[2 * i + 1] = d[p[i] & 15]; }
    out[2 * len] = '\0';
}

static void json_escape(const uint8_t *s, size_t n, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; i < n && o + 7 < cap; i++) {
        uint8_t c = s[i];
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c < 0x20 || c == 0x7F) o += (size_t)snprintf(out + o, cap - o, "\\u%04x", c);
        else out[o++] = (char)c;
    }
    out[o] = '\0';
}

uint64_t gm_node_mesh_ms(gm_node_t *n) { return gm_clock_now(&n->c, local_ms(n)); }
uint16_t gm_node_wire_epoch(gm_node_t *n) { return gm_wire_epoch(n->c.cur_epoch); }

void gm_node_pseudonym(gm_node_t *n, uint8_t out[4])
{
    uint16_t e = gm_node_wire_epoch(n);
    if (!n->pseudo_valid || n->wire_epoch_cached != e) {
        gm_pseudonym(n->c.pseudo_secret, e, n->pseudo_cached);
        n->wire_epoch_cached = e;
        n->pseudo_valid = true;
    }
    memcpy(out, n->pseudo_cached, 4);
}

/* ------------------------------------------------------------------------ */
/* timers: polled table, so routing callbacks all run on the caller's task   */
/* ------------------------------------------------------------------------ */

static void p_timer_start(void *ctx, uint32_t token, uint32_t delay_ms)
{
    gm_node_t *n = ctx;
    gm_timer_t *free_slot = NULL;
    for (int i = 0; i < GM_NODE_MAX_TIMERS; i++) {
        gm_timer_t *t = &n->timers[i];
        if (t->used && t->token == token) { t->due = local_ms(n) + delay_ms; return; }   /* restart */
        if (!t->used && !free_slot) free_slot = t;
    }
    if (!free_slot) { emit(n, "{\"ev\":\"error\",\"reason\":\"timer_table_full\"}"); return; }
    free_slot->used = true;
    free_slot->token = token;
    free_slot->due = local_ms(n) + delay_ms;
}

static void p_timer_cancel(void *ctx, uint32_t token)
{
    gm_node_t *n = ctx;
    for (int i = 0; i < GM_NODE_MAX_TIMERS; i++)
        if (n->timers[i].used && n->timers[i].token == token) n->timers[i].used = false;
}

static void fire_due_timers(gm_node_t *n)
{
    uint64_t now = local_ms(n);
    for (int i = 0; i < GM_NODE_MAX_TIMERS; i++) {
        gm_timer_t *t = &n->timers[i];
        if (!t->used || t->due > now) continue;
        t->used = false;                     /* clear first: the callback may restart it */
        rt_on_timer(&n->rt, t->token);
    }
}

/* ------------------------------------------------------------------------ */
/* rt_platform_t callbacks                                                   */
/* ------------------------------------------------------------------------ */

static void p_transmit(void *ctx, const rt_frame_t *f)
{
    gm_node_t *n = ctx;
    n->st.tx_frames++;
    indicate(n, GM_IND_TX);
    n->hw.transmit(n->hw.ctx, (const uint8_t *)f);
}

static uint32_t p_now_ms(void *ctx) { return (uint32_t)gm_node_mesh_ms(ctx); }

static uint32_t p_random_u32(void *ctx)
{
    gm_node_t *n = ctx;
    uint32_t v;
    n->hw.rng(n->hw.ctx, (uint8_t *)&v, sizeof v);
    return v;
}

/* "Ready to originate or relay": the clock is synced AND gm_tick has initialised the epoch chain
 * (have_chain). gm_clock_on_beacon sets c.synced synchronously when the first beacon arrives, but
 * cur_epoch, have_chain and the rotated MAC are only set on the next gm_tick (in gm_node_poll).
 * Gating on have_chain keeps routing from relaying in that gap, which is where a frame would
 * otherwise go out under the board's factory MAC and stale pseudonym (first-sync race,
 * docs/results/hardware-smoke-2026-11-18.md §3.1). gm_node_rx forces the tick to run on the very
 * next poll after a syncing beacon, so the gap is one poll, not a 100 ms tick period. */
static bool node_ready(const gm_node_t *n) { return n->c.synced && n->c.have_chain; }
static bool p_is_synced(void *ctx) { return node_ready((const gm_node_t *)ctx); }

static bool p_link_tag_ok(void *ctx, const rt_frame_t *f)
{
    return gm_link_tag_ok(((gm_node_t *)ctx)->c.network_key, f);
}

static void p_compute_link_tag(void *ctx, const rt_frame_t *f, uint8_t out[8])
{
    gm_link_tag(((gm_node_t *)ctx)->c.network_key, f, out);
}

static bool p_encrypt(void *ctx, const rt_inner_t *in, rt_frame_t *f) { return gm_encrypt(&((gm_node_t *)ctx)->c, in, f); }
static bool p_try_decrypt(void *ctx, const rt_frame_t *f, rt_inner_t *out) { return gm_try_decrypt(&((gm_node_t *)ctx)->c, f, out); }

/* §9.8 block matching: src_pseudo matches AND (radio MAC matches OR target MAC all zero). */
static const uint8_t ZERO_MAC[6] = {0};

static bool p_is_blocked(void *ctx, const rt_frame_t *f, const uint8_t src_mac[6])
{
    gm_node_t *n = ctx;
    uint64_t now = gm_node_mesh_ms(n);
    for (int i = 0; i < GM_NODE_MAX_BLOCKS; i++) {
        gm_block_t *b = &n->blocks[i];
        if (!b->used) continue;
        if (now >= b->until_ms) { b->used = false; continue; }
        for (int k = 0; k < 2; k++) {
            if (memcmp(b->pseudo[k], f->src_pseudo, 4) != 0) continue;
            if (memcmp(b->mac[k], ZERO_MAC, 6) == 0 || (src_mac && memcmp(b->mac[k], src_mac, 6) == 0))
                return true;
        }
    }
    return false;
}

static void p_keys_receive(void *ctx, const rt_frame_t *f)
{
    gm_keys_receive(&((gm_node_t *)ctx)->c, f->ciphertext);
}

static void apply_block(gm_node_t *n, uint64_t issued, const uint8_t *p)
{
    /* block_id(4) until_ms(8) reason(1) 2 x [pseudo(4) mac(6) epoch(2)] */
    uint32_t id = gm_get_be32(p);
    uint64_t until = gm_get_be64(p + 4);
    gm_block_t *slot = NULL;
    for (int i = 0; i < GM_NODE_MAX_BLOCKS && !slot; i++)
        if (n->blocks[i].used && n->blocks[i].block_id == id) slot = &n->blocks[i];
    for (int i = 0; i < GM_NODE_MAX_BLOCKS && !slot; i++)
        if (!n->blocks[i].used) slot = &n->blocks[i];
    if (!slot) slot = &n->blocks[0];

    char buf[96];
    if (until <= issued) {                     /* re-issue with until == issued ends it early */
        if (slot->used && slot->block_id == id) slot->used = false;
        snprintf(buf, sizeof buf, "{\"ev\":\"unblock\",\"block_id\":%lu}", (unsigned long)id);
        emit(n, buf);
        return;
    }
    slot->used = true;
    slot->block_id = id;
    slot->issued_ms = issued;
    slot->until_ms = until;
    slot->reason = p[12];
    for (int k = 0; k < 2; k++) {
        memcpy(slot->pseudo[k], p + 13 + 12 * k, 4);
        memcpy(slot->mac[k], p + 17 + 12 * k, 6);
    }
    n->st.blocks_applied++;
    char ps[9];
    hex(slot->pseudo[0], 4, ps);
    snprintf(buf, sizeof buf, "{\"ev\":\"block\",\"block_id\":%lu,\"pseudo\":\"%s\",\"reason\":%u}",
             (unsigned long)id, ps, slot->reason);
    emit(n, buf);
}

/* CTRL verify budget (decisions 8d, 10b). Only FAILED verifies count (Jose, Nov 17): counting every
 * frame made a node 2 hops from W drop a fresh BLOCK whenever a TIME beacon had come through the
 * same neighbour in the last 5 s. A transmitter that failed in the last 5 s is skipped, and the
 * mesh as a whole is skipped after 2 failures in the last second. Valid CTRL from W never costs budget. */
static gm_ctrl_track_t *ctrl_track(gm_node_t *n, const rt_frame_t *f, bool create)
{
    gm_ctrl_track_t *oldest = &n->ctrl_track[0];
    for (int i = 0; i < GM_NODE_CTRL_TRACK; i++) {
        gm_ctrl_track_t *c = &n->ctrl_track[i];
        if (c->used && !memcmp(c->pseudo, f->src_pseudo, 4) && !memcmp(c->mac, n->cur_rx_mac, 6)) return c;
        if (!c->used || c->last_ms < oldest->last_ms) oldest = c;
    }
    if (!create) return NULL;
    oldest->used = true;
    memcpy(oldest->pseudo, f->src_pseudo, 4);
    memcpy(oldest->mac, n->cur_rx_mac, 6);
    return oldest;
}

static bool ctrl_budget_ok(gm_node_t *n, const rt_frame_t *f)
{
    uint64_t now = local_ms(n);
    if (n->ctrl_budget_ms[0] && now - n->ctrl_budget_ms[0] < 1000) return false;   /* 2 failures in the last second */
    gm_ctrl_track_t *t = ctrl_track(n, f, false);
    return !(t && t->last_ms && now - t->last_ms < 5000);
}

static void ctrl_note_failure(gm_node_t *n, const rt_frame_t *f)
{
    uint64_t now = local_ms(n);
    ctrl_track(n, f, true)->last_ms = now;
    n->ctrl_budget_ms[0] = n->ctrl_budget_ms[1];
    n->ctrl_budget_ms[1] = now;
}

/* Returns true only if the CTRL frame verified and was applied, so routing relays it. */
static bool p_ctrl_verify(void *ctx, const rt_frame_t *f)
{
    gm_node_t *n = ctx;
    const uint8_t *region = f->ciphertext;
    uint8_t sub_peek = region[0];
    uint64_t issued_peek = gm_get_be64(region + 1);

    /* skip, without verifying, anything not newer than what we already hold */
    if (sub_peek == GM_CTRL_TIME && issued_peek <= n->last_beacon_issued) return false;
    if (sub_peek == GM_CTRL_BLOCK) {
        uint32_t id = gm_get_be32(region + GM_CTRL_HDR_BYTES);
        for (int i = 0; i < GM_NODE_MAX_BLOCKS; i++)
            if (n->blocks[i].used && n->blocks[i].block_id == id && issued_peek <= n->blocks[i].issued_ms)
                return false;
    }
    if (!ctrl_budget_ok(n, f)) return false;

    uint8_t sub; uint64_t issued; const uint8_t *payload; size_t plen;
    if (!gm_ctrl_verify(&n->c, region, &sub, &issued, &payload, &plen)) { ctrl_note_failure(n, f); return false; }

    if (sub == GM_CTRL_TIME) {
        if (!gm_clock_on_beacon(&n->c, issued, local_ms(n))) return false;
        n->last_beacon_issued = issued;
        n->st.beacons_ok++;
        return true;
    }
    if (sub == GM_CTRL_BLOCK && plen == GM_CTRL_BLOCK_PAYLOAD_BYTES) {
        apply_block(n, issued, payload);
        return true;
    }
    return false;
}

static void p_my_pseudonym(void *ctx, uint8_t out[4]) { gm_node_pseudonym(ctx, out); }
static uint16_t p_current_epoch(void *ctx) { return gm_node_wire_epoch(ctx); }

static void p_deliver(void *ctx, const rt_inner_t *msg)
{
    gm_node_t *n = ctx;
    char from = gm_node_peer_name(n, msg->sender_id);
    char text[RT_BODY_MAX * 6 + 1], buf[RT_BODY_MAX * 6 + 96];
    json_escape(msg->body, msg->len, text, sizeof text);
    snprintf(buf, sizeof buf, "{\"ev\":\"rx\",\"from\":\"%c\",\"text\":\"%s\",\"seq\":%lu,\"rssi\":%d}",
             from, text, (unsigned long)msg->seq, n->st.last_rssi);
    emit(n, buf);
    snprintf(n->st.last_msg, sizeof n->st.last_msg, "<%c: %.*s", from, (int)(msg->len > 40 ? 40 : msg->len),
             (const char *)msg->body);
    indicate(n, GM_IND_RX_MINE);
}

static void p_notify(void *ctx, uint32_t handle, rt_status_t status)
{
    gm_node_t *n = ctx;
    char to = '?';
    int slot = -1;
    for (int i = 0; i < RT_MAX_OUTSTANDING; i++)
        if (n->handles[i].handle == handle) { to = n->handles[i].to; slot = i; break; }
    if (slot < 0 && status == RT_STATUS_SENT) to = n->sending_to;     /* fires inside rt_send */
    static const char *names[] = {"sent", "delivered", "failed"};
    static const char *marks[] = {"v", "vv", "X"};
    char buf[96];
    snprintf(buf, sizeof buf, "{\"ev\":\"%s\",\"to\":\"%c\",\"handle\":%lu}", names[status], to, (unsigned long)handle);
    emit(n, buf);
    snprintf(n->st.last_send, sizeof n->st.last_send, ">%c %s #%lu", to, marks[status], (unsigned long)handle);
    if (status != RT_STATUS_SENT && slot >= 0) n->handles[slot].handle = 0;
    if (status == RT_STATUS_DELIVERED) indicate(n, GM_IND_RX_MINE);
}

static void p_log(void *ctx, rt_log_t event, const rt_frame_t *f)
{
    gm_node_t *n = ctx;
    if ((unsigned)event <= GM_NODE_LOG_LAST) n->st.log_counts[event]++;
    if (event == RT_LOG_BAD_LINK_TAG || event == RT_LOG_BLOCKED) indicate(n, GM_IND_DROP_BAD);
    if (!n->verbose && !log_is_important(event)) return;
    char id[17] = "", buf[128];
    if (f) hex(f->msg_id, 8, id);
    snprintf(buf, sizeof buf, "{\"ev\":\"log\",\"what\":\"%s\",\"msg_id\":\"%s\",\"ttl\":%d,\"hop\":%d}",
             gm_node_log_name(event), id, f ? f->ttl : -1, f ? f->hop_count : -1);
    emit(n, buf);
}

/* ------------------------------------------------------------------------ */
/* KEYS frames (§9.6): built here, flooded like DATA                          */
/* ------------------------------------------------------------------------ */

static void send_keys(gm_node_t *n)
{
    rt_frame_t f;
    memset(&f, 0, sizeof f);
    if (!gm_keys_build(&n->c, f.ciphertext)) return;
    f.ver_type = RT_FRAME_KEYS;
    f.flags = 0;
    n->hw.rng(n->hw.ctx, f.msg_id, 8);
    uint8_t pad = (uint8_t)(p_random_u32(n) % ((uint32_t)n->rt_cfg.hop_pad_max + 1));   /* §9.9 */
    f.hop_count = pad;
    f.ttl = (uint8_t)(n->rt_cfg.default_ttl - pad);
    gm_node_pseudonym(n, f.src_pseudo);
    gm_put_be16(f.epoch, gm_node_wire_epoch(n));
    n->hw.rng(n->hw.ctx, f.nonce, sizeof f.nonce);            /* look like DATA on the air */
    n->hw.rng(n->hw.ctx, f.aead_tag, sizeof f.aead_tag);
    gm_link_tag(n->c.network_key, &f, f.link_tag);

    memcpy(n->own_echo[n->own_echo_i], f.msg_id, 8);          /* drop our own echo when relays send it back */
    n->own_echo_i = (uint8_t)((n->own_echo_i + 1) % GM_NODE_OWN_ECHO);
    n->st.keys_sent++;
    p_transmit(n, &f);
}

/* ------------------------------------------------------------------------ */
/* public API                                                                 */
/* ------------------------------------------------------------------------ */

void gm_node_init(gm_node_t *n, const gm_node_keys_t *keys, const gm_hw_t *hw,
                  const uint8_t *state, size_t state_len)
{
    memset(n, 0, sizeof *n);
    n->keys = *keys;
    n->hw = *hw;
    n->rotate_mac = true;
    n->rssi_gate = -127;

    gm_init(&n->c, keys->node_id, keys->network_key, keys->pseudo_secret, keys->x25519_sk,
            keys->watchtower_pk, hw->rng, hw->ctx);
    for (int i = 0; i < keys->peer_count; i++)
        if (!gm_add_peer(&n->c, keys->peers[i].id, keys->peers[i].pk))
            emit(n, "{\"ev\":\"error\",\"reason\":\"add_peer_failed\"}");
    if (state && state_len) {
        if (!gm_state_import(&n->c, state, state_len))
            emit(n, "{\"ev\":\"error\",\"reason\":\"state_import_failed\"}");
    }

    n->plat = (rt_platform_t){
        .transmit = p_transmit, .now_ms = p_now_ms, .random_u32 = p_random_u32, .is_synced = p_is_synced,
        .timer_start = p_timer_start, .timer_cancel = p_timer_cancel,
        .link_tag_ok = p_link_tag_ok, .compute_link_tag = p_compute_link_tag,
        .encrypt = p_encrypt, .try_decrypt = p_try_decrypt,
        .is_blocked = p_is_blocked, .keys_receive = p_keys_receive, .ctrl_verify = p_ctrl_verify,
        .my_pseudonym = p_my_pseudonym, .current_epoch = p_current_epoch,
        .deliver = p_deliver, .notify = p_notify, .log = p_log,
    };
    rt_default_config(&n->rt_cfg, keys->node_id);
    rt_init(&n->rt, &n->rt_cfg, &n->plat, n);
}

void gm_node_rx(gm_node_t *n, const uint8_t frame[240], const uint8_t mac[6], int8_t rssi)
{
    n->st.rx_frames++;
    n->st.last_rssi = rssi;
    uint64_t now = local_ms(n);
    n->st.last_rx_local = now;

    /* neighbour table for the OLED (by radio MAC) */
    int slot = -1, oldest = 0;
    for (int i = 0; i < 8; i++) {
        if (!memcmp(n->st.heard[i].mac, mac, 6)) { slot = i; break; }
        if (n->st.heard[i].at < n->st.heard[oldest].at) oldest = i;
    }
    if (slot < 0) { slot = oldest; memcpy(n->st.heard[slot].mac, mac, 6); }
    n->st.heard[slot].rssi = rssi;
    n->st.heard[slot].at = now;

    /* topology control (§8): applied before routing, so a filtered frame looks like it never arrived */
    if (rssi < n->rssi_gate) { n->st.gate_drops++; return; }
    if (n->allow_n) {
        bool ok = false;
        for (int i = 0; i < n->allow_n && !ok; i++) ok = !memcmp(n->allow[i], mac, 6);
        if (!ok) { n->st.allow_drops++; return; }
    }

    rt_frame_t f;
    memcpy(&f, frame, sizeof f);
    for (int i = 0; i < GM_NODE_OWN_ECHO; i++)
        if (!memcmp(n->own_echo[i], f.msg_id, 8)) { n->st.own_echo_drops++; return; }

    memcpy(n->cur_rx_mac, mac, 6);

    bool was_synced = n->c.synced;
    rt_on_receive(&n->rt, &f, mac, rssi);

    /* routing.c (Rashad's first-beacon fix) now takes the first signed TIME beacon while unsynced
     * and syncs the clock (c.synced flips here), but it does not relay that beacon under the board's
     * old identity. gm_tick still has to run to initialise the epoch chain and switch the MAC, and
     * node_ready() / p_is_synced keeps routing from relaying anything until it has. Force that tick
     * onto the very next poll instead of waiting up to a full tick period, so the board becomes
     * relay-ready in one poll and never transmits under its factory MAC (first-sync race §3.1). */
    if (!was_synced && n->c.synced) n->next_tick_local = 0;
}

static bool try_send_now(gm_node_t *n, char to, const uint8_t *text, uint8_t len)
{
    uint32_t id = peer_id_by_name(n, to);
    if (!id) { emit(n, "{\"ev\":\"error\",\"reason\":\"unknown_peer\"}"); return true; }   /* drop, don't queue */
    n->sending_to = to;
    uint32_t h = rt_send(&n->rt, id, text, len);
    if (!h) return false;
    for (int i = 0; i < RT_MAX_OUTSTANDING; i++)
        if (!n->handles[i].handle) { n->handles[i].handle = h; n->handles[i].to = to; break; }
    return true;
}

bool gm_node_send(gm_node_t *n, char to, const char *text, size_t len)
{
    if (len > RT_BODY_MAX) { emit(n, "{\"ev\":\"error\",\"reason\":\"too_long\"}"); return false; }
    if (node_ready(n) && try_send_now(n, to, (const uint8_t *)text, (uint8_t)len)) return true;
    if (node_ready(n)) { emit(n, "{\"ev\":\"error\",\"reason\":\"busy\"}"); return false; }
    if (n->sendq_n >= GM_NODE_SENDQ) { emit(n, "{\"ev\":\"error\",\"reason\":\"queue_full\"}"); return false; }
    n->sendq[n->sendq_n].to = to;
    n->sendq[n->sendq_n].len = (uint8_t)len;
    memcpy(n->sendq[n->sendq_n].text, text, len);
    n->sendq_n++;
    char buf[64];
    snprintf(buf, sizeof buf, "{\"ev\":\"queued\",\"to\":\"%c\",\"waiting\":%u}", to, n->sendq_n);
    emit(n, buf);
    return true;
}

static void flush_sendq(gm_node_t *n)
{
    while (n->sendq_n && node_ready(n)) {
        if (!try_send_now(n, n->sendq[0].to, n->sendq[0].text, n->sendq[0].len)) return;   /* busy: later */
        memmove(&n->sendq[0], &n->sendq[1], sizeof n->sendq[0] * (size_t)(n->sendq_n - 1));
        n->sendq_n--;
    }
}

void gm_node_debug_set_time(gm_node_t *n, uint64_t unix_ms)
{
    bool ok = gm_clock_on_beacon(&n->c, unix_ms, local_ms(n));
    char buf[96];
    snprintf(buf, sizeof buf, "{\"ev\":\"debug_time\",\"accepted\":%s,\"unix_ms\":%llu}",
             ok ? "true" : "false", (unsigned long long)unix_ms);
    emit(n, buf);
    n->next_tick_local = 0;    /* run gm_tick on the next poll */
}

static void set_epoch_mac(gm_node_t *n)
{
    if (!n->rotate_mac || !n->hw.set_mac) return;
    uint8_t mac[6];
    gm_mac(n->c.pseudo_secret, gm_node_wire_epoch(n), mac);
    n->st.last_mac_outage_us = n->hw.set_mac(n->hw.ctx, mac);
}

static void emit_peer_mask(gm_node_t *n, const char *ev, uint8_t mask)
{
    for (int i = 0; i < GM_MAX_PEERS; i++) {
        if (!(mask & (1u << i)) || !n->c.peers[i].used) continue;
        char buf[64];
        snprintf(buf, sizeof buf, "{\"ev\":\"%s\",\"peer\":\"%c\"}", ev, gm_node_peer_name(n, n->c.peers[i].node_id));
        emit(n, buf);
    }
}

void gm_node_poll(gm_node_t *n)
{
    fire_due_timers(n);

    uint64_t now = local_ms(n);
    if (now < n->next_tick_local) return;
    n->next_tick_local = now + 100;

    gm_events_t ev;
    memset(&ev, 0, sizeof ev);
    gm_tick(&n->c, now, &ev);

    /* gm_tick only raises synced_now on a board's first boot; after a reboot with saved state
     * the clock still syncs, so detect the transition ourselves */
    bool newly_synced = n->c.synced && !n->was_synced;
    n->was_synced = n->c.synced;
    if (ev.synced_now || newly_synced) {
        set_epoch_mac(n);
        char buf[96];
        snprintf(buf, sizeof buf, "{\"ev\":\"synced\",\"epoch\":%u,\"mac_outage_us\":%lu}",
                 gm_node_wire_epoch(n), (unsigned long)n->st.last_mac_outage_us);
        emit(n, buf);
    }
    if (ev.epoch_changed) {
        n->pseudo_valid = false;
        set_epoch_mac(n);
        uint8_t ps[4]; char psh[9], buf[128];
        gm_node_pseudonym(n, ps);
        hex(ps, 4, psh);
        snprintf(buf, sizeof buf, "{\"ev\":\"epoch\",\"epoch\":%u,\"pseudo\":\"%s\",\"mac_outage_us\":%lu}",
                 gm_node_wire_epoch(n), psh, (unsigned long)n->st.last_mac_outage_us);
        emit(n, buf);
    }
    if (ev.keys_due && n->c.synced) send_keys(n);
    if (ev.state_changed && n->hw.save_state) {
        static uint8_t blob[GM_STATE_BYTES];
        size_t len = gm_state_export(&n->c, blob, sizeof blob);
        if (len) n->hw.save_state(n->hw.ctx, blob, len);
    }
    if (ev.no_beacon) emit(n, "{\"ev\":\"no_beacon\",\"secs\":30}");
    if (ev.no_dh_mask) emit_peer_mask(n, "no_dh", ev.no_dh_mask);
    if (ev.resync_mask) emit_peer_mask(n, "resync", ev.resync_mask);

    flush_sendq(n);
}

void gm_node_status(gm_node_t *n)
{
    char buf[640];
    uint8_t ps[4]; char psh[9];
    gm_node_pseudonym(n, ps);
    hex(ps, 4, psh);
    const uint32_t *L = n->st.log_counts;
    snprintf(buf, sizeof buf,
             "{\"ev\":\"status\",\"name\":\"%c\",\"synced\":%s,\"mesh_ms\":%llu,\"epoch\":%u,\"pseudo\":\"%s\","
             "\"rx\":%lu,\"tx\":%lu,\"keys_sent\":%lu,\"beacons\":%lu,\"delivered\":%lu,\"acked\":%lu,"
             "\"failed\":%lu,\"relayed\":%lu,\"dup\":%lu,\"cancelled\":%lu,\"bad_link_tag\":%lu,"
             "\"bad_epoch\":%lu,\"blocked\":%lu,\"not_synced\":%lu,\"stale\":%lu,\"rate_limited\":%lu,"
             "\"gate_drops\":%lu,\"allow_drops\":%lu,\"queued\":%u,\"mac_outage_us\":%lu}",
             n->keys.name, n->c.synced ? "true" : "false", (unsigned long long)gm_node_mesh_ms(n),
             gm_node_wire_epoch(n), psh, (unsigned long)n->st.rx_frames, (unsigned long)n->st.tx_frames,
             (unsigned long)n->st.keys_sent, (unsigned long)n->st.beacons_ok,
             (unsigned long)L[RT_LOG_DELIVERED], (unsigned long)L[RT_LOG_ACK_MATCHED],
             (unsigned long)L[RT_LOG_SEND_FAILED], (unsigned long)L[RT_LOG_RELAY_SCHEDULED],
             (unsigned long)(L[RT_LOG_DUPLICATE] + L[RT_LOG_DUP_COUNTED]), (unsigned long)L[RT_LOG_RELAY_CANCELLED],
             (unsigned long)L[RT_LOG_BAD_LINK_TAG], (unsigned long)L[RT_LOG_BAD_EPOCH],
             (unsigned long)L[RT_LOG_BLOCKED], (unsigned long)L[RT_LOG_NOT_SYNCED],
             (unsigned long)L[RT_LOG_REPLAY_STALE], (unsigned long)L[RT_LOG_RATE_LIMITED],
             (unsigned long)n->st.gate_drops, (unsigned long)n->st.allow_drops, n->sendq_n,
             (unsigned long)n->st.last_mac_outage_us);
    emit(n, buf);
}

void gm_node_boot_banner(gm_node_t *n, const char *fw_version)
{
    char self[10], net[10], wt[10], buf[200];
    gm_fingerprint(n->c.x_pk, self);
    gm_fingerprint(n->c.network_key, net);
    gm_fingerprint(n->c.watchtower_pk, wt);
    snprintf(buf, sizeof buf,
             "{\"ev\":\"boot\",\"name\":\"%c\",\"id\":%lu,\"fw\":\"%s\",\"peers\":%d,"
             "\"fp\":{\"self\":\"%s\",\"network\":\"%s\",\"watchtower\":\"%s\"}}",
             n->keys.name, (unsigned long)n->keys.node_id, fw_version, n->keys.peer_count, self, net, wt);
    emit(n, buf);
}

void gm_node_bench(gm_node_t *n, uint32_t runs)
{
    if (!node_ready(n)) { emit(n, "{\"ev\":\"error\",\"reason\":\"not_ready\"}"); return; }

    int pi = -1;
    for (int i = 0; i < GM_MAX_PEERS; i++)
        if (n->c.peers[i].used) { pi = i; break; }
    if (pi < 0) { emit(n, "{\"ev\":\"error\",\"reason\":\"no_peer\"}"); return; }

    if (runs == 0) runs = 2000;
    if (runs > 50000) runs = 50000;             /* keep the processing task well under the watchdog */

    rt_inner_t in;
    memset(&in, 0, sizeof in);
    in.sender_id    = n->keys.node_id;
    in.recipient_id = n->c.peers[pi].node_id;
    in.timestamp    = (uint32_t)gm_node_mesh_ms(n);
    in.type         = RT_TYPE_DATA;
    in.len          = 16;
    memset(in.body, 0x5a, in.len);

    /* encrypt: fill the AEAD-authenticated cleartext header once (gm_encrypt makes its own nonce). */
    rt_frame_t f;
    memset(&f, 0, sizeof f);
    f.ver_type = RT_FRAME_DATA;
    f.flags = 0;
    n->hw.rng(n->hw.ctx, f.msg_id, 8);
    gm_put_be16(f.epoch, gm_node_wire_epoch(n));

    uint64_t t0 = local_ms(n);
    for (uint32_t i = 0; i < runs; i++) gm_encrypt(&n->c, &in, &f);
    uint64_t enc_ms = local_ms(n) - t0;         /* f now holds a valid frame addressed to the peer */

    /* decrypt: trial-decrypt that frame. The pair key (me,peer) is symmetric, so the AEAD open
     * succeeds; the recipient_id != me check then rejects it. Either way this times a full
     * per-message decrypt attempt, the cost every relayed frame pays. */
    rt_inner_t out;
    uint64_t t1 = local_ms(n);
    for (uint32_t i = 0; i < runs; i++) gm_try_decrypt(&n->c, &f, &out);
    uint64_t dec_ms = local_ms(n) - t1;

    char buf[192];
    snprintf(buf, sizeof buf,
             "{\"ev\":\"bench\",\"runs\":%lu,\"peer\":\"%c\",\"enc_ms\":%lu,\"dec_ms\":%lu,"
             "\"enc_us\":%lu,\"dec_us\":%lu}",
             (unsigned long)runs, gm_node_peer_name(n, n->c.peers[pi].node_id),
             (unsigned long)enc_ms, (unsigned long)dec_ms,
             (unsigned long)(enc_ms * 1000u / runs), (unsigned long)(dec_ms * 1000u / runs));
    emit(n, buf);
}
