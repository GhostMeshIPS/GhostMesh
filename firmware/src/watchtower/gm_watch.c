/*
 * gm_watch.c - see gm_watch.h. Spec: PROTOCOL.md §9.2 (TIME beacon), §9.8 (BLOCK), ips/schema.py (log line).
 */
#include "gm_watch.h"

#include <stdio.h>
#include <string.h>

static uint64_t local_ms(gm_watch_t *w) { return w->hw.local_ms(w->hw.ctx); }
static void emit(gm_watch_t *w, const char *s) { w->hw.emit(w->hw.ctx, s); }

static void hex(const uint8_t *p, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = d[p[i] >> 4]; out[2 * i + 1] = d[p[i] & 15]; }
    out[2 * n] = '\0';
}

static void mac_str(const uint8_t m[6], char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static const char *type_name(uint8_t vt)
{
    switch (vt) {
    case RT_FRAME_DATA:  return "DATA";
    case RT_FRAME_HELLO: return "HELLO";
    case RT_FRAME_CTRL:  return "CTRL";
    case RT_FRAME_KEYS:  return "KEYS";
    default:             return "UNKNOWN";
    }
}

static uint8_t reason_code(const char *r)
{
    if (!r) return 0;
    if (!strcmp(r, "flood"))   return 1;
    if (!strcmp(r, "replay"))  return 2;
    if (!strcmp(r, "spoof"))   return 3;
    if (!strcmp(r, "routing")) return 4;
    return 0;
}

uint64_t gm_watch_now(gm_watch_t *w)
{
    return w->clock_set ? (uint64_t)((int64_t)local_ms(w) + w->offset_ms) : 0;
}

static uint32_t abs_epoch(gm_watch_t *w) { return (uint32_t)(gm_watch_now(w) / 60000u); }

/* Pseudonym + MAC of every node for epochs e-1, e, e+1 (frames may be ±1 epoch off, §9.4). */
static void build_table(gm_watch_t *w, uint32_t e)
{
    w->table_epoch = e;
    for (int k = 0; k < 3; k++) {
        uint16_t wire = gm_wire_epoch(e - 1 + (uint32_t)k);
        for (int i = 0; i < w->keys.node_count; i++) {
            gm_pseudonym(w->keys.nodes[i].pseudo_secret, wire, w->pseudo[k][i]);
            gm_mac(w->keys.nodes[i].pseudo_secret, wire, w->mac[k][i]);
        }
    }
}

char gm_watch_identify(gm_watch_t *w, const uint8_t pseudo[4], const uint8_t mac[6], bool *mac_matches)
{
    *mac_matches = false;
    for (int k = 0; k < 3; k++)
        for (int i = 0; i < w->keys.node_count; i++)
            if (!memcmp(w->pseudo[k][i], pseudo, 4)) {
                *mac_matches = mac && !memcmp(w->mac[k][i], mac, 6);
                return w->keys.nodes[i].name;
            }
    return '?';
}

/* Build, sign and broadcast one CTRL frame. */
static bool send_ctrl(gm_watch_t *w, uint8_t subtype, const uint8_t *payload, size_t plen)
{
    rt_frame_t f;
    memset(&f, 0, sizeof f);
    uint64_t now = gm_watch_now(w);
    if (!gm_ctrl_sign(&w->c, w->keys.sk, subtype, now, payload, plen, f.ciphertext)) {
        emit(w, "{\"ev\":\"error\",\"reason\":\"ctrl_sign_failed\"}");
        return false;
    }
    f.ver_type = RT_FRAME_CTRL;
    w->hw.rng(w->hw.ctx, f.msg_id, 8);
    f.ttl = 7;                                         /* routing's default TTL */
    w->hw.rng(w->hw.ctx, f.src_pseudo, 4);             /* W has no pseudonym secret of its own */
    gm_put_be16(f.epoch, gm_wire_epoch(abs_epoch(w)));
    w->hw.rng(w->hw.ctx, f.nonce, sizeof f.nonce);
    w->hw.rng(w->hw.ctx, f.aead_tag, sizeof f.aead_tag);
    gm_link_tag(w->keys.network_key, &f, f.link_tag);
    w->last_ctrl_local = local_ms(w);
    w->any_ctrl_sent = true;
    memcpy(w->own_ids[w->own_i], f.msg_id, 8);         /* so relayed copies get logged as node "W" */
    w->own_i = (uint8_t)((w->own_i + 1) % GM_WATCH_OWN_IDS);
    w->hw.transmit(w->hw.ctx, (const uint8_t *)&f);
    return true;
}

static int node_index(gm_watch_t *w, char name)
{
    for (int i = 0; i < w->keys.node_count; i++) if (w->keys.nodes[i].name == name) return i;
    return -1;
}

/* BLOCK payload: block_id(4) until_ms(8) reason(1) 2 x [pseudo(4) mac(6) epoch(2)] */
static bool send_block(gm_watch_t *w, const gm_watch_block_t *b, uint64_t until_ms)
{
    uint8_t p[GM_CTRL_BLOCK_PAYLOAD_BYTES];
    memset(p, 0, sizeof p);
    gm_put_be32(p, b->block_id);
    gm_put_be64(p + 4, until_ms);
    p[12] = b->reason;
    uint32_t e = abs_epoch(w);
    int ni = node_index(w, b->node);
    if (ni >= 0) {
        /* known node: this epoch and the next, so the block holds across the boundary */
        for (int k = 0; k < 2; k++) {
            uint16_t wire = gm_wire_epoch(e + (uint32_t)k);
            gm_pseudonym(w->keys.nodes[ni].pseudo_secret, wire, p + 13 + 12 * k);
            gm_mac(w->keys.nodes[ni].pseudo_secret, wire, p + 17 + 12 * k);
            gm_put_be16(p + 23 + 12 * k, wire);
        }
    } else {
        memcpy(p + 13, b->pseudo, 4);
        memcpy(p + 17, b->mac, 6);
        gm_put_be16(p + 23, gm_wire_epoch(e));
    }
    return send_ctrl(w, GM_CTRL_BLOCK, p, sizeof p);
}

void gm_watch_init(gm_watch_t *w, const gm_watch_keys_t *keys, const gm_hw_t *hw)
{
    memset(w, 0, sizeof *w);
    w->keys = *keys;
    w->hw = *hw;
    w->next_block_id = 1;
    /* gm_ctrl_sign only needs the context's RNG; the key arguments are unused placeholders */
    gm_init(&w->c, 5, keys->network_key, keys->network_key, keys->network_key, keys->pk, hw->rng, hw->ctx);
    for (int i = 0; i < GM_WATCH_MAX_NODES; i++) w->per_node_rssi[i] = -127;
}

void gm_watch_set_time(gm_watch_t *w, uint64_t unix_ms)
{
    w->offset_ms = (int64_t)unix_ms - (int64_t)local_ms(w);
    w->clock_set = true;
    build_table(w, abs_epoch(w));
    w->next_beacon_local = 0;                          /* beacon right away */
    w->any_ctrl_sent = false;
    char buf[96];
    snprintf(buf, sizeof buf, "{\"ev\":\"clock_set\",\"unix_ms\":%llu,\"epoch\":%u}",
             (unsigned long long)unix_ms, gm_wire_epoch(abs_epoch(w)));
    emit(w, buf);
}

void gm_watch_poll(gm_watch_t *w)
{
    if (!w->clock_set) return;
    uint64_t now = gm_watch_now(w);
    uint32_t e = abs_epoch(w);

    if (e != w->table_epoch) {
        build_table(w, e);
        int reissued = 0;
        for (int i = 0; i < GM_WATCH_MAX_BLOCKS; i++) {
            gm_watch_block_t *b = &w->blocks[i];
            if (!b->used) continue;
            if (now >= b->until_ms) { b->used = false; continue; }
            if (b->node == '?') { b->used = false; continue; }   /* pair blocks end at rotation (O9) */
            b->send_due = true;                                  /* goes out when the CTRL gap allows */
            reissued++;
        }
        char buf[80];
        snprintf(buf, sizeof buf, "{\"ev\":\"epoch\",\"epoch\":%u,\"blocks_reissued\":%d}", gm_wire_epoch(e), reissued);
        emit(w, buf);
    }

    /* One CTRL frame per gap. Order: unblocks, then blocks, then the beacon (a late beacon is harmless). */
    if (w->any_ctrl_sent && local_ms(w) - w->last_ctrl_local < GM_WATCH_CTRL_GAP_MS) return;
    for (int i = 0; i < GM_WATCH_MAX_BLOCKS; i++) {
        gm_watch_block_t *b = &w->blocks[i];
        if (!b->used || !b->unblock_due) continue;
        send_block(w, b, gm_watch_now(w));              /* until == issued: nodes drop the block */
        b->used = false;
        char buf[80];
        snprintf(buf, sizeof buf, "{\"ev\":\"unblock_sent\",\"block_id\":%lu}", (unsigned long)b->block_id);
        emit(w, buf);
        return;
    }
    for (int i = 0; i < GM_WATCH_MAX_BLOCKS; i++) {
        gm_watch_block_t *b = &w->blocks[i];
        if (!b->used || !b->send_due) continue;
        b->send_due = false;
        if (!send_block(w, b, b->until_ms)) return;
        w->blocks_sent++;
        char buf[128];
        snprintf(buf, sizeof buf, "{\"ev\":\"block_sent\",\"block_id\":%lu,\"node\":\"%c\",\"reason\":%u,\"until_ms\":%llu}",
                 (unsigned long)b->block_id, b->node, b->reason, (unsigned long long)b->until_ms);
        emit(w, buf);
        return;
    }
    if (local_ms(w) >= w->next_beacon_local) {
        w->next_beacon_local = local_ms(w) + GM_WATCH_BEACON_MS;
        if (send_ctrl(w, GM_CTRL_TIME, NULL, 0)) w->beacons_sent++;
    }
}

void gm_watch_rx(gm_watch_t *w, const uint8_t frame[240], const uint8_t mac[6], int8_t rssi,
                 const gm_watch_meta_t *meta)
{
    const rt_frame_t *f = (const rt_frame_t *)frame;
    w->frames++;
    bool link_ok = gm_link_tag_ok(w->keys.network_key, f);
    if (!link_ok) w->bad_tag_frames++;

    char node = '?';
    bool id_ok = false;
    for (int i = 0; i < GM_WATCH_OWN_IDS; i++)
        if (!memcmp(w->own_ids[i], f->msg_id, 8)) { node = 'W'; id_ok = true; break; }
    if (node == '?') node = gm_watch_identify(w, f->src_pseudo, mac, &id_ok);
    if (node == '?') w->unknown_frames++;
    int ni = node_index(w, node);
    if (ni >= 0 && ni < GM_WATCH_MAX_NODES) { w->per_node_frames[ni]++; w->per_node_rssi[ni] = rssi; }

    uint64_t t = w->clock_set ? gm_watch_now(w) : local_ms(w);
    static char buf[900];                              /* one caller (the processing task): static is fine */
    char macs[18], ps[9], id[17], raw[481];
    mac_str(mac, macs);
    hex(f->src_pseudo, 4, ps);
    hex(f->msg_id, 8, id);
    hex(frame, 240, raw);
    int n = snprintf(buf, sizeof buf,
             "{\"t\":%llu.%03u,\"mac\":\"%s\",\"pseudo\":\"%s\",\"type\":\"%s\",\"msg_id\":\"%s\","
             "\"ttl\":%u,\"hop\":%u,\"rssi\":%d,\"len\":240,\"link_ok\":%s,\"node\":\"%c\",\"id_ok\":%s,"
             "\"epoch\":%u,\"flags\":%u",
             (unsigned long long)(t / 1000), (unsigned)(t % 1000), macs, ps, type_name(f->ver_type), id,
             f->ttl, f->hop_count, rssi, link_ok ? "true" : "false", node, id_ok ? "true" : "false",
             gm_get_be16(f->epoch), f->flags);
    if (meta)
        n += snprintf(buf + n, sizeof buf - (size_t)n, ",\"rx_us\":%lu,\"rate\":%u,\"sig_mode\":%u,\"mcs\":%u",
                      (unsigned long)meta->rx_us, meta->rate, meta->sig_mode, meta->mcs);
    snprintf(buf + n, sizeof buf - (size_t)n, ",\"raw\":\"%s\"}", raw);
    emit(w, buf);
}

uint32_t gm_watch_block(gm_watch_t *w, char node, const uint8_t pseudo[4], const uint8_t mac[6],
                        const char *reason, uint64_t until_ms)
{
    if (!w->clock_set) { emit(w, "{\"ev\":\"error\",\"reason\":\"clock_not_set\"}"); return 0; }
    if (node != '?' && node_index(w, node) < 0) { emit(w, "{\"ev\":\"error\",\"reason\":\"unknown_node\"}"); return 0; }
    gm_watch_block_t *b = NULL;
    for (int i = 0; i < GM_WATCH_MAX_BLOCKS && !b; i++) {        /* same target: update it */
        gm_watch_block_t *x = &w->blocks[i];
        if (!x->used) continue;
        if ((node != '?' && x->node == node) ||
            (node == '?' && x->node == '?' && pseudo && !memcmp(x->pseudo, pseudo, 4))) b = x;
    }
    for (int i = 0; i < GM_WATCH_MAX_BLOCKS && !b; i++) if (!w->blocks[i].used) b = &w->blocks[i];
    if (!b) { emit(w, "{\"ev\":\"error\",\"reason\":\"block_table_full\"}"); return 0; }
    if (!b->used) b->block_id = w->next_block_id++;
    b->used = true;
    b->node = node;
    if (pseudo) memcpy(b->pseudo, pseudo, 4); else memset(b->pseudo, 0, 4);
    if (mac) memcpy(b->mac, mac, 6); else memset(b->mac, 0, 6);
    b->reason = reason_code(reason);
    b->until_ms = until_ms;
    b->unblock_due = false;
    b->send_due = true;
    char buf[96];
    snprintf(buf, sizeof buf, "{\"ev\":\"block_queued\",\"block_id\":%lu,\"node\":\"%c\"}", (unsigned long)b->block_id, node);
    emit(w, buf);
    gm_watch_poll(w);                                  /* send now if the gap allows */
    return b->block_id;
}

bool gm_watch_unblock(gm_watch_t *w, char node, const uint8_t pseudo[4], const uint8_t mac[6])
{
    (void)mac;
    for (int i = 0; i < GM_WATCH_MAX_BLOCKS; i++) {
        gm_watch_block_t *b = &w->blocks[i];
        if (!b->used) continue;
        bool match = node != '?' ? b->node == node : (b->node == '?' && pseudo && !memcmp(b->pseudo, pseudo, 4));
        if (!match) continue;
        b->send_due = false;
        b->unblock_due = true;                         /* sent by gm_watch_poll when the gap allows */
        gm_watch_poll(w);
        return true;
    }
    emit(w, "{\"ev\":\"error\",\"reason\":\"no_such_block\"}");
    return false;
}

void gm_watch_status(gm_watch_t *w)
{
    char buf[512];
    int n = snprintf(buf, sizeof buf,
                     "{\"ev\":\"status\",\"name\":\"W\",\"clock_set\":%s,\"mesh_ms\":%llu,\"epoch\":%u,"
                     "\"frames\":%lu,\"beacons\":%lu,\"blocks_sent\":%lu,\"unknown\":%lu,\"bad_link_tag\":%lu,\"nodes\":{",
                     w->clock_set ? "true" : "false", (unsigned long long)gm_watch_now(w),
                     w->clock_set ? gm_wire_epoch(abs_epoch(w)) : 0, (unsigned long)w->frames,
                     (unsigned long)w->beacons_sent, (unsigned long)w->blocks_sent,
                     (unsigned long)w->unknown_frames, (unsigned long)w->bad_tag_frames);
    for (int i = 0; i < w->keys.node_count && i < GM_WATCH_MAX_NODES && n < (int)sizeof buf - 48; i++)
        n += snprintf(buf + n, sizeof buf - (size_t)n, "%s\"%c\":{\"frames\":%lu,\"rssi\":%d}", i ? "," : "",
                      w->keys.nodes[i].name, (unsigned long)w->per_node_frames[i], w->per_node_rssi[i]);
    snprintf(buf + n, sizeof buf - (size_t)n, "}}");
    emit(w, buf);
}
