/*
 * routing.c - GhostMesh v1 forwarding (managed flooding)
 * Spec: PROTOCOL.md §5.1 (receive), §5.2 (send), §5.3 (relay timing), §9 (security rules routing enforces).
 * Node IDs in comments (LT, SC, PR, ...) match the Mermaid charts.
 */
#include "routing.h"

#include <string.h>

/* ---- Timer tokens: kind in the top byte, table slot below ------------- */
enum { RT_TIMER_RELAY = 1, RT_TIMER_RETRY = 2, RT_TIMER_ACK = 3 };

static uint32_t make_token(uint8_t kind, uint32_t slot) { return ((uint32_t)kind << 24) | (slot & 0xFFFFFFu); }
static uint8_t  token_kind(uint32_t token)              { return (uint8_t)(token >> 24); }
static uint32_t token_slot(uint32_t token)              { return token & 0xFFFFFFu; }

/* ---- Small helpers ------------------------------------------------------ */

// epoch is big-endian on the wire (§9)
static uint16_t get_be16(const uint8_t *p)        { return (uint16_t)((p[0] << 8) | p[1]); }
static void     put_be16(uint8_t *p, uint16_t v)  { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

// fills a buffer with random bytes from the platform RNG (used for msg_ids)
static void random_bytes(rt_node_t *n, uint8_t *out, int len)
{
    for (int i = 0; i < len; i += 4) {
        uint32_t r = n->p->random_u32(n->ctx);
        for (int b = 0; b < 4 && i + b < len; b++) out[i + b] = (uint8_t)(r >> (8 * b));
    }
}

/* ---- Forward declarations --------------------------------------------- */
static int  cache_find(rt_node_t *n, const uint8_t msg_id[8]);
static int  cache_insert(rt_node_t *n, const uint8_t msg_id[8]);
static bool long_find(rt_node_t *n, const uint8_t msg_id[8]);
static void long_insert(rt_node_t *n, const uint8_t msg_id[8]);
static bool insert_allowed(rt_node_t *n, const rt_frame_t *f, const uint8_t src_mac[6]);
static bool epoch_ok(rt_node_t *n, const rt_frame_t *f);
static bool is_fresh(rt_node_t *n, uint32_t timestamp);
static void handle_ack(rt_node_t *n, const rt_inner_t *in, const rt_frame_t *f);
static void handle_data(rt_node_t *n, const rt_inner_t *in, const rt_frame_t *f);
static void queue_ack(rt_node_t *n, uint32_t recipient_id, uint32_t seq, const uint8_t msg_id[8]);
static void ack_fire(rt_node_t *n, int slot);
static void relay_schedule(rt_node_t *n, int slot, const rt_frame_t *f, int8_t rssi);
static void relay_fire(rt_node_t *n, int slot);
static uint32_t jitter_ms(rt_node_t *n, int8_t rssi);
static bool build_and_send(rt_node_t *n, uint8_t type, uint32_t recipient_id, uint32_t seq,
                           const uint8_t *body, uint8_t len, int out_slot);
static void retry_fire(rt_node_t *n, int out_slot);
static rt_peer_t *peer_get(rt_node_t *n, uint32_t peer_id);
static bool seq_seen(rt_node_t *n, const rt_peer_t *peer, uint32_t seq);
static void seq_remember(rt_node_t *n, rt_peer_t *peer, uint32_t seq);

/* ---- Entry points ------------------------------------------------------ */

void rt_default_config(rt_config_t *cfg, uint32_t node_id)
{
    // current §12 values. default_ttl is still TBD at the freeze (3 hops + 2 for hop padding)
    memset(cfg, 0, sizeof *cfg);
    cfg->node_id              = node_id;
    cfg->default_ttl          = 5;
    cfg->hop_pad_max          = 2;
    cfg->k                    = 2;
    cfg->jitter_rand_pct      = 50;
    cfg->jitter_min_ms        = 10;
    cfg->jitter_max_ms        = 50;
    cfg->rssi_weak            = -90;
    cfg->rssi_strong          = -40;
    cfg->cache_expiry_ms      = 60000;
    cfg->long_cache_expiry_ms = 180000;
    cfg->insert_limit_per_s   = 20;
    cfg->ack_delay_max_ms     = 400;
    cfg->fresh_ms             = 5000;
    cfg->seq_memory_ms        = 15000;
    cfg->retry_backoff_ms[0]  = 1000;
    cfg->retry_backoff_ms[1]  = 2000;
    cfg->retry_backoff_ms[2]  = 4000;
}

void rt_init(rt_node_t *n, const rt_config_t *cfg, const rt_platform_t *p, void *ctx)
{
    memset(n, 0, sizeof *n);
    n->cfg = *cfg;
    n->p = p;
    n->ctx = ctx;
    n->next_handle = 1; /* 0 means "rejected" */
}

void rt_on_receive(rt_node_t *n, const rt_frame_t *f, const uint8_t src_mac[6], int8_t rssi)
{
    // sync state when the frame ARRIVED. a TIME beacon can sync the node partway through this
    // function, but its epoch / pseudonym / MAC only switch on the firmware's next tick, so a frame
    // that arrived before sync must never be relayed (it would go out under the old identity)
    bool was_synced = n->p->is_synced(n->ctx);

    // (LT) checks the link_tag first so outsiders get dropped before anything else
    if(!n->p->link_tag_ok(n->ctx, f)){
        n->p->log(n->ctx, RT_LOG_BAD_LINK_TAG, f);
        return;
    }

    // drops anything from a blocked transmitter right away, these never get relayed (§9.8)
    if(n->p->is_blocked(n->ctx, f, src_mac)){
        n->p->log(n->ctx, RT_LOG_BLOCKED, f);
        return;
    }

    // only the previous, current, or next epoch is accepted (§9.2).
    // exception: an unsynced node has no real epoch yet (it's 0), so it has to let a TIME beacon
    // through or it could never sync. the signature + "newer than last" checks in ctrl_verify still apply
    bool first_beacon = !was_synced && f->ver_type == RT_FRAME_CTRL && f->ciphertext[0] == RT_CTRL_TIME;
    if(!first_beacon && !epoch_ok(n, f)){
        n->p->log(n->ctx, RT_LOG_BAD_EPOCH, f);
        return;
    }

    // HELLO is 1 hop only and v1 doesn't use it (v2 route learning will). unknown types get dropped
    if(f->ver_type == RT_FRAME_HELLO){
        n->p->log(n->ctx, RT_LOG_HELLO, f);
        return;
    }
    if(f->ver_type != RT_FRAME_DATA && f->ver_type != RT_FRAME_CTRL && f->ver_type != RT_FRAME_KEYS){
        n->p->log(n->ctx, RT_LOG_BAD_TYPE, f);
        return;
    }

    int slot = cache_find(n, f->msg_id);
    if (slot >= 0){                                                          // (SC) checks if msg_id is already in cache
        rt_cache_entry_t *e = &n->cache[slot];
        if(e->relay_pending){                                                // (PR) checks if there's a pending relay
            e->dup_count++;
            if(e->dup_count >= n->cfg.k) {                                   // (KC) checks if the # of duplicates reached k
                n->p->timer_cancel(n->ctx, make_token(RT_TIMER_RELAY, (uint32_t)slot));
                e->relay_pending = false;
                n->p->log(n->ctx, RT_LOG_RELAY_CANCELLED, f);
            }
            else{
                n->p->log(n->ctx, RT_LOG_DUP_COUNTED, f);
            }
        }
        else{
            n->p->log(n->ctx, RT_LOG_DUPLICATE, f);
        }
        return;
    }

    // older than the seen-cache but still inside the 180 s window means it's a replay, so drop it (§9.7)
    if(long_find(n, f->msg_id)){
        n->p->log(n->ctx, RT_LOG_DUPLICATE, f);
        return;
    }

    // each transmitter can only add so many new msg_ids per second, so nobody can flush the caches (§9.9)
    if(!insert_allowed(n, f, src_mac)){
        n->p->log(n->ctx, RT_LOG_RATE_LIMITED, f);
        return;
    }

    // new frame: remember it in both caches
    slot = cache_insert(n, f->msg_id);
    long_insert(n, f->msg_id);

    // what happens next depends on the cleartext type
    if(f->ver_type == RT_FRAME_KEYS){                                          // KEYS: hand to Jose's key layer, then flood it
        n->p->keys_receive(n->ctx, f);
    }
    else if(f->ver_type == RT_FRAME_CTRL){                                     // CTRL: only relay it if it verifies (§9.8)
        if(!n->p->ctrl_verify(n->ctx, f)){
            n->p->log(n->ctx, RT_LOG_CTRL_UNVERIFIED, f);
            return;
        }
    }
    else{
        rt_inner_t in;
        if (n->p->try_decrypt(n->ctx, f, &in)){                                // (CMD) attempt to decrypt the packet. Then check for ACK or DATA type
            if (in.type == RT_TYPE_ACK) handle_ack(n, &in, f);
            else handle_data(n, &in, f);
        }
    }

    if(f->ttl == 0){                                                           // (TTL) check for ttl == 0
        n->p->log(n->ctx, RT_LOG_TTL_EXPIRED, f);
    }
    else if(!was_synced){                                                      // no relaying anything that arrived before sync (§9.2)
        n->p->log(n->ctx, RT_LOG_NOT_SYNCED, f);
    }
    else{
        relay_schedule(n, slot, f, rssi);
    }
}

uint32_t rt_send(rt_node_t *n, uint32_t recipient_id, const uint8_t *text, uint8_t len)
{
    // (LEN) message is too long for one frame
    if(len > RT_BODY_MAX){
        n->p->log(n->ctx, RT_LOG_TOO_LONG, NULL);
        return 0;
    }

    // not synced yet: firmware queues it and tries again later (§9.2), we just say no
    if(!n->p->is_synced(n->ctx)){
        n->p->log(n->ctx, RT_LOG_NOT_SYNCED, NULL);
        return 0;
    }

    rt_peer_t *peer = peer_get(n, recipient_id);
    if(!peer) return 0;

    // find a free "waiting for ACK" slot
    int slot = -1;
    for(int i = 0; i < RT_MAX_OUTSTANDING; i++){
        if(!n->out[i].used){ slot = i; break; }
    }
    if(slot < 0) return 0;

    // (REGISTER) store everything a retry needs to rebuild the frame
    rt_outstanding_t *o = &n->out[slot];
    memset(o, 0, sizeof *o);
    o->used = true;
    o->handle = n->next_handle++;
    if(n->next_handle == 0) n->next_handle = 1;                                // 0 means "rejected", so skip it on wrap
    o->recipient_id = recipient_id;
    o->seq = peer->next_seq_tx++;
    o->len = len;
    memcpy(o->text, text, len);

    // first attempt
    if(!build_and_send(n, RT_TYPE_DATA, recipient_id, o->seq, o->text, o->len, slot)){
        memset(o, 0, sizeof *o);
        return 0;
    }

    // (FIRST/SENT) only the first attempt tells the laptop it was sent
    n->p->notify(n->ctx, o->handle, RT_STATUS_SENT);
    return o->handle;
}

void rt_on_timer(rt_node_t *n, uint32_t token)
{
    uint32_t slot = token_slot(token);
    switch (token_kind(token)) {
    case RT_TIMER_RELAY: if (slot < RT_CACHE_SIZE)       relay_fire(n, (int)slot); break;
    case RT_TIMER_RETRY: if (slot < RT_MAX_OUTSTANDING)  retry_fire(n, (int)slot); break;
    case RT_TIMER_ACK:   if (slot < RT_MAX_PENDING_ACKS) ack_fire(n, (int)slot);   break;
    default: break;
    }
}

/* ---- Seen-cache --------------------------------------------------------- */

static int cache_find(rt_node_t *n, const uint8_t msg_id[8])
{
    uint32_t now = n->p->now_ms(n->ctx);

    for(int i = 0; i < RT_CACHE_SIZE; i++){
        rt_cache_entry_t *e = &n->cache[i];

        if (!e->used) continue;                                      // slot is empty
        if (now - e->seen_at_ms > n->cfg.cache_expiry_ms) continue;  // expired
        if (memcmp(e->msg_id, msg_id, 8) == 0) return i;             // found the message in cache
    }
    return -1;                                                       // Did not find in cache
}

static int cache_insert(rt_node_t *n, const uint8_t msg_id[8])
{
    uint32_t now = n->p->now_ms(n->ctx);
    int victim = -1;
    uint32_t oldest_age = 0;

    for(int i = 0; i < RT_CACHE_SIZE; i++){     //searching through slots (find unused/expired/oldest)
        rt_cache_entry_t *e = &n->cache[i];
        if(!e->used){                            //free slot
            victim = i;
            break;
        }

        uint32_t age = now - e->seen_at_ms;
        if(age > n->cfg.cache_expiry_ms){        //expired slot
            victim = i;
            break;
        }
        if(age >= oldest_age){                   //oldest so far
            oldest_age = age;
            victim = i;
        }
    }

    rt_cache_entry_t *e = &n->cache[victim];
    if (e->used && e->relay_pending){           // evicting a live relay
        n->p->timer_cancel(n->ctx, make_token(RT_TIMER_RELAY, (uint32_t)victim));
    }

    memset(e, 0, sizeof *e);                    //wiping the slot and filling it in (clears relay_pending, dup_count, pending frame)
    e->used = true;
    memcpy(e->msg_id, msg_id, 8);
    e->seen_at_ms = now;
    return victim;
}

/* ---- Long replay cache (§9.7) -------------------------------------------- */

// msg_id only, 180 s. catches replays that already fell out of the 60 s seen-cache
static bool long_find(rt_node_t *n, const uint8_t msg_id[8])
{
    uint32_t now = n->p->now_ms(n->ctx);

    for(int i = 0; i < RT_LONG_CACHE_SIZE; i++){
        rt_long_entry_t *e = &n->long_cache[i];
        if(!e->used) continue;
        if(now - e->seen_at_ms > n->cfg.long_cache_expiry_ms) continue;
        if(memcmp(e->msg_id, msg_id, 8) == 0) return true;
    }
    return false;
}

// ring buffer: entries go in time order, so the next slot is always the oldest one
static void long_insert(rt_node_t *n, const uint8_t msg_id[8])
{
    rt_long_entry_t *e = &n->long_cache[n->long_next];
    n->long_next = (uint16_t)((n->long_next + 1) % RT_LONG_CACHE_SIZE);

    e->used = true;
    memcpy(e->msg_id, msg_id, 8);
    e->seen_at_ms = n->p->now_ms(n->ctx);
}

// per-transmitter limit on new msg_ids per second (§9.9). transmitter = src_pseudo + radio MAC
static bool insert_allowed(rt_node_t *n, const rt_frame_t *f, const uint8_t src_mac[6])
{
    if(n->cfg.insert_limit_per_s == 0) return true;                 // 0 turns the limit off

    uint32_t now = n->p->now_ms(n->ctx);
    rt_tx_track_t *t = NULL;
    rt_tx_track_t *victim = NULL;
    uint32_t oldest_age = 0;

    //looking for this transmitter, or a slot to reuse (free or least recently active)
    for(int i = 0; i < RT_MAX_TX_TRACK; i++){
        rt_tx_track_t *e = &n->tx_track[i];
        if(e->used && memcmp(e->pseudo, f->src_pseudo, 4) == 0 && memcmp(e->mac, src_mac, 6) == 0){
            t = e;
            break;
        }
        uint32_t age = e->used ? now - e->window_start_ms : UINT32_MAX;
        if(!victim || age > oldest_age){ victim = e; oldest_age = age; }
    }

    //new transmitter: start tracking it
    if(!t){
        t = victim;
        t->used = true;
        memcpy(t->pseudo, f->src_pseudo, 4);
        memcpy(t->mac, src_mac, 6);
        t->window_start_ms = now;
        t->count = 0;
    }

    //new 1 second window
    if(now - t->window_start_ms >= 1000){
        t->window_start_ms = now;
        t->count = 0;
    }

    if(t->count >= n->cfg.insert_limit_per_s) return false;
    t->count++;
    return true;
}

/* ---- Receive helpers ---------------------------------------------------- */

// wire epoch is mod 65536, so uint16 math handles the wrap
static bool epoch_ok(rt_node_t *n, const rt_frame_t *f)
{
    uint16_t cur  = n->p->current_epoch(n->ctx);
    uint16_t diff = (uint16_t)(get_be16(f->epoch) - cur);
    return diff == 0 || diff == 1 || diff == 0xFFFF;                // current, next, previous
}

// |now - timestamp| <= fresh_ms, done in unsigned math so clock wrap can't break it
static bool is_fresh(rt_node_t *n, uint32_t timestamp)
{
    uint32_t now   = n->p->now_ms(n->ctx);
    uint32_t ahead = now - timestamp;
    uint32_t back  = timestamp - now;
    uint32_t gap   = ahead < back ? ahead : back;
    return gap <= n->cfg.fresh_ms;
}

static void handle_ack(rt_node_t *n, const rt_inner_t *in, const rt_frame_t *f)
{
    // stale ACKs are replays, ignore them
    if(!is_fresh(n, in->timestamp)){
        n->p->log(n->ctx, RT_LOG_REPLAY_STALE, f);
        return;
    }

    // (MNR) the ACK body is the msg_id it acks. any attempt's msg_id counts, since retries get new ones
    for(int i = 0; i < RT_MAX_OUTSTANDING; i++){
        rt_outstanding_t *o = &n->out[i];
        if(!o->used) continue;

        for(int a = 0; a < o->attempts; a++){
            if(memcmp(o->attempt_ids[a], in->body, 8) == 0){
                n->p->timer_cancel(n->ctx, make_token(RT_TIMER_RETRY, (uint32_t)i));   // stop retrying
                n->p->notify(n->ctx, o->handle, RT_STATUS_DELIVERED);                // laptop shows ✓✓
                n->p->log(n->ctx, RT_LOG_ACK_MATCHED, f);
                memset(o, 0, sizeof *o);
                return;
            }
        }
    }

    // a second ACK for the same message finds nothing, which is fine
    n->p->log(n->ctx, RT_LOG_ACK_UNMATCHED, f);
}

static void handle_data(rt_node_t *n, const rt_inner_t *in, const rt_frame_t *f)
{
    // stale: drop silently, no ACK (§9.7)
    if(!is_fresh(n, in->timestamp)){
        n->p->log(n->ctx, RT_LOG_REPLAY_STALE, f);
        return;
    }

    // (SEQ) have we already delivered this seq from this sender recently?
    rt_peer_t *peer = peer_get(n, in->sender_id);
    bool seen = peer && seq_seen(n, peer, in->seq);

    if(!seen){                                                       // (DSA) new message: deliver it
        if(peer) seq_remember(n, peer, in->seq);
        n->p->deliver(n->ctx, in);
        n->p->log(n->ctx, RT_LOG_DELIVERED, f);
    }
    else{                                                            // (REACK) the first ACK got lost, ACK again only
        n->p->log(n->ctx, RT_LOG_REACK, f);
    }

    // either way the sender gets an ACK for this attempt's msg_id
    queue_ack(n, in->sender_id, in->seq, f->msg_id);
}

// ACKs wait a random 0..ack_delay_max_ms so timing doesn't link sender and recipient (§9.7)
static void queue_ack(rt_node_t *n, uint32_t recipient_id, uint32_t seq, const uint8_t msg_id[8])
{
    for(int i = 0; i < RT_MAX_PENDING_ACKS; i++){
        rt_pending_ack_t *a = &n->acks[i];
        if(a->used) continue;

        a->used = true;
        a->recipient_id = recipient_id;
        a->seq = seq;
        memcpy(a->acked_msg_id, msg_id, 8);

        uint32_t delay = n->cfg.ack_delay_max_ms ? n->p->random_u32(n->ctx) % ((uint32_t)n->cfg.ack_delay_max_ms + 1) : 0;
        n->p->timer_start(n->ctx, make_token(RT_TIMER_ACK, (uint32_t)i), delay);
        return;
    }

    //no free slot, so just send it now instead of losing it
    build_and_send(n, RT_TYPE_ACK, recipient_id, seq, msg_id, 8, -1);
}

static void ack_fire(rt_node_t *n, int slot)
{
    rt_pending_ack_t *a = &n->acks[slot];
    if(!a->used) return;

    //copy out first, then free the slot before sending
    rt_pending_ack_t ack = *a;
    memset(a, 0, sizeof *a);
    build_and_send(n, RT_TYPE_ACK, ack.recipient_id, ack.seq, ack.acked_msg_id, 8, -1);
}

/* ---- Relay timing (§5.3) ------------------------------------------------ */

static uint32_t jitter_ms(rt_node_t *n, int8_t rssi)
{

    //defining jitter / rssi range
    uint16_t minimum = n->cfg.jitter_min_ms;
    uint16_t range = n->cfg.jitter_max_ms - minimum;
    uint32_t pct = n->cfg.jitter_rand_pct;
    if (pct > 100) pct = 100;
    uint32_t rand_span = range * pct / 100;
    uint32_t rssi_span = range - rand_span;

    //setting up clamps

    if (rssi < n->cfg.rssi_weak){ rssi = n->cfg.rssi_weak; }
    if (rssi > n->cfg.rssi_strong){ rssi = n->cfg.rssi_strong; }

    int position = rssi - n->cfg.rssi_weak;
    int rssi_range = n->cfg.rssi_strong - n->cfg.rssi_weak;

    //setting up the jitter

    uint32_t base = 0;
    if (rssi_range > 0){
        base = (uint32_t)position * rssi_span / (uint32_t)rssi_range;
    }
    uint32_t jitter = n->p->random_u32(n->ctx) % (rand_span + 1);

    return minimum + base + jitter;

}

static void relay_schedule(rt_node_t *n, int slot, const rt_frame_t *f, int8_t rssi)
{
    rt_cache_entry_t *e = &n->cache[slot];
    e->pending = *f;                                                       // copy f into cache[slot].pending

    e->pending.ttl--;                                                      // decrease ttl, increase hop count, set the pseudonym, and set next_hop = 0
    e->pending.hop_count++;
    n->p->my_pseudonym(n->ctx, e->pending.src_pseudo);
    memset(e->pending.next_hop, 0, 4);
    n->p->compute_link_tag(n->ctx, &e->pending, e->pending.link_tag);     // link_tag last since it covers everything above

    e->relay_pending = true;
    e->dup_count = 0;

    uint32_t delay = jitter_ms(n, rssi);                                   // start timer and set delay
    n->p->timer_start(n->ctx, make_token(RT_TIMER_RELAY, (uint32_t)slot), delay);
    n->p->log(n->ctx, RT_LOG_RELAY_SCHEDULED, f);

}

static void relay_fire(rt_node_t *n, int slot)
{
    rt_cache_entry_t *e = &n->cache[slot];

    if(!e->relay_pending) return;                 // cancelled by k, or already sent

    n->p->transmit(n->ctx, &e->pending);
    n->p->log(n->ctx, RT_LOG_TX, &e->pending);
    e->relay_pending = false;
}

/* ---- Send path (§5.2) --------------------------------------------------- */

// builds one frame and sends it. used for new messages, retries (out_slot >= 0) and ACKs (out_slot = -1)
static bool build_and_send(rt_node_t *n, uint8_t type, uint32_t recipient_id, uint32_t seq,
                           const uint8_t *body, uint8_t len, int out_slot)
{
    // nothing goes out before the first clock sync (§9.2)
    if(!n->p->is_synced(n->ctx)){
        n->p->log(n->ctx, RT_LOG_NOT_SYNCED, NULL);
        return false;
    }

    rt_frame_t f;
    memset(&f, 0, sizeof f);

    // (NEW_MSG) fresh random msg_id every time, even retries
    random_bytes(n, f.msg_id, 8);

    // fields the encryption authenticates have to be set BEFORE encrypting (§9.6).
    // cleartext type is always DATA, the real type (DATA/ACK) is hidden inside
    f.ver_type = RT_FRAME_DATA;
    f.flags = 0;
    put_be16(f.epoch, n->p->current_epoch(n->ctx));

    // (BHD) inner header: new timestamp every attempt, same seq on retries
    rt_inner_t in;
    memset(&in, 0, sizeof in);
    in.sender_id = n->cfg.node_id;
    in.recipient_id = recipient_id;
    in.timestamp = n->p->now_ms(n->ctx);
    in.seq = seq;
    in.type = type;
    in.len = len;
    memcpy(in.body, body, len);

    // (ENC) encrypt for the recipient
    if(!n->p->encrypt(n->ctx, &in, &f)){
        n->p->log(n->ctx, RT_LOG_ENCRYPT_FAILED, &f);
        return false;
    }

    // (FILL) the rest of the header. hop padding: start at hop_count = pad, ttl = default - pad (§9.9)
    uint8_t pad = n->cfg.hop_pad_max ? (uint8_t)(n->p->random_u32(n->ctx) % ((uint32_t)n->cfg.hop_pad_max + 1)) : 0;
    if(pad > n->cfg.default_ttl) pad = n->cfg.default_ttl;
    f.hop_count = pad;
    f.ttl = (uint8_t)(n->cfg.default_ttl - pad);
    n->p->my_pseudonym(n->ctx, f.src_pseudo);
    memset(f.next_hop, 0, 4);                                              // v1 always floods

    // (COMPUTE) link_tag last since it covers the finished header
    n->p->compute_link_tag(n->ctx, &f, f.link_tag);

    // (ADD) cache our own msg_id so the echo gets dropped
    cache_insert(n, f.msg_id);
    long_insert(n, f.msg_id);

    // (REGISTER) DATA only: remember this attempt's msg_id and (re)start the retry timer
    if(out_slot >= 0){
        rt_outstanding_t *o = &n->out[out_slot];
        memcpy(o->attempt_ids[o->attempts], f.msg_id, 8);
        o->attempts++;

        // waits are 1s / 2s / 4s after attempts 1-3, and the last attempt reuses the longest wait
        int idx = o->attempts - 1;
        if(idx > RT_MAX_ATTEMPTS - 2) idx = RT_MAX_ATTEMPTS - 2;
        n->p->timer_start(n->ctx, make_token(RT_TIMER_RETRY, (uint32_t)out_slot), n->cfg.retry_backoff_ms[idx]);
    }

    // (TRANSMIT) originator sends right away, no jitter
    n->p->transmit(n->ctx, &f);
    n->p->log(n->ctx, RT_LOG_TX, &f);
    return true;
}

static void retry_fire(rt_node_t *n, int out_slot)
{
    rt_outstanding_t *o = &n->out[out_slot];
    if(!o->used) return;                                             // already ACKed

    // (FAIL) out of retries: tell the laptop and clear the entry
    if(o->attempts >= RT_MAX_ATTEMPTS){
        n->p->notify(n->ctx, o->handle, RT_STATUS_FAILED);
        n->p->log(n->ctx, RT_LOG_SEND_FAILED, NULL);
        memset(o, 0, sizeof *o);
        return;
    }

    // (RETRY) new msg_id + timestamp, SAME seq so the recipient knows it's the same message
    if(!build_and_send(n, RT_TYPE_DATA, o->recipient_id, o->seq, o->text, o->len, out_slot)){
        // couldn't even build it (lost keys/sync), so give up instead of hanging forever
        n->p->notify(n->ctx, o->handle, RT_STATUS_FAILED);
        n->p->log(n->ctx, RT_LOG_SEND_FAILED, NULL);
        memset(o, 0, sizeof *o);
    }
}

/* ---- Peers + sequence numbers (§9.7) ------------------------------------ */

// finds a peer, or adds it. new peers start their send seq at a random value.
// when the table is full, the least recently used peer gets forgotten. that's safe because
// a recipient only needs 15 s of seq memory (§9.7), so a peer that's been quiet longer has nothing to lose
static rt_peer_t *peer_get(rt_node_t *n, uint32_t peer_id)
{
    uint32_t now = n->p->now_ms(n->ctx);
    rt_peer_t *victim = NULL;
    uint32_t oldest_age = 0;

    for(int i = 0; i < RT_MAX_PEERS; i++){
        rt_peer_t *p = &n->peers[i];
        if(p->used && p->peer_id == peer_id){                        // already known
            p->last_used_ms = now;
            return p;
        }
        uint32_t age = p->used ? now - p->last_used_ms : UINT32_MAX; // free slots count as oldest
        if(!victim || age > oldest_age){ victim = p; oldest_age = age; }
    }

    //table full: forget the least recently used peer (logged so the sim can count it)
    if(victim->used) n->p->log(n->ctx, RT_LOG_PEER_EVICTED, NULL);

    memset(victim, 0, sizeof *victim);
    victim->used = true;
    victim->peer_id = peer_id;
    victim->next_seq_tx = n->p->random_u32(n->ctx);
    victim->last_used_ms = now;
    return victim;
}

// was this seq delivered from this peer in the last seq_memory_ms?
static bool seq_seen(rt_node_t *n, const rt_peer_t *peer, uint32_t seq)
{
    uint32_t now = n->p->now_ms(n->ctx);
    for(int i = 0; i < RT_SEQ_MEMORY; i++){
        const rt_seq_seen_t *s = &peer->seen[i];
        if(s->used && s->seq == seq && now - s->seen_at_ms <= n->cfg.seq_memory_ms) return true;
    }
    return false;
}

// remembers a delivered seq, reusing a free/expired slot or the oldest one
static void seq_remember(rt_node_t *n, rt_peer_t *peer, uint32_t seq)
{
    uint32_t now = n->p->now_ms(n->ctx);
    int victim = 0;
    uint32_t oldest_age = 0;

    for(int i = 0; i < RT_SEQ_MEMORY; i++){
        rt_seq_seen_t *s = &peer->seen[i];
        uint32_t age = s->used ? now - s->seen_at_ms : UINT32_MAX;
        if(age > n->cfg.seq_memory_ms){ victim = i; break; }        // free or expired
        if(age >= oldest_age){ oldest_age = age; victim = i; }
    }

    peer->seen[victim].used = true;
    peer->seen[victim].seq = seq;
    peer->seen[victim].seen_at_ms = now;
}
