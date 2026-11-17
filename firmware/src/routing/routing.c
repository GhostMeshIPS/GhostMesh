/*
 * routing.c - GhostMesh v1 forwarding (managed flooding)
 * Spec: PROTOCOL.md §5.1 (receive), §5.2 (send), §5.3 (relay timing).
 * Node IDs in comments (LT, SC, PR, ...) match the Mermaid charts.
 */
#include "routing.h"

#include <string.h>

/* ---- Timer tokens: kind in the top byte, table slot below ------------- */
enum { RT_TIMER_RELAY = 1, RT_TIMER_RETRY = 2 };

static uint32_t make_token(uint8_t kind, uint32_t slot) { return ((uint32_t)kind << 24) | (slot & 0xFFFFFFu); }
static uint8_t  token_kind(uint32_t token)              { return (uint8_t)(token >> 24); }
static uint32_t token_slot(uint32_t token)              { return token & 0xFFFFFFu; }

/* ---- Forward declarations --------------------------------------------- */
static int  cache_find(rt_node_t *n, const uint8_t msg_id[8]);
static int  cache_insert(rt_node_t *n, const uint8_t msg_id[8]);
static bool link_tag_valid(rt_node_t *n, const rt_frame_t *f);
static void handle_ack(rt_node_t *n, const rt_inner_t *in);
static void handle_data(rt_node_t *n, const rt_inner_t *in, const uint8_t msg_id[8]);
static void relay_schedule(rt_node_t *n, int slot, const rt_frame_t *f, int8_t rssi);
static void relay_fire(rt_node_t *n, int slot);
static uint32_t jitter_ms(rt_node_t *n, int8_t rssi);
static void build_and_send(rt_node_t *n, uint8_t type, uint32_t recipient_id, uint32_t seq,
                           const uint8_t *body, uint8_t len, int out_slot);
static void retry_fire(rt_node_t *n, int out_slot);
static rt_peer_t *peer_get(rt_node_t *n, uint32_t peer_id);

/* ---- Entry points ------------------------------------------------------ */

void rt_init(rt_node_t *n, const rt_config_t *cfg, const rt_platform_t *p, void *ctx)
{
    memset(n, 0, sizeof *n);
    n->cfg = *cfg;
    n->p = p;
    n->ctx = ctx;
    n->next_handle = 1; /* 0 means "rejected" */
}

void rt_on_receive(rt_node_t *n, const rt_frame_t *f, int8_t rssi)
{
    if(!link_tag_valid(n, f)){
        n->p->log(n->ctx, RT_LOG_BAD_LINK_TAG, f);
        return;
    }

    int slot = cache_find(n, f->msg_id);
    if (slot >= 0){                                                          // checks if msg_id is already in cache
        rt_cache_entry_t *e = &n->cache[slot];
        if(e->relay_pending){                                                // checks if there's a pending relay
            e->dup_count++;
            if(e->dup_count >= n->cfg.k) {                                   // checks if the # of duplicates is greater than k
                n->p->timer_cancel(n->ctx, make_token(RT_TIMER_RELAY, slot));
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
    slot = cache_insert(n, f->msg_id);

    rt_inner_t in;
    if (n->p->try_decrypt(n->ctx, f, &in)){                                    // attempt to decrypt the packet. Then check for ACK or DATA type
        if (in.type == RT_TYPE_ACK) handle_ack(n, &in);                              
        else handle_data(n, &in, f->msg_id);
    }

    if(f->ttl == 0){                                                           // check for ttl == 0
        n->p->log(n->ctx, RT_LOG_TTL_EXPIRED, f);
    }
    else{
        relay_schedule(n, slot, f, rssi);
    }

}

uint32_t rt_send(rt_node_t *n, uint32_t recipient_id, const uint8_t *text, uint8_t len)
{
    /* TODO (LEN) len > RT_BODY_MAX -> log RT_LOG_TOO_LONG, return 0. */
    /* TODO find a free rt_outstanding_t slot (none -> return 0), store text,
     *      recipient, seq = peer's next_seq_tx++, handle = next_handle++. */
    /* TODO build_and_send(DATA, ...) for the first attempt. */
    /* TODO (FIRST/SENT) notify RT_STATUS_SENT after the first transmit. */
    (void)n; (void)recipient_id; (void)text; (void)len;
    (void)build_and_send; (void)peer_get;
    return 0;
}

void rt_on_timer(rt_node_t *n, uint32_t token)
{
    uint32_t slot = token_slot(token);
    switch (token_kind(token)) {
    case RT_TIMER_RELAY: if (slot < RT_CACHE_SIZE)      relay_fire(n, (int)slot); break;
    case RT_TIMER_RETRY: if (slot < RT_MAX_OUTSTANDING) retry_fire(n, (int)slot); break;
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

/* ---- Receive helpers ---------------------------------------------------- */

static bool link_tag_valid(rt_node_t *n, const rt_frame_t *f)
{
    /* TODO compute_link_tag() over the received header and memcmp with f->link_tag. */
    (void)n; (void)f;
    return true;
}

static void handle_ack(rt_node_t *n, const rt_inner_t *in)
{
    /* TODO (MNR) body holds the acked msg_id. Search every outstanding entry's
     *      attempt_ids. Match -> cancel retry timer, notify RT_STATUS_DELIVERED,
     *      free the entry, log RT_LOG_ACK_MATCHED. No match -> log RT_LOG_ACK_UNMATCHED. */
    (void)n; (void)in;
}

static void handle_data(rt_node_t *n, const rt_inner_t *in, const uint8_t msg_id[8])
{
    /* TODO (SEQ) seq already seen from in->sender_id?
     *   No  -> (DSA) deliver(), update last_seq_rx, ACK it
     *   Yes -> (REACK) ACK again, don't deliver, log RT_LOG_REACK
     *   ACK = build_and_send(ACK, sender, seq, <this frame's msg_id>, 8, -1).
     *   Note: you need the received frame's msg_id here; pass it in or restructure. */
    (void)n; (void)in; (void)msg_id;
}

/* ---- Relay timing (§5.3) ------------------------------------------------ */

static uint32_t jitter_ms(rt_node_t *n, int8_t rssi)
{
    /* TODO map rssi to a wait inside [jitter_min_ms, jitter_max_ms]:
     *      weaker RSSI -> shorter wait, plus randomness from random_u32(). */
    (void)rssi;
    return n->cfg.jitter_min_ms;
}

static void relay_schedule(rt_node_t *n, int slot, const rt_frame_t *f, int8_t rssi)
{
    /* TODO (REL) copy f into cache[slot].pending, then:
     *      ttl--, hop_count++, src_pseudo = my_pseudonym(), next_hop = 0,
     *      link_tag recomputed LAST.
     *      relay_pending = true, dup_count = 0,
     *      timer_start(make_token(RT_TIMER_RELAY, slot), jitter_ms(rssi)),
     *      log RT_LOG_RELAY_SCHEDULED. */
    (void)n; (void)slot; (void)f; (void)rssi;
    (void)jitter_ms; (void)make_token;

    rt_cache_entry_t *e = &n->cache[slot];
    e->pending = *f;                                                       // copy f into cache[slot].pending

    e->pending.ttl--;                                                      // decrease ttl, increase hop count, set the pseudonym, and set next_hop = 0
    e->pending.hop_count++;
    n->p->my_pseudonym(n->ctx, e->pending.src_pseudo);
    memset(e->pending.next_hop, 0, 4);
    n->p->compute_link_tag(n->ctx, &e->pending, e->pending.link_tag);

    e->relay_pending = true;
    e->dup_count = 0;

    uint32_t delay = jitter_ms(n, rssi);                                   // start timer and set delay
    n->p->timer_start(n->ctx, make_token(RT_TIMER_RELAY, (uint32_t)slot), delay);
    n->p->log(n->ctx, RT_LOG_RELAY_SCHEDULED, f);

}

static void relay_fire(rt_node_t *n, int slot)
{
    /* TODO if still pending: transmit(cache[slot].pending), log RT_LOG_TX, relay_pending = false. */
    (void)n; (void)slot;
}

/* ---- Send path (§5.2) --------------------------------------------------- */

static void build_and_send(rt_node_t *n, uint8_t type, uint32_t recipient_id, uint32_t seq,
                           const uint8_t *body, uint8_t len, int out_slot)
{
    /* TODO (NEW_MSG) fresh random msg_id from random_u32().
     * TODO (BHD)  fill rt_inner_t: sender = cfg.node_id, recipient, timestamp, seq, type, len, body.
     * TODO (ENC)  encrypt().
     * TODO (FILL) ver_type, flags, msg_id, ttl = default, hop_count = 0,
     *             src_pseudo = mine, next_hop = 0, epoch = current.
     * TODO (COMPUTE) link_tag last.
     * TODO (ADD)  cache_insert(msg_id) so the echo is dropped.
     * TODO (DATA) out_slot >= 0: append msg_id to attempt_ids, attempts++,
     *             timer_start(RETRY token, retry_backoff_ms[attempts - 1]).
     * TODO (TRANSMIT) transmit(), log RT_LOG_TX. */
    (void)n; (void)type; (void)recipient_id; (void)seq; (void)body; (void)len; (void)out_slot;
}

static void retry_fire(rt_node_t *n, int out_slot)
{
    /* TODO (RETRY) attempts == RT_MAX_ATTEMPTS ?
     *   (FAIL) notify RT_STATUS_FAILED, free the entry, log RT_LOG_SEND_FAILED
     *   : build_and_send(DATA, same recipient, SAME seq, stored text, ..., out_slot). */
    (void)n; (void)out_slot;
}

static rt_peer_t *peer_get(rt_node_t *n, uint32_t peer_id)
{
    /* TODO find the peer entry for peer_id, creating one if there's room; NULL if full. */
    (void)n; (void)peer_id;
    return NULL;
}
