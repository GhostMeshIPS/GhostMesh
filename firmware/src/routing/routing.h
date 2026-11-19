/*
 * routing.h - GhostMesh v1 forwarding (managed flooding)
 *
 * Portable C11: no ESP32 headers. Everything hardware- or crypto-specific
 * comes in through rt_platform_t, so the same code runs in firmware and in
 * the Python sim (via ctypes). Spec: PROTOCOL.md §5 (routing), §9 (security).
 */
#ifndef GHOSTMESH_ROUTING_H
#define GHOSTMESH_ROUTING_H

#include <stdbool.h>
#include <stdint.h>

/* ---- Limits (fixed-size tables, no malloc) ---------------------------- */
#define RT_CACHE_SIZE        128   // seen-cache entries, 60 s (§12)
#define RT_LONG_CACHE_SIZE   512   // msg_id-only replay cache, 180 s (§9.7)
#define RT_MAX_OUTSTANDING   8     // messages waiting for an ACK
#define RT_MAX_ATTEMPTS      4     // first send + 3 retries
#define RT_MAX_PEERS         8     // nodes we track sequence numbers for
#define RT_SEQ_MEMORY        16    // recent seqs remembered per peer (§9.7)
#define RT_MAX_PENDING_ACKS  8     // ACKs waiting out their random delay
#define RT_MAX_TX_TRACK      16    // transmitters tracked for the insertion limit (§9.9)
#define RT_MAX_NEIGHBORS     16    // 1-hop neighbors tracked (v2, §6)
#define RT_BODY_MAX          152   // plaintext message bytes (§9.5, was 153)

/* ---- Frame (§4.1, offsets in §9.4) -------------------------------------
 * TEMP: replace with the shared definition from Comp E's frame codec.
 * All fields are byte arrays so the struct has no padding and is exactly
 * 240 bytes on every compiler. Multi-byte values are big-endian. */
typedef struct {
    uint8_t ver_type;
    uint8_t flags;
    uint8_t msg_id[8];
    uint8_t ttl;
    uint8_t hop_count;
    uint8_t src_pseudo[4];
    uint8_t next_hop[4];
    uint8_t epoch[2];
    uint8_t link_tag[8];
    uint8_t nonce[24];
    uint8_t ciphertext[170];
    uint8_t aead_tag[16];
} rt_frame_t;

// cleartext ver_type: what relays and sniffers see (§9.4). ACKs go out as DATA. Values TBD with Jose.
enum { RT_FRAME_DATA = 1, RT_FRAME_HELLO = 2, RT_FRAME_CTRL = 3, RT_FRAME_KEYS = 4 };

// CTRL subtype = first byte of the CTRL region (ciphertext[0]). must match GM_CTRL_TIME in gm_crypto.h
#define RT_CTRL_TIME 1

// inner type: the real type, only visible after decrypting. gm_crypto uses these, so keep the names.
enum { RT_TYPE_DATA = 1, RT_TYPE_ACK = 2 };

/* Decrypted inner header + body (§9.5). Packed on the wire by gm_inner_pack. */
typedef struct {
    uint32_t sender_id;            // real node ID, not a pseudonym
    uint32_t recipient_id;
    uint32_t timestamp;            // mesh clock ms, mod 2^32
    uint32_t seq;                  // per sender->recipient sequence number
    uint8_t  type;                 // RT_TYPE_DATA or RT_TYPE_ACK
    uint8_t  len;
    uint8_t  body[RT_BODY_MAX];    // DATA: text. ACK: the acked attempt's msg_id
} rt_inner_t;

/* ---- Events reported to the platform log (§5.4) ----------------------- */
typedef enum {
    // drops on receive
    RT_LOG_BAD_LINK_TAG,
    RT_LOG_BAD_EPOCH,             // outside the ±1 epoch window
    RT_LOG_BAD_TYPE,              // unknown cleartext ver_type
    RT_LOG_BLOCKED,               // matched an active BLOCK
    RT_LOG_RATE_LIMITED,          // transmitter over the cache-insertion limit
    RT_LOG_DUPLICATE,             // dropped, no pending relay
    RT_LOG_DUP_COUNTED,           // counted toward k, relay still pending
    RT_LOG_RELAY_CANCELLED,       // count reached k
    RT_LOG_TTL_EXPIRED,
    RT_LOG_CTRL_UNVERIFIED,       // CTRL failed (or skipped) verification, not relayed
    RT_LOG_REPLAY_STALE,          // timestamp outside the freshness window, no ACK
    RT_LOG_NOT_SYNCED,            // before first clock sync: no transmit / relay
    // normal events
    RT_LOG_RELAY_SCHEDULED,
    RT_LOG_TX,
    RT_LOG_DELIVERED,
    RT_LOG_REACK,                 // repeat seq: ACK resent, not delivered again
    RT_LOG_ACK_MATCHED,
    RT_LOG_ACK_UNMATCHED,         // late duplicate ACK, ignored
    RT_LOG_HELLO,                 // v1 ignores HELLO (v2 route learning uses it)
    // send-side failures
    RT_LOG_TOO_LONG,
    RT_LOG_ENCRYPT_FAILED,
    RT_LOG_SEND_FAILED,           // out of retries
    RT_LOG_PEER_EVICTED,          // peer table full: least recently used peer forgotten
    // v2 route learning (§6)
    RT_LOG_ROUTE_SCOPED,          // send used a learned distance instead of the default TTL
    RT_LOG_ROUTE_STALE,           // no ACK: learned distance dropped, retry floods with the default TTL
} rt_log_t;

typedef enum { RT_STATUS_SENT, RT_STATUS_DELIVERED, RT_STATUS_FAILED } rt_status_t;

/* ---- Platform callbacks ------------------------------------------------
 * Supplied by firmware (Comp E) or by the sim/test harness. `ctx` is passed
 * back untouched on every call. */
typedef struct {
    // radio + time
    void     (*transmit)(void *ctx, const rt_frame_t *f);
    uint32_t (*now_ms)(void *ctx);           // mesh clock in ms (gm_clock_now), mod 2^32
    uint32_t (*random_u32)(void *ctx);       // firmware: esp_random. sim: seeded RNG
    bool     (*is_synced)(void *ctx);        // false until the first TIME beacon (§9.2)

    // timers: call rt_on_timer(node, token) after delay_ms. starting a running token restarts it
    void     (*timer_start)(void *ctx, uint32_t token, uint32_t delay_ms);
    void     (*timer_cancel)(void *ctx, uint32_t token);

    // crypto (Jose): gm_link_tag_ok, gm_link_tag, gm_encrypt, gm_try_decrypt
    bool     (*link_tag_ok)(void *ctx, const rt_frame_t *f);              // constant-time check
    void     (*compute_link_tag)(void *ctx, const rt_frame_t *f, uint8_t out[8]);
    bool     (*encrypt)(void *ctx, const rt_inner_t *in, rt_frame_t *f);  // needs ver_type/flags/msg_id/epoch filled first
    bool     (*try_decrypt)(void *ctx, const rt_frame_t *f, rt_inner_t *out);

    // control plane (Jose + Yunus)
    bool     (*is_blocked)(void *ctx, const rt_frame_t *f, const uint8_t src_mac[6]); // §9.8 block matching
    void     (*keys_receive)(void *ctx, const rt_frame_t *f);             // gm_keys_receive(f->ciphertext)
    bool     (*ctrl_verify)(void *ctx, const rt_frame_t *f);              // verified + applied -> true means relay it

    // identity
    void     (*my_pseudonym)(void *ctx, uint8_t out[4]);
    uint16_t (*current_epoch)(void *ctx);    // wire epoch (gm_wire_epoch)

    // to the laptop over serial
    void     (*deliver)(void *ctx, const rt_inner_t *msg);
    void     (*notify)(void *ctx, uint32_t handle, rt_status_t status);
    void     (*log)(void *ctx, rt_log_t event, const rt_frame_t *f);
} rt_platform_t;

/* ---- Tunable parameters (§12) ----------------------------------------- */
typedef struct {
    uint32_t node_id;
    uint8_t  default_ttl;          // already includes the +2 for hop padding (§9.9)
    uint8_t  hop_pad_max;          // originator pads hop_count by 0..hop_pad_max (§9.9)
    uint8_t  k;                    // suppression threshold (§5.3)
    uint8_t  jitter_rand_pct;      // share of the jitter window that's random, 0-100
    uint16_t jitter_min_ms;
    uint16_t jitter_max_ms;
    int8_t   rssi_weak;            // RSSI mapped to the shortest wait
    int8_t   rssi_strong;          // RSSI mapped to the longest wait
    uint32_t cache_expiry_ms;      // seen-cache, 60 s
    uint32_t long_cache_expiry_ms; // msg_id-only replay cache, 180 s
    uint16_t insert_limit_per_s;   // new msg_ids per transmitter per second, ~20
    uint16_t ack_delay_max_ms;     // ACKs wait a random 0..this, 400
    uint32_t fresh_ms;             // recipient freshness window, 5 s
    uint32_t seq_memory_ms;        // how long a peer's seq counts as seen, 15 s
    uint32_t retry_backoff_ms[RT_MAX_ATTEMPTS - 1]; // e.g. 1000, 2000, 4000
    // v2 route learning (§6). route_learning = 0 keeps plain v1 flooding
    uint8_t  route_learning;       // 1 = scope sends to a learned distance
    uint8_t  scope_margin;         // extra hops on top of the learned distance
    uint16_t hello_interval_ms;    // HELLO beacon period, 0 = off (neighbors are still learned from traffic)
    uint32_t neighbor_expiry_ms;   // neighbor forgotten after this long without hearing it
    uint32_t route_expiry_ms;      // learned distance forgotten after this long without being confirmed
} rt_config_t;

/* ---- Node state --------------------------------------------------------
 * Opaque to callers in spirit; defined here so it can live in static memory. */
typedef struct {
    bool       used;
    uint8_t    msg_id[8];
    uint32_t   seen_at_ms;
    bool       relay_pending;
    uint8_t    dup_count;          // duplicates heard while pending
    rt_frame_t pending;            // the modified frame to rebroadcast
    /* v2: incoming neighbor (breadcrumb) goes here */
} rt_cache_entry_t;

typedef struct {
    bool     used;
    uint8_t  msg_id[8];
    uint32_t seen_at_ms;
} rt_long_entry_t;

typedef struct {
    bool     used;
    uint32_t handle;               // reported back via notify()
    uint32_t recipient_id;
    uint32_t seq;
    uint8_t  len;
    uint8_t  text[RT_BODY_MAX];
    uint8_t  attempts;
    uint8_t  attempt_ids[RT_MAX_ATTEMPTS][8];
} rt_outstanding_t;

typedef struct {
    bool     used;
    uint32_t seq;
    uint32_t seen_at_ms;
} rt_seq_seen_t;

typedef struct {
    bool          used;
    uint32_t      peer_id;         // real node ID
    uint32_t      next_seq_tx;     // next seq when sending to this peer (random start, §9.7)
    uint32_t      last_used_ms;    // last send to / delivery from this peer (for eviction)
    bool          route_known;     // v2: have a fresh distance to this peer
    uint8_t       route_hops;      // v2: fewest relays seen on a frame from this peer (incl. its padding)
    uint32_t      route_seen_ms;   // v2: when that distance was last confirmed
    rt_seq_seen_t seen[RT_SEQ_MEMORY]; // seqs delivered from this peer recently
} rt_peer_t;

typedef struct {
    bool     used;
    uint32_t recipient_id;
    uint32_t seq;
    uint8_t  acked_msg_id[8];
    uint8_t  hops;                 // v2: hop_count of the copy being ACKed (a path that exists right now)
} rt_pending_ack_t;

typedef struct {
    bool     used;
    uint8_t  pseudo[4];
    uint8_t  mac[6];
    uint32_t window_start_ms;
    uint16_t count;
} rt_tx_track_t;

typedef struct {
    bool     used;
    uint8_t  pseudo[4];            // neighbor's current pseudonym (changes every epoch)
    int8_t   rssi;                 // last signal strength heard from it
    uint32_t last_heard_ms;
} rt_neighbor_t;

typedef struct {
    rt_config_t          cfg;
    const rt_platform_t *p;
    void                *ctx;
    rt_cache_entry_t     cache[RT_CACHE_SIZE];
    rt_long_entry_t      long_cache[RT_LONG_CACHE_SIZE];
    uint16_t             long_next;          // ring position in long_cache
    rt_outstanding_t     out[RT_MAX_OUTSTANDING];
    rt_peer_t            peers[RT_MAX_PEERS];
    rt_pending_ack_t     acks[RT_MAX_PENDING_ACKS];
    rt_tx_track_t        tx_track[RT_MAX_TX_TRACK];
    rt_neighbor_t        neighbors[RT_MAX_NEIGHBORS];
    uint32_t             next_handle;
} rt_node_t;

/* ---- Entry points ------------------------------------------------------ */

// fills cfg with the current §12 defaults (TTL still TBD at freeze)
void rt_default_config(rt_config_t *cfg, uint32_t node_id);

void rt_init(rt_node_t *n, const rt_config_t *cfg, const rt_platform_t *p, void *ctx);

// a frame arrived from the radio (§5.1). src_mac is the ESP-NOW sender MAC
void rt_on_receive(rt_node_t *n, const rt_frame_t *f, const uint8_t src_mac[6], int8_t rssi);

// the laptop wants to send text (§5.2, trigger T1).
// returns a handle used in notify(), or 0 if rejected (too long, not synced, table full, unknown peer)
uint32_t rt_send(rt_node_t *n, uint32_t recipient_id, const uint8_t *text, uint8_t len);

// a timer started with timer_start() fired
void rt_on_timer(rt_node_t *n, uint32_t token);

// v2: copies the live 1-hop neighbors into out (up to max) and returns how many. for the serial neighbor table
int rt_neighbors(rt_node_t *n, rt_neighbor_t *out, int max);

// v2: learned distance (relays) to a peer, or -1 if unknown / expired
int rt_route_hops(rt_node_t *n, uint32_t peer_id);

#endif /* GHOSTMESH_ROUTING_H */
