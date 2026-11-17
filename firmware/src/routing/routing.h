/*
 * routing.h - GhostMesh v1 forwarding (managed flooding)
 *
 * Portable C11: no ESP32 headers. Everything hardware- or crypto-specific
 * comes in through rt_platform_t, so the same code runs in firmware and in
 * the Python sim (via ctypes). Spec: PROTOCOL.md §5.
 */
#ifndef GHOSTMESH_ROUTING_H
#define GHOSTMESH_ROUTING_H

#include <stdbool.h>
#include <stdint.h>

/* ---- Limits (fixed-size tables, no malloc) ---------------------------- */
#define RT_CACHE_SIZE        128   /* seen-cache entries (§12) */
#define RT_MAX_OUTSTANDING   8     /* messages waiting for an ACK */
#define RT_MAX_ATTEMPTS      4     /* first send + 3 retries */
#define RT_MAX_PEERS         8     /* senders we track sequence numbers for */
#define RT_BODY_MAX          153   /* plaintext message bytes */

/* ---- Frame (§4.1) ------------------------------------------------------
 * TEMP: replace with the shared definition from Comp E's frame codec.
 * All fields are byte arrays so the struct has no padding and is exactly
 * 240 bytes on every compiler; multi-byte values are encoded by the codec. */
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

enum { RT_TYPE_DATA = 1, RT_TYPE_ACK = 2, RT_TYPE_HELLO = 3, RT_TYPE_BLOCK = 4 }; /* values TBD */

/* Decrypted inner header + body: what routing needs after try_decrypt.
 * Exact layout and sizes belong to Network #2. */
typedef struct {
    uint32_t sender_id;            /* real node ID, not a pseudonym */
    uint32_t recipient_id;
    uint32_t timestamp;
    uint32_t seq;                  /* per sender->recipient sequence number */
    uint8_t  type;                 /* RT_TYPE_DATA or RT_TYPE_ACK */
    uint8_t  len;
    uint8_t  body[RT_BODY_MAX];    /* DATA: text. ACK: the acked msg_id */
} rt_inner_t;

/* ---- Events reported to the platform log (§5.4) ----------------------- */
typedef enum {
    RT_LOG_BAD_LINK_TAG,
    RT_LOG_DUPLICATE,             /* dropped, no pending relay */
    RT_LOG_DUP_COUNTED,           /* counted toward k, relay still pending */
    RT_LOG_RELAY_CANCELLED,       /* count reached k */
    RT_LOG_TTL_EXPIRED,
    RT_LOG_RELAY_SCHEDULED,
    RT_LOG_TX,
    RT_LOG_DELIVERED,
    RT_LOG_REACK,                 /* repeat seq: ACK resent, not delivered */
    RT_LOG_ACK_MATCHED,
    RT_LOG_ACK_UNMATCHED,         /* late duplicate ACK, ignored */
    RT_LOG_TOO_LONG,
    RT_LOG_SEND_FAILED,
} rt_log_t;

typedef enum { RT_STATUS_SENT, RT_STATUS_DELIVERED, RT_STATUS_FAILED } rt_status_t;

/* ---- Platform callbacks ------------------------------------------------
 * Supplied by firmware (Comp E) or by the sim/test harness. `ctx` is passed
 * back untouched on every call. */
typedef struct {
    void     (*transmit)(void *ctx, const rt_frame_t *f);
    uint32_t (*now_ms)(void *ctx);
    uint32_t (*random_u32)(void *ctx);

    /* Ask the platform to call rt_on_timer(node, token) after delay_ms.
     * Starting a token that is already running restarts it. */
    void     (*timer_start)(void *ctx, uint32_t token, uint32_t delay_ms);
    void     (*timer_cancel)(void *ctx, uint32_t token);

    /* Crypto (Network #2). try_decrypt returns true only if the frame is for us. */
    bool     (*try_decrypt)(void *ctx, const rt_frame_t *f, rt_inner_t *out);
    void     (*encrypt)(void *ctx, const rt_inner_t *in, rt_frame_t *f); /* fills nonce, ciphertext, aead_tag */
    void     (*compute_link_tag)(void *ctx, const rt_frame_t *f, uint8_t out[8]);

    void     (*my_pseudonym)(void *ctx, uint8_t out[4]);
    uint16_t (*current_epoch)(void *ctx);

    /* To the laptop over serial */
    void     (*deliver)(void *ctx, const rt_inner_t *msg);
    void     (*notify)(void *ctx, uint32_t handle, rt_status_t status);
    void     (*log)(void *ctx, rt_log_t event, const rt_frame_t *f);
} rt_platform_t;

/* ---- Tunable parameters (§12) ----------------------------------------- */
typedef struct {
    uint32_t node_id;
    uint8_t  default_ttl;
    uint8_t  k;                    /* suppression threshold */
    uint16_t jitter_min_ms;
    uint16_t jitter_max_ms;
    int8_t   rssi_weak;            /* RSSI mapped to the shortest wait */
    int8_t   rssi_strong;          /* RSSI mapped to the longest wait */
    uint32_t cache_expiry_ms;
    uint32_t retry_backoff_ms[RT_MAX_ATTEMPTS - 1]; /* e.g. 1000, 2000, 4000 */
} rt_config_t;

/* ---- Node state --------------------------------------------------------
 * Opaque to callers in spirit; defined here so it can live in static memory. */
typedef struct {
    bool     used;
    uint8_t  msg_id[8];
    uint32_t seen_at_ms;
    bool     relay_pending;
    uint8_t  dup_count;            /* duplicates heard while pending */
    rt_frame_t pending;            /* the modified frame to rebroadcast */
    /* v2: incoming neighbor (breadcrumb) goes here */
} rt_cache_entry_t;

typedef struct {
    bool       used;
    uint32_t   handle;             /* reported back via notify() */
    uint32_t   recipient_id;
    uint32_t   seq;
    uint8_t    len;
    uint8_t    text[RT_BODY_MAX];
    uint8_t    attempts;
    uint8_t    attempt_ids[RT_MAX_ATTEMPTS][8];
} rt_outstanding_t;

typedef struct {
    bool     used;
    uint32_t peer_id;              /* real node ID */
    uint32_t last_seq_rx;          /* highest seq delivered from this peer */
    uint32_t next_seq_tx;          /* next seq to use when sending to this peer */
} rt_peer_t;

typedef struct {
    rt_config_t          cfg;
    const rt_platform_t *p;
    void                *ctx;
    rt_cache_entry_t     cache[RT_CACHE_SIZE];
    rt_outstanding_t     out[RT_MAX_OUTSTANDING];
    rt_peer_t            peers[RT_MAX_PEERS];
    uint32_t             next_handle;
} rt_node_t;

/* ---- Entry points ------------------------------------------------------ */
void rt_init(rt_node_t *n, const rt_config_t *cfg, const rt_platform_t *p, void *ctx);

/* A frame arrived from the radio (§5.1). */
void rt_on_receive(rt_node_t *n, const rt_frame_t *f, int8_t rssi);

/* The laptop wants to send text (§5.2, trigger T1).
 * Returns a handle used in notify(), or 0 if rejected (too long / table full). */
uint32_t rt_send(rt_node_t *n, uint32_t recipient_id, const uint8_t *text, uint8_t len);

/* A timer started with timer_start() fired. */
void rt_on_timer(rt_node_t *n, uint32_t token);

#endif /* GHOSTMESH_ROUTING_H */
