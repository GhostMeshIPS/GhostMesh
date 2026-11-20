/*
 * gm_node.h - one GhostMesh node: Rashad's routing + Jose's crypto, wired together.
 * Owner: Yunus (Comp E).
 *
 * Portable C11, no ESP32 headers, so the exact same code runs on the boards
 * (firmware/src/main.cpp) and in the laptop integration test (firmware/test_host/).
 * It implements every rt_platform_t callback routing.c needs:
 *   - timers (a table polled from gm_node_poll, so everything runs on one task)
 *   - crypto callbacks -> gm_crypto
 *   - signed CTRL frames: verify budget (§9.8, 10b), TIME beacons, BLOCK table
 *   - KEYS frames built every ~10 s when gm_tick asks (§9.6)
 *   - laptop sends queued until the clock syncs (§9.2)
 *   - serial events as JSON (PROTOCOL.md §10)
 *
 * The hardware side only supplies gm_hw_t: transmit, clock, RNG, serial out, MAC change.
 */
#ifndef GHOSTMESH_GM_NODE_H
#define GHOSTMESH_GM_NODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gm_crypto.h"
#include "routing.h"

#define GM_NODE_MAX_TIMERS     (RT_CACHE_SIZE + RT_MAX_OUTSTANDING + RT_MAX_PENDING_ACKS + 8)
#define GM_NODE_SENDQ          8      /* laptop sends held before first sync (§9.2) */
#define GM_NODE_MAX_BLOCKS     8
#define GM_NODE_OWN_ECHO       16     /* msg_ids of KEYS frames we originated */
#define GM_NODE_CTRL_TRACK     8      /* transmitters tracked for the CTRL verify budget */
#define GM_NODE_ALLOW_MAX      6
#define GM_NODE_LOG_LAST       RT_LOG_PEER_EVICTED   /* last rt_log_t value: update when routing adds one */

/* What the hardware (or the sim) provides. */
typedef struct {
    void     *ctx;
    void     (*transmit)(void *ctx, const uint8_t frame[240]);
    uint64_t (*local_ms)(void *ctx);                     /* monotonic, ms since boot */
    void     (*rng)(void *ctx, uint8_t *out, size_t n);  /* cryptographic */
    void     (*emit)(void *ctx, const char *json);       /* one JSON object, no newline */
    /* Optional (may be NULL): */
    uint32_t (*set_mac)(void *ctx, const uint8_t mac[6]); /* returns radio outage in us */
    void     (*save_state)(void *ctx, const uint8_t *blob, size_t len);
    void     (*indicate)(void *ctx, int what);           /* GM_IND_* for LED */
} gm_hw_t;

enum { GM_IND_TX = 0, GM_IND_RX_MINE, GM_IND_DROP_BAD };

typedef struct { uint32_t id; char name; const uint8_t *pk; } gm_peer_key_t;

/* Pointers into keys_<N>.h (security/keygen.py output). */
typedef struct {
    uint32_t             node_id;
    char                 name;
    const uint8_t       *network_key;     /* 32 */
    const uint8_t       *pseudo_secret;   /* 32 */
    const uint8_t       *x25519_sk;       /* 32 */
    const uint8_t       *watchtower_pk;   /* 32 */
    const gm_peer_key_t *peers;
    int                  peer_count;
} gm_node_keys_t;

typedef struct { bool used; uint32_t token; uint64_t due; } gm_timer_t;

typedef struct {
    bool     used;
    uint32_t block_id;
    uint64_t issued_ms;         /* newest version applied (skip older re-issues) */
    uint64_t until_ms;          /* mesh clock */
    uint8_t  reason;
    uint8_t  pseudo[2][4];
    uint8_t  mac[2][6];
} gm_block_t;

typedef struct { bool used; uint8_t pseudo[4]; uint8_t mac[6]; uint64_t last_ms; } gm_ctrl_track_t;

/* Counters + latest values, for status and the OLED. */
typedef struct {
    uint32_t log_counts[GM_NODE_LOG_LAST + 1];
    uint32_t rx_frames, tx_frames, keys_sent, beacons_ok, blocks_applied;
    uint32_t gate_drops, allow_drops, own_echo_drops;
    int8_t   last_rssi;
    uint64_t last_rx_local;
    uint32_t last_mac_outage_us;
    char     last_msg[48];      /* "A: meet at 9" */
    char     last_send[24];     /* ">B ✓✓ #3" */
    /* neighbours heard recently (by radio MAC, since pseudonyms rotate) */
    struct { uint8_t mac[6]; int8_t rssi; uint64_t at; } heard[8];
} gm_node_stats_t;

typedef struct {
    /* configuration */
    gm_node_keys_t  keys;
    gm_hw_t         hw;
    bool            rotate_mac;     /* derive + set the epoch MAC (§9.3). Off = factory MAC */
    bool            verbose;        /* print every routing log event */
    int8_t          rssi_gate;      /* -127 = off */
    uint8_t         allow[GM_NODE_ALLOW_MAX][6];
    uint8_t         allow_n;        /* 0 = allowlist off */

    /* the two teammate modules */
    rt_node_t       rt;
    rt_config_t     rt_cfg;
    rt_platform_t   plat;
    gm_crypto_t     c;

    /* glue state */
    gm_timer_t      timers[GM_NODE_MAX_TIMERS];
    gm_block_t      blocks[GM_NODE_MAX_BLOCKS];
    gm_ctrl_track_t ctrl_track[GM_NODE_CTRL_TRACK];
    uint64_t        ctrl_budget_ms[2];   /* last two verify times (global ~2/s) */
    uint64_t        last_beacon_issued;
    uint8_t         cur_rx_mac[6];  /* MAC of the frame being processed (ctrl_verify has no MAC arg) */
    char            sending_to;     /* name for the notify(SENT) that fires inside rt_send */
    uint8_t         own_echo[GM_NODE_OWN_ECHO][8];
    uint8_t         own_echo_i;
    struct { char to; uint8_t len; uint8_t text[RT_BODY_MAX]; } sendq[GM_NODE_SENDQ];
    uint8_t         sendq_n;
    struct { uint32_t handle; char to; } handles[RT_MAX_OUTSTANDING];
    uint64_t        next_tick_local;
    uint32_t        wire_epoch_cached;
    uint8_t         pseudo_cached[4];
    bool            pseudo_valid;
    bool            was_synced;     /* to report the first sync even after a state import */
    gm_node_stats_t st;
} gm_node_t;

/* Set up from keys. `state` (may be NULL) is a gm_state_export blob from flash. */
void gm_node_init(gm_node_t *n, const gm_node_keys_t *keys, const gm_hw_t *hw,
                  const uint8_t *state, size_t state_len);

/* A 240-byte frame arrived from the radio. */
void gm_node_rx(gm_node_t *n, const uint8_t frame[240], const uint8_t mac[6], int8_t rssi);

/* Laptop wants to send text to a node by letter. Queued if not synced yet. */
bool gm_node_send(gm_node_t *n, char to, const char *text, size_t len);

/* DEBUG / bench only: set the mesh clock as if a TIME beacon arrived.
 * The real source is the watchtower's signed beacon (§9.2). */
void gm_node_debug_set_time(gm_node_t *n, uint64_t unix_ms);

/* Call often (every 1-5 ms): fires timers, runs gm_tick every 100 ms. */
void gm_node_poll(gm_node_t *n);

/* Prints {"ev":"status"} with counters. */
void gm_node_status(gm_node_t *n);

/* Prints {"ev":"boot"} with fingerprints (compare with firmware/config/roster.json). */
void gm_node_boot_banner(gm_node_t *n, const char *fw_version);

/* Micro-benchmark: time per-message encrypt and trial-decrypt over `runs` iterations (0 = default)
 * and print {"ev":"bench",...} with enc_us/dec_us. Needs the node synced with at least one peer.
 * Fills the "encrypt + decrypt on ESP32-S3" row of the results table. */
void gm_node_bench(gm_node_t *n, uint32_t runs);

/* Helpers for the OLED / status. */
uint64_t    gm_node_mesh_ms(gm_node_t *n);
uint16_t    gm_node_wire_epoch(gm_node_t *n);
void        gm_node_pseudonym(gm_node_t *n, uint8_t out[4]);
const char *gm_node_log_name(rt_log_t e);
char        gm_node_peer_name(gm_node_t *n, uint32_t id);

#endif
