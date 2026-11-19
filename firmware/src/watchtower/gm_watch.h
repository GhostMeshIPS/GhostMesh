/*
 * gm_watch.h - the watchtower (W). Owner: Yunus.
 *
 * Portable C (same rule as node/gm_node.c): runs on the W board and in the laptop test.
 * W does NOT route and cannot read messages. It:
 *   - holds the mesh clock (set from the laptop) and floods signed TIME beacons every 10 s (§9.2)
 *   - logs every frame it hears as one JSON line for the IPS (ips/schema.py), tagged with the
 *     real node behind the pseudonym ("node"), worked out from every node's pseudonym secret
 *   - signs BLOCK / unblock CTRL frames for the IPS and re-issues them every epoch so a block
 *     on a known node survives pseudonym + MAC rotation (decision 8b, O9)
 */
#ifndef GHOSTMESH_GM_WATCH_H
#define GHOSTMESH_GM_WATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gm_crypto.h"
#include "gm_node.h"      /* gm_hw_t */

#define GM_WATCH_MAX_NODES   8
#define GM_WATCH_MAX_BLOCKS  8
#define GM_WATCH_OWN_IDS     16
#define GM_WATCH_BEACON_MS   10000u
#define GM_WATCH_CTRL_GAP_MS 3000u   /* min gap between any two CTRL frames W sends (Jose, Nov 17) */

typedef struct { uint32_t id; char name; const uint8_t *pseudo_secret; } gm_watch_node_t;

typedef struct {
    const uint8_t         *network_key;   /* 32 */
    const uint8_t         *sk;            /* 64, Ed25519 (Monocypher layout) */
    const uint8_t         *pk;            /* 32 */
    const gm_watch_node_t *nodes;
    int                    node_count;
} gm_watch_keys_t;

typedef struct {
    bool     used;
    uint32_t block_id;
    char     node;          /* 'A'..'X' = follow that node every epoch; '?' = fixed pseudo+mac pair */
    uint8_t  pseudo[4];
    uint8_t  mac[6];
    uint8_t  reason;
    uint64_t until_ms;
    bool     send_due;      /* waiting for the CTRL gap */
    bool     unblock_due;
} gm_watch_block_t;

typedef struct {
    gm_watch_keys_t  keys;
    gm_hw_t          hw;
    gm_crypto_t      c;               /* only used for its RNG by gm_ctrl_sign */
    bool             clock_set;
    int64_t          offset_ms;       /* unix_ms = local_ms + offset */
    uint64_t         next_beacon_local;
    uint64_t         last_ctrl_local;   /* when W last sent any CTRL frame */
    bool             any_ctrl_sent;
    uint32_t         table_epoch;     /* absolute epoch the table below was built for */
    uint8_t          pseudo[3][GM_WATCH_MAX_NODES][4];   /* [epoch-1, epoch, epoch+1] */
    uint8_t          mac[3][GM_WATCH_MAX_NODES][6];
    uint8_t          own_ids[GM_WATCH_OWN_IDS][8];
    uint8_t          own_i;
    gm_watch_block_t blocks[GM_WATCH_MAX_BLOCKS];
    uint32_t         next_block_id;
    /* counters for status / OLED */
    uint32_t         frames, beacons_sent, blocks_sent, unknown_frames, bad_tag_frames;
    uint32_t         per_node_frames[GM_WATCH_MAX_NODES];
    int8_t           per_node_rssi[GM_WATCH_MAX_NODES];
} gm_watch_t;

void     gm_watch_init(gm_watch_t *w, const gm_watch_keys_t *keys, const gm_hw_t *hw);
void     gm_watch_set_time(gm_watch_t *w, uint64_t unix_ms);
uint64_t gm_watch_now(gm_watch_t *w);                    /* unix ms, 0 if clock not set */
void     gm_watch_poll(gm_watch_t *w);                   /* beacons + epoch rollover; call often */
/* Radio metadata for the optional log fields (notes-for-hannan.md §2.1). The S3 has no noise_floor. */
typedef struct { uint32_t rx_us; uint8_t rate, sig_mode, mcs; } gm_watch_meta_t;

/* meta may be NULL (laptop test). */
void     gm_watch_rx(gm_watch_t *w, const uint8_t frame[240], const uint8_t mac[6], int8_t rssi,
                     const gm_watch_meta_t *meta);

/* BLOCK. node: 'A'..'X' to follow a node, or '?' with pseudo+mac for a single pair.
 * reason: "flood", "replay", "spoof", "routing" (anything else = 0). until_ms is mesh time.
 * Returns the block_id (0 on failure). Sent as soon as the CTRL gap allows (<= 3 s); emits
 * {"ev":"block_sent",...} when it actually goes out. */
uint32_t gm_watch_block(gm_watch_t *w, char node, const uint8_t pseudo[4], const uint8_t mac[6],
                        const char *reason, uint64_t until_ms);
/* Ends a block early (re-issue with until == issued). Match by node, or by pseudo+mac for '?'. */
bool     gm_watch_unblock(gm_watch_t *w, char node, const uint8_t pseudo[4], const uint8_t mac[6]);

void     gm_watch_status(gm_watch_t *w);
char     gm_watch_identify(gm_watch_t *w, const uint8_t pseudo[4], const uint8_t mac[6], bool *mac_matches);

#endif
