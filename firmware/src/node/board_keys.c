/*
 * board_keys.c - turns one keygen header (firmware/config/keys/keys_<N>.h) into a gm_node_keys_t.
 *
 * Each keys header defines the same symbol names (GM_NETWORK_KEY, GM_PEERS, ...) as
 * `static const`, so each one lives in its own translation unit: the firmware compiles
 * this file once with -DGM_KEYS_FILE="keys_A.h"; the host test compiles it once per board
 * with a different GM_KEYS_FN name.
 */
#include "gm_node.h"

#ifndef GM_KEYS_FILE
#error "Build with -DGM_KEYS_FILE=\"keys_<N>.h\" (run python security/keygen.py first)"
#endif
#ifndef GM_KEYS_FN
#define GM_KEYS_FN gm_board_keys
#endif

#include GM_KEYS_FILE

const gm_node_keys_t *GM_KEYS_FN(void)
{
    static gm_peer_key_t  peers[GM_PEER_COUNT];
    static gm_node_keys_t k;
    for (int i = 0; i < GM_PEER_COUNT; i++) {
        peers[i].id = GM_PEERS[i].id;
        peers[i].name = GM_PEERS[i].name;
        peers[i].pk = GM_PEERS[i].pk;
    }
    k.node_id = GM_NODE_ID;
    k.name = GM_NODE_NAME[0];
    k.network_key = GM_NETWORK_KEY;
    k.pseudo_secret = GM_PSEUDO_SECRET;
    k.x25519_sk = GM_X25519_SK;
    k.watchtower_pk = GM_WATCHTOWER_PK;
    k.peers = peers;
    k.peer_count = GM_PEER_COUNT;
    return &k;
}
