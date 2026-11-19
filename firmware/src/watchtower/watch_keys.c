/* watch_keys.c - turns config/keys/keys_W.h into a gm_watch_keys_t (W build only). */
#include "gm_watch.h"
#include "keys_W.h"

const gm_watch_keys_t *gm_watch_board_keys(void)
{
    static gm_watch_node_t nodes[GM_NODE_COUNT];
    static gm_watch_keys_t k;
    for (int i = 0; i < GM_NODE_COUNT; i++) {
        nodes[i].id = GM_NODES[i].id;
        nodes[i].name = GM_NODES[i].name;
        nodes[i].pseudo_secret = GM_NODES[i].pseudo_secret;
    }
    k.network_key = GM_NETWORK_KEY;
    k.sk = GM_WATCHTOWER_SK;
    k.pk = GM_WATCHTOWER_PK;
    k.nodes = nodes;
    k.node_count = GM_NODE_COUNT;
    return &k;
}
