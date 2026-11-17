/* Test-only: exposes the watchtower's signing key so test_node.c can sign TIME beacons. */
#include <stdint.h>
#include "keys_W.h"

const uint8_t *wt_sk(void) { return GM_WATCHTOWER_SK; }
const uint8_t *wt_network_key(void) { return GM_NETWORK_KEY; }
