/*
 * shim.c - small helpers so Python (ctypes) can use routing.c.
 * Compiled into the same librouting.so as routing.c. No routing logic here.
 */
#include "routing.h"

#include <stddef.h>

// python can't know sizeof(rt_node_t), so it asks
size_t sim_node_size(void) { return sizeof(rt_node_t); }

// sanity checks for the ctypes mirrors in bindings.py
size_t sim_frame_size(void)  { return sizeof(rt_frame_t); }
size_t sim_inner_size(void)  { return sizeof(rt_inner_t); }
size_t sim_config_size(void) { return sizeof(rt_config_t); }

// log event names straight from the enum, so python never has its own copy to drift
const char *sim_log_name(int ev)
{
    switch ((rt_log_t)ev) {
    case RT_LOG_BAD_LINK_TAG:    return "BAD_LINK_TAG";
    case RT_LOG_BAD_EPOCH:       return "BAD_EPOCH";
    case RT_LOG_BAD_TYPE:        return "BAD_TYPE";
    case RT_LOG_BLOCKED:         return "BLOCKED";
    case RT_LOG_RATE_LIMITED:    return "RATE_LIMITED";
    case RT_LOG_DUPLICATE:       return "DUPLICATE";
    case RT_LOG_DUP_COUNTED:     return "DUP_COUNTED";
    case RT_LOG_RELAY_CANCELLED: return "RELAY_CANCELLED";
    case RT_LOG_TTL_EXPIRED:     return "TTL_EXPIRED";
    case RT_LOG_CTRL_UNVERIFIED: return "CTRL_UNVERIFIED";
    case RT_LOG_REPLAY_STALE:    return "REPLAY_STALE";
    case RT_LOG_NOT_SYNCED:      return "NOT_SYNCED";
    case RT_LOG_RELAY_SCHEDULED: return "RELAY_SCHEDULED";
    case RT_LOG_TX:              return "TX";
    case RT_LOG_DELIVERED:       return "DELIVERED";
    case RT_LOG_REACK:           return "REACK";
    case RT_LOG_ACK_MATCHED:     return "ACK_MATCHED";
    case RT_LOG_ACK_UNMATCHED:   return "ACK_UNMATCHED";
    case RT_LOG_HELLO:           return "HELLO";
    case RT_LOG_TOO_LONG:        return "TOO_LONG";
    case RT_LOG_ENCRYPT_FAILED:  return "ENCRYPT_FAILED";
    case RT_LOG_SEND_FAILED:     return "SEND_FAILED";
    case RT_LOG_PEER_EVICTED:    return "PEER_EVICTED";
    }
    return "UNKNOWN";
}
