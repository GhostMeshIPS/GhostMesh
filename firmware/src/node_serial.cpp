// node_serial.cpp - JSON commands for NODE boards (A-D). Parsed on the loop task, queued as
// gm_cmd_t, executed on the processing task in main.cpp.
#include <ArduinoJson.h>

#include "app.h"

void app_handle_line(const char *line)
{
    JsonDocument doc;
    if (deserializeJson(doc, line)) { serial_error("bad_json"); return; }
    const char *cmd = doc["cmd"] | "";
    gm_cmd_t c;
    memset(&c, 0, sizeof c);

    if (!strcmp(cmd, "send")) {
        const char *to = doc["to"] | "";
        const char *text = doc["text"] | "";
        size_t n = strlen(text);
        if (strlen(to) != 1) { serial_error("bad_to"); return; }
        if (n > RT_BODY_MAX) { serial_error("too_long"); return; }
        c.kind = CMD_SEND;
        c.to = (char)toupper(to[0]);
        c.len = (uint8_t)n;
        memcpy(c.text, text, n);
    } else if (!strcmp(cmd, "status")) {
        c.kind = CMD_STATUS;
    } else if (!strcmp(cmd, "set_time")) {          // DEBUG on nodes; the watchtower's beacon is the real source
        c.kind = CMD_SET_TIME;
        c.u64 = doc["unix_ms"] | (uint64_t)0;
        if (!c.u64) { serial_error("bad_unix_ms"); return; }
    } else if (!strcmp(cmd, "verbose")) {
        c.kind = CMD_VERBOSE;
        c.value = (doc["on"] | false) ? 1 : 0;
    } else if (!strcmp(cmd, "txpower")) {
        c.kind = CMD_TXPOWER;
        c.value = doc["qdbm"] | 8;
    } else if (!strcmp(cmd, "rssi_gate")) {
        c.kind = CMD_RSSI_GATE;
        c.value = doc["dbm"] | -127;
    } else if (!strcmp(cmd, "allow")) {
        c.kind = CMD_ALLOW;
        for (JsonVariant v : doc["macs"].as<JsonArray>())
            if (c.allow_n < GM_NODE_ALLOW_MAX && mac_from_str(v | "", c.allow[c.allow_n])) c.allow_n++;
    } else if (!strcmp(cmd, "rotate_mac")) {
        c.kind = CMD_ROTATE_MAC;
        c.value = (doc["on"] | true) ? 1 : 0;
    } else if (!strcmp(cmd, "auto")) {              // hands-free test traffic, saved in flash
        c.kind = CMD_AUTO;
        const char *to = doc["to"] | "";
        c.to = strlen(to) == 1 ? (char)toupper(to[0]) : 0;
        c.value = doc["every_s"] | 0;
    } else if (!strcmp(cmd, "bench")) {             // time encrypt + trial-decrypt on this board
        c.kind = CMD_BENCH;
        c.value = doc["runs"] | 0;
    } else if (!strcmp(cmd, "wipe_state")) {
        c.kind = CMD_WIPE_STATE;
    } else if (!strcmp(cmd, "reboot")) {
        c.kind = CMD_REBOOT;
    } else {
        serial_error("unknown_cmd");
        return;
    }
    if (xQueueSend(serial_cmd_queue(), &c, 0) != pdTRUE) serial_error("cmd_queue_full");
}

