// serial_if.cpp - newline-delimited JSON over USB serial (PROTOCOL.md §10).
// Lines are parsed here (Arduino loop task) into gm_cmd_t and queued; the processing task
// runs them, so the node state is only ever touched from one task.
#include <ArduinoJson.h>

#include "app.h"

static QueueHandle_t s_cmd_q;
static SemaphoreHandle_t s_out_mtx;
static char s_line[512];
static size_t s_len;

void serial_if_init(QueueHandle_t q)
{
    s_cmd_q = q;
    s_out_mtx = xSemaphoreCreateMutex();
}

void serial_emit(const char *json)
{
    if (s_out_mtx) xSemaphoreTake(s_out_mtx, portMAX_DELAY);
    Serial.println(json);
    if (s_out_mtx) xSemaphoreGive(s_out_mtx);
}

static void err(const char *why)
{
    char buf[80];
    snprintf(buf, sizeof buf, "{\"ev\":\"error\",\"reason\":\"%s\"}", why);
    serial_emit(buf);
}

static void handle_line(const char *line)
{
    JsonDocument doc;
    if (deserializeJson(doc, line)) { err("bad_json"); return; }
    const char *cmd = doc["cmd"] | "";
    gm_cmd_t c;
    memset(&c, 0, sizeof c);

    if (!strcmp(cmd, "send")) {
        const char *to = doc["to"] | "";
        const char *text = doc["text"] | "";
        size_t n = strlen(text);
        if (strlen(to) != 1) { err("bad_to"); return; }
        if (n > RT_BODY_MAX) { err("too_long"); return; }
        c.kind = CMD_SEND;
        c.to = (char)toupper(to[0]);
        c.len = (uint8_t)n;
        memcpy(c.text, text, n);
    } else if (!strcmp(cmd, "status")) {
        c.kind = CMD_STATUS;
    } else if (!strcmp(cmd, "set_time")) {          // DEBUG on nodes; the watchtower's beacon is the real source
        c.kind = CMD_SET_TIME;
        c.u64 = doc["unix_ms"] | (uint64_t)0;
        if (!c.u64) { err("bad_unix_ms"); return; }
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
    } else if (!strcmp(cmd, "wipe_state")) {
        c.kind = CMD_WIPE_STATE;
    } else if (!strcmp(cmd, "reboot")) {
        c.kind = CMD_REBOOT;
    } else {
        err("unknown_cmd");
        return;
    }
    if (xQueueSend(s_cmd_q, &c, 0) != pdTRUE) err("cmd_queue_full");
}

void serial_if_poll()
{
    while (Serial.available()) {
        int ch = Serial.read();
        if (ch == '\r') continue;
        if (ch == '\n') {
            s_line[s_len] = '\0';
            if (s_len) handle_line(s_line);
            s_len = 0;
        } else if (s_len < sizeof s_line - 1) {
            s_line[s_len++] = (char)ch;
        } else {
            s_len = 0;
            err("line_too_long");
        }
    }
}

void mac_to_str(const uint8_t m[6], char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

bool mac_from_str(const char *s, uint8_t out[6])
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return true;
}
