// serial_if.cpp - newline-delimited JSON over USB serial (PROTOCOL.md §10): line reader,
// thread-safe output, MAC helpers. Each board type parses its own commands in
// app_handle_line() (node: node_serial.cpp, watchtower: watchtower/main_w.cpp).

#include "app.h"

static QueueHandle_t s_cmd_q;

QueueHandle_t serial_cmd_queue() { return s_cmd_q; }
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
    // On a power bank no laptop is reading USB: skip printing instead of waiting on a full buffer.
    // (Serial is false until a host opens the port.)
    if (!Serial) return;
    if (s_out_mtx) xSemaphoreTake(s_out_mtx, portMAX_DELAY);
    Serial.println(json);
    if (s_out_mtx) xSemaphoreGive(s_out_mtx);
}

void serial_error(const char *why)
{
    char buf[80];
    snprintf(buf, sizeof buf, "{\"ev\":\"error\",\"reason\":\"%s\"}", why);
    serial_emit(buf);
}

void serial_if_poll()
{
    while (Serial.available()) {
        int ch = Serial.read();
        if (ch == '\r') continue;
        if (ch == '\n') {
            s_line[s_len] = '\0';
            if (s_len) app_handle_line(s_line);
            s_len = 0;
        } else if (s_len < sizeof s_line - 1) {
            s_line[s_len++] = (char)ch;
        } else {
            s_len = 0;
            serial_error("line_too_long");
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
