// app.h - ESP32-only glue shared by main.cpp, radio.cpp, serial_if.cpp, display.cpp, led.cpp.
// The protocol logic is NOT here: it's in node/gm_node.c (+ routing/ and crypto/), which is portable.
#pragma once

#include <Arduino.h>

extern "C" {
#include "gm_node.h"
}

#define GM_FW_VERSION "0.2.0"

// One received frame, handed from the ESP-NOW callback to the processing task.
struct gm_rx_item_t {
    uint8_t frame[240];
    int8_t  rssi;
    uint8_t mac[6];
};

// Commands parsed from serial (loop task), executed on the processing task.
enum gm_cmd_kind_t : uint8_t {
    CMD_SEND, CMD_STATUS, CMD_SET_TIME, CMD_VERBOSE, CMD_TXPOWER, CMD_RSSI_GATE,
    CMD_ALLOW, CMD_ROTATE_MAC, CMD_WIPE_STATE, CMD_REBOOT,
};

struct gm_cmd_t {
    gm_cmd_kind_t kind;
    char          to;
    uint8_t       len;
    char          text[RT_BODY_MAX + 1];
    uint64_t      u64;
    int32_t       value;
    uint8_t       allow[GM_NODE_ALLOW_MAX][6];
    uint8_t       allow_n;
};

// radio.cpp
bool     radio_init(QueueHandle_t rx_queue, int8_t tx_power_qdbm);
void     radio_send(const uint8_t frame[240]);       // queued, non-blocking
void     radio_set_tx_power(int8_t qdbm);
uint32_t radio_set_mac(const uint8_t mac[6]);        // returns radio outage in us (Jose's decision 2a: measure it)
void     radio_get_mac(uint8_t out[6]);
uint32_t radio_airtime_avg_us();
uint32_t radio_rx_overflows();
uint32_t radio_tx_failures();

// serial_if.cpp
void serial_if_init(QueueHandle_t cmd_queue);
void serial_if_poll();                // from loop(): reads lines, queues commands
void serial_emit(const char *json);   // thread-safe println

// led.cpp
void led_init();
void led_indicate(int what);          // GM_IND_* from gm_node.h
void led_service();

// display.cpp (SSD1306 128x64 over I2C; does nothing if no screen answers)
struct gm_display_snap_t {
    char     name;
    bool     synced;
    uint16_t epoch;
    uint8_t  pseudo[4];
    uint8_t  mac[6];
    uint32_t rx, tx, keys, delivered, dup, bad_tag, bad_epoch, not_synced, gate, allow;
    uint8_t  heard_n;
    int8_t   heard_best;
    int8_t   last_rssi;
    uint32_t mac_outage_us;
    uint8_t  queued;
    char     last_msg[22];
    char     last_send[22];
};
void display_init();
void display_publish(const gm_display_snap_t &s);    // from the processing task; display task redraws ~4 Hz

// misc
void mac_to_str(const uint8_t mac[6], char out[18]);
bool mac_from_str(const char *s, uint8_t out[6]);
