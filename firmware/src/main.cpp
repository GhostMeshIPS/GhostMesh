// main.cpp - GhostMesh NODE firmware (boards A-D). Owner: Yunus.
//
//   ESP-NOW rx callback -> rx queue --+
//   USB serial (loop)   -> cmd queue -+--> processing task --> gm_node (routing + crypto) --> radio_send --> tx task
//                                     |          +--> display snapshot (OLED task redraws ~4 Hz)
//
// The processing task is the ONLY task that touches gm_node. Keys come from
// config/keys/keys_<N>.h, picked by the PlatformIO env (pio run -e A).
#include <Preferences.h>
#include <esp_random.h>
#include <esp_timer.h>

#include "app.h"

extern "C" const gm_node_keys_t *gm_board_keys(void);   // node/board_keys.c

static gm_node_t s_node;                // ~50 KB: static, never on a stack
static QueueHandle_t s_rx_q, s_cmd_q;
static Preferences s_prefs;
static char s_auto_to;              // hands-free test traffic: send to this node...
static uint16_t s_auto_every_s;     // ...every N seconds once synced (0 = off). Saved in flash.
static uint32_t s_auto_n, s_next_auto;

// ---- gm_hw_t: what gm_node needs from the hardware -------------------------
static void hw_transmit(void *, const uint8_t f[240]) { radio_send(f); }
static uint64_t hw_local_ms(void *) { return (uint64_t)(esp_timer_get_time() / 1000); }
static void hw_rng(void *, uint8_t *out, size_t n) { esp_fill_random(out, n); }   // true RNG while Wi-Fi is on
static void hw_emit(void *, const char *json) { serial_emit(json); }
static uint32_t hw_set_mac(void *, const uint8_t mac[6]) { return radio_set_mac(mac); }
static void hw_indicate(void *, int what) { led_indicate(what); }
static void hw_save_state(void *, const uint8_t *blob, size_t len) { s_prefs.putBytes("gm_state", blob, len); }

// ---- OLED snapshot -----------------------------------------------------------
static void publish_display()
{
    gm_display_snap_t s = {};
    gm_node_t *n = &s_node;
    s.name = n->keys.name;
    s.synced = n->c.synced;
    s.epoch = n->c.synced ? gm_node_wire_epoch(n) : 0;
    gm_node_pseudonym(n, s.pseudo);
    radio_get_mac(s.mac);
    const uint32_t *L = n->st.log_counts;
    s.rx = n->st.rx_frames;
    s.tx = n->st.tx_frames;
    s.keys = n->st.keys_sent;
    s.dup = L[RT_LOG_DUPLICATE] + L[RT_LOG_DUP_COUNTED];
    s.bad_tag = L[RT_LOG_BAD_LINK_TAG];
    s.bad_epoch = L[RT_LOG_BAD_EPOCH];
    s.not_synced = L[RT_LOG_NOT_SYNCED];
    s.gate = n->st.gate_drops;
    s.allow = n->st.allow_drops;
    s.last_rssi = n->st.last_rssi;
    s.mac_outage_us = n->st.last_mac_outage_us;
    s.queued = n->sendq_n;
    s.heard_best = -127;
    uint64_t now = hw_local_ms(nullptr);
    for (auto &h : n->st.heard) {
        if (!h.at || now - h.at > 5000) continue;
        s.heard_n++;
        if (h.rssi > s.heard_best) s.heard_best = h.rssi;
    }
    s.auto_to = s_auto_to;
    s.auto_every_s = s_auto_every_s;
    s.ok = L[RT_LOG_ACK_MATCHED];
    s.failed = L[RT_LOG_SEND_FAILED];
    strlcpy(s.last_msg, n->st.last_msg, sizeof s.last_msg);
    strlcpy(s.last_send, n->st.last_send, sizeof s.last_send);
    display_publish(s);
}

// ---- commands ------------------------------------------------------------------
static void emit_radio_status()
{
    char buf[260];
    snprintf(buf, sizeof buf,
             "{\"ev\":\"radio\",\"airtime_avg_us\":%lu,\"rx_overflow\":%lu,\"tx_fail\":%lu,\"free_heap\":%lu,"
             "\"rotate_mac\":%s,\"rssi_gate\":%d,\"allow_n\":%u,\"auto_to\":\"%c\",\"auto_every_s\":%u}",
             (unsigned long)radio_airtime_avg_us(), (unsigned long)radio_rx_overflows(),
             (unsigned long)radio_tx_failures(), (unsigned long)ESP.getFreeHeap(),
             s_node.rotate_mac ? "true" : "false", s_node.rssi_gate, s_node.allow_n,
             s_auto_to ? s_auto_to : '-', s_auto_every_s);
    serial_emit(buf);
}

static void on_command(const gm_cmd_t &c)
{
    gm_node_t *n = &s_node;
    switch (c.kind) {
    case CMD_SEND:      gm_node_send(n, c.to, c.text, c.len); break;
    case CMD_STATUS:    gm_node_status(n); emit_radio_status(); break;
    case CMD_SET_TIME:  gm_node_debug_set_time(n, c.u64); break;
    case CMD_VERBOSE:   n->verbose = c.value != 0; break;
    case CMD_TXPOWER:
        radio_set_tx_power((int8_t)constrain(c.value, 8, 84));
        s_prefs.putChar("txpow", (int8_t)constrain(c.value, 8, 84));
        emit_radio_status();
        break;
    case CMD_RSSI_GATE:
        n->rssi_gate = (int8_t)constrain(c.value, -127, 0);
        s_prefs.putChar("rssi_gate", n->rssi_gate);
        emit_radio_status();
        break;
    case CMD_ALLOW:
        memcpy(n->allow, c.allow, sizeof n->allow);
        n->allow_n = c.allow_n;
        if (n->allow_n && n->rotate_mac)
            serial_emit("{\"ev\":\"warning\",\"reason\":\"allowlist_needs_rotate_mac_off\"}");
        emit_radio_status();
        break;
    case CMD_ROTATE_MAC:
        n->rotate_mac = c.value != 0;
        s_prefs.putBool("rotmac", n->rotate_mac);
        serial_emit("{\"ev\":\"warning\",\"reason\":\"reboot_to_apply_rotate_mac\"}");
        break;
    case CMD_WIPE_STATE:
        s_prefs.remove("gm_state");
        serial_emit("{\"ev\":\"state_wiped\",\"rebooting\":true}");
        delay(100);
        ESP.restart();
        break;
    case CMD_REBOOT:    ESP.restart(); break;
    case CMD_BENCH:     gm_node_bench(n, (uint32_t)c.value); break;
    case CMD_AUTO: {
        s_auto_to = c.to;
        s_auto_every_s = (uint16_t)constrain(c.value, 0, 3600);
        if (!s_auto_to) s_auto_every_s = 0;
        s_prefs.putChar("auto_to", s_auto_to);
        s_prefs.putUShort("auto_s", s_auto_every_s);
        s_next_auto = millis() + 3000;
        char buf[80];
        snprintf(buf, sizeof buf, "{\"ev\":\"auto\",\"to\":\"%c\",\"every_s\":%u}", s_auto_to ? s_auto_to : '-', s_auto_every_s);
        serial_emit(buf);
        break;
    }
    }
}

// ---- processing task -----------------------------------------------------------
static void proc_task(void *)
{
    gm_rx_item_t it;
    gm_cmd_t c;
    uint32_t next_display = 0;
    for (;;) {
        if (xQueueReceive(s_rx_q, &it, pdMS_TO_TICKS(2)) == pdTRUE) {
            gm_node_rx(&s_node, it.frame, it.mac, it.rssi);
            while (xQueueReceive(s_rx_q, &it, 0) == pdTRUE) gm_node_rx(&s_node, it.frame, it.mac, it.rssi);
        }
        while (xQueueReceive(s_cmd_q, &c, 0) == pdTRUE) on_command(c);
        gm_node_poll(&s_node);
        led_service();
        if (s_auto_every_s && s_node.c.synced && (int32_t)(millis() - s_next_auto) >= 0) {
            s_next_auto = millis() + s_auto_every_s * 1000u;
            char text[40];
            int len = snprintf(text, sizeof text, "auto %c#%lu", s_node.keys.name, (unsigned long)++s_auto_n);
            gm_node_send(&s_node, s_auto_to, text, (size_t)len);
        }
        if ((int32_t)(millis() - next_display) >= 0) { next_display = millis() + 250; publish_display(); }
    }
}

void setup()
{
    Serial.setTxBufferSize(2048);                       // whole JSON lines fit (status is ~600 bytes)
    Serial.begin(115200);
    delay(300);                                         // let USB CDC enumerate
    led_init();

    s_prefs.begin("ghostmesh", false);
    int8_t txpow = s_prefs.getChar("txpow", 8);         // lowest power by default: helps force multi-hop
    static uint8_t state[GM_STATE_BYTES];
    size_t state_len = s_prefs.getBytes("gm_state", state, sizeof state);

    s_rx_q = xQueueCreate(32, sizeof(gm_rx_item_t));
    s_cmd_q = xQueueCreate(8, sizeof(gm_cmd_t));
    serial_if_init(s_cmd_q);
    if (!radio_init(s_rx_q, txpow)) serial_emit("{\"ev\":\"error\",\"reason\":\"espnow_init_failed\"}");

    gm_hw_t hw = { nullptr, hw_transmit, hw_local_ms, hw_rng, hw_emit, hw_set_mac, hw_save_state, hw_indicate };
    gm_node_init(&s_node, gm_board_keys(), &hw, state_len == GM_STATE_BYTES ? state : nullptr,
                 state_len == GM_STATE_BYTES ? state_len : 0);
    s_node.rotate_mac = s_prefs.getBool("rotmac", true);
    s_node.rssi_gate = s_prefs.getChar("rssi_gate", -127);
    s_auto_to = (char)s_prefs.getChar("auto_to", 0);
    s_auto_every_s = s_prefs.getUShort("auto_s", 0);
    s_next_auto = millis() + 5000;

    gm_node_boot_banner(&s_node, GM_FW_VERSION);
    emit_radio_status();
    display_init();

    xTaskCreatePinnedToCore(proc_task, "gm_proc", 16384, nullptr, 5, nullptr, 1);
}

void loop()
{
    serial_if_poll();
    vTaskDelay(pdMS_TO_TICKS(2));
}
