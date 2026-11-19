// main_w.cpp - WATCHTOWER firmware (board W, stays on the laptop). Owner: Yunus.
//
//   ESP-NOW rx -> rx queue --+
//   USB serial -> cmd queue -+--> processing task --> gm_watch (beacons, IPS log, BLOCK) --> radio_send
//
// Commands (one JSON per line):
//   {"cmd":"set_time","unix_ms":1763400000000}        start the mesh clock (chat_client --sync does this)
//   {"cmd":"status"}
//   {"cmd":"block","node":"X","reason":"flood","until":1763400300.0}          IPS format (ips/schema.py)
//   {"cmd":"block","node":"?","pseudo":"1a2b3c4d","mac":"aa:..","reason":"spoof","until":...}
//   {"cmd":"unblock","node":"X"}   /   {"cmd":"unblock","node":"?","pseudo":"..","mac":".."}
//   {"cmd":"txpower","qdbm":8}     {"cmd":"reboot"}
#include <ArduinoJson.h>
#include <Preferences.h>
#include <esp_random.h>
#include <esp_timer.h>

#include "app.h"

extern "C" {
#include "gm_watch.h"
const gm_watch_keys_t *gm_watch_board_keys(void);
}

enum w_cmd_kind_t : uint8_t { W_SET_TIME, W_STATUS, W_BLOCK, W_UNBLOCK, W_TXPOWER, W_REBOOT };

struct w_cmd_t {
    w_cmd_kind_t kind;
    uint64_t     u64;          // unix ms (set_time, block until)
    char         node;
    bool         has_pseudo, has_mac;
    uint8_t      pseudo[4];
    uint8_t      mac[6];
    char         reason[12];
    int32_t      value;
};

static gm_watch_t s_w;
static QueueHandle_t s_rx_q, s_cmd_q;
static Preferences s_prefs;

static void hw_transmit(void *, const uint8_t f[240]) { radio_send(f); led_indicate(GM_IND_TX); }
static uint64_t hw_local_ms(void *) { return (uint64_t)(esp_timer_get_time() / 1000); }
static void hw_rng(void *, uint8_t *out, size_t n) { esp_fill_random(out, n); }
static void hw_emit(void *, const char *json) { serial_emit(json); }

static bool parse_pseudo(const char *s, uint8_t out[4])
{
    if (strlen(s) != 8) return false;
    for (int i = 0; i < 4; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

// Parsed on the loop task, executed on the processing task.
void app_handle_line(const char *line)
{
    JsonDocument doc;
    if (deserializeJson(doc, line)) { serial_error("bad_json"); return; }
    const char *cmd = doc["cmd"] | "";
    w_cmd_t c = {};

    if (!strcmp(cmd, "set_time")) {
        c.kind = W_SET_TIME;
        c.u64 = doc["unix_ms"] | (uint64_t)0;
        if (!c.u64) { serial_error("bad_unix_ms"); return; }
    } else if (!strcmp(cmd, "status")) {
        c.kind = W_STATUS;
    } else if (!strcmp(cmd, "block") || !strcmp(cmd, "unblock")) {
        c.kind = !strcmp(cmd, "block") ? W_BLOCK : W_UNBLOCK;
        const char *node = doc["node"] | "";
        if (strlen(node) != 1) { serial_error("bad_node"); return; }
        c.node = (char)toupper(node[0]);
        c.has_pseudo = parse_pseudo(doc["pseudo"] | "", c.pseudo);
        c.has_mac = mac_from_str(doc["mac"] | "", c.mac);
        if (c.node == '?' && !c.has_pseudo) { serial_error("pair_block_needs_pseudo"); return; }
        strlcpy(c.reason, doc["reason"] | "", sizeof c.reason);
        double until_s = doc["until"] | 0.0;                    // IPS sends unix seconds
        c.u64 = until_s > 0 ? (uint64_t)(until_s * 1000.0) : 0;
    } else if (!strcmp(cmd, "txpower")) {
        c.kind = W_TXPOWER;
        c.value = doc["qdbm"] | 8;
    } else if (!strcmp(cmd, "reboot")) {
        c.kind = W_REBOOT;
    } else {
        serial_error("unknown_cmd");
        return;
    }
    if (xQueueSend(s_cmd_q, &c, 0) != pdTRUE) serial_error("cmd_queue_full");
}

static void on_command(const w_cmd_t &c)
{
    switch (c.kind) {
    case W_SET_TIME: gm_watch_set_time(&s_w, c.u64); break;
    case W_STATUS: {
        gm_watch_status(&s_w);
        char buf[160];
        snprintf(buf, sizeof buf, "{\"ev\":\"radio\",\"airtime_avg_us\":%lu,\"rx_overflow\":%lu,\"tx_fail\":%lu,\"free_heap\":%lu}",
                 (unsigned long)radio_airtime_avg_us(), (unsigned long)radio_rx_overflows(),
                 (unsigned long)radio_tx_failures(), (unsigned long)ESP.getFreeHeap());
        serial_emit(buf);
        break;
    }
    case W_BLOCK: {
        uint64_t until = c.u64 ? c.u64 : gm_watch_now(&s_w) + 120000;   // default 2 min
        gm_watch_block(&s_w, c.node, c.has_pseudo ? c.pseudo : nullptr, c.has_mac ? c.mac : nullptr, c.reason, until);
        break;
    }
    case W_UNBLOCK:
        gm_watch_unblock(&s_w, c.node, c.has_pseudo ? c.pseudo : nullptr, c.has_mac ? c.mac : nullptr);
        break;
    case W_TXPOWER:
        radio_set_tx_power((int8_t)constrain(c.value, 8, 84));
        s_prefs.putChar("txpow", (int8_t)constrain(c.value, 8, 84));
        break;
    case W_REBOOT: ESP.restart(); break;
    }
}

static void proc_task(void *)
{
    gm_rx_item_t it;
    w_cmd_t c;
    uint32_t next_hint = 0;
    for (;;) {
        if (xQueueReceive(s_rx_q, &it, pdMS_TO_TICKS(2)) == pdTRUE) {
            do {
                gm_watch_meta_t meta = { it.rx_us, it.rate, it.sig_mode, it.mcs };
                gm_watch_rx(&s_w, it.frame, it.mac, it.rssi, &meta);
            } while (xQueueReceive(s_rx_q, &it, 0) == pdTRUE);
        }
        while (xQueueReceive(s_cmd_q, &c, 0) == pdTRUE) on_command(c);
        gm_watch_poll(&s_w);
        led_service();
        if (!s_w.clock_set && (int32_t)(millis() - next_hint) >= 0) {   // nag until the laptop sets the clock
            next_hint = millis() + 5000;
            serial_emit("{\"ev\":\"warning\",\"reason\":\"clock_not_set\",\"hint\":\"send set_time (chat_client --sync)\"}");
        }
    }
}

void setup()
{
    Serial.setTxBufferSize(4096);                       // W prints a log line for every frame it hears
    Serial.begin(115200);
    delay(300);
    led_init();
    s_prefs.begin("ghostmesh", false);

    s_rx_q = xQueueCreate(64, sizeof(gm_rx_item_t));    // W hears everything: deeper queue
    s_cmd_q = xQueueCreate(8, sizeof(w_cmd_t));
    serial_if_init(s_cmd_q);
    if (!radio_init(s_rx_q, s_prefs.getChar("txpow", 8))) serial_emit("{\"ev\":\"error\",\"reason\":\"espnow_init_failed\"}");

    gm_hw_t hw = { nullptr, hw_transmit, hw_local_ms, hw_rng, hw_emit, nullptr, nullptr, nullptr };
    gm_watch_init(&s_w, gm_watch_board_keys(), &hw);

    uint8_t mac[6]; char ms[18], fp_net[10], fp_wt[10], buf[220];
    radio_get_mac(mac);
    mac_to_str(mac, ms);
    gm_fingerprint(s_w.keys.network_key, fp_net);
    gm_fingerprint(s_w.keys.pk, fp_wt);
    snprintf(buf, sizeof buf,
             "{\"ev\":\"boot\",\"name\":\"W\",\"id\":5,\"fw\":\"%s\",\"peers\":%d,\"mac\":\"%s\","
             "\"fp\":{\"self\":\"%s\",\"network\":\"%s\",\"watchtower\":\"%s\"}}",
             GM_FW_VERSION, s_w.keys.node_count, ms, fp_wt, fp_net, fp_wt);
    serial_emit(buf);

    xTaskCreatePinnedToCore(proc_task, "gm_proc", 12288, nullptr, 5, nullptr, 1);
}

void loop()
{
    serial_if_poll();
    vTaskDelay(pdMS_TO_TICKS(2));
}
