// main_x.cpp - ATTACKER X firmware (decision 18). Owner: Jose (Network #2).
//
// A thin radio passthrough for the attack scripts in security/attacks/. It holds NO keys and runs no
// routing: it never transmits on its own. All attack logic (crafting frames, link_tag, pseudonyms,
// replays, pacing, labels) runs on the laptop in Python.
//
//   ESP-NOW rx -> rx queue -> processing task -> {"ev":"rx",...} line per frame (when sniffing)
//   USB serial -> app_handle_line -> radio_send / radio_set_mac           (loop task)
//
// Commands (one JSON object per line):
//   {"cmd":"tx","hex":"<480 hex chars>"}        transmit one 240-byte frame as-is
//   {"cmd":"set_mac","mac":"aa:bb:cc:dd:ee:ff"}  change the radio MAC (restarts Wi-Fi, ~5.5 ms)
//   {"cmd":"sniff","on":false}                  stop/start printing received frames (default on)
//   {"cmd":"status"}   {"cmd":"txpower","qdbm":8}   {"cmd":"reboot"}
// Events:
//   {"ev":"boot","name":"X","role":"attacker","fw":"..","mac":".."}
//   {"ev":"rx","us":<esp_timer us>,"mac":"..","rssi":-60,"rx_us":..,"raw":"<480 hex>"}
//   {"ev":"mac","mac":"..","outage_us":5500}
//   {"ev":"status","tx":..,"tx_fail":..,"rx":..,"rx_overflow":..,"sniff":true,"mac":"..","uptime_ms":..}
//   {"ev":"error","reason":"..."}
//
// SECURITY: the raw-transmit command exists ONLY in this build ([env:X]); node and watchtower builds
// exclude src/attacker/ (platformio.ini). Never flash this onto a demo node.
#include <ArduinoJson.h>
#include <esp_timer.h>

#include "app.h"

static QueueHandle_t s_rx_q;
static volatile bool s_sniff = true;
static volatile uint32_t s_rx = 0, s_tx = 0;

static const char HEX_DIGITS[] = "0123456789abcdef";

static bool hex_to_frame(const char *hex, uint8_t out[240])
{
    if (strlen(hex) != 480) return false;
    for (int i = 0; i < 240; i++) {
        uint8_t v = 0;
        for (int k = 0; k < 2; k++) {
            char ch = hex[2 * i + k];
            uint8_t d;
            if (ch >= '0' && ch <= '9') d = ch - '0';
            else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
            else return false;
            v = (uint8_t)(v << 4 | d);
        }
        out[i] = v;
    }
    return true;
}

static void emit_status()
{
    uint8_t mac[6];
    char ms[18], buf[220];
    radio_get_mac(mac);
    mac_to_str(mac, ms);
    snprintf(buf, sizeof buf,
             "{\"ev\":\"status\",\"name\":\"X\",\"tx\":%lu,\"tx_fail\":%lu,\"rx\":%lu,\"rx_overflow\":%lu,"
             "\"sniff\":%s,\"mac\":\"%s\",\"airtime_avg_us\":%lu,\"uptime_ms\":%lu}",
             (unsigned long)s_tx, (unsigned long)radio_tx_failures(), (unsigned long)s_rx,
             (unsigned long)radio_rx_overflows(), s_sniff ? "true" : "false", ms,
             (unsigned long)radio_airtime_avg_us(), (unsigned long)millis());
    serial_emit(buf);
}

// Runs on the loop task. radio_send only queues the frame, so tx never blocks the reader.
void app_handle_line(const char *line)
{
    JsonDocument doc;
    if (deserializeJson(doc, line)) { serial_error("bad_json"); return; }
    const char *cmd = doc["cmd"] | "";

    if (!strcmp(cmd, "tx")) {
        uint8_t frame[240];
        if (!hex_to_frame(doc["hex"] | "", frame)) { serial_error("bad_hex"); return; }
        radio_send(frame);
        s_tx++;
        led_indicate(GM_IND_TX);
    } else if (!strcmp(cmd, "set_mac")) {
        uint8_t mac[6];
        if (!mac_from_str(doc["mac"] | "", mac)) { serial_error("bad_mac"); return; }
        if (mac[0] & 0x01) { serial_error("multicast_mac"); return; }     // ESP-NOW needs a unicast MAC
        uint32_t outage = radio_set_mac(mac);
        uint8_t now[6]; char ms[18], buf[96];
        radio_get_mac(now);
        mac_to_str(now, ms);
        snprintf(buf, sizeof buf, "{\"ev\":\"mac\",\"mac\":\"%s\",\"outage_us\":%lu}", ms, (unsigned long)outage);
        serial_emit(buf);
    } else if (!strcmp(cmd, "sniff")) {
        s_sniff = doc["on"] | true;
        emit_status();
    } else if (!strcmp(cmd, "status")) {
        emit_status();
    } else if (!strcmp(cmd, "txpower")) {
        int q = doc["qdbm"] | 8;
        radio_set_tx_power((int8_t)constrain(q, 8, 84));
    } else if (!strcmp(cmd, "reboot")) {
        ESP.restart();
    } else {
        serial_error("unknown_cmd");
    }
}

static void proc_task(void *)
{
    gm_rx_item_t it;
    static char line[620];
    for (;;) {
        if (xQueueReceive(s_rx_q, &it, pdMS_TO_TICKS(5)) == pdTRUE) {
            s_rx++;
            if (s_sniff) {
                char ms[18];
                mac_to_str(it.mac, ms);
                int n = snprintf(line, sizeof line, "{\"ev\":\"rx\",\"us\":%llu,\"mac\":\"%s\",\"rssi\":%d,\"rx_us\":%lu,\"raw\":\"",
                                 (unsigned long long)esp_timer_get_time(), ms, (int)it.rssi, (unsigned long)it.rx_us);
                for (int i = 0; i < 240; i++) {
                    line[n++] = HEX_DIGITS[it.frame[i] >> 4];
                    line[n++] = HEX_DIGITS[it.frame[i] & 0x0F];
                }
                line[n++] = '"';
                line[n++] = '}';
                line[n] = '\0';
                serial_emit(line);
            }
        }
        led_service();
    }
}

void setup()
{
    Serial.setTxBufferSize(8192);                       // one ~560-byte line per frame heard
    Serial.begin(115200);
    delay(300);
    led_init();

    s_rx_q = xQueueCreate(64, sizeof(gm_rx_item_t));
    serial_if_init(nullptr);                            // commands run directly in app_handle_line
    if (!radio_init(s_rx_q, 8)) serial_emit("{\"ev\":\"error\",\"reason\":\"espnow_init_failed\"}");

    uint8_t mac[6]; char ms[18], buf[140];
    radio_get_mac(mac);
    mac_to_str(mac, ms);
    snprintf(buf, sizeof buf, "{\"ev\":\"boot\",\"name\":\"X\",\"role\":\"attacker\",\"fw\":\"%s\",\"mac\":\"%s\"}",
             GM_FW_VERSION, ms);
    serial_emit(buf);

    xTaskCreatePinnedToCore(proc_task, "gm_x", 6144, nullptr, 5, nullptr, 1);
}

void loop()
{
    serial_if_poll();
    vTaskDelay(pdMS_TO_TICKS(1));
}
