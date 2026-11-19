// radio.cpp - ESP-NOW broadcast radio. Owner: Yunus.
//
// RX: the ESP-NOW receive callback runs on the Wi-Fi task. It only copies the frame, RSSI and
//     sender MAC into a FreeRTOS queue and returns. All logic runs on the processing task.
// TX: radio_send() queues the frame; a dedicated TX task calls esp_now_send().
#include <WiFi.h>
#include <atomic>
#include <esp_now.h>
#include <esp_timer.h>
#include <esp_wifi.h>

#include "app.h"

#ifndef GM_CHANNEL
#define GM_CHANNEL 1
#endif

static const uint8_t BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static QueueHandle_t s_rx_q, s_tx_q;
static SemaphoreHandle_t s_radio_mtx;            // held while the MAC is being changed
static int8_t s_tx_power = 8;

// written from the Wi-Fi task and the TX task, read from the processing task
static std::atomic<uint32_t> s_rx_overflow{0}, s_tx_fail{0};
static std::atomic<uint32_t> s_airtime_sum_us{0}, s_airtime_n{0};
static volatile int64_t s_tx_started_us;

static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    if (len != 240) return;                      // every GhostMesh frame is exactly 240 bytes
    gm_rx_item_t it;
    memcpy(it.frame, data, 240);
    memcpy(it.mac, info->src_addr, 6);
    it.rssi = (int8_t)info->rx_ctrl->rssi;
    it.rx_us = info->rx_ctrl->timestamp;           // radio's own µs clock (watchtower log: rx_us)
    it.rate = info->rx_ctrl->rate;
    it.sig_mode = info->rx_ctrl->sig_mode;
    it.mcs = info->rx_ctrl->mcs;
    if (xQueueSend(s_rx_q, &it, 0) != pdTRUE) s_rx_overflow++;
}

static void note_send_done(bool ok)
{
    if (!ok) s_tx_fail++;
    if (s_tx_started_us) {
        s_airtime_sum_us += (uint32_t)(esp_timer_get_time() - s_tx_started_us);
        s_airtime_n++;
        s_tx_started_us = 0;
    }
}

// The send-callback signature changed in ESP-IDF 5.5 (Arduino core 3.3).
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
static void on_sent(const wifi_tx_info_t *, esp_now_send_status_t st) { note_send_done(st == ESP_NOW_SEND_SUCCESS); }
#else
static void on_sent(const uint8_t *, esp_now_send_status_t st) { note_send_done(st == ESP_NOW_SEND_SUCCESS); }
#endif

static void tx_task(void *)
{
    uint8_t frame[240];
    for (;;) {
        if (xQueueReceive(s_tx_q, frame, portMAX_DELAY) != pdTRUE) continue;
        xSemaphoreTake(s_radio_mtx, portMAX_DELAY);
        for (int attempt = 0; attempt < 5; attempt++) {
            s_tx_started_us = esp_timer_get_time();
            esp_err_t e = esp_now_send(BCAST, frame, 240);
            if (e == ESP_OK) break;
            s_tx_started_us = 0;
            if (e != ESP_ERR_ESPNOW_NO_MEM) { s_tx_fail++; break; }
            vTaskDelay(1);                       // driver buffer full: try again shortly
        }
        xSemaphoreGive(s_radio_mtx);
    }
}

static bool start_espnow()
{
    if (esp_now_init() != ESP_OK) return false;
    esp_now_register_recv_cb(on_recv);
    esp_now_register_send_cb(on_sent);
    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, BCAST, 6);
    peer.channel = 0;
    peer.ifidx = WIFI_IF_STA;
    peer.encrypt = false;
    return esp_now_add_peer(&peer) == ESP_OK;
}

static void radio_settings()
{
    esp_wifi_set_ps(WIFI_PS_NONE);               // power save makes us miss broadcasts
    esp_wifi_set_channel(GM_CHANNEL, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_max_tx_power(s_tx_power);
}

bool radio_init(QueueHandle_t rx_queue, int8_t tx_power_qdbm)
{
    s_rx_q = rx_queue;
    s_tx_q = xQueueCreate(32, 240);
    s_radio_mtx = xSemaphoreCreateMutex();
    s_tx_power = tx_power_qdbm;
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    radio_settings();
    if (!start_espnow()) return false;
    xTaskCreatePinnedToCore(tx_task, "gm_tx", 4096, nullptr, 6, nullptr, 0);
    return true;
}

void radio_send(const uint8_t frame[240])
{
    if (xQueueSend(s_tx_q, frame, 0) != pdTRUE) s_tx_fail++;
}

void radio_set_tx_power(int8_t qdbm)
{
    s_tx_power = qdbm < 8 ? 8 : (qdbm > 84 ? 84 : qdbm);
    esp_wifi_set_max_tx_power(s_tx_power);
}

// MAC rotation every epoch (PROTOCOL §9.3). The MAC can only change while Wi-Fi is stopped,
// so this restarts Wi-Fi + ESP-NOW. Frames arriving during the gap are lost; the returned
// outage is what Jose asked us to measure (decision 2a).
uint32_t radio_set_mac(const uint8_t mac[6])
{
    xSemaphoreTake(s_radio_mtx, portMAX_DELAY);  // no esp_now_send while we're restarting
    int64_t t0 = esp_timer_get_time();
    esp_now_deinit();
    esp_wifi_stop();
    esp_err_t e = esp_wifi_set_mac(WIFI_IF_STA, mac);
    esp_wifi_start();
    radio_settings();
    bool ok = start_espnow();
    uint32_t outage = (uint32_t)(esp_timer_get_time() - t0);
    xSemaphoreGive(s_radio_mtx);
    if (e != ESP_OK || !ok) {
        char buf[96];
        snprintf(buf, sizeof buf, "{\"ev\":\"error\",\"reason\":\"set_mac_failed\",\"esp_err\":%d,\"espnow_ok\":%s}",
                 (int)e, ok ? "true" : "false");
        serial_emit(buf);
    }
    return outage;
}

void     radio_get_mac(uint8_t out[6]) { esp_wifi_get_mac(WIFI_IF_STA, out); }
uint32_t radio_airtime_avg_us() { uint32_t n = s_airtime_n; return n ? s_airtime_sum_us / n : 0; }
uint32_t radio_rx_overflows()   { return s_rx_overflow; }
uint32_t radio_tx_failures()    { return s_tx_fail; }
