// display.cpp - 128x64 OLED (SSD1306 by default; -DGM_OLED_SH1106 for 1.3" SH1106 screens).
// Debug view for bench tests. Runs in its own low-priority task: I2C writes take ~25 ms per
// frame and must never block the processing task. If no screen answers on I2C, it does nothing.
#include <U8g2lib.h>
#include <Wire.h>

#include "app.h"

#ifndef GM_OLED_SDA
#define GM_OLED_SDA 8
#endif
#ifndef GM_OLED_SCL
#define GM_OLED_SCL 9
#endif

#ifdef GM_OLED_SH1106
static U8G2_SH1106_128X64_NONAME_F_HW_I2C s_oled(U8G2_R0, U8X8_PIN_NONE);
#else
static U8G2_SSD1306_128X64_NONAME_F_HW_I2C s_oled(U8G2_R0, U8X8_PIN_NONE);
#endif

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static gm_display_snap_t s_snap;
static bool s_present;

void display_publish(const gm_display_snap_t &s)
{
    portENTER_CRITICAL(&s_mux);
    s_snap = s;
    portEXIT_CRITICAL(&s_mux);
}

static void draw(const gm_display_snap_t &s)
{
    char l[8][32];
    snprintf(l[0], 32, "%c node %s e:%u", s.name, s.synced ? "SYNC   " : "NO SYNC", s.epoch);
    snprintf(l[1], 32, "ps %02x%02x%02x%02x ..%02x:%02x:%02x", s.pseudo[0], s.pseudo[1], s.pseudo[2], s.pseudo[3],
             s.mac[3], s.mac[4], s.mac[5]);
    snprintf(l[2], 32, "hear %u best %d last %d", s.heard_n, s.heard_best, s.last_rssi);
    snprintf(l[3], 32, "rx %lu tx %lu keys %lu", (unsigned long)s.rx, (unsigned long)s.tx, (unsigned long)s.keys);
    if (s.bad_tag || s.bad_epoch)
        snprintf(l[4], 32, "!tag %lu !epoch %lu", (unsigned long)s.bad_tag, (unsigned long)s.bad_epoch);
    else
        snprintf(l[4], 32, "dup %lu gate %lu allow %lu", (unsigned long)s.dup, (unsigned long)s.gate, (unsigned long)s.allow);
    snprintf(l[5], 32, "%s", s.last_msg[0] ? s.last_msg : "<no messages yet");
    snprintf(l[6], 32, "%s", s.last_send[0] ? s.last_send : ">nothing sent");
    snprintf(l[7], 32, "q%u  macgap %lums", s.queued, (unsigned long)(s.mac_outage_us / 1000));

    s_oled.clearBuffer();
    s_oled.setFont(u8g2_font_5x8_tf);       // 25 chars x 8 lines
    for (int i = 0; i < 8; i++) s_oled.drawStr(0, 8 * i + 7, l[i]);
    if (!s.synced) s_oled.drawFrame(0, 0, 128, 9);   // box the top line until synced
    s_oled.sendBuffer();
}

static void display_task(void *)
{
    gm_display_snap_t s;
    for (;;) {
        portENTER_CRITICAL(&s_mux);
        s = s_snap;
        portEXIT_CRITICAL(&s_mux);
        draw(s);
        vTaskDelay(pdMS_TO_TICKS(250));
    }
}

void display_init()
{
    Wire.begin(GM_OLED_SDA, GM_OLED_SCL);
    uint8_t addr = 0;
    for (uint8_t a : {0x3C, 0x3D}) {
        Wire.beginTransmission(a);
        if (Wire.endTransmission() == 0) { addr = a; break; }
    }
    if (!addr) { serial_emit("{\"ev\":\"oled\",\"present\":false}"); return; }
    s_oled.setI2CAddress(addr * 2);
    s_oled.begin();
    s_present = true;
    char buf[64];
    snprintf(buf, sizeof buf, "{\"ev\":\"oled\",\"present\":true,\"addr\":\"0x%02x\"}", addr);
    serial_emit(buf);
    xTaskCreatePinnedToCore(display_task, "gm_oled", 4096, nullptr, 1, nullptr, 0);
}
