// led.cpp - onboard RGB LED: blue = we transmitted, green = message/ACK for us, red = bad/blocked frame.
#include "app.h"

#ifndef GM_LED_PIN
#define GM_LED_PIN 48
#endif
#define LED_LEVEL 24          // dim: full brightness washes out on camera

static volatile uint32_t s_off_at;
static volatile bool s_on;

#ifdef GM_LED_PLAIN
// WROOM dev boards: one plain LED, no colours. Any indication lights it.
static void set_rgb(uint8_t r, uint8_t g, uint8_t b) { digitalWrite(GM_LED_PIN, (r | g | b) ? HIGH : LOW); }
void led_init() { pinMode(GM_LED_PIN, OUTPUT); set_rgb(0, 0, 0); }
#else
static void set_rgb(uint8_t r, uint8_t g, uint8_t b) { rgbLedWrite(GM_LED_PIN, r, g, b); }
void led_init() { set_rgb(0, 0, 0); }
#endif

void led_indicate(int what)
{
    uint32_t ms = 60;
    switch (what) {
    case GM_IND_TX:       set_rgb(0, 0, LED_LEVEL); break;
    case GM_IND_RX_MINE:  set_rgb(0, LED_LEVEL, 0); ms = 300; break;
    case GM_IND_DROP_BAD: set_rgb(LED_LEVEL, 0, 0); ms = 200; break;
    default: return;
    }
    s_on = true;
    s_off_at = millis() + ms;
}

void led_service()
{
    if (s_on && (int32_t)(millis() - s_off_at) >= 0) { set_rgb(0, 0, 0); s_on = false; }
}
