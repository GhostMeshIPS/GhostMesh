# GhostMesh firmware

Owner: Yunus. One build per board (keys are compiled in). Node boards A–D run `src/main.cpp`; the
watchtower (W) and attacker (X) builds come next.

```
firmware/
├── platformio.ini        # env per board: pio run -e A
├── src/
│   ├── routing/          # Rashad: v1 flooding, ACK/retry, §9 rules       (portable C)
│   ├── crypto/           # Jose: link_tag, AEAD, ratchet, mesh clock      (portable C)
│   ├── node/gm_node.c    # Yunus: wires routing + crypto together          (portable C)
│   ├── node/board_keys.c # turns config/keys/keys_<N>.h into a struct
│   ├── main.cpp          # ESP32 tasks + commands
│   ├── radio.cpp         # ESP-NOW, MAC rotation, airtime
│   ├── serial_if.cpp     # JSON commands (PROTOCOL §10)
│   ├── display.cpp       # OLED debug screen
│   └── led.cpp           # blue = TX, green = for me, red = bad/blocked
├── lib/monocypher/       # vendored crypto library
├── config/keys/          # SECRET, gitignored: made by security/keygen.py
└── test/                 # laptop tests: crypto (Jose) + node integration (Yunus)
```

`gm_node.c` is portable on purpose: the same file runs on the boards and in
`test/node/test_node.c`, which simulates several boards on a laptop with real keys.

## Laptop test first (no boards)

```bash
pip install pynacl
python firmware/test/node/run_node_tests.py      # add -v to see every event
```

Expected: `21 passed, 0 failed`. It covers A↔B across epoch changes with the debug clock, and
W → A–B–C with signed TIME beacons and A → C through B.

## Bench test 1: two boards (A + B) with OLEDs

**What this proves:** the radio, Rashad's routing and Jose's crypto work together on real hardware.
Same keys on both boards, real encryption, KEYS exchange, pseudonym and MAC changes every 60 s,
end-to-end ACKs. **Not tested yet:** multi-hop (needs 3 boards and topology control) and the
watchtower (TIME beacons, BLOCK). The clock comes from the laptop with a DEBUG command instead.

### Wiring

OLED (SSD1306 128×64, I2C): `VCC → 3V3`, `GND → GND`, `SDA → GPIO 8`, `SCL → GPIO 9`.
For 1.3" SH1106 screens add `-DGM_OLED_SH1106` to `build_flags`. No screen is fine too.

### Steps

1. Keys (once, from the repo root): `python security/keygen.py`. Keep `firmware/config/keys/` private.
2. Flash: `cd firmware && pio run -e A -t upload` with A plugged in, then `pio run -e B -t upload` with B.
   Label the boards.
3. Open one terminal per board:
   `python tools/chat_client.py --port <A's port>` and the same for B.
4. **Check the boot line:** fingerprints must match `firmware/config/roster.json`. The OLED shows
   `NO SYNC` in a box.
5. **Sync:** type `/time` in both terminals. Expect `-- SYNCED ...` and the OLED top line changes to `SYNC`.
   Write down the `MAC change took … ms` number (Jose asked for it, decision 2a).
6. **Send:** in A's terminal `B: hello`. Expect A `✓`, then B `<< A: hello`, then A `✓✓`.
   LEDs: A blue, B green, then B blue (ACK), A green.
7. **Leave it running 3+ minutes** and send a message each minute. Every 60 s both terminals print
   `-- epoch …` with a new pseudonym. Messages must keep arriving after each change (keys ratchet).
8. `/status` on both and save the output. `radio.airtime_avg_us` is the airtime number Rashad needs.

### Pass / fail

| Check | Pass | If it fails |
|---|---|---|
| Fingerprints match roster | yes | wrong keys header compiled in: re-run keygen, reflash both |
| OLED `!tag` stays 0 | yes | boards have different network keys (flashed from different keygen runs) |
| `hello` arrives + `✓✓` | within ~1 s | check both are SYNC; `/verbose` and look for `not_synced` or `bad_epoch` |
| Delivery after each epoch change | 3/3 minutes | note any `no_dh` / `resync` events and send the log to Jose |
| MAC change time | a few ms; no `set_mac_failed` | turn rotation off: `{"cmd":"rotate_mac","on":false}` + reboot, tell Jose |
| No crashes for 5 min | yes | copy the decoded backtrace from `pio device monitor` |

## Serial commands (nodes)

| Command | Example |
|---|---|
| send | `{"cmd":"send","to":"B","text":"hi"}` (≤ 152 bytes) |
| status | `{"cmd":"status"}` |
| set_time | `{"cmd":"set_time","unix_ms":1763400000000}`, **DEBUG/bench only** |
| verbose | `{"cmd":"verbose","on":true}`: print every routing event |
| txpower | `{"cmd":"txpower","qdbm":8}` (8–84, quarter-dBm; saved) |
| rssi_gate | `{"cmd":"rssi_gate","dbm":-60}` (-127 = off; saved) |
| allow | `{"cmd":"allow","macs":["aa:bb:cc:dd:ee:ff"]}`: only with rotation off |
| rotate_mac | `{"cmd":"rotate_mac","on":false}` then reboot |
| wipe_state | clears saved ratchet state and reboots (use after re-running keygen) |

## Known issues

- **First-beacon bug (routing):** `rt_on_receive` checks the epoch window before CTRL, so an unsynced
  node drops its first TIME beacon. `gm_node_rx` works around it; the side effect is that sync spreads
  one hop per beacon (10 s). Fix belongs in `routing.c` (exempt CTRL TIME from the epoch check while unsynced).
- Originated KEYS frames: routing has no "originate" call, so `gm_node` filters its own echoes itself.
- MAC rotation restarts Wi-Fi each epoch. Untested on hardware until bench test 1.
