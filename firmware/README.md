# GhostMesh firmware

Owner: Yunus (Comp E). ESP32-S3 Super Mini boards, PlatformIO + Arduino-ESP32 core 3.x.
One build per board, because each board's secret keys are compiled in.

| Board | Build | Runs | Where it lives |
|---|---|---|---|
| A, B, C, D | `pio run -e A` … `-e D` | node: routing + crypto, relays, delivers, OLED | power bank / wall charger (or the laptop for debugging) |
| W | `pio run -e W` | watchtower: mesh clock, signed TIME beacons, IPS log, BLOCK | plugged into the laptop |
| X | `pio run -e X` | attacker passthrough (decision 18): sniffs and prints frames, sends frames the laptop gives it, sets its MAC. **No keys, never transmits on its own**; attacks run in `security/attacks/` | the attack laptop, only during attack segments |

```
firmware/
├── platformio.ini            # one env per board
├── src/
│   ├── routing/              # Rashad: v1 flooding, ACK/retry, §9 rules         (portable C)
│   ├── crypto/               # Jose: link_tag, AEAD, ratchet, mesh clock        (portable C)
│   ├── node/gm_node.c        # Yunus: wires routing + crypto into a node        (portable C)
│   ├── node/board_keys.c     # turns config/keys/keys_<N>.h into a struct
│   ├── watchtower/gm_watch.c # Yunus: beacons, IPS log lines, BLOCK              (portable C)
│   ├── watchtower/main_w.cpp # W board: tasks + commands
│   ├── main.cpp              # node boards: tasks, commands, /auto traffic
│   ├── node_serial.cpp       # node JSON command parser
│   ├── radio.cpp             # ESP-NOW, RX/TX queues, MAC rotation, airtime
│   ├── serial_if.cpp         # line reader + output (never blocks without a laptop)
│   ├── display.cpp           # OLED debug screen (nodes)
│   └── led.cpp               # blue = TX, green = for me, red = bad/blocked
├── lib/monocypher/           # vendored crypto library
├── config/keys/              # SECRET, gitignored: made by security/keygen.py
├── config/roster.json        # public: fingerprints to check boot lines against
└── test/                     # laptop tests: routing (Rashad), crypto (Jose), node + watchtower (Yunus)
```

`gm_node.c` and `gm_watch.c` are portable on purpose: the same files run on the boards and in
`test/node/test_node.c`, which simulates several boards plus the watchtower on a laptop with real keys.

---

## 1. One-time setup

```powershell
pip install pynacl pyserial
python security/keygen.py          # from the repo root: writes firmware/config/keys/ + roster.json
```

Keep `firmware/config/keys/` private: it's gitignored, never commit it. Re-running keygen makes
new keys for **every** board, so then reflash all of them and run `{"cmd":"wipe_state"}` on each node.

## 2. Flashing

Always name the port. Auto-detect picks whichever board it finds first, which once flashed A's keys
onto D's board.

```powershell
pio device list                                     # which COM port is which board
cd firmware
pio run -e A -t upload --upload-port COM8           # same for B, C, D
pio run -e W -t upload --upload-port COM13
```

If the upload hangs at `Connecting...` or reports `Guru Meditation`: hold **BOOT**, tap **RST**,
release BOOT, then upload again (the port number may change in this mode). Press **RST** afterwards.
Close every chat client or monitor on that port first.

A good flash ends with `Hash of data verified` → `Hard resetting`. Check the board's boot line says the
right `"name"` and its fingerprints match `config/roster.json`.

## 3. Running a mesh

### Watchtower (stays on the laptop)

```powershell
python tools/chat_client.py --port COM13 --sync --log ips/data/raw/run1.jsonl
```

- `--sync` sets W's clock from the laptop. W then floods a signed TIME beacon every 10 s, and every
  node takes its clock from that. **Nodes don't transmit anything until they've heard one.**
- `--log` saves every line W prints (one per frame it hears) for the IPS. `/mark <note>` adds a
  timestamped ground-truth note. `ips/data/` is gitignored: share the files directly.
- `/status` shows frames, beacons, unknown transmitters, and per-node frame counts + RSSI.
- `/verbose` streams the frames W hears. `/block C` / `/unblock C` block a node for 2 min.
- W keeps its clock as long as it stays powered, but on Windows reopening the port resets it: keep
  one session open, or type `/time` after reopening (see Known issues).

### Nodes on power banks

Set each node up once while it's plugged into the laptop. `/auto` is saved in flash:

```powershell
python tools/chat_client.py --port COM8
/auto C 20          # this node sends a test message to C every 20 s once synced
```

Then unplug, power from a power bank, and start W. Check delivery on the OLED (bottom line).

### Nodes on the laptop (debugging)

```powershell
python tools/chat_client.py --port COM8          # B: hello   /status   /verbose
python tools/chat_client.py --port COM8 --sync   # DEBUG only: sets the node's clock without W
```

`--sync` / `/time` on a **node** is a bench-only shortcut (decision log, Nov 17). In the demo the clock
comes only from W's signed beacon.

## 4. OLED (nodes)

```
B node SYNC    e:31402        sync state + epoch           (NO SYNC boxed = not heard W yet)
ps 1a2b3c4d ..ca:0e:dd        pseudonym + MAC tail         (both change every 60 s)
hear 2 best -58 last -63      boards heard in 5 s, RSSI    (tune range / multi-hop with this)
rx 412 tx 230 keys 61         frames in/out, KEYS sent     (~6 KEYS per minute)
dup 210 gate 0 allow 0        normal: duplicates, filters  (!tag N / !epoch N = keys or clock problem)
<A: auto A#12                 last message for this board
>D vv #4                      last send: v sent, vv delivered, X failed
auto>D/20s ok31 x0            /auto target, delivered vs failed
```

LED: blue = transmitted, green = message or ACK for this board, red = bad or blocked frame.

## 5. Serial commands

Full list in `PROTOCOL.md` §10. The common ones:

| Board | Command |
|---|---|
| node | `{"cmd":"send","to":"B","text":"hi"}` (≤ 152 bytes), `status`, `auto` (`to`, `every_s`, 0 = off), `verbose`, `txpower` (`qdbm` 8–84), `rssi_gate` (`dbm`, −127 = off), `allow` (`macs`, rotation off only), `rotate_mac` (`on`, then reboot), `bench` (`runs`, 0 = default 2000; times encrypt + trial-decrypt, prints `{"ev":"bench",...}` with `enc_us`/`dec_us`), `wipe_state`, `reboot`, `set_time` (**bench only**) |
| W | `set_time` (`unix_ms`), `status`, `block` (`node` or `?` + `pseudo` + `mac`, `reason`, `until` in unix s), `unblock`, `txpower`, `reboot` |

## 6. Tests (no hardware)

```bash
python firmware/test/node/run_node_tests.py   # node + watchtower integration, 34 checks (gcc + pynacl)
python firmware/test/run_crypto_tests.py      # Jose's crypto, 131 checks
gcc -std=c11 -Ifirmware/src/routing firmware/test/test_routing.c firmware/src/routing/routing.c -o tr && ./tr   # Rashad's routing, 63 checks
```

The integration test covers: A↔B across epoch changes; nodes syncing from W's signed beacons through
relays; A → C through B; W tagging frames with the real node; a BLOCK on C surviving C's pseudonym + MAC
change; unblock; a BLOCK arriving right after a beacon at a node 2 hops from W.

On Windows these need gcc (MSYS2 ucrt64 or WSL).

## 7. Status (Nov 18)

| Piece | State |
|---|---|
| Node firmware (routing + crypto, relays, ACKs, ratchet, MAC rotation, NVS state, OLED, `/auto`) | ✅ On hardware: 4 boards on a table, 3 boards untethered |
| Watchtower (beacons, IPS log, BLOCK/unblock) | ✅ On hardware: nodes sync from W alone; BLOCK enforced |
| Topology control (RSSI gate, MAC allowlist) | Built, not yet used on hardware |
| Attacker (X) | Builds (`pio run -e X`); not yet run on hardware. Demo 2 (flood as X → BLOCK) passes on the laptop: `test_node.c` |
| Route learning (v2) | Not started |

Measurements: `docs/results/hardware-bench-2026-11-17.md`.

## 8. Known issues

- ~~**First-beacon bug (routing):**~~ Fixed in `routing.c` (Rashad): an unsynced node now takes the first
  signed TIME beacon (epoch check skipped for TIME only) and syncs; it still doesn't relay that beacon
  under its old identity. The `gm_node_rx` workaround has been removed.
- ~~**Factory-MAC leak at first sync:**~~ Fixed. The clock syncs in rx but the epoch chain + rotated MAC
  are only set on the next `gm_tick`, so routing now gates relaying on `node_ready` (synced **and**
  `have_chain`), and `gm_node_rx` forces that tick onto the next poll. Nothing is relayed under the factory
  MAC. Regression test: `test_first_sync_no_factory_mac` in `firmware/test/node/test_node.c`.
- ~~**Opening a serial port resets the board on Windows**~~ (W loses its clock): `tools/chat_client.py` now
  re-sends `set_time` whenever W reports `clock_not_set` (same as `ips/ingest.py`), so W recovers on its own.
  `/time` still forces a manual re-send.
- Board D isn't working (to debug).
- Frames that W hears before its clock is set carry local time and `node: "?"`. Drop `t < 1e9` from logs.
