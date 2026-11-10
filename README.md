# GhostMesh

**An off-grid, surveillance-resistant mesh network on ESP32-S3, defended by an AI intrusion prevention system.**

> Meshtastic leaks who's talking. We built a mesh protocol that doesn't, and an AI watchtower that catches and blocks attackers inside the network.

Built for **Patriot HackFest 2026**: *bypass surveillance, build survival tools, design tomorrow's underground tech.*

> 🚧 **Status:** In development (hackathon week). Sections marked _TBD_ get filled in as features land.

---

## The problem

When the internet is shut down or watched, cell towers and routers are choke points: they can be switched off, and they log who talks to whom. Existing off-grid meshes like Meshtastic keep working without towers, but they send a cleartext routing header that still reveals who is talking.

## What GhostMesh does

- **Multi-hop messaging with no infrastructure.** Cheap ESP32-S3 boards relay end-to-end encrypted text over ESP-NOW. If A can't reach C, B forwards it.
- **Self-healing routing.** Nodes learn routes from traffic and HELLO beacons. Unplug a relay and traffic reroutes through another node within seconds.
- **Metadata privacy.** The destination never appears in cleartext, sender pseudonyms and Wi-Fi MACs rotate every epoch, and every frame is a fixed 240 bytes.
- **Replay and outsider protection.** A network-key link tag drops outsider frames at the first hop; sequence numbers and timestamps inside the ciphertext stop replays.
- **AI intrusion prevention.** A watchtower node streams traffic metadata to an ML-based IPS that detects spoofing, flooding, replay, and routing abuse, then broadcasts a signed BLOCK so the mesh ejects the attacker.

## Architecture

```
 [Laptop chat]           [Laptop chat]
      │ serial                │ serial
   ┌──┴──┐    ┌─────┐     ┌───┴─┐
   │  A  │────│  B  │─────│  C  │       ← mesh nodes (ESP32-S3, ESP-NOW)
   └──┬──┘    └─────┘     └──┬──┘
      │       ┌─────┐        │
      └───────│  D  │────────┘           ← backup relay (reroute path)
              └─────┘
   ┌──────────────┐  serial   ┌─────────────────────────────┐
   │  Watchtower  │──────────▶│ Laptop: IPS (features → ML) │
   │ (listens all)│◀──────────│ → signed BLOCK broadcast    │
   └──────────────┘           └─────────────────────────────┘
   ┌──────────────┐
   │   Attacker   │  ← red-team node: flood / replay / spoof / routing abuse
   └──────────────┘
```

All boards run the same firmware; the role (`NODE`, `WATCHTOWER`, `ATTACKER`) is set by config.

| Layer | Tech |
|---|---|
| Radio | ESP-NOW (connectionless Wi-Fi frames, 250-byte max payload) |
| Firmware | C/C++ on ESP32-S3, FreeRTOS tasks _(Arduino-ESP32 vs. ESP-IDF: TBD)_ |
| Crypto | X25519 + XChaCha20-Poly1305, Ed25519-signed BLOCKs _(Monocypher or libsodium: TBD)_ |
| Routing | Managed flooding → reverse-path route learning with flood fallback |
| Simulation | Python discrete-event sim (`networkx`), 20–50 nodes |
| IPS | Python: Isolation Forest + Random Forest, rule-based baseline, Streamlit dashboard |
| Analysis | `.pcap` export + Wireshark Lua dissector |

Full protocol spec (frame format, forwarding rules, serial schema): **[PROTOCOL.md](PROTOCOL.md)** _(TBD)_

## Repository layout

```
ghostmesh/
├── README.md
├── PROTOCOL.md
├── firmware/            # Node firmware: radio, frame codec, routing, crypto, roles
│   ├── src/
│   └── config/          # Per-board role, keys, neighbor allowlist
├── sim/                 # Network simulator, experiments, plots
├── security/            # Keygen, pcap converter, Wireshark dissector, attacks, threat model
├── ips/                 # Ingest, features, models, dashboard, datasets
├── tools/
│   └── chat_client.py   # Laptop chat over serial
└── docs/                # Diagrams, results, slides, video link
```

## Getting started

> _TBD: filled in once the toolchain is locked on Monday._

### Hardware

| Item | Qty |
|---|---|
| ESP32-S3 dev boards | 4 minimum, 6 ideal |
| USB-C **data** cables | One per board |
| Power banks | 2–3 (so relays can sit apart) |
| Laptops | 2+ (chat client, IPS) |

### Flash the firmware

```bash
# TBD
```

### Run the chat client

```bash
pip install -r requirements.txt
python tools/chat_client.py --port /dev/ttyUSB0   # TBD
```

### Run the IPS dashboard

```bash
# TBD
```

### Run the simulator

```bash
# TBD
```

## Results

| Metric | Target | Actual |
|---|---|---|
| Delivery rate, A → C via B (50 msgs) | ≥ 95% | _TBD_ |
| Reroute time after relay unplugged | ≤ 10 s | _TBD_ |
| Replay rejection | 100% | _TBD_ |
| Encrypt + decrypt time on ESP32-S3 | < 5 ms | _TBD_ |
| Detection time per attack (ML) | ≤ 5 s | _TBD_ |
| IPS recall / FPR (ML vs. rules) | ML ≥ rules | _TBD_ |
| Sim: transmissions per delivered msg, flooding vs. route learning (50 nodes) | Route learning lower | _TBD_ |

## Known limitations

- **Range is tabletop-scale.** ESP-NOW is short range; multi-hop in one room is forced with low TX power and an RSSI gate. A fixed neighbor allowlist exists as a fallback for demo reliability, and it only works in segments that don't use MAC rotation.
- **Route learning leaks some metadata.** The `next_hop` field reveals neighbor relationships. Pure flooding hides more but costs more transmissions; we measure that tradeoff.
- **MAC-rotating attackers** can try to dodge a block. Per-neighbor rate limits and the link-tag requirement limit this to insiders.
- Keys are pre-provisioned for the demo; there's no in-field key exchange yet.
- Text only, no formal security proofs.

## Future work

- LoRa radios for kilometer-scale range (same protocol, different radio layer)
- Clustered routing with gateway election on hardware
- Store-and-forward to the internet when a node regains connectivity
- Phone app over BLE
- Federated IPS where multiple watchtowers vote before blocking
- Cover traffic to resist timing analysis

## Team

| Role | Focus | Member |
|---|---|---|
| Comp E | Node firmware & hardware | Yunus Hassen |
| Network #1 | Routing & reliability, simulator | _TBD_ |
| Network #2 | Secure transport, traffic analysis, red team | _TBD_ |
| AI/ML | Intrusion prevention system | _TBD_ |

## License

_TBD (MIT suggested)._
