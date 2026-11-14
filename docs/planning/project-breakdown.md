# Patriot HackFest 2026 — Hardened Off-Grid Mesh with AI IPS

> Working name: **GhostMesh**
> Theme fit: *Bypass surveillance · Build survival tools · Design tomorrow's underground tech*
> Timeline: Monday–Thursday build, **Friday submission deadline**

---

## 1. The Idea

| Item | Description |
|---|---|
| Problem | In a dystopian scenario, the internet is shut down or watched. Cell towers and routers are choke points that can be switched off or logged. |
| Our answer | A decentralized, multi-hop mesh of cheap ESP32-S3 boards that carries end-to-end encrypted text messages with **no towers, routers, or internet**. |
| Multi-hop | If A can't reach C directly, B forwards the packet: A → B → C. That's what makes it a mesh rather than a plain ad-hoc network. |
| What's new vs. Meshtastic | Meshtastic (the popular open-source LoRa mesh) sends a **cleartext routing header** that shows who is talking, and its routing is plain flooding. Our design hides who's talking, learns routes, and is defended by an **AI intrusion prevention system (IPS)**. |
| Why build our own | Our team designs the protocol (packet format, forwarding, routing, reliability), so we get real networking experience instead of configuring someone else's stack. Meshtastic is the reference design and the "before" in our demo. |
| Radio | **ESP-NOW** (connectionless Wi-Fi frames on the ESP32, up to 250-byte payload). ESP-NOW only goes one hop, so **we write all multi-hop logic ourselves**. |

### One-line pitch
> "Meshtastic leaks who's talking. We built a mesh protocol that doesn't, and an AI watchtower that catches and blocks attackers inside the network."

---

## 2. Project Goals

| # | Goal | Measurable success criterion |
|---|---|---|
| G1 | Multi-hop messaging works | A → C delivered through B with ≥ 95% delivery over 50 test messages |
| G2 | Self-healing | When B is unplugged, traffic reroutes through D within **≤ 10 s** with no manual action |
| G3 | Content privacy | A sniffer captures only ciphertext; tampered packets are rejected (Poly1305 tag fails) |
| G4 | Metadata privacy | Sender IDs rotate every epoch; all frames are a fixed size, so length doesn't leak content |
| G5 | Replay resistance | Re-sent captured packets are dropped 100% of the time |
| G6 | Intrusion prevention | IPS detects each of the 4 attacks within **≤ 5 s**, broadcasts a signed block, and the mesh recovers |
| G7 | ML adds value | The ML model beats the rule-based baseline on at least one metric (recall, false-positive rate, or detection time) |
| G8 | Scales beyond hardware | Python sim of 20–50 nodes shows flooding vs. route learning (transmissions per delivered message, delivery rate) |

### Non-goals (explicitly out of scope)
- Long range (ESP-NOW range is fine for a tabletop demo; LoRa is future work)
- Voice, images, or files (text only)
- Phone app (laptop serial chat client is enough; BLE is a stretch goal)
- Formal security proofs

---

## 3. System Architecture

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

### Node roles (same firmware, role set by config)

| Node | Role |
|---|---|
| A | Sender, connected to a laptop for typing messages |
| B | Main relay, the one unplugged in the demo |
| C | Receiver |
| D | Backup relay, takes over when B drops |
| Watchtower | Hears all traffic, streams per-packet metadata + RSSI to the IPS laptop, broadcasts signed BLOCK messages |
| Attacker | Runs flood, replay, spoofing, and routing-abuse modes |

### Hardware

| Item | Qty | Status / note |
|---|---|---|
| ESP32-S3 dev boards | 6 ideal (4 minimum) | 4 owned. With 4: Watchtower doubles as D, and the Attacker is a reflashed node used only during the attack segment |
| USB-C data cables | 6 | Must be data cables, not charge-only |
| Power banks | 2–3 | So relays can sit apart, untethered |
| Laptops | 2+ | One for chat client(s), one for the IPS |
| SSD1306 OLED (optional) | 1–4 | Shows packets hopping; onboard RGB LED is enough otherwise |

### Forcing multi-hop in one room
Every board can hear every other board on a table, so multi-hop has to be enforced:

| Method | How | Tradeoff |
|---|---|---|
| Low TX power | `esp_wifi_set_max_tx_power()` at minimum + spread boards out | Physical, honest; can be flaky |
| RSSI gate | Drop frames below a configurable RSSI threshold | Identity-independent, so it works with rotating IDs; noisy indoors |
| Topology allowlist (fallback) | Each node only accepts frames from configured neighbor MACs | Deterministic, but only usable in the non-privacy demo segments since it needs fixed MACs |

Use the RSSI gate + low TX power by default. Keep the allowlist as the "demo must work" fallback, and say so in the README.

---

## 4. Protocol Design

### 4.1 Frame format (fixed 240 bytes, fits ESP-NOW's 250-byte limit)

| Field | Bytes | Visible to relays? | Purpose |
|---|---|---|---|
| `ver_type` | 1 | Yes | Version + type: DATA, ACK, HELLO, RREQ, RREP, BLOCK |
| `flags` | 1 | Yes | e.g., SOS priority, needs-ACK |
| `msg_id` | 8 | Yes | **Random** ID (not a counter) used for duplicate suppression |
| `ttl` | 1 | Yes | Remaining hops; drop at 0 |
| `hop_count` | 1 | Yes | Hops so far (used by route learning, checked by IPS) |
| `src_pseudo` | 4 | Yes | Pseudonym of the node that **transmitted** this frame: the originator on hop 1, then each relay overwrites it with its own. **Rotates every epoch** |
| `next_hop` | 4 | Yes | 0 = flood; otherwise the pseudonym of the relay that should forward |
| `epoch` | 2 | Yes | Which pseudonym epoch this frame belongs to |
| `link_tag` | 8 | Yes | Network-key MAC over the live header, **recomputed by each relay**, so outsiders' frames are dropped at the first hop (exact coverage and keying: Network #2) |
| `nonce` | 24 | Yes | Random nonce for XChaCha20-Poly1305 |
| `ciphertext` | 170 | **No** | Inner header (real sender ID, recipient ID, timestamp, sequence #, length) + message body (up to ~153 B), padded to fixed size |
| `aead_tag` | 16 | — | Poly1305 authentication tag |
| **Total** | **240** | | Every frame is the same size |

**Key design point:** in flood mode the destination isn't in the cleartext header at all. Every node tries to decrypt, and only the real recipient succeeds ("trial decryption"). That hides **who is talking to whom** from both sniffers and relays. The true sender exists only in the encrypted inner header; the cleartext `src_pseudo` names the last transmitter, so an observer can't watch a flood spread out from its source (see §4.7).

**Tradeoff for the team to discuss:** route learning needs a `next_hop` field, which reveals neighbor relationships. Measure how much efficiency route learning buys over flooding, and decide whether it's worth that metadata cost. That comparison is a strong slide.

### 4.2 Forwarding rules (managed flooding, Phase 1)

| Step | Rule |
|---|---|
| 1 | Verify `link_tag`. If it fails, drop and log `BAD_LINK_TAG` |
| 2 | If `msg_id` is in the seen-cache (ring buffer, ~128 entries, 60 s expiry), drop as a duplicate |
| 3 | Add `msg_id` to the cache. Try to decrypt; if it succeeds, the message is for us: deliver to serial and send an ACK |
| 4 | If `ttl == 0`, stop |
| 5 | Otherwise `ttl--`, `hop_count++`, set `src_pseudo` to our own current-epoch pseudonym and recompute `link_tag`, then wait a **random 10–50 ms jitter** (weaker RSSI → shorter wait, so farther nodes relay first, as Meshtastic does) |
| 6 | If the same `msg_id` is heard from someone else during the wait, cancel (rebroadcast suppression). Otherwise rebroadcast |

### 4.3 Route learning + self-healing (Phase 2)

| Mechanism | Detail |
|---|---|
| HELLO beacons | Every node broadcasts HELLO every 2 s. A neighbor expires after 3 missed beacons (~6 s) |
| Reverse-path learning | The neighbor N that handed us a frame is its `src_pseudo`. The recipient, which decrypts and learns the true sender X, stores `X → N, h` (keep the lowest h). Relays can't read X, so they learn only their neighbors. Directed forwarding past two hops is **open** (Network #1, §4.7) |
| Directed forwarding | If a route to the destination is known, set `next_hop`; only that neighbor relays |
| Fallback | No ACK within timeout → retry as a flood, and mark the route stale |
| Self-healing | When B dies, its HELLOs stop, the route via B expires, and the next send floods, which relearns a route via D |
| Stretch: clusters | Nodes form local "cities" (flood inside a cluster) with elected gateways between clusters. Sim only unless time allows |

### 4.4 Reliability

| Mechanism | Detail |
|---|---|
| End-to-end ACK | Recipient sends an encrypted ACK containing the original `msg_id` |
| Retries | Sender retries up to 3 times with exponential backoff (1 s, 2 s, 4 s) |
| Delivery status | Chat client shows ✓ sent / ✓✓ delivered |

### 4.5 Security

| Feature | Implementation |
|---|---|
| End-to-end encryption | X25519 key agreement + XChaCha20-Poly1305 (Monocypher, a single C file, or libsodium). Public keys are pre-provisioned for the demo |
| Network membership | Shared network key used for `link_tag`, recomputed per hop because relays rewrite `src_pseudo`. Frames from outsiders are dropped at the first hop. Insiders hold the key and can still forge `ttl`/`hop_count`, so routing abuse is a detection problem (§5.6) |
| Replay protection | Per-sender sequence # + timestamp inside the ciphertext; reject old or seen values. The `msg_id` cache catches naive replays |
| Pseudonym rotation | `src_pseudo = KDF(node_secret, epoch)`, rotating every 60 s. Recipients can derive it; observers can't link epochs |
| MAC rotation | ESP-NOW frames carry the real Wi-Fi MAC, which would undo pseudonyms. Set a random locally-administered MAC per epoch with `esp_wifi_set_mac()` |
| Fixed frame size | All frames padded to 240 B |
| Signed BLOCKs | Watchtower signs BLOCK messages with Ed25519; nodes have its public key baked in. A counter prevents block replay |
| Stretch | Panic button that wipes keys; SOS priority flag |

### 4.6 Serial protocol (node ⇄ laptop), newline-delimited JSON

| Direction | Example |
|---|---|
| Laptop → node | `{"cmd":"send","to":"C","text":"meet at 9"}` |
| Node → laptop | `{"ev":"rx","from":"A","text":"meet at 9","hops":2}` |
| Node → laptop | `{"ev":"fwd","msg_id":"9f3a…","ttl":3}` / `{"ev":"drop","reason":"dup"}` |
| Watchtower → IPS | `{"t":1731264000.123,"mac":"…","pseudo":"…","type":"DATA","msg_id":"…","ttl":4,"hop":1,"rssi":-52,"len":240,"link_ok":true}` |

**The watchtower log schema is frozen on Monday.** The sim, the attack scripts, and the IPS all read and write the same format.

`pseudo` in the watchtower log is the **transmitter's** pseudonym (the frame's `src_pseudo`), not the originator's. Logs show the last hop; the originator is recoverable only from sim ground truth (§4.7).

### 4.7 Decision log

| Date | Decision | Owner | Status |
|---|---|---|---|
| Nov 14 | **Relays rewrite `src_pseudo` with their own pseudonym before rebroadcasting.** The field means "who just transmitted this," not "who originated it." Zero extra bytes. Why: §4.3 route learning needs to know which neighbor handed over a frame, and nothing else in §4.1 carries that (MACs rotate every 60 s); a cleartext originator pseudonym leaked the flood's source to passive observers; and the IPS's RSSI-per-identity feature saw every relayed frame as a spoof. Impact: firmware rewrites the field and recomputes `link_tag` per hop (Comp E); Network #2 defines the per-hop `link_tag`; watchtower `pseudo` = transmitter (AI/ML). Write-up: https://claude.ai/artifact/QZENs6ZDvkPTan5YicPo8Q | Network #1 | Decided. Open: directed forwarding past two hops (Network #1) |

---

## 5. Team Breakdown

### 5.1 Overview

| Role | Member | Focus | Core skills gained |
|---|---|---|---|
| **Comp E** | Yunus Hassen | Node firmware & hardware platform | Embedded C/C++, ESP-NOW/Wi-Fi driver, FreeRTOS tasks, crypto on microcontrollers |
| **Network #1** | Rashad Safir | Routing & reliability (the protocol's brain) | Forwarding, flooding control, route discovery, ACK/retransmit, network simulation & performance analysis |
| **Network #2** | Jose Perez | Secure transport, traffic analysis & red team | Protocol header privacy, packet capture, Wireshark dissectors, replay/spoofing attacks |
| **AI/ML** | Hannan Ahmed | AI intrusion prevention system | Feature engineering from network telemetry, anomaly detection, classifiers, real-time pipelines |

### 5.2 Comp E — Node firmware & hardware

| Area | Tasks | Deliverable |
|---|---|---|
| Toolchain | Pick Arduino-ESP32 (core 3.x) or ESP-IDF on Monday morning, and set up a shared build for all 6 boards | One firmware, role selected by config |
| Radio layer | ESP-NOW init, broadcast send/receive, RSSI from the receive callback, TX power control, MAC setting | `radio.c` that the routing layer calls |
| Frame codec | Pack/unpack the 240-byte frame (§4.1) | `frame.c` + unit test |
| Task structure | RX queue → processing task → TX queue with jitter timers (keep the ESP-NOW callback tiny) | No dropped frames under load |
| Serial interface | JSON command/event protocol (§4.6) | Laptop can send/receive |
| Crypto integration | Port Monocypher/libsodium; benchmark encrypt+decrypt time on the S3 | Bench numbers in README |
| Watchtower mode | Log every heard frame + RSSI to serial; receive BLOCK commands from the laptop and broadcast them signed | Watchtower firmware role |
| Block-list | Nodes verify signed BLOCKs and drop frames from blocked identifiers | Enforcement working |
| Attacker mode | Firmware hooks for Network #2's attacks (flood rate, replay buffer, forged fields) | Attacker role |
| Visuals | Onboard RGB LED: blue = TX, green = delivered, red = dropped/blocked. Optional OLED | Visible packet hops on camera |

### 5.3 Network #1 — Routing & reliability

| Area | Tasks | Deliverable |
|---|---|---|
| Managed flooding | Seen-cache, TTL, jitter, rebroadcast suppression (§4.2), written as portable C so the same logic runs on the board and in the sim | `routing.c` v1 |
| Topology control | RSSI gate + allowlist fallback to force A → B → C | Repeatable multi-hop on a table |
| Reliability | E2E ACKs, retries, delivery status (§4.4) | ✓✓ delivery in chat client |
| Neighbor discovery | HELLO beacons, neighbor table, expiry | Live neighbor table on serial |
| Route learning | Reverse-path learning, `next_hop`, flood fallback, self-healing (§4.3) | `routing.c` v2; B-unplug reroute |
| Simulation | Python discrete-event sim (`networkx` random geometric graphs, 20–50 nodes) with radio range, collisions/loss, node failures. **Emits the frozen watchtower log schema** | `sim/` + plots |
| Experiments | Flooding vs. route learning: delivery ratio, transmissions per delivered message, latency (hops/ms), recovery time after node failure, versus node count | 3–4 graphs for slides/video |
| Stretch | Clustered "cities" routing with gateway election, in the sim | One comparison graph |

### 5.4 Network #2 — Secure transport, traffic analysis & red team

| Area | Tasks | Deliverable |
|---|---|---|
| Header privacy design | Finalize which fields are cleartext vs. encrypted; pseudonym KDF + epoch rotation; MAC rotation; fixed-size padding | Design section in README |
| Crypto protocol | Key provisioning script, X25519 + XChaCha20-Poly1305 message format, network `link_tag`, replay window. Integrate with Comp E | Encrypted mesh |
| Sniffer + Wireshark | Python tool turning watchtower serial output into `.pcap` (DLT_USER0) + a **Wireshark Lua dissector** for the protocol | Wireshark screenshots for the demo |
| Meshtastic comparison | From Meshtastic's docs, document what its cleartext header exposes vs. ours. Optional live capture if anyone has a LoRa board | "Before vs. after" slide |
| Attack scripts | 4 attack modes on the attacker node (§5.6), each with on/off timing and intensity, logged with ground-truth labels | Labeled attack datasets for AI/ML |
| Threat model | Assets, attackers (outsider sniffer, outsider injector, compromised insider), in-scope/out-of-scope | One-page threat model |
| Stretch | Panic key-wipe button; traffic-analysis test (can an observer link pseudonyms across epochs?) | Bonus demo moment |

### 5.5 AI/ML — Intrusion prevention system

| Area | Tasks | Deliverable |
|---|---|---|
| Ingestion | `pyserial` reader for watchtower JSON; same code reads sim logs and recorded files (**start Monday on synthetic/sim data**) | `ips/ingest.py` |
| Feature extraction | Per transmitter (MAC + pseudonym), 1-second sliding windows (feature table below) | `ips/features.py` |
| Rule baseline | Hand-written thresholds (e.g., rate > N/s, RSSI jump > X dB) | Baseline numbers to beat |
| Anomaly model | Isolation Forest trained on **normal** traffic only (catches unknown attacks) | `models/iforest.pkl` |
| Classifier | Random Forest (or XGBoost) on Network #2's labeled attack runs, to name *which* attack | `models/clf.pkl` |
| Evaluation | Precision, recall, false-positive rate, mean time-to-detect, per attack, ML vs. rules | Results table + confusion matrix |
| Prevention | On a confident detection, send a BLOCK to the watchtower (auto mode, or confirm-click mode) with expiry | Closed-loop IPS |
| Console | Streamlit (or Flask) dashboard: live packet rate per node, RSSI per node, anomaly score timeline, alert log, BLOCK button, live topology graph | Dashboard on screen in the demo |

**IPS features (per transmitter, per 1-s window)**

| Feature | Catches |
|---|---|
| Packets/sec, bytes/sec | Flooding / DoS |
| Duplicate `msg_id` ratio, repeated nonces | Replay |
| Mean RSSI, RSSI std, Δ vs. that identity's history | Spoofing (same ID, different signal) |
| Hop count vs. RSSI consistency (strong signal but claims many hops, or vice versa) | Routing abuse |
| TTL values outside the normal range | Routing abuse |
| Inter-arrival time mean / variance | Scripted/automated sending |
| `link_tag` failure count | Outsider injection |
| HELLO rate vs. expected 0.5 Hz | Fake neighbor advertisement |

### 5.6 IPS threat coverage

| Attack (Network #2 runs it) | How it works | Detection signal | Response |
|---|---|---|---|
| Spoofing | Attacker transmits using another node's pseudonym/MAC | RSSI for that identity suddenly shifts; two RSSI clusters for one ID | BLOCK the spoofing transmitter |
| Flooding / DoS | High-rate junk or valid-looking frames | Packet-rate spike, airtime share | BLOCK + per-neighbor rate limit |
| Replay | Re-sends captured frames | Duplicate `msg_id`/nonce, stale sequence | Drop + BLOCK |
| Routing abuse | Advertises fake low hop counts to attract traffic (black-hole) | Hop count inconsistent with RSSI/topology; traffic vanishes after that node | BLOCK node, purge its routes |

**Known limitation:** an attacker who also rotates MACs can try to dodge a block. Mitigations are per-neighbor rate limits and requiring a valid `link_tag`, so only insiders get that far.

---

## 6. Weekly Schedule (Monday–Thursday build, Friday deadline)

### Day 0 — Weekend prep

| Who | Task |
|---|---|
| All | Install toolchain, flash Blink to every board, verify USB data cables |
| Comp E | Two boards exchange a raw ESP-NOW broadcast |
| All | Create GitHub repo with folder structure (§8), shared group chat, task board |
| All | Confirm who physically holds the boards. If the team isn't co-located, the board holder runs the physical mesh and everyone else works against the sim/logs |

### Monday — Design freeze + foundations

| Who | Tasks | End-of-day milestone |
|---|---|---|
| All (first 2 hrs) | Freeze frame format (§4.1), serial JSON, **watchtower log schema**, node roles, repo layout | `PROTOCOL.md` committed |
| Comp E | Toolchain decision, radio layer, frame codec, serial command interface | 2 boards exchange 240-byte frames, decoded on serial |
| Network #1 | Flooding logic as portable C; sim skeleton (graph, nodes, flooding) | Sim floods a message across a 20-node graph |
| Network #2 | Threat model; pick crypto lib; key provisioning script; start pcap converter | Crypto lib builds for ESP32-S3 |
| AI/ML | Synthetic log generator (or sim output) in frozen schema; ingest + feature extraction | Features computed from synthetic logs |
| **Checkpoint (evening)** | 15-min sync: demo what works, flag blockers | |

### Tuesday — Multi-hop works (critical gate)

| Who | Tasks | End-of-day milestone |
|---|---|---|
| Comp E | RX/TX task queues + jitter; LED feedback; integrate routing v1; watchtower logging mode | Firmware runs routing v1 |
| Network #1 | Topology control (RSSI gate / allowlist); E2E ACK + retries; sim flooding experiments | **A → B → C delivery on hardware** |
| Network #2 | Encrypt/decrypt bench test on S3; `link_tag`; Wireshark Lua dissector v1 | Encrypted frame round-trips on one board |
| AI/ML | Rule-based baseline; Isolation Forest on sim/synthetic normal traffic; dashboard skeleton | Baseline + model scoring live from a log file |
| **GO / NO-GO (evening)** | If 3-node multi-hop is **not** working, everyone swarms on it Wednesday morning. Nothing else matters until it does | |

### Wednesday — Security, self-healing, real data

| Who | Tasks | End-of-day milestone |
|---|---|---|
| Comp E | Integrate crypto, pseudonyms, MAC rotation; block-list enforcement; attacker-mode hooks | Encrypted multi-hop on hardware |
| Network #1 | HELLO + neighbor table; route learning; flood fallback; test unplug-B reroute via D | **Reroute ≤ 10 s on hardware** |
| Network #2 | Replay protection; implement all 4 attacks; record labeled attack runs (≥ 5 min normal + ≥ 2 min per attack) | Labeled dataset delivered to AI/ML |
| AI/ML | Watchtower live stream → IPS; retrain Isolation Forest on **real** normal traffic; train classifier on labeled runs; evaluate vs. baseline | Live alerts on a real attack |
| **Checkpoint (evening)** | End-to-end dry run of the demo, even if rough | |

### Thursday — Close the loop, freeze, record

| Time | Tasks | Milestone |
|---|---|---|
| Morning | Comp E + AI/ML: IPS → watchtower → signed BLOCK → nodes drop attacker. Network #1: final sim experiments + graphs. Network #2: Wireshark captures, Meshtastic comparison slide | Full closed loop |
| **12:00 — Feature freeze** | Bug fixes only after this | |
| Afternoon | Full demo rehearsal ×3; fix flaky steps (pre-set TX power, label boards, charge power banks); write README sections; build slides | Demo runs clean 3 times in a row |
| Evening | **Record the demo video** (§7.3); record backup takes of each segment | Raw footage captured |

### Friday — Deadline (no new features)

| Tasks | Owner |
|---|---|
| Edit video, add captions/graphics, export | Whoever is best at editing |
| Final README, architecture diagram, results tables | All (each owns their section) |
| Slides (if required) | Network #2 leads, all contribute |
| Tag release `v1.0`, verify repo builds from clean clone | Comp E |
| Submit **several hours before** the deadline | Team lead |

### Fallback / cut list (if behind)

| If this slips… | Cut to… |
|---|---|
| Route learning | Managed flooding only; show route learning in the sim |
| MAC rotation | Pseudonym rotation only; document MAC rotation as next step |
| ML classifier | Isolation Forest + rules only |
| Automatic blocking | Human-click BLOCK button in the dashboard (still prevention) |
| 6 boards | 4 boards: watchtower doubles as D; reflash one node as attacker for the attack segment |
| Wireshark dissector | Pretty-printed packet log from the Python sniffer |

---

## 7. Deliverables & Demo Video

### 7.1 Deliverables

| Deliverable | Description | Owner |
|---|---|---|
| Node firmware | Single codebase, roles: NODE / WATCHTOWER / ATTACKER | Comp E |
| `PROTOCOL.md` | Frame format, forwarding rules, routing, crypto, serial schema | Network #1 + #2 |
| Network simulator | Python sim + experiment scripts + generated graphs | Network #1 |
| Security package | Threat model, key provisioning, pcap tool, Wireshark Lua dissector, attack scripts | Network #2 |
| IPS | Ingest → features → models → BLOCK, plus live dashboard; saved models + datasets | AI/ML |
| Results | Tables: delivery %, reroute time, detection metrics (ML vs. rules), crypto bench, sim graphs | All |
| README | Pitch, architecture diagram, how to build/flash/run, results, limitations, future work | All |
| Demo video | 3 minutes or less (see storyboard) | All |
| Slides (if required) | 6–8 slides mirroring the video | Network #2 lead |

### 7.2 Results table (fill in by Thursday)

| Metric | Target | Actual |
|---|---|---|
| Delivery rate, A → C via B (50 msgs) | ≥ 95% | |
| Reroute time after B unplugged | ≤ 10 s | |
| Replay rejection | 100% | |
| Encrypt + decrypt time on S3 | < 5 ms | |
| Detection time per attack (ML) | ≤ 5 s | |
| IPS recall / FPR (ML vs. rules) | ML ≥ rules | |
| Sim: transmissions per delivered msg, flooding vs. route learning (50 nodes) | Route learning lower | |

### 7.3 Demo video storyboard (~3 minutes)

| Time | Segment | On screen | Key line |
|---|---|---|---|
| 0:00–0:20 | Hook | Dark title card → "internet shut down" mock headline → boards on table | "When the network is the surveillance, you build your own." |
| 0:20–0:45 | Architecture | Diagram from §3, role labels on each board | "Six $10 boards. No towers, no routers, no internet." |
| 0:45–1:15 | Multi-hop | Split screen: A's laptop sends → B's LED flashes → C's laptop receives (✓✓) | "C is out of A's range. B carries the message." |
| 1:15–1:40 | Self-healing | Unplug B on camera → next message flows via D; timer overlay | "Lose a node, the mesh routes around it in seconds." |
| 1:40–2:05 | Surveillance-proof | Wireshark: fixed-size frames, ciphertext, pseudonym changes at epoch boundary. Side-by-side with Meshtastic's cleartext header | "A sniffer can't read it, and can't tell who's talking." |
| 2:05–2:40 | Attack + IPS | Attacker starts flooding/spoofing → dashboard anomaly score spikes → alert → BLOCK broadcast → attacker's LED red, mesh traffic recovers | "Our AI watchtower catches the attacker and kicks it off the mesh." |
| 2:40–2:55 | Scale + results | Sim graph (flooding vs. route learning at 50 nodes) + results table | "And it scales past the boards on our table." |
| 2:55–3:00 | Close | Team names, repo link | |

---

## 8. Repository Structure

```
ghostmesh/
├── README.md
├── PROTOCOL.md
├── firmware/            # Comp E (+ routing.c from Network #1, crypto glue from Network #2)
│   ├── src/
│   └── config/          # per-board role, keys, neighbor allowlist
├── sim/                 # Network #1: simulator, experiments, plots
├── security/            # Network #2: keygen, pcap converter, Wireshark dissector, attacks, threat model
├── ips/                 # AI/ML: ingest, features, models, dashboard, data
├── tools/chat_client.py # laptop chat over serial
└── docs/                # diagrams, results, slides, video link
```

---

## 9. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Multi-hop can't be forced in one room | High | High | RSSI gate + low TX power; allowlist fallback; spread boards across a hallway |
| Only 4 boards | Confirmed | Medium | Role doubling (§6 cut list); sim covers scale |
| Team not co-located (virtual) | Medium | High | Board holder runs hardware; others use sim + shared recorded logs; frozen log schema makes this work |
| Crypto too slow / won't build on S3 | Low | Medium | Monocypher is a single portable C file; bench on Tuesday |
| IPS has no real data until Wednesday | High | Medium | Start Monday on sim/synthetic logs in the same schema |
| ESP-NOW frame loss under flood attack | Medium | Low | That's the point of the demo; retries + rate limiting |
| Integration crunch on Thursday | High | High | Daily evening checkpoints, Tuesday go/no-go, Thursday noon feature freeze |
| Demo fails live | Medium | High | Video is the primary deliverable; backup takes of every segment |

---

## 10. Future Work

- LoRa radios for kilometer-scale range (same protocol, different radio layer)
- Clustered "city" routing with gateway election on hardware
- Store-and-forward to the internet when any node regains connectivity
- Phone app over BLE
- Federated IPS: several watchtowers vote before blocking
- Cover traffic (dummy packets) to resist timing analysis
