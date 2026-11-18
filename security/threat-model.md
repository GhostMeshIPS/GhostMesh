# GhostMesh threat model

Owner: Jose Perez (Network #2). Spec: [`PROTOCOL.md` §9](../PROTOCOL.md). Decisions and open items:
[`project-breakdown.md` §4.7](../docs/planning/project-breakdown.md). Rationale: [`protocol-design-motivation.md`](protocol-design-motivation.md).
Decision numbers (1–15) and open items (O1–O23) refer to §4.7.

## 1. What we protect (assets)

| Asset | Meaning |
|---|---|
| **Content** | Message text, and the real sender and recipient IDs |
| **Relationships** | Who talks to whom, and when |
| **Identity over time** | Linking a node's transmissions across 60 s epochs |
| **Past and future traffic after a key theft** | Forward secrecy and post-compromise security |
| **Availability** | Messages keep getting delivered, and the mesh recovers after attacks and node loss |
| **IPS integrity** | BLOCKs and the mesh clock come only from the watchtower and can't be turned against honest nodes |
| **Watchtower logs** | Per-node behaviour profiles (`node`, RSSI, timing, `raw` frames; decision 1b). They are exactly what the protocol hides from outsiders, so they are sensitive. Live logs auto-delete (`ips/retention.py`); only deliberately recorded, labeled sessions are kept |

## 2. Trust assumptions

- **Trusted and physically guarded:** the watchtower, the IPS laptop, and the provisioning laptop
  that runs `keygen.py`. Physical access to any of them, or to any serial port, means compromise (O16). The
  watchtower holds every `pseudo_secret`, the network key and the Ed25519 signing key, so it can identify nodes
  but **can't read messages** (it holds no X25519 private keys).
- **Chat laptops** attached to nodes are trusted by their owners.
- **Provisioning is checked, not blindly trusted.** keygen writes key fingerprints to the public
  `firmware/config/roster.json`, and every board prints `gm_fingerprint()` of the keys it actually loaded at boot.
  A mismatch means tampering between keygen and flashing (closed O13, decision 15).
- **4-board setup (open, O21):** board D loads `keys_D.h` and `keys_W.h`, so a relay in the radio path also holds
  every `pseudo_secret` and the signing key. The "watchtower is guarded" assumption then has to cover D too. With
  6 boards, W is a separate board.

## 3. Adversaries in scope

| ID | Adversary | Capabilities |
|---|---|---|
| **A1** | Outsider, passive | Records every frame in range (RSSI, timing, cleartext header, cleartext KEYS/CTRL contents). No keys |
| **A2** | Outsider, active | A1, plus injecting, replaying, delaying and **selectively jamming** frames (e.g. by type). No keys |
| **A3** | Compromised insider | A captured or malicious board. Our attacker **X** is keyed exactly like a node (decision 15): it holds `network_key`, its own `pseudo_secret` and X25519 keys, and is every node's peer. It can forge any cleartext field, spoof pseudonyms and MACs, flood and abuse routing. It does **not** hold the signing key or other nodes' secrets |
| **A4** | Funded adversary | Records everything long term, **later seizes boards** and dumps flash (keys are unencrypted, O15), and can combine this with A2/A3 |

## 4. What a sniffer sees (A1)

Every frame is 240 bytes. A sniffer reads the cleartext header (`ver_type`, `flags`, `msg_id`, `ttl`,
`hop_count`, `src_pseudo`, `next_hop`, `epoch`), the radio MAC and RSSI. `link_tag` stops outsiders changing these
fields; it doesn't hide them.

| `ver_type` | Cleartext body? | What it reveals | Hidden |
|---|---|---|---|
| DATA (messages **and** ACKs) | No (AEAD) | That a message or ACK was sent, when, the transmitter's current pseudonym, and the SOS bit (6d) | Content, real IDs, length, DATA vs. ACK (5), recipient |
| HELLO | Routing beacon (§6) | That a node with this pseudonym is present, every 2 s. Together with KEYS: how many nodes are active per epoch (O22, open) | Real identity across epochs |
| KEYS | Yes: `target_epoch`, `mode`, `next_pk`, slots | That a node is rekeying (~6 per epoch), RESYNC events (`mode`). The `conf` hashes are unkeyed, so hashing every heard `next_pk` reveals which nodes hold pair keys with which. With all-to-all keygen that graph is complete, so this adds only peer counts and a little reachability (O23, accepted in 12d) | Chain keys, pair tags |
| CTRL | Yes: subtype, `issued_at_ms`, BLOCK targets, signature | Mesh time, that a BLOCK is active, its reason and the blocked node's pseudonym+MAC for this and the next epoch | Nothing (public by design; authenticity comes from the signature) |

## 5. What we claim

| Against | Claim | How (PROTOCOL §) | Residual / limit |
|---|---|---|---|
| A1 | Content, real IDs, message length and DATA vs. ACK are hidden | AEAD (9.6), fixed 240 B, hidden ACKs (9.5) | The SOS bit is cleartext (6d) |
| A1 | Relationships are hard to read from DATA headers | No destination in cleartext, `src_pseudo` = transmitter, hop padding (9.9), 0–400 ms ACK delay (9.7) | **Timing** can still reveal the originator and pair senders with recipients on a quiet mesh (O1/O2). KEYS `conf` exposes the pair-key graph, which is complete under our keygen, so it adds only peer counts; it would reveal groups if provisioning became partial (O23, accepted in 12d) |
| A1 | Identities can't be linked across epochs from the protocol | Pseudonym and MAC rotate together, at the same moment on every node (9.2, 9.3) | **RSSI** tracks static boards (O3). The number of active nodes is visible (O22, open) |
| A2 | Outsider frames never get past the first hop | `link_tag` over the whole frame (9.4) | — |
| A2 | Replays don't deliver, don't trigger ACKs and don't re-flood | Five replay layers (9.7) | — |
| A2 | Delayed or replayed control frames can't move the clock back or forge blocks | Ed25519 CTRL, monotonic clock with slew (9.2, 9.8) | Local jamming delays a BLOCK in that area (`no_beacon` alert after 30 s) |
| A2 | Jamming is **detected**, not prevented | `noise_floor`, rate drops, `no_beacon` / `no_dh` alerts | One fixed channel (O17); selective KEYS jamming forces hash-only epochs (O18, alerted) |
| A3 | Can't read others' messages or forge their keys | Pairwise keys; KEYS tags use pair chain keys (9.6) | Reads anything addressed to X itself |
| A3 | Can't forge TIME or BLOCK | Only the watchtower holds the Ed25519 key; only verified CTRL is relayed (9.8) | — |
| A3 | Flooding, spoofing, replay and routing abuse are detected and blocked by the IPS | Per-node features, BLOCK by node or by (pseudo, MAC) pair (9.8) | Stays an insider until reflash (O14). Spoof-like evidence (signal > 6 dB off the node's usual level) never auto-blocks: the operator confirms and only the (pseudo, MAC) pair is blocked (O9, closed). A full copy of a victim's pseudo **and** MAC can only be told apart by RSSI and the operator; a wrong confirmation blocks the victim until the block expires |
| A3 | Can't exhaust CPU or caches for everyone | Per-transmitter verify and insertion limits (9.8, 9.9) | An insider that cycles identities falls back to the global limits |
| A4 | A seized board doesn't reveal traffic older than ~2 epochs | Chain keys deleted each epoch (9.6) | Flash may keep the last saved state (O15) |
| A4 | After a theft, future traffic is safe again from the first successful DH | Chained epoch DH (9.6) | Not if the thief **actively** forges KEYS frames, or forces RESYNC with a stolen static key (rate-limited and reported, 10d; a pair that is already silent accepts RESYNC without the rate limit, 14b) |

## 6. How each claim is checked

The protocol is tested on the host now; the simulator and the ESP32 testbed supply the network conditions
(loss, collisions, node failure, real RF) that host tests can't.

| Claim area | Checked now | Still to measure (sim / testbed) |
|---|---|---|
| Crypto correctness (link_tag, pseudonyms, AEAD, CTRL, ratchet) | `firmware/test/run_crypto_tests.py`: 131/131, cross-checked against PyNaCl/libsodium and `cryptography`; 16 of 18 mutations caught | ESP32-S3 build and timing (crypto bench < 5 ms, X25519 per epoch) |
| Forward secrecy, post-compromise healing, convergence, RESYNC | Ratchet simulation in `test_ratchet.c` (thief locked out two epochs later, forks, gaps, own echo) | Same behaviour across real boot-time skew and frame loss on the testbed |
| Key provisioning and fingerprints | `security/test_keygen.py`: 30/30 | Boot fingerprints match `roster.json` on every board |
| Replay rejection (G5) | Replay layers in host tests (`test_routing.c`, ratchet replay case) | Results-table row "Replay rejection 100%" on hardware |
| Flood limits (10b, 10g) | — | Busy honest relay's `msg_id` rate in Rashad's sim, to confirm the ~20/s insertion limit |
| Rotation (2a) and identity linking (O3) | — | MAC-change outage per rotation; stretch traffic-analysis test (can an observer link pseudonyms across epochs by RSSI?) |
| Jamming detection (O17–O19) | — | `noise_floor` accuracy on hardware (1b) |
| IPS detection and block policy (G6, O9) | IPS on synthetic sessions (`ips/synth.py`) | Detection time ≤ 5 s per attack on labeled testbed runs |

## 7. Out of scope (not claimed)

- **That the network exists.** The ESP-NOW vendor marker and fixed frame size reveal it (O7).
- **Preventing RF jamming** of the single channel (O17). We detect it; channel hopping is future work.
- **Multi-sniffer RF direction-finding** or global traffic correlation.
- **Quantum adversaries.** X25519 and Ed25519 aren't post-quantum, and a post-quantum key exchange can't fit 240 bytes.
- **A compromised watchtower, IPS laptop or provisioning laptop**, or physical access to any serial port (O16).
- **Hardware defenses** against key extraction: no flash encryption or secure boot this week (O15). The panic key-wipe is a stretch goal.
- **Revoking** a captured node's network membership without reflashing (O14). BLOCK, re-issued every epoch, is the mitigation.
- **Side channels** (power, EM, timing on the board).
- **Hiding the pair-key graph** in KEYS frames (O23, 12d). It is complete under our all-to-all provisioning;
  keying the `conf` hash is future work.

## 8. Open items

| ID | Issue | Status |
|---|---|---|
| O21 | 4-board setup: relay D also holds the watchtower's secrets | Open |
| O22 | HELLO and KEYS cadence reveal how many nodes are active per epoch | Open |
