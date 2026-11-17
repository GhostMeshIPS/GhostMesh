# GhostMesh threat model

Owner: Jose Perez (Network #2). Spec: [`PROTOCOL.md` §9](../PROTOCOL.md). Decisions and open items:
[`project-breakdown.md` §4.7](../docs/planning/project-breakdown.md). Rationale: [`protocol-design-motivation.md`](protocol-design-motivation.md).

## 1. What we protect (assets)

| Asset | Meaning |
|---|---|
| **Content** | Message text, and the real sender and recipient IDs |
| **Relationships** | Who talks to whom, and when |
| **Identity over time** | Linking a node's transmissions across 60 s epochs |
| **Past and future traffic after a key theft** | Forward secrecy and post-compromise security |
| **Availability** | Messages keep getting delivered, and the mesh recovers after attacks and node loss |
| **IPS integrity** | BLOCKs and the mesh clock come only from the watchtower and can't be turned against honest nodes |

## 2. Trust assumptions

- **Trusted and physically guarded:** the watchtower, the IPS laptop, and the provisioning laptop
  that runs `keygen.py`. Physical access to any of them means compromise (O16). The watchtower holds every
  `pseudo_secret` and the signing key, so it can identify nodes but **can't read messages**.
- **Chat laptops** attached to nodes are trusted by their owners.
- **Provisioning is honest.** Keys are flashed without tampering. Key fingerprint checks are pending (O13, task 15).

## 3. Adversaries in scope

| ID | Adversary | Capabilities |
|---|---|---|
| **A1** | Outsider, passive | Records every frame in range (RSSI, timing, cleartext header). No keys |
| **A2** | Outsider, active | A1, plus injecting, replaying, delaying and **selectively jamming** frames (e.g. by type). No keys |
| **A3** | Compromised insider | A captured or malicious board (our attacker **X**): holds `network_key` and its own keys. Can forge any cleartext field, spoof pseudonyms, flood and abuse routing |
| **A4** | Funded adversary | Records everything long term, **later seizes boards** and dumps flash (keys are unencrypted, O15), and can combine this with A2/A3 |

## 4. What we claim

| Against | Claim | How (PROTOCOL §) | Residual / limit |
|---|---|---|---|
| A1 | Content, real IDs, message length and DATA vs. ACK are hidden | AEAD (9.6), fixed 240 B, hidden ACKs (9.5) | — |
| A1 | Relationships are hard to read from headers | No destination in cleartext, `src_pseudo` = transmitter, hop padding (9.9) | **Timing** can still reveal the originator and pair senders with recipients on a quiet mesh (O1/O2) |
| A1 | Identities can't be linked across epochs from the protocol | Pseudonym and MAC rotate together every 60 s (9.3) | **RSSI** tracks static boards (O3) |
| A2 | Outsider frames never get past the first hop | `link_tag` over the whole frame (9.4) | — |
| A2 | Replays don't deliver, don't trigger ACKs and don't re-flood | Five replay layers (9.7) | — |
| A2 | Delayed or replayed control frames can't move the clock back or forge blocks | Ed25519 CTRL, monotonic clock (9.2, 9.8) | Local jamming delays a BLOCK in that area (alert after 30 s) |
| A2 | Jamming is **detected**, not prevented | `noise_floor`, rate drops, `no_beacon` / `no_dh` alerts | One fixed channel (O17) |
| A3 | Can't read others' messages or forge their keys | Pairwise keys; KEYS tags use pair chain keys (9.6) | — |
| A3 | Flooding, spoofing, replay and routing abuse are detected and blocked by the IPS | Per-node features, BLOCK by (pseudo, MAC) (9.8) | Stays an insider until reflash (O14). A full spoof can trick the IPS into blocking a real node (O9, open) |
| A3 | Can't exhaust CPU or caches for everyone | Per-transmitter verify and insertion limits (9.8, 9.9) | An insider that cycles identities falls back to the global limits |
| A4 | A seized board doesn't reveal traffic older than ~2 epochs | Chain keys deleted each epoch (9.6) | Flash may keep the last saved state (O15) |
| A4 | After a theft, future traffic is safe again from the first successful DH | Chained epoch DH (9.6) | Not if the thief **actively** forges KEYS frames, or forces RESYNC with a stolen static key (rate-limited and reported, 10d) |

## 5. Out of scope (not claimed)

- **That the network exists.** The ESP-NOW vendor marker and fixed frame size reveal it (O7).
- **Preventing RF jamming** of the single channel (O17). We detect it; channel hopping is future work.
- **Multi-sniffer RF direction-finding** or global traffic correlation.
- **Quantum adversaries.** X25519 and Ed25519 aren't post-quantum, and a post-quantum key exchange can't fit 240 bytes.
- **A compromised watchtower, IPS laptop or provisioning laptop**, or physical access to any serial port (O16).
- **Hardware defenses** against key extraction: no flash encryption or secure boot this week (O15). The panic key-wipe is a stretch goal.
- **Revoking** a captured node's network membership without reflashing (O14). BLOCK is the mitigation.
- **Side channels** (power, EM, timing on the board).
