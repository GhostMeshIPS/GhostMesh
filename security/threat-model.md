# GhostMesh threat model

Owner: Jose Perez (Network #2). Spec: [`PROTOCOL.md` §9](../PROTOCOL.md). Decisions and open items:
[`project-breakdown.md` §4.7](../docs/planning/project-breakdown.md). Rationale: [`protocol-design-motivation.md`](protocol-design-motivation.md).
Decision numbers (1–16) and open items (O1–O29) refer to §4.7. Diagrams: [`docs/diagrams/`](../docs/diagrams/).

## 1. What we protect (assets)

| Asset | Meaning |
|---|---|
| **Content** | Message text, and the real sender and recipient IDs |
| **Relationships** | Who talks to whom, and when |
| **Identity over time** | Linking a node's transmissions across 60 s epochs |
| **Past and future traffic after a key theft** | Forward secrecy and post-compromise security |
| **Availability** | Messages keep getting delivered, and the mesh recovers after attacks and node loss. For a censor (A5) this is the primary target |
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
- **4-board setup (accepted, O21 / 12e):** board D loads `keys_D.h` and `keys_W.h`, so it is both a relay and
  the watchtower and inherits the watchtower's trust level. With 6 boards, W is a separate board.

## 3. Adversaries

| ID | Adversary | Goal | Capabilities |
|---|---|---|---|
| **A1** | Outsider, passive | Learn who talks to whom | Records every frame in range (RSSI, timing, cleartext header, cleartext KEYS/CTRL contents). No keys |
| **A2** | Outsider, active | Read, forge or disrupt without keys | A1, plus injecting, replaying, delaying and **selectively jamming** frames (e.g. by type) |
| **A3** | Compromised insider | Abuse membership | A captured or malicious board. Our attacker **X** is keyed exactly like a node (decision 15): it holds `network_key`, its own `pseudo_secret` and X25519 keys, and is every node's peer. It can forge any cleartext field, spoof pseudonyms and MACs, flood and abuse routing. It does **not** hold the signing key or other nodes' secrets |
| **A4** | Funded adversary | Read recorded traffic later | Records everything long term, **later seizes boards** and dumps flash (keys are unencrypted, O15), and can combine this with A2/A3 |
| **A5** | **Censor** (12f) | **Stop the mesh from working**, because unapproved networks read as organizing or press, and find the people running it | Combines A2–A4 for denial of service: wideband or reactive jammers, junk floods, one captured board used as an insider, attacks timed to epoch boundaries, targeting the watchtower first, seizing boards. Doesn't need to read anything: a mesh that is unreliable enough gets abandoned |

A5 is the realistic adversary for the hackathon premise. Against A5 our claims are about **resilience and
detection**, not prevention: no protocol stops a wideband jammer, and the network's existence is visible (O7).

## 4. What a sniffer sees (A1)

Every frame is 240 bytes. A sniffer reads the cleartext header (`ver_type`, `flags`, `msg_id`, `ttl`,
`hop_count`, `src_pseudo`, `next_hop`, `epoch`), the radio MAC and RSSI. `link_tag` stops outsiders changing these
fields; it doesn't hide them.

| `ver_type` | Cleartext body? | What it reveals | Hidden |
|---|---|---|---|
| DATA (messages **and** ACKs) | No (AEAD) | That a message or ACK was sent, when, the transmitter's current pseudonym, and the SOS bit (6d) | Content, real IDs, length, DATA vs. ACK (5), recipient |
| HELLO | Routing beacon (§6) | That a node with this pseudonym is present, every 2 s. Together with KEYS: how many nodes are active per epoch (O22, accepted in 12e) | Real identity across epochs |
| KEYS | Yes: `target_epoch`, `mode`, `next_pk`, slots | That a node is rekeying (~6 per epoch), RESYNC events (`mode`). The `conf` hashes are unkeyed, so hashing every heard `next_pk` reveals which nodes hold pair keys with which. With all-to-all keygen that graph is complete, so this adds only peer counts and a little reachability (O23, accepted in 12d) | Chain keys, pair tags |
| CTRL | Yes: subtype, `issued_at_ms`, BLOCK targets, signature | Mesh time, that a BLOCK is active, its reason and the blocked node's pseudonym+MAC for this and the next epoch. TIME beacons start at the watchtower every 10 s, so first-copy timing and RSSI **locate the watchtower** (O26, accepted in 16c) | Nothing (public by design; authenticity comes from the signature) |

## 5. What we claim

| Against | Claim | How (PROTOCOL §) | Residual / limit |
|---|---|---|---|
| A1 | Content, real IDs, message length and DATA vs. ACK are hidden | AEAD (9.6), fixed 240 B, hidden ACKs (9.5) | The SOS bit is cleartext (6d) |
| A1 | Relationships are hard to read from DATA headers | No destination in cleartext, `src_pseudo` = transmitter, hop padding (9.9), 0–400 ms ACK delay (9.7) | **Timing** can still reveal the originator and pair senders with recipients on a quiet mesh (O1/O2). KEYS `conf` exposes the pair-key graph, which is complete under our keygen, so it adds only peer counts; it would reveal groups if provisioning became partial (O23, accepted in 12d) |
| A1 | Identities can't be linked across epochs from the protocol | Pseudonym and MAC rotate together, at the same moment on every node (9.2, 9.3) | **RSSI** tracks static boards (O3). The number of active nodes is visible (O22, accepted in 12e) |
| A2 | Outsider frames never get past the first hop | `link_tag` over the whole frame (9.4) | They still use airtime: an outsider junk flood acts like jamming (§8) |
| A2 | No outsider man-in-the-middle | Pair roots come from pre-provisioned static keys with boot fingerprint checks (9.1); KEYS frames are tagged with pair chain keys (9.6) | — |
| A2 | Replays don't deliver, don't trigger ACKs and don't re-flood | Five replay layers (9.7) | — |
| A2 | Delayed or replayed control frames can't move the clock back or forge blocks | Ed25519 CTRL, monotonic clock with slew (9.2, 9.8) | Local jamming delays a BLOCK in that area (`no_beacon` alert after 30 s) |
| A2, A5 | Jamming is **detected**, not prevented | `noise_floor`, rate drops, `no_beacon` / `no_dh` alerts | One fixed channel (O17); selective KEYS jamming forces hash-only epochs (O18, alerted) |
| A3 | Can't read others' messages, forge their keys or sit in the middle of another pair | Pairwise keys; KEYS tags use pair chain keys (9.6) | Reads anything addressed to X itself |
| A3 | Can't forge TIME or BLOCK | Only the watchtower holds the Ed25519 key; only verified CTRL is relayed (9.8) | — |
| A3 | Flooding, spoofing, replay and routing abuse are detected and blocked by the IPS | Per-node features, BLOCK by node or by (pseudo, MAC) pair (9.8) | Stays an insider until reflash (O14). Spoof-like evidence (signal > 6 dB off the node's usual level) never auto-blocks: the operator confirms and only the (pseudo, MAC) pair is blocked (O9, closed by 12c). A full copy of a victim's pseudo **and** MAC can only be told apart by RSSI and the operator; a wrong confirmation blocks the victim until the block expires |
| A3 | Can't exhaust CPU or caches for everyone | Per-transmitter verify and insertion limits (9.8, 9.9) | An insider that cycles identities falls back to the global limits |
| A3 | Capturing one node doesn't expose other pairs' traffic | Pairwise keys; no key is shared between pairs except `network_key` (§7) | `network_key` makes the thief an insider everywhere (O14) |
| A4 | A seized board doesn't reveal traffic older than ~2 epochs | Chain keys deleted each epoch (9.6) | Flash may keep the last saved state (O15) |
| A4 | After a theft, future traffic is safe again from the first successful DH | Chained epoch DH (9.6) | Not if the thief **actively** forges KEYS frames, or forces RESYNC with a stolen static key (rate-limited and reported, 10d; a pair that is already silent accepts RESYNC without the rate limit, 14b) |
| A5 | Losing a relay doesn't stop delivery while another path exists | Flooding, retries, flood fallback (5, 6, 7) | A board whose loss splits the mesh in two (a cut vertex) can't be routed around |
| A5 | Attacks are detected within 5 s and insider attackers are blocked | IPS + signed BLOCK (G6) | Depends on the watchtower being alive and in range (§7). If it goes silent, blocks lapse within ~2 min (16c). Demo floods stay under the rate its log can carry (16e) |

## 6. Attack classes

What each class looks like against GhostMesh, who can attempt it, and what stops it. These describe the attack
surface; the attack scripts themselves are task 11.

| Class | Attack against GhostMesh | Who | Stopped by | Residual |
|---|---|---|---|---|
| **Eavesdropping / traffic analysis** | Read content; link pseudonyms; pair DATA with ACKs; count nodes | A1 | AEAD, hidden ACKs, rotation, hop padding, ACK delay | Timing on a quiet mesh (O1/O2), RSSI tracking (O3), node count (O22) |
| **Man-in-the-middle** | Get between A and C and read or change their messages | A2, A3 | Static pair roots + fingerprints; KEYS tagged with pair chain keys; AEAD; X holds no other pair's keys | Stolen static key + active KEYS forgery or forced RESYNC takes over that node's pairs (A4, 10d). A tampered provisioning laptop before fingerprints are checked |
| **Injection / tampering** | Forge headers, swap ciphertext, flood junk | A2 | `link_tag` on every byte; AEAD with header fields in the AD | Junk still costs airtime |
| **Replay** | Resend captured DATA, KEYS, CTRL or RESYNC | A2, A3 | Five replay layers (9.7); CTRL time checks (9.8); RESYNC nonce + rate limit (10d) | — |
| **Spoofing / impersonation** | Transmit under another node's pseudonym and MAC; get the real node blocked | A3 | IPS RSSI and MAC↔pseudonym checks; O9 policy (12c) | Full pseudo+MAC copy relies on RSSI and the operator |
| **Privilege escalation** | (1) Outsider → insider: a malformed frame crashes or takes over a node's parser. (2) Node → watchtower: capture the board holding the signing key. (3) Laptop → node: unauthenticated serial commands | A2, A3, A5 | (1) Outsiders can't reach parsers past `link_tag`; fixed-size layout. (2) Only W holds the signing key. (3) Physical access is out of scope (O16) | (1) An insider **can** reach the KEYS, CTRL and inner-header parsers, and KEYS frames are relayed to every node before anyone can check them, so one bad frame reaches the whole mesh. The parsers use fixed offsets and bounds checks, but this isn't tested yet (O24, open). (2) In the 4-board setup the signing key sits on relay D (O21) |
| **Lateral movement** | From one captured node, reach others' traffic or control | A3, A4 | Pairwise keys keep each pair separate (§7). Nodes never learn `pseudo_secret`s of others. CTRL needs the watchtower's key | `network_key` is shared, so one capture = insider everywhere (O14). A parser exploit would spread by flooding (O24, open). Capturing the watchtower reaches everything except content |
| **Denial of service** | Stop delivery: jam, flood, desynchronize keys or clocks, exhaust CPU, take out the watchtower, trick the IPS into blocking honest nodes | A2, A3, A5 | Detection + BLOCK; rate limits; retries and flooding; free-running clock | See §8 for each outage type |
| **IPS manipulation** | Stay just under detection thresholds; slowly shift a node's baseline; behave normally while normal traffic is recorded for training | A3, A5 | Per-node baselines, ML + rules | Normal training traffic is recorded with X powered off (16f). Low-and-slow attacks under the thresholds and slow baseline drift remain |

## 7. Single points of failure and blast radius

**What one compromise reaches:**

| Compromised | Reaches | Doesn't reach |
|---|---|---|
| One node (A3) | Mesh membership (`network_key`), its own conversations, the ability to spoof and flood | Other pairs' content, the signing key, other nodes' `pseudo_secret`s |
| One node + static key used actively (A4) | Its pairs' future traffic (MITM via forged KEYS / RESYNC) | Pairs it isn't part of |
| **Watchtower** | Every node's identity map, forging TIME (push all clocks forward for good, 10c) and BLOCKs (eject everyone), all watchtower logs | Message content (no X25519 private keys) |
| IPS laptop | Issue BLOCK commands, set the mesh clock through the watchtower | Signing key, content |
| Provisioning laptop | Every key ever generated | Nothing — it's the root of trust, which is why fingerprints are checked at boot |

**The watchtower is a single point of failure for detection, prevention and time.** A5's best first move is to
find it (§4: CTRL frames start there) and then jam, overload or seize it.

| Watchtower failure | Effect | Recovery |
|---|---|---|
| Dead, jammed or out of range | TIME beacons stop (nodes free-run, fine for hours). BLOCKs aren't re-issued, and each one names only the current and next epoch's identifiers, so **every block lapses within ~2 min** (accepted, 16c). The IPS is blind | When it comes back: next TIME beacon (≤ 10 s), IPS re-issues blocks |
| Dead + a node reboots | The rebooted node has no clock and waits for a TIME beacon before it may transmit, so **it stays mute until the watchtower returns** (accepted, 16b) | Only when the watchtower returns |
| Overloaded by a flood | Its serial log to the IPS can't keep up (each line carries the 240-byte `raw` frame as hex), so above ~120 frames/s at 921600 baud the IPS lags during the very attack it should detect. Demo floods stay under ~100 frames/s; native USB is future work (16e) | When the flood stops |
| Captured | See the table above. Out of scope by 12b, but it is the most valuable target | Reflash and re-key everything |

## 8. Outages: causes, detection and recovery

What can stop delivery, how far it reaches, how it's seen, and what brings the mesh back. Recovery times come
from the spec; measured values belong in the results table.

| Outage | Cause | Scope | Detected by | Recovery | Recovery time (spec) |
|---|---|---|---|---|---|
| **Relay loss** | Battery, unplugged, crashed, seized | Paths through it | HELLO expiry, missing ACKs | Flooding + retries; route relearned via D | ≤ 10 s target (G2) |
| **Partition** | Loss of a board whose loss splits the mesh, or jamming that cuts the mesh in two | Everything across the cut | Delivery ratio drops to 0 between groups | None until a path returns | — |
| **Wideband / channel jamming** | A5 jammer on the single channel | Everything in its range | `noise_floor`, rate drops everywhere | None until the jammer stops; then retries (attempts at 0/1/3/7 s), later messages must be resent | Jammer-dependent |
| **Selective jamming** | Reactive jammer drops KEYS, CTRL or DATA by type | Targeted nodes or pairs | `no_dh` (3 epochs), `no_beacon` (30 s) | KEYS: hash-only epochs still deliver (no PCS healing). CTRL: local BLOCK not enforced | While jamming lasts |
| **Outsider junk flood** | Frames without a valid `link_tag` at full rate | Airtime in its range | `link_tag` failures, `node = "?"` | Dropped at the first hop, but **BLOCK can't stop the airtime use**; behaves like jamming | While it lasts |
| **Insider flood** | X floods valid-looking frames | Airtime + CPU (trial decryption) in its range | IPS rate features | Per-transmitter insertion limit (10g), then BLOCK | Detection ≤ 5 s (G6) + BLOCK propagation |
| **Key desync** | Lost or jammed KEYS frames split a pair's chain | One pair | Messages stop decrypting; RESYNC events; `no_dh` | Alternate-key convergence, then RESYNC after 2 silent epochs | Up to ~2–3 min per pair |
| **Clock / boundary stress** | Every node rotates MAC, pseudonym and keys at the same, publicly known moment; route tables reset | Whole mesh for the length of the MAC-change outage | Delivery dips every 60 s | Retries | MAC-change outage (to measure). An attacker can time floods or jamming to boundaries |
| **Node reboot** | Crash, brownout, power-bank swap, crash caused by a malformed frame (O24) | One node | Serial boot log, missing HELLOs | Wait for TIME (≤ 10 s), then RESYNC to peers | ≤ 10 s + resync; **never** while the watchtower is down (16b) |
| **CTRL starvation** | Forged CTRL frames sent to use up the verify budget | BLOCK/TIME enforcement beyond the forger's neighbours | Missing `BLOCKED` drops, `no_beacon` | Only **failed** verifies cost a transmitter's budget (5 s after a failure; mesh-wide 2 failures/s), so genuine TIME and BLOCK frames are always checked; the watchtower spaces CTRL ≥ 3 s apart (16d, implemented) | None for genuine CTRL; an identity-cycling insider falls back to the mesh-wide cap |
| **False block** | IPS blocks an honest node (spoof, false positive) | That node | Operator, dashboard | Block expires or is ended early | Until `until_ms` |
| **Watchtower loss** | See §7 | Detection, prevention, time | Missing TIME → `no_beacon` | Watchtower returns | Blocks lapse within ~2 min (16c) |

## 9. Failure metrics

Metrics for availability under attack and failure. Delivery ratio, latency and transmissions per delivered
message are defined in [`PROTOCOL.md` §13](../PROTOCOL.md); the rest are defined here.

| Metric | Definition | Tells us |
|---|---|---|
| **Time to detect** | Attack or failure start → first IPS alert or node event (`no_beacon`, `no_dh`) | How fast we notice (G6: ≤ 5 s) |
| **Time to block** | First IPS alert → every reachable node drops the attacker's frames | Whether prevention reaches the far side of the mesh |
| **Time to recover** | Attack or failure start → delivery ratio back within 5 % of the pre-attack value | How long users actually lose service |
| **Reroute time** | Relay loss → first message delivered over another path | G2 (≤ 10 s) |
| **Resync time** | Key desync → first message decrypting again for that pair | Key-layer outage length |
| **Blast radius** | Nodes (or pairs) whose delivery ratio drops during an attack | How local an attack stays |
| **Delivery ratio under attack** | Delivery ratio during the attack window | Resilience while the attack is still running |
| **Availability** | Share of 10 s windows with delivery ratio above a set threshold | One number for "the mesh works" |
| **False-block rate / duration** | Honest nodes blocked per hour and how long each stays blocked | Cost of our own defense |
| **IPS blind time** | Time the watchtower log lags more than 1 s behind the air or drops frames | Whether the watchtower itself is the weak link |

## 10. How each claim is checked

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
| Receive-path robustness (O24) | Fixed offsets and bounds checks in `gm_crypto` / `gm_ratchet` | Fuzz test under AddressSanitizer/UBSan (to write) |
| IPS detection and block policy (G6, O9) | IPS on synthetic sessions (`ips/synth.py`) | Detection time ≤ 5 s per attack on labeled testbed runs |

## 11. Out of scope (not claimed)

- **That the network exists.** The ESP-NOW vendor marker and fixed frame size reveal it (O7).
- **Preventing RF jamming** of the single channel (O17). We detect it; channel hopping is future work.
- **Multi-sniffer RF direction-finding** or global traffic correlation. A5 would use these to find operators; we
  don't claim to stop it.
- **Quantum adversaries.** X25519 and Ed25519 aren't post-quantum, and a post-quantum key exchange can't fit 240 bytes.
- **A compromised watchtower, IPS laptop or provisioning laptop**, or physical access to any serial port (O16).
  §7 still describes what their loss or capture would cause.
- **Hardware defenses** against key extraction: no flash encryption or secure boot this week (O15). The panic key-wipe is a stretch goal.
- **Revoking** a captured node's network membership without reflashing (O14). BLOCK, re-issued every epoch, is the mitigation.
- **Side channels** (power, EM, timing on the board).
- **Hiding the pair-key graph** in KEYS frames (O23, 12d). It is complete under our all-to-all provisioning;
  keying the `conf` hash is future work.

## 12. Open items

| ID | Issue | Status |
|---|---|---|
| O24 | Insider-reachable parsers (KEYS, CTRL, inner header) and KEYS flooding make one malformed frame a mesh-wide crash or exploit; the ESP-NOW receive callback is reachable by outsiders | Open |

O1–O23 and O25–O29 are closed; each closing decision is in [`project-breakdown.md` §4.7](../docs/planning/project-breakdown.md).
