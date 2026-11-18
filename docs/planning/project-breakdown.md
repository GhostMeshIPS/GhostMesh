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
| `ver_type` | 1 | Yes | Version + type: DATA, ACK, HELLO, BLOCK |
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
| 6 | Count copies of the same `msg_id` heard from others during the wait (the copy that started the timer doesn't count). Once the count reaches **k**, cancel (rebroadcast suppression). Otherwise rebroadcast when the timer fires. k is set by a sim sweep (proposed 2–3); the jitter window must be at least 2–3× the airtime of k frames |

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
| Nov 14 | **RREQ and RREP dropped from `ver_type`.** Route discovery comes from the first data flood (relays note which neighbor each frame came from) and the ACK retracing that path; no separate discovery frames. A standard RREQ would also put the destination in cleartext. May return later as a sim-only scaling experiment if time allows. | Network #1 | Decided |
| Nov 15 | **Rebroadcast suppression cancels after k duplicates, not 1.** Cancelling on the first duplicate leaves coverage holes: if X and Y both hear A and each other, and Z hears only X, Y relays first (weaker RSSI, shorter wait), X cancels, and Z never gets the message. Because the wait is RSSI-based this repeats on every retry. Fix follows Trickle's suppression constant (RFC 6206 §6.5–6.6): cancel only after k duplicates, with the jitter window at least 2–3× the airtime of k frames. Estimated airtime is ~3 ms per 240-byte frame at ESP-NOW's 1 Mbps default, so k = 2–3 fits the 10–50 ms window. Impact: each pending relay keeps a duplicate counter (Network #1, firmware: Comp E); Comp E measures real broadcast airtime on Tuesday. | Network #1 | Decided. Value of k: from sim sweep, confirm at freeze |
| Nov 15 | **Retries use a new `msg_id`; repeats are caught by sequence number.** Resending with the same `msg_id` fails: every relay still holds it in the seen-cache (~60 s) and drops the retry as a duplicate, and the IPS would read it as a replay. Each retry now gets a fresh random `msg_id` but keeps the original inner sequence number. The recipient delivers a message only for a new sequence number; a repeat means the first ACK was lost, so it resends the ACK without delivering again. The sender accepts an ACK for any attempt's `msg_id`, stops the retry timer on the first one, and ignores later ones. Impact: duplicate detection at the recipient moves from `msg_id` to sequence number (Network #2's replay window); a retry looks like a new message to the IPS, not a replay (AI/ML). Spec: `PROTOCOL.md` §5.1–5.2. | Network #1 | Decided. Confirm at freeze with Network #2 and AI/ML |

#### Network #2 security decisions (Jose)

Moved here from `security/design-decisions.md` (Nov 16–17). Decision IDs (1–15) and open-item IDs (O1–O20) are kept as-is, since code comments and the `security/` docs cite them. Formulas and wire layouts live in `PROTOCOL.md` §9.

| # | Topic | Decision | Affects | Status |
|---|---|---|---|---|
| 1 | Watchtower identity mapping | The watchtower holds every node's **pseudonym/MAC secret** (`pseudo_secret`) plus the network key, but **no X25519 private keys**. It can tell which real node transmitted a frame, but cannot read message content. The lookup runs **on the watchtower firmware**: each epoch it derives every node's pseudonym and tags each log line with a new optional field `"node"` (`"A"`…`"D"`, `"X"`, or `"?"` when no node matches). The IPS groups features by `node`, BLOCKs target the real node ID (so blocks survive rotation), and `"?"` is itself an outsider/spoof signal. Threat-model note: the watchtower is a trusted insider; if it's captured, every node's identity is exposed, but message content isn't. The sniffer-privacy claim still holds against outsiders. | Yunus (watchtower lookup + `node` field), Hannan (group by `node`, BLOCK by node ID), task 3 (KDF must be derivable from `pseudo_secret` alone), task 8 (BLOCK target) | Decided (Jose), to confirm with Hannan + Yunus |
| 1b | Per-node behaviour metadata | Because identities are now continuous (#1), the IPS keeps a **per-node baseline** (how A normally behaves vs. A right now). The watchtower adds these **optional** log fields, read from ESP-NOW's `rx_ctrl` and the frame header: `rx_us` (radio µs timestamp, for fine inter-arrival timing; `t` stays the laptop arrival time), `noise_floor` (jamming / airtime saturation; check accuracy on hardware), `rate` / `sig_mode` / `mcs` (radio fingerprint: our firmware uses fixed settings), `flags`, `epoch`, `next_hop`, and `raw` (hex of the full 240-byte frame, also needed by the pcap tool). Frame size is not logged as a feature (always 240 by design); TX power is not observable, so RSSI is its proxy. Relay-vs-originate behaviour (black-hole detection) is **derived by the IPS** from `msg_id` + `t`, not tagged by firmware. Retention: live logs follow the existing IPS auto-delete (`ips/retention.py`); only deliberately recorded labeled sessions are kept. Threat-model note: these logs are exactly the per-node profile the protocol hides from outsiders, so they are sensitive. | Yunus (extra fields in watchtower output), Hannan (schema optional fields, per-node baseline features, relay-ratio feature), task 12 (threat model) | Decided (Jose), to confirm with Hannan + Yunus |
| 2a | Epoch length | **60 s.** `epoch = floor(clock_s / 60) mod 65536` (2-byte field wraps after ~45 days). Every rotation changes pseudonym + MAC; on ESP-IDF the MAC change briefly stops Wi-Fi, so each rotation costs a short outage and resets pseudonym-keyed neighbor/route tables (Yunus to measure the outage; Rashad covers boundary behaviour in PROTOCOL §6). | Yunus, Rashad, Hannan (rotation visible every 60 s), §12 | Decided (Jose) |
| 2b | Time source | **Signed watchtower time beacon.** The watchtower broadcasts a time beacon signed with its Ed25519 key (the same key as BLOCKs) about every 10 s, with a counter so it can't be replayed. Nodes set their clock from a valid beacon and free-run on their crystal in between (drift is milliseconds per hour). If the watchtower dies, nodes keep their last time. All nodes rotate at the same moment, which matters for privacy: a node that rotates alone can be linked across epochs. Open: frame type and whether relays forward the beacon (decide with task 8, BLOCK format). | Yunus (beacon on watchtower, clock on nodes), task 7 (replay timestamps use this clock), task 8 | Decided (Jose) |
| 2c | Accepted epochs + pre-sync behaviour | **Window: ±1 epoch.** Relays and recipients accept frames whose `epoch` is the previous, current or next one, and drop the rest. Recipients and the watchtower derive pseudonyms for all three. This covers crystal drift and frames crossing a rotation, and limits outsider replay to about 2 min (`link_tag` stops outsiders editing `epoch`). **Before sync: queue sends.** A freshly booted node receives and decrypts, but doesn't transmit or relay until its first valid time beacon (≤ ~10 s). Text the laptop sends meanwhile is held in a small queue and sent once synced, not rejected. The queue holds **at most 8 messages** (same as `RT_MAX_OUTSTANDING`). When it's full, new sends are **rejected** with an error to the laptop. | Rashad (epoch check in receive path, pre-sync gate in `rt_send`), Yunus (queue + sync flag), task 7 | Decided (Jose) |
| 3 | Pseudonym + MAC derivation | Each node has a random 32-byte `pseudo_secret` (from keygen; held by that node and the watchtower only). **Hash: keyed BLAKE2b** (Monocypher `crypto_blake2b_keyed`; Python `hashlib.blake2b(key=…, digest_size=…)`). The output length is set with BLAKE2b's digest-size parameter, not by truncating a longer hash, because the two give different bytes. **Pseudonym:** `BLAKE2b(key=pseudo_secret, digest_size=4, msg="GM-PSEUDO" ‖ epoch_be16)`. **MAC:** `BLAKE2b(key=pseudo_secret, digest_size=6, msg="GM-MAC" ‖ epoch_be16)`, then `mac[0] = (mac[0] & 0xFC) \| 0x02` (locally administered, unicast). The watchtower checks that a frame's MAC matches its pseudonym, which is an extra spoof signal. **Reserved pseudonyms:** `0x00000000` (flood marker in `next_hop`) and `0xFFFFFFFF` (kept for future broadcast). If the hash gives either, rehash with a counter byte appended (`"GM-PSEUDO" ‖ epoch_be16 ‖ 0x01`, then `0x02`, …). Labels are ASCII with no terminator. **Byte order: big-endian (network order)** for `epoch` and every multi-byte header field (§3). **Test vector:** `pseudo_secret = 00 01 02 … 1f`, epoch `0x0102` → pseudo `ac341587`, MAC `6a:a7:07:ca:0e:dd`. | Yunus (codec byte order, MAC set per epoch, watchtower lookup), Rashad (byte order in sim), Hannan (MAC↔pseudo consistency feature), task 13 (Monocypher), task 15 (keygen makes `pseudo_secret`) | Decided (Jose); byte order to confirm with Rashad + Yunus |
| 4 | `link_tag` | `link_tag = BLAKE2b(key=network_key, digest_size=8, msg="GM-LINK" ‖ frame[0:22] ‖ frame[30:240])`. **Coverage: the whole frame except the tag itself**: header bytes 0–21 (`ver_type` … `epoch`) plus bytes 30–239 (`nonce`, `ciphertext`, `aead_tag`). An outsider can't change any byte, so they can't spoof `src_pseudo`, edit `ttl`/`hop_count`/`epoch`, or put junk ciphertext under a captured header to get it flooded. **Key:** the shared 32-byte `network_key` used directly; the `"GM-LINK"` label keeps it separate from the task 3 hashes. **Input:** the tag field is skipped (incremental hash of the two ranges), not zeroed. **Size:** 8 bytes (unchanged §4.1). Rules: computed last, after every other field is final (sender and each relay, matching `relay_schedule()`); verified first on receive with a **constant-time** compare; the watchtower holds `network_key` and reports the result as `link_ok`. Known limit: a captured frame resent unchanged still passes; it's caught by the seen-cache, the ±1 epoch window, and the recipient's sequence check (task 7). Frame offsets: `ver_type` 0, `flags` 1, `msg_id` 2–9, `ttl` 10, `hop_count` 11, `src_pseudo` 12–15, `next_hop` 16–19, `epoch` 20–21, `link_tag` 22–29, `nonce` 30–53, `ciphertext` 54–223, `aead_tag` 224–239. **Test vector:** `network_key = 20 21 … 3f`, frame byte *i* = *i* (0x00…0xef) → `152ee8ad612ca586`. | Rashad (`link_tag_valid()` stub in `routing.c`), Yunus (codec offsets), Hannan (`link_ok`), task 14 (`compute_link_tag` callback) | Decided (Jose) |
| 5 | Inner header layout | Plaintext inside `ciphertext` is exactly 170 bytes, big-endian: `sender_id` 0–3 (u32, real node ID), `recipient_id` 4–7 (u32), `timestamp_ms` 8–11 (u32, send time in ms on the synced clock from 2b, mod 2³²), `seq` 12–15 (u32, per sender→recipient), `type` 16 (u8: DATA or ACK, same values as `RT_TYPE_*`), `len` 17 (u8), `body` 18–169 (**152 bytes**, zero-padded after `len`). **Body max is 152, not 153**, so `RT_BODY_MAX`, PROTOCOL §5.2's length check and the breakdown's "~153 B" all change. **Hidden ACKs:** every end-to-end encrypted frame carries cleartext `ver_type = DATA`; the real DATA/ACK type is only in the inner `type`. HELLO and BLOCK keep their own cleartext types (they aren't end-to-end encrypted). ACK body = the acked attempt's 8-byte `msg_id`, `len = 8`. Recipient rules after a successful decrypt: `recipient_id` must equal own ID and `sender_id` must equal the peer whose key decrypted it (stops reflection), and `len` ≤ 152 for DATA (= 8 for ACK), otherwise drop. Open, for task 7: `seq` restarts at 0 when a sender reboots. | Rashad (`RT_BODY_MAX` 153→152, §5.2 length check, ACK frames sent as cleartext DATA, recipient checks), Yunus (inner codec), Hannan (no cleartext ACK type in logs), task 6, task 7 | Decided (Jose); body size change to confirm with Rashad |
| 6a | Key setup: epoch DH ratchet (**revised**; replaces per-message ephemeral keys) | **Goal:** forward secrecy *and* post-compromise security (future epochs heal after a compromise, against a passive adversary) at low cost. **No frame-format change**: `nonce` (24, random), `ciphertext` 170, body 152 as in #4/#5. **Static keys (kept on the board):** X25519 key pair per node from keygen. **Root per pair:** `root[S,R] = BLAKE2b(32, "GM-ROOT" ‖ X25519(sk_S, pk_R) ‖ pk_lo ‖ pk_hi)` (public keys sorted). **Chain start / resync:** `ck[e] = BLAKE2b(key=root, 32, "GM-RESYNC" ‖ e_be16)`. Two nodes that both start fresh at epoch *e* derive the same key with no messages. **Epoch keys:** during epoch *e* each node generates a fresh X25519 pair `r(e+1)` and floods its public half in a **KEYS frame** (below) about every 10 s. **Confirmation:** each KEYS slot also carries `conf = BLAKE2b(4, "GM-CONF" ‖ peer's r(e+1) pk)` for each peer key received. **Boundary e → e+1, per pair (chained DH):** mix the DH only if this node holds the peer's `r(e+1)` pk **and** the peer has confirmed holding ours: `ck[e+1] = BLAKE2b(key=ck[e], 32, "GM-CHAIN" ‖ (e+1)_be16 ‖ [X25519(r_me(e+1).sk, r_peer(e+1).pk)])`; otherwise the same hash with no DH term. **Convergence:** a node that can compute both versions keeps the other one as an alternate for epoch e+1. If a peer's KEYS tag (or a message) verifies under the alternate, rule: **the DH version wins**. A node on the hash-only version switches to it; a node on the DH version stays. Confirmation guarantees both sides *can* compute the DH version whenever either side used it. **Fork + RESYNC:** if no KEYS frame from an expected peer verifies for 2 full epochs, the node floods a RESYNC (a KEYS frame in resync mode, tags keyed with `root`). Both sides then reset `ck[e]` with the chain-start formula. Accepted cost: a resync from `root` gives no post-compromise healing until the next DH epoch. A board on first boot also sends RESYNC to every peer. **Message key:** `mk[e] = BLAKE2b(key=ck[e], 32, "GM-MSG")`, XChaCha20-Poly1305 with a random 24-byte nonce (many messages per epoch is fine with 192-bit random nonces). **Deletion:** keep `ck` for the current and previous epoch (±1 window), wipe older; wipe `r(e).sk` once epoch e+1 has passed. **KEYS frame:** new cleartext `ver_type = KEYS`, flooded like DATA (seen-cache, TTL, jitter, k suppression, `link_tag`). Contents in the 170-byte region: `target_epoch`(2) ‖ `mode`(1: normal / resync) ‖ `next_pk`(32) ‖ 8 slots × (`tag`(8) ‖ `conf`(4)) = 131 bytes, rest random. `tag[P] = BLAKE2b(key=ck[e][me,P] (root in resync mode), 8, "GM-KEYS" ‖ target_epoch ‖ mode ‖ next_pk ‖ conf)`. Slots are in random order, and unused slots and the `nonce`/`aead_tag` fields are random bytes, so the peer count is hidden. A recipient identifies the sender by which pair key verifies a tag (≤ 64 short hashes per KEYS frame). **Persistence:** after each boundary, write the state to NVS, overwriting the previous copy: `ck` current + previous + alternate per peer, own `r(e+1)` pair, peers' `r(e+1)` pks, confirmation flags. Caveat: flash erase is less certain than RAM wipe. **Cost:** per node per epoch: 1 key generation + ≤ 8 X25519 (≈ 9 per minute). **Per message: symmetric crypto only.** **Properties:** forward secrecy with ~2-epoch granularity. Post-compromise security heals at the first successful DH epoch after compromise, against a passive attacker. An attacker who holds a stolen `ck` and *actively* forges KEYS frames can intercept indefinitely (standard limit), and a stolen static key plus active interception can force RESYNC and take over a pair. Not quantum-resistant. | Rashad (new flooded `ver_type` KEYS through `rt_on_receive`; a hook to hand KEYS frames to the key layer), Yunus (NVS state, epoch-boundary task, X25519 bench), Hannan (KEYS in `PACKET_TYPES`; expected KEYS rate ~0.1 Hz per node is a feature), dissector, breakdown §4.1 `ver_type` list | Decided (Jose); new frame type to confirm with the team |
| 6b | Associated data | `AD = ver_type ‖ flags ‖ msg_id ‖ epoch` = `frame[0:10] ‖ frame[20:22]` (12 bytes, the fields relays never change). Even an insider can't re-wrap a captured ciphertext under a fresh `msg_id` (to slip past seen-caches) or a new `epoch` (to stretch a replay); the recipient's AEAD check fails. AEAD: XChaCha20-Poly1305 (Monocypher `crypto_aead_lock`/`unlock`). | Task 14, task 7 | Decided (Jose) |
| 6c | Trial decryption | Every node tries every DATA frame that passes `link_tag`, using the precomputed `mk` for each peer (≤ `RT_MAX_PEERS` = 8). It picks the epoch's `mk` by the frame's `epoch` (±1 window), and at a boundary also tries the alternate, so usually 8–16 AEAD tag checks and **no X25519 per frame**. Last-successful peer first. A failed try costs only the tag check, since the AEAD verifies before decrypting. No cleartext key hint, because a hint would let sniffers group a conversation (N1). | Yunus (bench), Rashad (`try_decrypt` semantics unchanged) | Decided (Jose) |
| 6d | `flags` (closes O6) | Cleartext `flags` bit 0 = **SOS**; all other bits reserved, must be 0. **needs-ACK is removed** from §4.1: it would reveal DATA vs. ACK in cleartext and undo #5, and the inner `type` already implies it (DATA is always ACKed, ACK never is). `flags` is bound in the AD (6b). Relays may treat SOS with shorter jitter (Rashad's call). Accepted leak: a sniffer can see which frames are SOS. Document it. | Rashad, breakdown §4.1, threat model | Decided (Jose) |
| 7 | Replay window | **Layers, outermost first.** (1) **Relays:** `link_tag`; the main seen-cache (60 s, holds pending relays); **a separate msg_id-only cache covering 180 s** (the full ±1 epoch window; ~512 entries of 8-byte `msg_id` + time ≈ 6 KB, oldest evicted first). A replay inside the window is dropped at the first relay instead of being flooded again (amplification part of O4). (2) **Epoch window ±1** (2c), with `epoch` bound in the AD (6b) so even insiders can't re-date. (3) **Key deletion (6a):** frames older than ~2 epochs can't be decrypted at all. (4) **Recipient freshness, 5 s:** every attempt (first send *and* each retry) carries a fresh inner `timestamp_ms`. DATA is accepted only if `|now − timestamp_ms| ≤ 5 s` on the synced clock; stale → **drop silently**, log `REPLAY_STALE`, **no ACK** (closes the ACK-leak part of O4). (5) **Recipient seq dedup:** per peer, remember the seqs seen in the last **15 s**. That must cover the whole retry schedule (attempts at 0/1/3/7 s) plus freshness, otherwise attempt 4 would be delivered twice. Fresh + new seq → deliver + ACK; fresh + remembered seq → re-ACK only (the ACK was lost). Dedup is **set membership, not "highest seq"**, so reordered messages aren't dropped; ~16 entries per peer. **Retries:** new `msg_id`, **same seq**, **new timestamp** (updates PROTOCOL §5.2, which says retries rebuild the inner header). **Seq start (closes O5):** on boot a sender starts each peer's seq at a **random 32-bit value**. No flash needed: the recipient only remembers 15 s, and reboot + time sync takes longer. A rebooted *recipient* stays safe because stale frames fail freshness and fast replays hit the msg_id caches. **ACK delay (O2):** the recipient waits a random **0–400 ms** before sending an ACK (under the 1 s first retry). This only blurs DATA→ACK pairing when other traffic is around; the residual leak is documented and cover traffic is future work. ACK replays are harmless: an ACK only matches an outstanding attempt's `msg_id`. KEYS replays within the window carry identical content and are dropped by caches. | Rashad (`rt_peer_t.last_seq_rx` → recent-seq set; retry builds a new timestamp; ACK delay timer; second msg_id cache), Yunus (RAM for the 180 s cache), Hannan (`REPLAY_STALE` drop events; retries look like new messages), results table "Replay rejection 100%" | Decided (Jose) |
| 8a | Signature scheme | **Standard Ed25519** (RFC 8032, SHA-512) via Monocypher's optional `monocypher-ed25519.c`; Python tools use `cryptography`/PyNaCl. The watchtower holds the only private key (from keygen, in `firmware/config/keys/`); every node has the public key baked in. Signed bytes: `"GM-CTRL" ‖ subtype ‖ issued_at_ms ‖ payload` (domain-separated; hop-changed header fields are not signed). | Yunus (Ed25519 sign on watchtower, verify on nodes), task 13, task 15 | Decided (Jose) |
| 8b | BLOCK target | **The watchtower sends per-epoch identifiers.** The IPS sends one command naming a real node (or `"?"` + the observed pseudo/MAC); the watchtower computes the target's pseudonym + MAC for the **current and next epoch**, signs, floods, and **re-issues every epoch** until it expires. Nodes never learn a `pseudo_secret`, so after the block ends they can't track the node. **Match rule:** a target matches a frame if `src_pseudo` matches **and** (the radio source MAC matches, or the target's MAC field is all-zero). This lets the IPS block a *spoofer's* (victim pseudo, attacker MAC) pair without cutting off the victim, if their MACs differ. **Enforcement:** right after `link_tag` on receive: drop, don't relay, log `BLOCKED`. Because `src_pseudo` is the transmitter, a blocked node's own transmissions die at its neighbours. | Rashad (block check in `rt_on_receive`), Yunus (watchtower re-issue loop, block table on nodes), Hannan (`make_block_cmd` → `{"cmd":"block","node":"X" or "?","pseudo","mac","reason","until"}`; spoof may become blockable by MAC pair) | Decided (Jose) |
| 8c | Anti-replay for signed messages | **Time-based, no counter.** The mesh clock is **Unix time in ms**, set on the watchtower by the IPS laptop over serial, so watchtower logs, beacons and the IPS share **one clock source** (Hannan's "Everyone" item). `epoch = floor(unix_s / 60) mod 65536` (2a). **TIME:** accepted only if `issued_at_ms` > the last accepted beacon; the node sets its clock to `issued_at_ms` (error ≈ flood delay, ~100 ms). `last_beacon_ms` is saved to NVS with the ratchet state each epoch, so after a reboot a replayed old beacon can't drag the clock back. **BLOCK:** valid from `issued_at_ms` to `until_ms`; an old BLOCK has expired by the time it could be replayed, and a replay of a live one changes nothing. **Unblock early:** re-issue the same `block_id` with `until_ms = issued_at_ms`. | Yunus (NVS field, clock set from beacon, laptop → watchtower time command), Hannan (`t` and block times in the same Unix clock), replaces "counter" in §4.5 | Decided (Jose) |
| 8d | CTRL frame + verify rate limit (closes the 2b frame-type question) | **One signed flooded type: `ver_type = CTRL`** (replaces BLOCK). Cleartext types are now **DATA, HELLO, CTRL, KEYS**. Body in the 170-byte region: `subtype`(1: TIME / BLOCK) ‖ `issued_at_ms`(8) ‖ payload ‖ `sig`(64). TIME payload: none (73 bytes). BLOCK payload: `block_id`(4) ‖ `until_ms`(8) ‖ `reason`(1: flood/replay/spoof/routing/manual) ‖ 2 × [`pseudo`(4) ‖ `mac`(6) ‖ `epoch`(2)] (110 bytes). The rest of the region, `nonce` and `aead_tag` are random. TIME is sent about every 10 s, BLOCK once per epoch while active. **CPU protection:** first, skip without verifying anything not newer than what's held (TIME not newer than `last_beacon_ms`; BLOCK whose `block_id` is already held with the same or newer `issued_at_ms`); then verify at most **~2 CTRL frames/s**. **Only verified CTRL frames are relayed** (closes O8); skipped or over-budget ones are dropped, so a forged CTRL flood never travels past the first hop. Unlike DATA, CTRL relaying therefore waits for the verify step. | Rashad (CTRL through `rt_on_receive`: relay only after the key layer reports "verified"), Yunus (verify queue + rate limit), breakdown §4.1 `ver_type` list, dissector | Decided (Jose) |
| 10a | Hop padding (closes O1) | The originator picks `pad` uniformly from {0, 1, 2} and sends with `hop_count = pad`, `ttl = default_ttl − pad`, so `hop_count + ttl` is the same on every frame and the padding is invisible. Relays are unchanged. A sniffer can no longer read "hop 0 = originator"; it has to fall back to first-copy timing (still possible, documented). Costs: route-learning hop counts and the IPS hop-vs-RSSI feature are noisy by up to 2; effective range drops by up to 2 hops (raise `default_ttl` by 2 to compensate). The IPS "hop decreasing for the same `msg_id`" signal is unaffected. | Rashad (§5.2 FILL step, route-learning metric, `default_ttl`), Hannan (hop features ±2) | Decided (Jose) |
| 10b | Per-transmitter CTRL verify budget (closes O10) | On top of the global ~2 verifies/s cap, each transmitter identity (`src_pseudo` + radio MAC) gets **1 verify per 5 s**; frames over its budget are dropped unverified (and, per 8d, not relayed). A flooder spends only its own share, so CTRL frames relayed by honest neighbours still get checked. Limit: an insider that changes its pseudo/MAC on every frame falls back to the global cap (documented). | Rashad, Yunus | Decided (Jose) |
| 10c | Monotonic clock with slew (closes O11) | A valid beacon only moves the clock **forward**: `target = max(local, issued_at_ms)`. Forward corrections under 1 s are slewed over ~5 s; larger ones jump (first sync, after reboot). A late or delayed beacon is harmless because the free-running local clock is already ahead of it. Crystal drift (ms/hour) is never corrected backward, which is acceptable at 60 s epochs and 5 s freshness. Limit: a compromised watchtower can push clocks forward and they can't come back (see O16). | Yunus (clock code), 2b/8c | Decided (Jose) |
| 10d | RESYNC hardening (closes O12) | A RESYNC's tagged content gains `epoch` and a random 8-byte `nonce`. A node acts on **at most one RESYNC per pair per 5 epochs**, ignores a repeated nonce, prints a serial event (`{"ev":"resync","peer":"C"}`), and the watchtower counts RESYNC frames per node (their `mode` byte is visible) so the IPS can flag spikes. Doesn't stop a static-key thief (nothing light does) but makes the attack loud and stops replayed RESYNCs from repeatedly wiping healing. | Yunus, Hannan (RESYNC-rate feature), 6a | Decided (Jose) |
| 10e | Missing-DH alert (closes O18) | A node prints `{"ev":"no_dh","peer":"C","epochs":3}` when a pair has had no DH step for 3 epochs in a row. The watchtower's log already lets the IPS count KEYS frames per node per epoch (expected ~6). Selective KEYS jamming becomes **visible**; it is not prevented (disguising KEYS was rejected in 6a). | Yunus, Hannan (KEYS-per-node feature) | Decided (Jose) |
| 10f | Missing-beacon alert (closes O19) | A node that hears no valid TIME beacon for **30 s** prints `{"ev":"no_beacon","secs":30}` and keeps free-running (10c). Accepted limit: a BLOCK jammed locally isn't enforced in that area until the jamming stops. | Yunus | Decided (Jose) |
| 10g | Per-transmitter cache-insertion limit (closes O20) | Each transmitter identity (`src_pseudo` + radio MAC) may add at most **~20 new `msg_id`s per second** to the relay caches; beyond that its frames are dropped (not cached, not relayed). Outsiders never reach this point (`link_tag` is checked first). The limit must sit well above a busy honest relay's rate (relays forward everyone's traffic), so confirm the value against Rashad's sim. Limit: identity cycling by an insider, as in 10b; the IPS sees it as a flood. | Rashad (cache insert path), Hannan | Decided (Jose); value to confirm with Rashad's sim |
| 12a | Accepted limitations (closes O3, O7, O14, O15, O16, O17) | All six are **documented, not fixed this week**: RSSI tracking of static boards (O3); the network's existence is visible (O7, a non-goal); no network-key revocation, so a captured board stays an insider until reflash, with BLOCK re-issued every epoch as the mitigation (O14); keys unencrypted in flash, no eFuse changes, panic wipe as stretch (O15); unauthenticated serial, so physical access = compromise and the watchtower and IPS laptop are trusted and guarded (O16); one fixed channel, so jamming is detected by the IPS but not prevented (O17). Future work: signed network re-key, flash encryption + secure boot, channel hopping. | README limitations, threat model | Decided (Jose) |
| 12b | Threat-model scope | **In scope:** A1 outsider passive sniffer, A2 outsider active (inject/replay/delay/selective jam), A3 compromised insider node, A4 funded adversary (long-term recording + later board seizure). **Out of scope:** hiding the network's existence, preventing RF jamming, multi-sniffer direction-finding, quantum, a compromised watchtower/IPS/provisioning laptop, physical serial access, hardware key-extraction defenses, side channels. See `security/threat-model.md`. | Everyone (README, slides) | Decided (Jose) |
| 12c | IPS block policy for spoof-like evidence (closes O9) | **Adopt Hannan's `ips/live.py` policy.** When attack traffic under a node's name is > 6 dB off that node's usual RSSI, the IPS never auto-blocks the whole node, even with auto-block on: it raises a PENDING alert, the operator confirms, and the block targets only the (pseudo, MAC) pair. Residual (documented): an attacker that copies both the victim's pseudonym **and** MAC produces the same pair, so only RSSI and the operator can tell them apart; a wrong confirmation blocks the victim until the block expires. | Hannan (already implemented), threat model §5, PROTOCOL §9.10 | Decided (Jose) |
| 12d | Unkeyed KEYS `conf` hashes (closes O23) | **Accept and document.** A sniffer can recompute `conf` for every cleartext `next_pk` and learn which nodes hold pair keys with which others. Because keygen makes every node a peer of every other (decision 15), that graph is complete, so the leak adds only per-node peer counts (≈ the node count already visible, O22) and a little reachability (which KEYS floods reached which node). This corrects 6a's "the peer count is hidden". It becomes a real relationship leak only if provisioning becomes partial (groups holding keys only among themselves). Future work: key it with the pair key, `conf = BLAKE2b(key=ck[e][me,P] (root in resync), 4, "GM-CONF" ‖ peer pk)`; no frame change. No code change before the freeze. | Threat model §4–5, PROTOCOL §9.10 | Decided (Jose) |
| 13 | Crypto library | **Monocypher 4.0.2**, vendored unmodified in `firmware/lib/monocypher/` (`monocypher.c/.h`, `monocypher-ed25519.c/.h`, `LICENCE.md`; dual BSD-2 / CC0). Provides everything specified in 3–8: keyed BLAKE2b, XChaCha20-Poly1305, X25519, Ed25519 (RFC 8032). **Provenance:** release tarball SHA-512 matches the one published on monocypher.org, and the source files match GitHub tag `4.0.2` apart from the version stamp. **Verified on the laptop:** upstream test suite passes (gcc, `-Wall -Wextra -pedantic`, 0 warnings); C outputs match PyNaCl/libsodium and `cryptography` byte for byte for BLAKE2b (our test vectors), XChaCha20-Poly1305 with AD, X25519 and Ed25519. **Pending:** ESP32-S3 build and benchmark once Yunus picks Arduino-ESP32 or ESP-IDF (no ESP toolchain on Jose's laptop). | Yunus (include `firmware/lib/monocypher` in the build; X25519/Ed25519/AEAD bench), task 14 | Decided (Jose); S3 build pending |
| 14 | Crypto glue, stage 14a | **Staged:** 14a (done) = `link_tag`, pseudonym/MAC, inner-header codec, encrypt/trial-decrypt, CTRL sign/verify, i.e. what `routing.h` calls today; 14b (next) = epoch ratchet, KEYS/RESYNC, mesh clock, plugged in behind `gm_peer_message_key()` (until then keys come from the static root key: **no forward secrecy yet**). **Layout:** portable C in `firmware/src/crypto/gm_crypto.c/.h`; tests in `firmware/test/` (`test_crypto.c` + `run_crypto_tests.py`, which builds with gcc and cross-checks against an independent Python implementation using PyNaCl/libsodium and `cryptography`). **Encrypt order:** routing fills `ver_type`/`flags`/`msg_id`/`epoch` *before* `encrypt()`, because they're AEAD associated data (Rashad reorders `build_and_send`). **Freshness:** the 5 s check lives in routing's `handle_data` (new `RT_LOG_REPLAY_STALE`); `try_decrypt` does crypto + recipient/sender/len checks only. **Results:** 56/56 pass (40 C + 16 Python cross-checks); 6 deliberate mutations all caught; untested: the reserved-pseudonym rehash branch. Also flagged: the `encrypt` callback should return `bool`. | Rashad (reorder `build_and_send`, cleartext DATA for ACKs, `RT_BODY_MAX` 152, `encrypt` → bool, `link_tag_valid`, freshness in `handle_data`), Yunus (`rt_platform_t` adapters, `esp_fill_random` RNG) | Decided (Jose); 14b pending |
| 14b | Ratchet, KEYS/RESYNC, clock, persistence (stage 14b) | **Done** in `firmware/src/crypto/gm_ratchet.c`. **Jose's choices:** one `gm_tick(local_ms)` call drives the clock, epoch steps, KEYS cadence and alerts, returning an events struct; missed epochs are **hash-stepped up to 10**, longer gaps RESYNC; RESYNC triggers only if a peer is silent for 2 epochs **and** an unverifiable KEYS frame was heard (a powered-off peer causes no RESYNC flood); state persists as an **export/import blob** (1517 bytes, versioned) that firmware writes to NVS. **Refinements found while building and testing, within those choices:** (1) a RESYNC is also accepted when the pair is already silent, even inside the 5-epoch rate limit, because otherwise boards that boot at different times deadlock for ~8 min; replays against healthy pairs stay rate-limited; (2) an unresolved alternate is **carried through hash-only boundaries**, because otherwise a split that isn't resolved within one epoch becomes permanent (found by the gap test); (3) a node **ignores KEYS frames carrying its own `next_pk`**: pair keys are symmetric, so a reflected copy of its own frame would verify and plant its own key as the peer's (found by the post-compromise test). **Results:** 131/131 (14a + 14b C tests + Python cross-checks); the simulation covers forward secrecy, a thief with stolen state being **locked out two epochs later** (post-compromise security), one-way loss, convergence, fork + RESYNC, replay, a powered-off peer, gaps, persistence, the ±1 window and own-echo; 16 of 18 mutations caught (the other two can't be caught by any test). | Yunus (call `gm_tick`, flood KEYS, write/read the NVS blob, forward TIME beacons, rotate the MAC at `epoch_changed`), Rashad (route KEYS/CTRL frames to the key layer, items 1–8 in `firmware/src/crypto/README.md`), PROTOCOL §9.6/§12 updated | Decided (Jose); refinements (1)–(3) approved by Jose |
| 15 | Key provisioning (`security/keygen.py`, closes O13) | **Output:** one SECRET C header per board in `firmware/config/keys/` (gitignored): `keys_A.h`…`keys_D.h`, `keys_X.h` (network key, own pseudonym secret, own X25519 secret, watchtower public key, peer table) and `keys_W.h` (network key, Ed25519 signing key as Monocypher's seed‖pk, every node's pseudonym secret, **no X25519 keys**). Plus a PUBLIC `firmware/config/roster.json` (IDs, public keys, fingerprints; safe to commit). Node IDs: A=1, B=2, C=3, D=4, W=5, X=6. **Attacker X = full insider** (threat model A3): it has the network key and its own keys and is everyone's peer, so its KEYS frames verify and the watchtower labels it "X". **Fingerprints:** `1a2b-3c4d` = first 4 bytes of BLAKE2b("GM-FP" ‖ key), for each node's X25519 public key, the watchtower's Ed25519 key and the network key; boards print `gm_fingerprint()` of the keys they *hold* at boot (new C function) for comparison with the roster. **Randomness:** OS CSPRNG only (`secrets.token_bytes`), no seeded mode. **Safety:** refuses to overwrite existing keys without `--force` (re-keying means reflashing every board). **Tests** (`security/test_keygen.py`, 30/30): runs in a temp dir; checks key consistency, peer lists, the watchtower holding pseudonym secrets but no X25519 keys, no secrets in the roster, overwrite protection; compiles the headers with `gm_crypto` and shows boards A and C derive the same root, the boot fingerprint matches the roster, and the watchtower's signature verifies. | Yunus (include `keys_<board>.h` by build flag, print fingerprints at boot, 4-board setup = D includes `keys_D.h` + `keys_W.h`), whoever holds the boards runs keygen once | Decided (Jose) |

#### Network #2 open items (checkpoint review after task 5)

Each needs a decision (or an explicit "accept and document") from Jose before the task named in "Decide by".

| ID | Issue | Why it matters | Options to weigh | Affects | Decide by |
|---|---|---|---|---|---|
| O1 | **Originator exposed in cleartext.** On the first transmission `hop_count = 0` and `ttl` = default, and `src_pseudo` is the transmitter, so the originator's current pseudonym is visible. The first copy of a new `msg_id` a sniffer hears also usually comes from the originator. | Weakens N1 within an epoch; the Nov 14 `src_pseudo` rewrite only hides the originator on relayed copies | Random starting `hop_count`/`ttl` ("hop padding"); originator adds a random delay; accept and document | Rashad (route learning keeps the lowest `hop_count`), Hannan (hop/RSSI consistency feature) | **Closed by 10a**: hop padding |
| O2 | **Sender→recipient linkable by timing.** A hop-0 DATA from P1 followed shortly by a hop-0 "DATA" (really an ACK) from P2 links the pair within an epoch, even with ACKs hidden (#5). | N1: who talks to whom | Random ACK delay; cover traffic (future work); accept and document | Rashad (ACK timing vs. retry timeouts) | **Partly addressed by 7**: random 0–400 ms ACK delay; residual leak accepted and documented; cover traffic is future work |
| O3 | **RSSI tracking across epochs.** With static boards, a sniffer can follow a node through rotation by its signal strength alone. | Limits what pseudonym/MAC rotation buys on a tabletop | Accept and document (README limitations, threat model); TX power jitter (hurts topology control) | Threat model, README | **Closed by 12a**: documented (README limitations, threat model §4); measured by the stretch traffic-analysis test |
| O4 | **Replay triggers a re-ACK.** A replay 60 s–~2 min old passes relays (cache expired, inside the ±1 epoch window), gets flooded again, and the recipient resends the ACK for the repeated seq. That confirms the recipient to the attacker and amplifies traffic. | N1 (recipient confirmation) + N3 | Re-ACK only if the inner `timestamp_ms` is within the sender's retry horizon (~7–10 s), otherwise drop silently; rate-limit re-ACKs | Rashad (REACK branch in §5.1 / `handle_data`) | **Closed by 7**: 5 s freshness (no ACK for stale frames) + 180 s relay msg_id cache |
| O5 | **`seq` resets on reboot** (carried from #5). A rebooted sender restarts at 0 and the recipient drops its new messages; a rebooted recipient forgets seen seqs, so a replay inside the window is delivered again. | N3, N7 | Persist seq in NVS flash; per-boot session ID; seed seq from the synced clock | Rashad (`rt_peer_t`), Yunus (NVS) | **Closed by 7**: random seq start per boot + 15 s dedup memory, no flash |
| O6 | **`flags` (e.g. SOS) in cleartext.** Shows which messages are urgent. | N1 (minor) | Move priority into the inner header (relays then can't prioritise); accept and document | Rashad, Yunus | **Closed by 6d**: SOS stays in cleartext (bound in AD), needs-ACK removed, leak documented |
| O8 | **CTRL frames over the verify limit: relay or drop?** The 8d option as worded relays excess CTRL frames unverified. Then an insider flooding fake CTRL frames gets them re-flooded by every relay (amplification), and every node spends its verify budget on them. | N4, N7 | Relay only verified CTRL; relay unverified | Rashad, Yunus | **Closed**: **relay only verified CTRL.** A CTRL frame is relayed only after its signature verifies; frames skipped as not-newer or over the ~2/s verify budget are dropped, not relayed. Real TIME/BLOCK repeat every 10 s / every epoch, so drops under attack are harmless |
| O7 | **Network existence is visible.** ESP-NOW's vendor marker plus fixed 240-byte frames fingerprint GhostMesh traffic. | Out of scope for N1 (we hide who talks, not that the mesh exists) | Accept and document as a non-goal | Threat model | **Closed by 12a**: documented as a non-goal (threat model §5) |
| O9 | **The IPS can be made to block a real node.** The watchtower assigns frames to a `node` by pseudonym, and blocks target the node. An insider that copies A's pseudonym *and* MAC and misbehaves gets the real A blocked in every epoch. | N4, N7: our own defense ejects an honest node | Never block a whole node on spoof-like evidence (two RSSI clusters, MAC mismatch, `?`): block only the (pseudo, MAC) pair, or require a human click; accept and document | Hannan (`live.py` block policy), task 8b | **Closed by 12c**: operator confirms spoof-like blocks, pair-only block; full pseudo+MAC copy documented as residual |
| O10 | **A forged CTRL flood starves real BLOCKs.** The ~2/s verify budget is shared. Forged CTRL frames with fresh `issued_at` aren't skipped, so an attacker's own BLOCK and the TIME beacons never get checked in time. | N4: the attacker escapes its own block | Per-transmitter verify budget (e.g., 1 verify per 5 s per neighbour pseudo/MAC); accept and document | Rashad, Yunus, 8d | **Closed by 10b**: per-transmitter verify budget |
| O11 | **A delayed time beacon drags a node's clock back.** "Accept if newer than the last" doesn't stop delay. Jam a beacon for one node and hand it over late, and that node's clock lags. | N1 (that node rotates at a different moment and can be linked; see 2b), N7 (it gets cut off) | Clock never moves backward: `clock = max(local, issued_at)`, with small corrections applied gradually; accept and document | Yunus, 2b/8c | **Closed by 10c**: clock never moves backward + slew |
| O12 | **RESYNC is a downgrade lever.** A captured RESYNC replayed inside the ±1 window forces a pair back to the root-derived key. With a stolen static key, an attacker can forge RESYNC and then KEYS frames and sit in the middle indefinitely. | Post-compromise security (6a) | Freshness check + rate limit on RESYNC, and report each RESYNC to the IPS; accept and document | Yunus, Hannan, 6a | **Closed by 10d**: RESYNC freshness + rate limit + reporting |
| O13 | **No key fingerprint check.** Keygen output and the flashing laptop are trusted blindly; tampering there puts an attacker in the middle of every pair from the start. | MITM from day 0 | Keygen prints short fingerprints; boards show them on serial/OLED for comparison (also a demo moment); accept and document | Task 15 (keygen), Yunus | **Closed by 15**: keygen prints fingerprints and writes them to the public `roster.json`; each board prints `gm_fingerprint()` of the keys it actually holds at boot |
| O14 | **One shared network key, no revocation.** A captured board is a full insider (passes `link_tag`, can spoof pseudonyms, forge `hop`/`ttl`). The only remedy is BLOCK, which expires. | N2, N4 | Signed network-key re-key that excludes the captured node (a few frames); accept and document | Yunus, Rashad, threat model | **Closed by 12a**: documented; captured board stays an insider until reflash, BLOCK re-issued every epoch as mitigation; signed re-key is future work |
| O15 | **Keys sit unencrypted in flash.** Ratchet state, static keys and pseudonym secrets are in plain NVS. A seized board dumped with esptool gives everything, including the last epoch's chain keys (partly undoing forward secrecy). | Forward secrecy, N1 | ESP32-S3 flash encryption (development mode; eFuses make it risky this week); panic key-wipe (stretch); accept and document | Yunus, threat model | **Closed by 12a**: documented; no eFuse changes this week; panic key-wipe stays a stretch goal; flash encryption + secure boot are future work |
| O16 | **The serial ports have no authentication.** USB access to the watchtower lets anyone issue BLOCKs (eject everyone) or push the clock far ahead (DoS). USB access to a node lets them read and send as it. | N4, N7 | Signed commands to the watchtower; document "physical access = compromise" | Yunus (serial §10), Hannan | **Closed by 12a**: documented; physical access = compromise; watchtower and IPS laptop are trusted and guarded |
| O17 | **One fixed Wi-Fi channel.** A continuous jammer or a busy Wi-Fi device on that channel takes down the whole mesh. The IPS can detect it (`noise_floor`, rates falling everywhere), but BLOCK can't stop a jammer. | N7, G6 (prevention doesn't cover jamming) | Channel hopping `channel = H(network_key, epoch) mod 13` (beats a fixed-channel jammer, not a wideband one; risk of nodes on different channels); ESP32 long-range mode; accept and document | Yunus, Rashad, threat model | **Closed by 12a**: documented; jamming detected by the IPS, not prevented; channel hopping is future work |
| O18 | **KEYS frames are visible, so they can be jammed selectively.** A jammer that reacts to frame type can force every epoch to the hash-only step. Combined with one stolen chain key, post-compromise security is lost for good. | Post-compromise security (6a) | Nodes report "no DH for N epochs" to the IPS (cheap); disguise KEYS as DATA; accept and document | Yunus, Hannan, 6a | **Closed by 10e**: missing-DH alerts + KEYS-rate feature (jamming detected, not prevented) |
| O19 | **CTRL frames can be jammed selectively.** A reactive jammer near a victim drops BLOCKs and beacons in that area only, so the attacker escapes its block locally and the victim's clock drifts. | N4, N7 | O11's clock rule plus a node alert after > 30 s without a beacon; accept and document | Yunus, Hannan | **Closed by 10f**: missing-beacon alert (local BLOCK delay accepted) |
| O20 | **Flushing the cache.** A flood of unique `msg_id`s evicts the 180 s cache's oldest entries, after which replays are relayed again. | N3 (7's relay layer) | Per-transmitter rate limit before cache insertion; accept and document | Rashad | **Closed by 10g**: per-transmitter cache-insertion limit |
| O21 | **Relay D holds the watchtower's secrets in the 4-board setup.** D loads `keys_D.h` + `keys_W.h` (decision 15), so a board that sits in the radio path and relays traffic holds every `pseudo_secret`, the network key and the CTRL signing key. | The threat model assumes the watchtower is trusted and physically guarded (12b); with D=W that assumption must cover a relay too. Capturing D gives identity mapping of every node and forged TIME/BLOCK | Accept and document (D inherits the watchtower's trust level; 6 boards keep W separate); watchtower stays passive in the 4-board demo (loses D as reroute path, hurts G2) | Yunus (4-board build), threat model §2 | Before Thursday 12:00 feature freeze |
| O22 | **Active node count is visible.** Every node sends cleartext-typed HELLO (every 2 s) and KEYS (~6 per epoch) under its current pseudonym, so a sniffer can count active nodes per epoch and see joins and leaves, without linking them across epochs. | N1 (minor): network size and presence | Accept and document (alongside O7); dummy HELLO/KEYS from a fixed number of slots (cover traffic, future work) | Rashad (HELLO), threat model §4 | Before Thursday 12:00 feature freeze |
| O23 | **KEYS `conf` hashes are unkeyed.** `conf = BLAKE2b(4, "GM-CONF" ‖ peer's next_pk)` and every `next_pk` is cleartext in KEYS frames, so a sniffer can hash each heard `next_pk` and match it against slots: it learns, every epoch, which nodes hold pair keys with which others and each node's peer count. Contradicts 6a's "the peer count is hidden". With our all-to-all keygen the graph is complete, so the demo leaks mostly the count; in a real deployment it is the social graph. | N1: relationships | Key it with the pair key: `conf = BLAKE2b(key=ck[e][me,P] (root in resync), 4, "GM-CONF" ‖ peer pk)` (no frame change; `gm_ratchet.c` `conf_hash`, tests, PROTOCOL §9.6); accept and document | Jose (`gm_ratchet.c`), threat model §4 | **Closed by 12d**: accepted and documented (complete key graph under all-to-all keygen); keyed `conf` is future work |

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
