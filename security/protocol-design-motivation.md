# GhostMesh security design: why we built it this way

Owner: Jose Perez (Network #2). This is the companion to
[`project-breakdown.md` §4.7](../docs/planning/project-breakdown.md). That file says **what** we decided; this one
says **why**: which construction we picked, what else we considered, and which project
needs made the choice the right one.

## The needs every decision is judged against

These come from the goals and constraints in `docs/planning/project-breakdown.md`.

| ID | Need | Source |
|---|---|---|
| N1 | **Metadata privacy against outsiders.** A sniffer can't tell who is talking or link a node across epochs | G4, the pitch vs. Meshtastic |
| N2 | **Outsider exclusion.** Frames from anyone without the network key die at the first hop | G3, §4.5 |
| N3 | **Replay resistance** | G5 |
| N4 | **An IPS that can detect and block** the 4 attacks within 5 s | G6, G7 |
| N5 | **Fits the hardware.** ESP32-S3, 240-byte fixed frame, no real-time clock, no malloc in the routing core | §4.1, `routing.h` |
| N6 | **Buildable this week** by 4 people. Few dependencies, firmware and Python must agree byte-for-byte | §6 schedule |
| N7 | **Demo-reliable.** Works on camera, degrades gracefully when a board dies | §7.3, §9 risks |

---

## 1. Watchtower identity mapping

**Decision:** the watchtower holds each node's `pseudo_secret` (not its encryption key) and
tags every log line with the real node (`"node": "A"`, or `"?"`). The lookup runs on the watchtower firmware.

**Problem it solves:** pseudonyms and MACs rotate every 60 s. An IPS that keys on them sees
every node as a stranger once a minute, so per-node history (the spoof signal) resets and a BLOCK
expires at the next rotation. That breaks N4.

| Option | Why not chosen |
|---|---|
| Watchtower holds no extra secrets; IPS tracks per epoch | Breaks N4: the attacker "reappears" every 60 s and the RSSI-history feature never builds up |
| No secrets; IPS links identities by RSSI/timing behaviour | Heuristic. Wrong links lead to wrong BLOCKs (cutting off a real node), which hurts N7. Kept as the stretch traffic-analysis experiment instead |
| Watchtower holds full node keys | Gives the watchtower message content it doesn't need. Fails least privilege |
| **Pseudonym secrets only (chosen)** | Gives the IPS continuous identity (N4) without content access. Outsiders still see only rotating identities, so N1 holds |

**Why the firmware does the lookup, not the laptop:** the secrets stay on one embedded board
instead of a laptop's disk, and the IPS just reads one more field. The laptop option needed
no firmware work but spread secrets onto more machines and into the sim/synth tools.

**Trade-off we accept:** the watchtower is a trusted insider. If it's captured, every
node's identity is exposed (but not content). The threat model states this.

### 1b. Per-node behaviour metadata

**Decision:** log extra receive-side and header fields (`rx_us`, `noise_floor`,
`rate`/`sig_mode`/`mcs`, `flags`, `epoch`, `next_hop`, `raw`) as optional schema fields. The IPS builds
a baseline for each node and derives relay behaviour itself.

**Why:** with continuous identity (#1), the strongest anomaly signal is "A is acting unlike A."
The ESP-NOW receive callback already hands us the radio's `rx_ctrl` metadata, so these fields
cost nothing to collect.

| Field | Need it serves | Alternative / why not |
|---|---|---|
| `rx_us` | Fine inter-arrival timing for scripted senders and replays (N4) | Laptop time only: has serial-port latency jitter of several ms |
| `noise_floor` | Jamming / airtime saturation (N4) | Infer from packet rate alone: can't tell "quiet" from "jammed" |
| `rate`, `sig_mode`, `mcs` | Radio fingerprint. Our firmware uses fixed settings; foreign firmware may not | No alternative signal at this layer |
| `flags`, `epoch`, `next_hop` | Out-of-window epochs, forged flags, route abuse in v2 | Without them the IPS can't see these fields at all |
| `raw` | Needed by the pcap/Wireshark tool anyway | A separate capture path: more firmware work |
| Frame size | **Not logged as a feature:** always 240 by design | — |
| TX power | **Not observable;** RSSI is the proxy | — |

**Relay vs. originate derived in the IPS, not tagged in firmware:** same information either way.
Keeping it in Python keeps the watchtower firmware simple (N6).

**Retention:** these logs are exactly the per-node profile the protocol hides from outsiders,
so live logs follow the existing auto-delete in `ips/retention.py` and only deliberate
labeled sessions are kept. Keeping everything was simpler but contradicts the privacy story.

---

## 2. Epochs and time

### 2a. Epoch length: 60 s

| Option | Trade-off |
|---|---|
| 30 s | Harder to link identities, but twice the rotation outages (the MAC change stops Wi-Fi) and twice the neighbor/route table resets. Neighbor expiry is ~6 s, so routing spends more time relearning |
| **60 s (chosen)** | At least one rotation visible in a 3-minute demo video (N7), outage cost is a small share of airtime, 2-byte counter wraps after ~45 days |
| 120 s | Fewer outages, but the demo might show only one rotation and identities stay linkable twice as long (N1) |

### 2b. Time source: signed watchtower time beacon

**Problem:** the boards have no real-time clock (N5), yet all nodes must agree on the epoch.
They must also **rotate at the same moment**: if one node rotates alone, an observer links its old
and new identity ("the one that vanished = the one that appeared"), which breaks N1.

| Option | Why not chosen |
|---|---|
| Adopt newer epochs from neighbors' frames | No authority, so any insider (including our attacker node) can drag the mesh's clock forward and desync it, which is an easy DoS |
| Set over serial at boot | Relays on power banks never get time, and a reboot loses it (N7) |
| NTP / GPS | No internet by premise; no GPS hardware |
| **Signed beacon (chosen)** | Reuses the Ed25519 key the watchtower already has for BLOCKs (N6). Insiders can't forge it. Nodes free-run on their crystal between beacons, so a dead watchtower doesn't stop the mesh (N7) |

**Trade-off we accept:** the watchtower is the time authority. If it's down at boot, new nodes
wait (see 2c).

### 2c. Accepted epochs and pre-sync behaviour

**Window ±1 epoch.** Frames in flight across a rotation, plus crystal drift, need some
slack. ±1 tolerates both. Combined with `link_tag` covering `epoch` (#4), it caps an outsider's
replay window at about 2 minutes (N3).

| Option | Why not chosen |
|---|---|
| Current epoch only | Drops boundary-crossing frames every 60 s, which hurts delivery (G1) |
| Current or previous only | A node with a slightly fast clock loses frames until the others catch up |

**Before sync: queue sends (max 8, reject when full).** A node that transmits with a guessed
epoch gets dropped anyway, and odd epoch-0 frames stand out to sniffers (N1). Listen-only was
simpler, but queueing means a user typing right after power-on doesn't lose the message
(N7). The limit of 8 matches `RT_MAX_OUTSTANDING`: fixed memory (N5), and an explicit error
instead of silent loss.

---

## 3. Pseudonym and MAC derivation

**Decision:** `pseudo = BLAKE2b(key=pseudo_secret, digest_size=4, "GM-PSEUDO" ‖ epoch_be16)`,
`MAC = BLAKE2b(key=pseudo_secret, digest_size=6, "GM-MAC" ‖ epoch_be16)` with the
locally-administered/unicast bits fixed; reserved values rehashed; big-endian everywhere.

**What the construction must provide:** a keyed pseudorandom function. Without the secret,
outputs for different epochs look independent (N1). With it, the watchtower and recipients
can compute any node's pseudonym for any epoch (#1).

| Choice | Alternatives | Why this one |
|---|---|---|
| **Keyed BLAKE2b** | HMAC-SHA256 (mbedTLS, SHA hardware); AES-based PRF; SipHash | BLAKE2b is in Monocypher, the same single-file library planned for encryption, so it's one dependency (N6). Python's `hashlib.blake2b` matches it exactly for keygen, sim and tests. HMAC-SHA256 is equally sound but adds a second library. SipHash only gives 64-bit output and is not in Monocypher |
| **Length set by `digest_size`** | Truncate a 64-byte hash | BLAKE2b mixes the output length into its state, so the two give *different bytes*. One fixed rule prevents a firmware/Python mismatch |
| **Domain labels** (`"GM-PSEUDO"`, `"GM-MAC"`) | Separate secrets per use | One secret per node is simpler to provision. Labels make the outputs independent anyway |
| **MAC derived** from the same secret | Random MAC per epoch from the hardware RNG | Derived lets the watchtower check MAC ↔ pseudonym consistency, an extra spoof signal (N4). A random MAC gives nothing to check. (A careful spoofer copies both from the air, so this only catches lazy ones) |
| **Reserve `0x00000000` and `0xFFFFFFFF`** | Reserve only 0; ignore | `next_hop = 0` means flood, so a node with pseudonym 0 would break routing. Odds are 1 in 2 billion, but the rule is one line. `0xFFFFFFFF` is kept for a future broadcast meaning |
| **Big-endian** | Little-endian (ESP32 native) | The convention for wire protocols. Hex dumps and the Wireshark dissector read naturally. The byte swap on the S3 costs nothing |
| 4-byte pseudonym | Longer | Fixed by the frame format. Collision chance across 6 nodes is about 1 in 10⁹ per epoch |

---

## 4. `link_tag`

**Decision:** `BLAKE2b(key=network_key, digest_size=8, "GM-LINK" ‖ frame[0:22] ‖ frame[30:240])`,
recomputed by every relay, checked first in constant time.

**What it must provide:** cheap per-hop proof that the frame came from a network member
(N2). Because relays rewrite `src_pseudo` (decision log, Nov 14), the tag can't be end-to-end. Every
relay must be able to recompute it, so it's a shared-key MAC by necessity.

| Choice | Alternatives | Why this one |
|---|---|---|
| **Keyed BLAKE2b** | HMAC-SHA256; Poly1305; per-node signatures | Same primitive and library as #3 (N6). Poly1305 is a *one-time* authenticator, so reusing its key across frames is insecure without extra nonce handling. Signatures (Ed25519) are too slow per hop and 64 bytes don't fit in 8 |
| **Whole-frame coverage** | Cleartext header only | With header-only coverage, an outsider can keep a captured valid header and swap in junk ciphertext. Every relay would accept and flood it, and only the final recipient's AEAD would reject it, so the mesh does the outsider's flooding for them. Covering everything costs one 232-byte hash per hop (microseconds) |
| **Network key + label** | Per-epoch subkey | `epoch` is already covered and checked against the ±1 window, so a per-epoch key adds no replay protection, just one more derivation. The label separates it from #3 |
| **Skip the tag bytes** (two-range hash) | Zero them and hash 240 | Equally secure. Skipping avoids a 240-byte copy on every verify and recompute (N5) |
| **8 bytes** | 16 bytes | 2⁻⁶⁴ forgery odds per attempt is far beyond what an attacker can try over the air. Growing it would change the frozen frame and the body length (N6) |
| **Constant-time compare** | `memcmp` | `memcmp` stops at the first wrong byte, which could let an attacker guess the tag byte by byte from timing |

**Known limit:** a frame resent unchanged carries a valid tag. That's the replay problem,
handled by the seen-cache, the ±1 epoch window and recipient sequence numbers (task 7).
`link_tag` also does nothing against insiders, who hold the key. That is the IPS's job (§5.6).

---

## 5. Inner header layout

**Decision:** 170 plaintext bytes = `sender_id`(4) `recipient_id`(4) `timestamp_ms`(4)
`seq`(4) `type`(1) `len`(1) `body`(152), big-endian; DATA and ACK look identical in cleartext.

**Constraint:** the ciphertext field is fixed at 170 bytes (§4.1), and XChaCha20 ciphertext is
the same length as the plaintext, so header plus body must total exactly 170 (N5). The draft
listed 18 bytes of inner header *and* a 153-byte body, which adds up to 171. Something had to give.

| Choice | Alternatives | Why this one |
|---|---|---|
| **Body 152 bytes** | Keep 153 by shrinking a field | 152 vs. 153 characters makes no difference to a text chat. Shrinking IDs or seq to save one byte would change `routing.h`, the sim and the codec (N6) |
| **Hide ACKs** (cleartext type is always DATA) | Cleartext ACK type | A visible ACK tells a sniffer "a message was just received and answered," which is exactly the who-talks-to-whom signal N1 hides. Relays flood both kinds identically, so they never needed to know. Cost: the IPS loses a cleartext ACK count (minor), and timing can still hint at ACKs. Cover traffic would fix that (future work) |
| **4-byte node IDs** | 1-byte IDs (+6 body bytes) | IDs are encrypted, so size doesn't affect privacy. Keeping `uint32` matches `rt_inner_t` and leaves room to grow (N6). 6 bytes of text wasn't worth changing three teammates' code |
| **4-byte ms timestamp** | Seconds; drop it | Protected by the AEAD, so even an insider who can rewrite the cleartext `epoch` (they hold the network key) can't change it. That gives task 7 a trustworthy send time. Milliseconds also give one-way latency for Rashad's metric (§13); seconds are too coarse for hops of a few ms. Dropping it would free 4 body bytes but lose both |
| **4-byte seq** | 2 bytes | Never wraps in practice, so there's no wraparound comparison code to get wrong. Matches `rt_inner_t.seq` |
| **Zero padding** | Random padding | The whole field is encrypted, so the padding looks random on the air either way. Zeros are deterministic and easy to test |
| **Recipient checks `recipient_id`/`sender_id`** | Trust a successful decrypt | With pairwise keys, a frame that decrypts could also be our *own* frame reflected back by someone. Checking both IDs makes such reflections fail cleanly |

**Open (task 7):** `seq` lives in RAM, so a rebooted sender starts again at 0 and the recipient
(which remembers the highest seq) would drop its new messages as repeats. The replay-window design has to handle this.

---

## 6. End-to-end encryption details

### 6a. Key setup: epoch DH ratchet (revised; replaces per-message ephemeral keys)

**Decision:** each pair's chain key advances once per 60 s epoch. A fresh X25519 exchange
between the two nodes' new epoch keys is mixed in (chained) when both sides have confirmed each other's
key; otherwise the step is a plain hash. Message keys come from the chain key. New epoch public keys
travel in a flooded, tag-authenticated **KEYS** frame. State is saved to flash each epoch, and static keys stay on
the board for restarts (RESYNC).

**What it must provide:** against a funded adversary that records everything and may later
seize a node, Jose wants both **forward secrecy** (a key stolen today doesn't open yesterday) and
**post-compromise security** (a key stolen today stops working soon after the thief stops actively interfering).
It also has to keep confidentiality and sender authentication end to end, with no recipient hint (N1), fit
240 bytes (N5), and stay cheap enough that floods can't exhaust the CPU (N4, N7).

**Key insight:** forward secrecy needs only *deletion* (hashing forward), which is nearly free.
Post-compromise security needs *fresh randomness the thief never saw*, injected through
Diffie-Hellman. Doing that DH **once per epoch instead of once per message** is what makes it cheap:
about 9 X25519 per node per minute, and messages use symmetric crypto only.

| Option | Forward secrecy | Post-compromise | Why not chosen / why chosen |
|---|---|---|---|
| Static X25519 pairwise key | No | No | A seized key opens everything, past and future |
| Per-message ephemeral + static auth (the first 6a) | Only if the *sender's* key is stolen | No | One X25519 on every node for every frame heard, so insider floods burn CPU mesh-wide. Needed a 32-byte field, which cut the body to 144. Still no healing |
| Epoch hash ratchet only | Yes | **No** | Whoever steals today's chain key computes every future one |
| Signal Double Ratchet per pair | Per message | Per message | X25519 per message, lots of per-pair state, and it needs back-and-forth traffic. A lossy, one-way-heavy mesh doesn't fit |
| Hash chain + per-epoch DH (not carried forward) | Yes | Per epoch | Never forks, but heals only epochs whose DH succeeded; a stolen chain key keeps reading every hash-only epoch |
| **Chained DH + confirmation (chosen)** | Yes (~2 epochs) | Yes, permanently from the first successful DH | Once a DH lands, the thief's chain is dead for good. Cost: the two sides can split, handled below |

**The two-generals problem and how it's handled:** two nodes can't be *certain* they agree whether to
mix a given epoch's DH, because the last confirmation might be lost. Three layers make a split rare and
recoverable:
1. **Confirmation**: a node mixes the DH only if the peer has confirmed holding its key, so whenever
   either side mixes, *both* are able to compute the DH version.
2. **Convergence**: each node keeps the other version as an alternate, and "the DH version wins" as
   soon as any KEYS tag or message verifies under it. KEYS frames go out about every 10 s, so the two agree within the epoch.
3. **RESYNC**: if a whole epoch of KEYS frames is lost and the chains really do split, either side
   floods a RESYNC authenticated with the static-derived root, and both restart from the same formula.
   Accepted cost: no healing until the next DH epoch.

**Why a flooded KEYS frame:** HELLO only reaches one hop, but A and C talk through B. A disguised-as-DATA
version would cost every node extra checks on every failed decryption, and its once-per-epoch rhythm would
likely still give it away. Carrying keys inside messages never heals pairs that don't talk. The KEYS frame
reveals only that each node announces once per epoch, which HELLO already shows. Random slot
order and random filler hide the number of peers.

**Why save state to flash:** keeping it only in RAM would force every reboot through a coordinated
restart from static keys. That means more protocol, and a holder of a static key could read the first epoch after each
reboot. Writing ~300 bytes per minute is trivial for NVS wear-levelling. Caveat recorded: erasing flash
is less certain than wiping RAM, so a seized board might still hold the previous epoch's state.

**Why keep the static keys:** they're the only way back after a split (RESYNC) and the only way to add a
node without reflashing everyone. Because chain keys are deleted, a static key stolen later still
reveals **no past traffic**. The remaining risk is active: static key + active interception, which
the panic key-wipe stretch goal and the IPS address.

**What it still doesn't do (stated honestly):**
- An attacker with a stolen chain key who *actively* forges KEYS frames can stay in the middle
  indefinitely. Every ratchet without out-of-band verification has this limit.
- A seized, unlocked node reads whatever its current keys open.
- X25519 isn't quantum-resistant. A post-quantum key exchange (ML-KEM, ~768-byte ciphertexts)
  can't fit a 240-byte frame, so "record now, decrypt later" remains a documented limit.

### 6b. Associated data: `ver_type ‖ flags ‖ msg_id ‖ epoch`

AEAD associated data is authenticated but not encrypted. It can only include fields relays never
touch. `ttl`, `hop_count`, `src_pseudo`, `next_hop` and `link_tag` all change per hop.

| Option | Why not chosen |
|---|---|
| No AD | An insider (who holds the network key and can recompute `link_tag`) could take an old ciphertext, give it a fresh `msg_id` to dodge every seen-cache and a current `epoch` to dodge the window, and it would decrypt fine |
| `msg_id` + `epoch` only | Leaves `ver_type`/`flags` editable, so an insider could flip SOS on someone else's message |
| **All four immutable fields (chosen)** | Any insider re-wrap fails at the recipient. Costs nothing: 12 bytes hashed, nothing transmitted |

### 6c. Trial decryption: try every peer

The recipient isn't named in cleartext (N1), so a node can't know which key to use. Each frame
uses each peer's precomputed epoch message key, usually 8–16 cheap AEAD tag checks and no X25519. A cleartext
key hint would make this one check, but the hint is constant per pair, so sniffers could group a
conversation. That trades away exactly what N1 protects.

### 6d. `flags`: cleartext SOS, needs-ACK removed (closes O6)

The §4.1 draft's **needs-ACK** flag would mark every DATA frame differently from ACKs in
cleartext, which undoes the ACK hiding from #5. It's also redundant, since the inner type already says
it. So it was removed. **SOS stays in cleartext** so relays can give it priority (the point
of an SOS flag in a survival mesh), and it's bound in the AD so insiders can't toggle it. Moving it
inside would hide it but make it cosmetic. Accepted leak: sniffers can see which frames are urgent.

---

## 7. Replay window

**Decision:** five layers. Relays: `link_tag`, the 60 s seen-cache and a separate 180 s msg_id-only cache.
Then the ±1 epoch window bound in the AD, then key deletion by the ratchet. At the recipient: a 5 s
freshness check on the AEAD-protected timestamp, then 15 s seq dedup by set membership. Seqs start at
a random value each boot. ACKs go out after a random 0–400 ms delay.

**What it must provide:** G5 says re-sent captured packets are dropped 100% of the time (N3).
Three gaps found in the checkpoint review had to close: O4 (a replay triggers a re-ACK and gets flooded
again), O5 (seq resets on reboot) and O2 (DATA→ACK timing). It also must not break legitimate retries (G1,
N7). And it can't rely on flash or per-message state beyond fixed tables (N5).

**Why layers instead of one check:** each place in the network can check different things.
Relays can't decrypt, so they can only use cleartext facts (tag, msg_id, epoch). Only the recipient
can see the protected timestamp and seq. Old replays are stopped by the cheapest layer that can see them, so
expensive checks rarely run.

| Choice | Alternatives | Why this one |
|---|---|---|
| **5 s freshness on every attempt** | 15 s; seq only | The timestamp is inside the AEAD, so even an insider can't re-date it. That makes it the one reliable way to tell "lost ACK" (fresh repeat → re-ACK) from "replay" (stale → silence). 5 s covers a multi-hop flood plus clock skew. 15 s would leak a re-ACK for replays up to 15 s old. Seq-only leaves O4 and O5 open |
| **New timestamp per retry** | Keep the original timestamp | With the original, the 7 s retry would fail a 5 s freshness check. Retries already rebuild the inner header (§5.2), so this costs nothing |
| **15 s seq memory, set membership** | 5 s memory; "highest seq" | Memory has to outlast the *whole* retry schedule (0/1/3/7 s) plus freshness, or the last retry would be delivered twice. "Highest seq" drops messages that arrive out of order (common with flooding and retries) and breaks on reboot. A ~16-entry set per peer is fixed-size and order-free |
| **Random seq start per boot** (O5) | Save to flash with a reserve jump; seq = clock ms | Freshness means the recipient only needs 15 s of memory, and a reboot plus time sync takes longer. A random 32-bit start then makes collisions practically impossible, with no flash writes or reserve logic. A clock-based seq would duplicate the timestamp |
| **180 s msg_id-only relay cache** (O4) | Stretch the main cache; accept amplification | Rashad's main cache stores a 240-byte pending frame per entry, so covering 180 s that way costs ~66 KB. A list of 8-byte IDs costs ~6 KB. It closes the window where a replayed frame gets flooded across the whole mesh |
| **Random 0–400 ms ACK delay** (O2) | Cover traffic now; accept | Blurs the DATA→ACK pairing whenever other traffic is present, for almost no cost, and stays under the 1 s first retry. Cover traffic would hide it properly but costs airtime, IPS retraining and firmware time this week. It's listed as future work, and the residual leak goes in the threat model |

**What still gets through (stated honestly):** on a quiet mesh, a nearby sniffer can still pair a
sender and recipient by timing (O2 residual). And a replay can force one extra relay hop before the
first relay's cache drops it, which is visible to the IPS as a duplicate `msg_id` from a new transmitter.

---

## 8. Signed control messages: BLOCK and TIME

**Decision:** one flooded, signed `CTRL` frame type with TIME and BLOCK subtypes, signed with standard
Ed25519 by the watchtower. BLOCKs name the target's per-epoch pseudonym + MAC and are re-issued each
epoch. Replay protection uses one Unix-ms mesh clock (no counter). Nodes rate-limit signature
checks.

**What it must provide:** the IPS's prevention step (G6, N4): an attacker is ejected within seconds
of detection, and nobody but the watchtower can issue or replay a block. The mesh clock from 2b must
also be impossible for insiders to forge (2b's reason for a signed beacon). The slow
signature check must not become a DoS lever (N7), and node-side privacy from #1 must hold (N1).

| Choice | Alternatives | Why this one |
|---|---|---|
| **Standard Ed25519** | Monocypher's EdDSA-BLAKE2b | §4.5 names Ed25519, and the laptop-side tools (keygen, IPS tests) can sign and verify with stock Python libraries (N6). The extra SHA-512 code is small. BLAKE2b-EdDSA would need custom Python bindings for a few KB saved |
| **Signatures over a domain-separated body only** | Sign the whole frame | Relays rewrite `ttl`, `hop_count`, `src_pseudo` and `link_tag`, so a whole-frame signature would break at the first hop. The `"GM-CTRL"` label keeps these signatures from being valid in any other context |
| **Per-epoch IDs from the watchtower, re-issued** | Reveal the blocked node's `pseudo_secret`; give every node every secret | Nodes only need *this epoch's* identifiers to drop frames. Revealing a secret lets every node track that node forever, which is bad if the block was a false positive. Giving every node every secret makes any captured node an identity oracle for the whole mesh, which undoes #1. Re-issuing costs one flood per minute per active block |
| **Match pseudo AND (MAC or wildcard)** | Match pseudo only | Spoofing copies the victim's pseudonym, so a pseudo-only block cuts off the victim. That's why `ips/live.py` currently refuses to block spoofs. If the spoofer's radio MAC differs, the (pseudo, MAC) pair singles it out (uses the MAC derivation from #3) |
| **Drop at receive, before relaying** | Drop only at the recipient | `src_pseudo` is the transmitter (Nov 14 decision), so neighbours drop a blocked node's frames at the first hop and nothing it sends spreads |
| **Time-based anti-replay, one Unix-ms clock** | Monotonic counter in flash on both sides (§4.5's wording) | The watchtower is already the time authority (2b), so "newer than the last beacon" is a counter that needs no extra state on the watchtower. A BLOCK carries its own expiry, so old BLOCKs are useless to replay. Unix time also gives every log, beacon and IPS window the **same clock**, which Hannan asked for. Nodes save `last_beacon_ms` to flash (alongside the ratchet state that's already saved), so a reboot can't be used to roll a node's clock back |
| **One CTRL type with subtypes** | Separate TIME and BLOCK types | One verify path, one replay rule and one rate limit; the `ver_type` list grows by one (KEYS) instead of two. Wireshark readability is handled by the dissector decoding the subtype |
| **Skip-if-not-newer, then ≤ 2 verifies/s** | Verify everything | A signature check is far slower than a hash. Without a cap, an insider could flood forged CTRL frames (which pass `link_tag`) and stall every node's CPU. Skipping stale ones first means legitimate repeats cost nothing, and the cap bounds the worst case. Real TIME and BLOCK messages repeat, so a dropped one is replaced within 10 s / one epoch |

**Relay only verified CTRL (closes O8).** The alternative, relaying frames over the verify
budget without checking them, keeps every legitimate CTRL moving under load. But it lets an insider's forged
CTRL flood be re-broadcast by every relay, multiplying the attack across the mesh, and every node
would waste its verify budget on the same junk. Dropping unverified frames confines a forged flood
to the attacker's own neighbours. The cost is small: a legitimate TIME or BLOCK dropped under attack
is repeated within 10 s (TIME) or one epoch (BLOCK), and nodes free-run on their clock in between (2b).

---

## 10. Hardening against basic attacks (closes O1, O10–O12, O18–O20)

**Context:** a review aimed at "basic" attacks (MITM, dumb and reactive jammers, floods) found
gaps that one attacker board could exploit in the demo. Each fix below was chosen because it is
**cheap** (a counter, a comparison, a serial line) and closes an attack that needs no special hardware.
The heavier gaps (O13–O17: key fingerprints, revocation, flash encryption, serial auth, channel
jamming) are left for task 12 or later, mostly as documented limitations.

| Decision | Alternatives | Why this one |
|---|---|---|
| **10a Hop padding** (O1): originator starts at hop 0–2, ttl lowered to match | Accept the leak | "hop == 0" made identifying the originator a matter of reading one byte. Padding forces a sniffer into timing analysis, which is harder and noisier. Keeping `hop + ttl` constant makes the padding itself invisible. Cost: ±2 noise in route-learning and IPS hop features, up to 2 hops of range (raise default TTL). The "hop decreases for the same msg_id" anomaly signal still works, because padding happens only at the source |
| **10b Per-transmitter verify budget** (O10) | Single global budget | A global budget is a shared resource, so one flooder can exhaust it for everyone, including the BLOCK aimed at it. Per-transmitter budgets make each flooder pay only from its own share. Honest limit: identity-cycling insiders fall back to the global cap |
| **10c Monotonic clock + slew** (O11) | "clock = beacon time" | A clock that a delayed message can drag backward lets an attacker give one node its own rotation timing, which makes it linkable (the 2b privacy reason for synchronized rotation) and cuts it off. Taking the max of local and beacon time makes delayed beacons harmless. Slewing avoids sudden jumps at boundaries. Accepted: crystal drift is never corrected backward (milliseconds per hour) |
| **10d RESYNC freshness, rate limit, reporting** (O12) | Accept | Replayed RESYNCs could repeatedly wipe post-compromise healing. A nonce plus "one per pair per 5 epochs" stops that. A static-key thief can still force a resync (nothing light stops it), but serial events and watchtower counts make it loud |
| **10e Missing-DH alert** (O18) | Disguise KEYS as DATA; accept | Disguising was already rejected in 6a for CPU and rhythm reasons. Alerts turn a silent healing failure into a visible event the operator and IPS can act on. Jamming is detected, not prevented |
| **10f Missing-beacon alert** (O19) | Accept | With 10c, losing beacons is safe (nodes free-run). The remaining risk is a locally jammed BLOCK, and the alert at least tells the operator that this area isn't receiving control traffic |
| **10g Per-transmitter cache-insertion limit** (O20) | Accept | Without it, a flood of unique IDs evicts the 180 s cache and re-opens the replay path closed in task 7. Charging insertions to the transmitter keeps one flooder from pushing out others' entries. The value (~20/s) must be checked against an honest busy relay's rate from Rashad's sim |

---

## 12. Threat model scope and accepted limitations

**12b Scope.** In scope: A1 outsider passive, A2 outsider active, A3 compromised insider, A4 funded
adversary (record now, seize boards later).

| Option | Why |
|---|---|
| **Include A4 (funded adversary)** | The hackathon premise is surveillance by a capable state, and 6a's ratchet was built precisely for record-now-seize-later. Leaving A4 out would hide the strongest part of the design and the honest limits that come with it (flash, active key forgery) |
| **Include A3 (insider)** | Our own demo attacker X is an insider; the IPS exists because cryptography can't stop someone holding the network key |
| **Exclude a compromised watchtower/IPS** | It holds every pseudonym secret and the signing key by design (#1, 8a). Claiming resistance to its compromise would be false; instead it is a trusted, guarded component |
| **Exclude quantum and multi-sniffer RF tracking** | No defense fits a 240-byte frame or ESP-NOW's radio; claiming otherwise would be overreach |

**12a Accepted limitations (O3, O7, O14–O17).** Each option that would have fixed these was costly
or risky this week: TX power jitter (O3) fights topology control and the IPS's RSSI features; disguising
traffic (O7) isn't possible with ESP-NOW's fixed format; signed re-key (O14) is several days of new frames;
flash encryption (O15) permanently changes eFuses on the only boards we have; serial authentication (O16)
buys little against someone who can reflash the device anyway; channel hopping (O17) risks nodes ending up on
different channels and adds downtime at each boundary. **Documenting them is a deliberate choice:** a threat
model that names its limits is more credible to judges than one that hides them, and each one has a
named future-work path.

**12c IPS block policy for spoof-like evidence (O9).** Hannan's `ips/live.py` policy, adopted as-is.

| Option | Why not / why |
|---|---|
| Auto-block the whole node | A spoofer copying A's identity would get the real A blocked in every epoch: our own defense ejects an honest node (N4, N7) |
| Alert only, never block on spoof | Safest for honest nodes, but the IPS could then never stop a spoofer, which weakens G6 for one of the four demo attacks |
| **Operator confirms, block only the (pseudo, MAC) pair** (chosen) | Keeps prevention (N4) while a human, not a threshold, decides when evidence is ambiguous. The pair block also spares the victim whenever the spoofer's MAC differs (8b match rule). It was already built and tested on synthetic sessions, so it costs nothing this week (N6). Residual: a full pseudo+MAC copy is the same pair, so RSSI and the operator are the only separation |

**12d Unkeyed KEYS `conf` hashes (O23): accept and document.** `conf` is an unkeyed hash of a public value
(each node's cleartext `next_pk`), so, like a CRC, anyone can recompute it. Here that lets a sniffer match hashes
and learn who holds pair keys with whom; it can't forge anything, because `conf` is inside the keyed `tag`.

| Option | Why not / why |
|---|---|
| Key `conf` with the pair key now | Cheap (one hash call, no frame change), but it changes `gm_ratchet.c` and its tests days before the feature freeze for no gain in our deployment (N6, N7) |
| **Accept and document** (chosen) | keygen makes every node a peer of every other, so the key graph is complete and reveals nothing about who talks to whom. What's left is per-node peer counts (≈ the node count already visible, O22) and a little reachability, which flooding makes nearly meaningless. The leak only matters if provisioning becomes partial (groups), so keyed `conf` is recorded as future work with that trigger |

**12e Accepted limitations O21 and O22.**

| Item | Alternatives | Why accept |
|---|---|---|
| **O21** Relay D is also the watchtower (4 boards) | Passive watchtower that doesn't relay; a watchtower that holds fewer secrets | A passive D removes the reroute path the unplug-B demo depends on (G2, N7). A watchtower without `pseudo_secret`s can't map frames to nodes or sign per-epoch BLOCKs, which is the whole IPS design (#1, 8b; N4). With only 4 boards the honest answer is that D inherits the watchtower's trust level; 6 boards remove the overlap |
| **O22** Active node count visible | Dummy HELLO/KEYS from a fixed number of slots | Padding both HELLO and KEYS costs constant airtime on a shared channel and new code in two layers, to hide a number that ESP-NOW traffic already roughly reveals (O7). Cost outweighs benefit this week (N6); cover traffic stays future work |

**12f Add A5, the censor.** The hackathon premise is a state that treats unapproved ad hoc networks as organizing
or press. Such an adversary doesn't need to read messages: making the mesh unreliable, finding the watchtower and
the people running it is enough. A1–A4 are framed around confidentiality and key theft, so they hid the
availability side of the design (flooding, retries, rate limits, the watchtower as a single point of failure).
Naming A5 forces the threat model to cover outage types, recovery and failure metrics, and is honest that against
A5 we offer resilience and detection, not prevention (jamming and direction-finding stay out of scope).

---

## 16. Availability hardening (closes O25–O29)

**Context:** adding the censor (A5, 12f) shifted the review from "who can read" to "who can stop the mesh".
Most of what it found sits on the watchtower and on paths an insider can reach. Each choice below favours
what is cheap now, before the code it touches is written, over what would need new hardware or new frames.

| Decision | Alternatives | Why this one |
|---|---|---|
| **16b Accept: watchtower required to rejoin** (O25) | Provisional peer time; backup signer | Peer time lets an insider with two fake identities set a node's clock, and needs new clock rules and tests in the key layer days before the freeze. A backup signer needs a spare board (we have 4) and copies the most sensitive key. The demo never runs without W, so the cost isn't justified this week; the limit is named, with both fixes as future work |
| **16c Accept: watchtower is the single point of failure** (O26) | BLOCK carrying 7 epochs of identifiers; backup watchtower | Killing the watchtower is a censor's obvious first move, and blocks then lapse within ~2 min. Extending BLOCK to 7 epochs would fit the CTRL region exactly, but it changes a wire layout the team is building against, for a scenario the demo never shows (the watchtower stays up). Keeping the frame format stable this week matters more (N6, N7); the 7-epoch BLOCK is recorded as the future-work fix |
| **16d Charge failures only, space CTRL** (O27) | Accept the budget as is; token bucket with bursts; also caching CTRL only after it verifies | Budgets exist to make forgers pay (10b). Counting every frame also made the watchtower's own TIME + BLOCK pairs pay, so a node two hops from W could drop a fresh BLOCK and wait up to a minute for the re-issue, which breaks the G6 demo (N4, N7). Valid CTRL can't be forged and replays are skipped before any verify, so only failures need charging. It was already built and tested in `gm_node.c` (0/6 → 6/6 on the laptop regression test), so the recorded data includes it and no wire format changes. A burst allowance would still drop legitimate frames beyond the burst. Caching after verify was not adopted: it would change `routing.c`'s receive order, and with the two rules above real CTRL is lost only if the mesh-wide cap is hit |
| **16e Accept, with a flood-rate limit for the demo** (O28) | Native USB + shed `raw` under load; drop `raw` from live logs | We control the attacker's flood rate (task 11), so keeping demo floods under ~100 frames/s avoids the ~120 frames/s log ceiling without asking Yunus or Hannan to change the watchtower output or schema this week (N6). A real flooder above that rate makes the IPS lag; native USB and shedding `raw` are the future-work fix |
| **16f Clean training data only** (O29) | Also absolute ceilings and slow baseline adaptation; accept | Recording normal traffic with X powered off is a procedure, not code, and removes the most damaging case: a model that learned the attacker as normal. Ceilings and slow adaptation are real IPS work in Hannan's area; low-and-slow evasion is an inherent limit of anomaly detection and is documented as such |

---

## 13. Crypto library: Monocypher 4.0.2

**Decision:** vendor Monocypher 4.0.2, unmodified, in `firmware/lib/monocypher/`.

| Option | Why not chosen / why chosen |
|---|---|
| **Monocypher (chosen)** | Two small portable C99 files plus an optional Ed25519 file, no dependencies, permissive dual licence. It has every primitive decisions 3–8 specify, so no redesign. It builds identically on the laptop (tests, sim) and on the ESP32-S3, and its outputs match the Python libraries our laptop tools use (verified). Cost: no hardware acceleration, so the Tuesday benchmark must confirm speed |
| libsodium | Same primitives and direct PyNaCl compatibility, but far larger and awkward to vendor for an Arduino build; nothing it adds is needed |
| mbedTLS (built into ESP-IDF) | Hardware SHA/AES on the S3, but no BLAKE2b and no XChaCha20, so tasks 3, 4 and 6 would have to be redesigned around HMAC-SHA256 and 12-byte nonces (nonce collisions become a real concern with random nonces) |

**Why vendor instead of a package manager:** the toolchain isn't chosen yet (N6). Files in
`firmware/lib/` work with PlatformIO, ESP-IDF (as a component), Arduino and plain gcc. Pinning exact files,
with recorded hashes, also means everyone builds the same verified code (supply-chain hygiene for a security project).

**Why verify twice:** the published SHA-512 sits on the same site as the tarball, so it only guards against
corruption. Comparing the source against the GitHub tag is an independent second source. The interop test
then checks the property we actually depend on: firmware and laptop tools compute identical bytes.

---

## 14. Crypto glue (stage 14a)

| Choice | Alternatives | Why this one |
|---|---|---|
| **Staged: core now, ratchet in 14b** | Everything at once | Rashad's routing already calls `encrypt`, `try_decrypt`, `compute_link_tag` and `my_pseudonym`. Shipping those first unblocks integration and Tuesday's "encrypted frame round-trips" milestone. The ratchet slots in behind one function (`gm_peer_message_key`), so callers won't change. Cost: until 14b, keys come from the static root key, so there's no forward secrecy yet |
| **Routing fills the AD fields before `encrypt()`** | Change the callback to pass them as arguments | A one-line reorder in Rashad's TODO keeps `routing.h`'s interface stable for everyone. Decision 6b requires those fields to be final when encrypting either way |
| **Freshness in routing (`handle_data`)** | Inside `try_decrypt` | "What to do with a message" (freshness, seq dedup, re-ACK) stays in one place with its logging. `try_decrypt` answers exactly one question: is this authentic and for me? |
| **Portable C + Python runner in `firmware/test/`** | Code and tests under `security/` | Same no-ESP-headers rule as `routing.c`, so it also runs in host tests and the sim. The runner needs only gcc and Python (no make/cmake), so any teammate can run it |
| **Cross-check against an independent Python implementation** | C unit tests only | C tests show the code agrees with *itself*. Re-deriving every byte in Python with different libraries (libsodium, `cryptography`) shows it agrees with the *spec*. The laptop tools (keygen, pcap converter, IPS) must compute identical bytes, so those Python functions become their reference |
| **Mutation check** | Trust a green run | The first run passed 54/54, but deliberately broken copies showed the recipient check, the sender check and the MAC bit-fix weren't really tested (each was hidden by another check or a lucky vector). Three targeted tests were added. A test suite that can't fail proves nothing |

---

## 14b. Ratchet implementation choices

| Choice | Alternatives | Why this one |
|---|---|---|
| **One `gm_tick()` driver** | Firmware calls separate functions on its own timers | Every timing rule (slew, 10 s KEYS cadence, 30 s beacon alert, epoch steps, RESYNC triggers) stays in portable, tested code. Firmware only forwards events, so there are fewer places for the two halves to disagree |
| **Hash-step up to 10 missed epochs, then RESYNC** | RESYNC after any gap; unlimited catch-up | A reboot or short power loss needs no extra messages (both sides hash-step identically). A long absence restarts cleanly instead of catching up through hundreds of hashes. The bound also limits CPU work at boot |
| **RESYNC only when unverifiable KEYS are heard** | Spec as first written (2 silent epochs) | Silence alone can't tell "split chain" from "board switched off". Hearing KEYS frames that none of our keys verify is the actual sign of a split, so powered-off peers don't trigger RESYNC floods (which the IPS would also have to filter) |
| **Export/import blob** | gm calls a save hook | gm never touches flash, so it stays portable and testable on the laptop, and firmware decides when to write (wear) |

**Refinements found by the tests** (each one is a case the written spec hadn't covered):
- **Accept RESYNC on an already-silent pair, even inside the rate limit.** Tracing boards that boot at different
  times showed a deadlock: each side's boot RESYNC rate-limits the other's. A pair that is already silent is broken
  anyway, so accepting is safe. Replays against a *healthy* pair, which 10d was aimed at, are still refused.
- **Carry the alternate through hash-only steps.** "The DH version wins" only works while the alternate exists.
  Dropping it at the next silent boundary turned a recoverable split into a permanent one (the RESYNC path
  would still recover it, but only after ~2 epochs).
- **Ignore your own KEYS echo.** Pair chain keys are symmetric, so a node can't tell its own KEYS frame from its
  peer's by the tag alone. A reflected frame would plant the node's own key as the peer's. Routing's seen-cache
  normally drops echoes; the key layer now refuses them too, so security doesn't depend on routing.

**Why simulate a thief:** "post-compromise security" is easy to claim and hard to show. The test copies a node's
*entire* state mid-epoch, gives the thief every KEYS frame the real node hears, and shows exactly what the design
promises: the thief reads the stolen epoch and the next one (it holds the next DH key), then is locked out, while
the real node keeps reading. That is the claim in the threat model (A4), demonstrated rather than asserted.

---

## 15. Key provisioning (closes O13)

| Choice | Alternatives | Why this one |
|---|---|---|
| **Per-board C header + public roster** | Per-board blob flashed into NVS | Headers work with whichever toolchain Yunus picks (Arduino, ESP-IDF, PlatformIO) and need no flashing tool. The roster separates what can be shared (public keys, fingerprints) from what can't, so it can live in the repo for everyone to check against. Cost: one build per board, which a build flag handles |
| **X as a full insider** | Network key only; no keys | Threat model A3 is a *captured board*, which has everything a node has. A half-keyed X would set off "unverifiable KEYS" alarms the real attack wouldn't, and spoofing and routing abuse can't be demonstrated without the network key. The watchtower can also label X's frames, which the IPS needs for ground truth |
| **8-hex fingerprints, printed from the key in use** | Word list | They fit a small OLED and serial line, with nothing extra in firmware. **Printing the fingerprint of the key the board actually loaded**, not a string from the header, is what catches tampering: a swapped key in a header would still carry the old fingerprint comment. 32 bits is plenty against tampering at provisioning, where the attacker can't search for collisions |
| **OS randomness only** | A seeded test mode | A guessable key set that could be flashed by mistake is a real risk in a hackathon rush. Tests already use their own fixed patterns and never need keygen to be deterministic |
| **Refuse to overwrite without `--force`** | Overwrite silently | Re-running keygen on one laptop would quietly re-key the network and break every board already flashed |
| **Watchtower header has no X25519 keys** | One "all keys" file | Enforces decision 1 at provisioning time: the watchtower can identify nodes but can't read messages, and the tests check this |

---

## 17. Packet capture: pcap exporter + Wireshark dissector

**Context:** the video's "surveillance-proof" segment and the Meshtastic before/after slide need a
sniffer's view of our traffic in a tool judges recognise. The watchtower already logs every frame's 240
bytes (`raw`), so the capture is built from its logs rather than a second radio.

| Choice | Alternatives | Why this one |
|---|---|---|
| **Capture header + frame** | Frame only; pcapng comments | Wireshark can then show and filter on RSSI and the watchtower's node lookup (`ghostmesh.cap.node == "X"`), which is what makes an attack visible on screen. The header is labelled as watchtower metadata, so the 240-byte frame below it stays an honest "what a sniffer sees". Comments can't be filtered or sorted |
| **Mesh clock `t` as timestamp** | Radio `rx_us` | One clock across Wireshark, the IPS, the labels files and the video timeline (8c). `rx_us` starts at the watchtower's boot and wraps, so it's kept in the header for fine timing only |
| **Offline + `--follow`** | Offline only | Live packets on camera without a second serial reader: the IPS keeps W's port, and the exporter tails a log file. Offline conversion covers every recorded dataset |
| **Header + CTRL/KEYS bodies** | Header only | CTRL and KEYS are cleartext by design (8d, 6a), so decoding them shows exactly what an outsider learns (block targets, rekey cadence) and nothing more. DATA stays opaque because no keys are given to Wireshark, which is the point of the demo (N1) |

---

## 18. Attacker X: thin passthrough firmware + Python attacks

**Context:** Hannan needs labelled recordings of the four attacks (and some known-issue variants) to train
and evaluate the IPS, and the video needs a live attack. X didn't exist yet.

| Choice | Alternatives | Why this one |
|---|---|---|
| **Passthrough firmware, attacks in Python** | Attack modes in C on X; hybrid with an on-board paced burst | Every attack is a different way of building or resending a 240-byte frame, which is quick to write and change in Python, without reflashing. The script that sends the frames also writes the labels, so ground truth is exact. Floods only need ≤ ~100 frames/s (16e), which native USB handles, so on-board pacing isn't needed yet (N6) |
| **X holds no keys in firmware** | Compile `keys_X.h` into X | The board is only a radio; the insider's secrets stay on the laptop that runs the attack. It also keeps the transmit command, which can send anything, away from any board that holds keys |
| **Transmit command only in the X build** | One firmware with a hidden attack mode | A raw-transmit command on a demo node would itself be an attack surface (O16 already says serial access is compromise; this keeps it from getting worse) |
| **Jose builds X** | Yunus | Yunus is on the factory-MAC race and the serial-reset bug, which block the demo. The X build is small (reuses `radio.cpp` and the serial helper) and sits next to the attack scripts |
| **Silent between attacks** | X as a normal node | The IPS is trained on normal traffic with X off (16f) and the runbook keeps X quiet until the attack segment; a silent sniffer matches both and needs no routing or key layer on X |

---

## 19. Labels file format

**Hannan's format plus an optional `variant`.** Keeping `label` to the four classes the IPS already
trains on means no IPS change (`read_labeled` ignores extra keys). Several attacks come in versions that
behave very differently (an outsider flood is dropped at the first hop, an insider flood is relayed; a
replay 30 s old hits a different cache than one 2 min old), and the results table and slides need numbers
per version. A `variant` field gives that without new label classes or file-naming conventions. The script
that sends the frames writes the row, so start and end are exact (18).

---

## 20. Attack specs

**Context:** the recordings have to train and evaluate the IPS (G6, G7), give the results table its replay
number (G5), and show the threat model's known issues on real hardware.

| Choice | Why |
|---|---|
| **Flood rates 80 / 15 / 50 / 8 per second** | Each sits on a mechanism: 80/s is far above the relays' 20/s insertion limit (10g), so most is dropped at the first hop; 15/s is under it, so relays amplify it, and it sits exactly at the IPS rule's threshold, which is where ML can beat rules (G7); 8/s is the low-and-slow residual (16f). Everything stays ≤ 100/s so the watchtower log keeps up (16e) |
| **Outsider flood included** | The only attack an outsider can run; shows `link_tag` dropping it at the first hop and that BLOCK can't stop the airtime (threat model §8) |
| **Three replay ages** | Each age is stopped by a different layer (seen-cache, 180 s cache, epoch window), so the recordings show the layers working separately and give an honest "replay rejection 100%" |
| **Both spoof variants** | The pseudonym-only spoof is easy (MAC mismatch); the pseudo + MAC spoof is the O9 case the operator policy exists for |
| **Victim followed by RSSI** | It's what a real insider could do (no access to the watchtower's map), and it turns O3 from a documented limitation into a measured one |
| **Both routing variants** | The TTL-fixed variant defeats the sum check, so it tests whether "hop went down for the same `msg_id`" alone is enough; matches Hannan's synthetic data |
| **Extras (cycling, CTRL forgery, watchtower outage)** | They exercise the residuals the threat model names (10b/10g identity cycling, 16d verify budget, 16b/16c watchtower loss) |
| **Sessions per type + held-out mixed session** | A bad moment spoils one short session, not everything, and the mixed session gives a test set with a different order and timing than training |

