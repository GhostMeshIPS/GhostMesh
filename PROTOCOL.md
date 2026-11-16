# GhostMesh Protocol

> **Status:** Draft.
> Section owners are listed under each heading. Background and rationale: [`docs/planning/project-breakdown.md`](docs/planning/project-breakdown.md).

## 1. Overview

_Owner: Rashad + Jose_

- What the protocol does, in one paragraph
- Node roles: `NODE`, `WATCHTOWER`, `ATTACKER`
- Version covered by this document (v1 flooding, v2 route learning)

## 2. Terminology

_Owner: Rashad + Jose_

- Originator, transmitter, relay, recipient
- Pseudonym, epoch
- Hop, TTL

## 3. Frame format

_Owner: Rashad + Jose (codec: Yunus)_

- Field table: name, size, cleartext or encrypted, who may change it
- Inner (encrypted) header layout
- Byte order and padding to 240 bytes

## 4. Frame types

_Owner: Rashad + Jose_

- `ver_type` values: DATA, ACK, HELLO, BLOCK
- For each type: who sends it, whether it is relayed, whether it is ACKed

## 5. Forwarding (v1: managed flooding)

_Owner: Rashad_

### 5.1 Receive rules

```mermaid
%%{init: {"flowchart": {"nodeSpacing": 30, "rankSpacing": 35}}}%%
flowchart TD
    RX([Packet received]) --> LT{"link_tag<br>valid?"}
    LT -->|No| LTD["Log & drop"]
    LT -->|Yes| SC{"msg_id<br>in cache?"}
    NOTE[/"Own frames cached<br>at send time"/] -.- SC

    SC -->|Yes| PR{"Pending relay<br>for msg_id?"}
    PR -->|"Yes: count++"| KC{"count >= k?"}
    KC -->|Yes| CPR["Cancel relay,<br>log duplicate"]
    KC -->|No| KEEP["Log duplicate,<br>keep relay pending"]
    PR -->|No| LD["Log duplicate,<br>drop"]

    SC -->|"No: add to cache"| CMD{"Decrypts?"}
    CMD -->|"Yes, ACK"| MNR["Match to 'waiting for ACK'<br>(any attempt's msg_id),<br>stop retry timer,<br>tell laptop delivered,<br>no reply"]    
    CMD -->|"Yes, DATA"| SEQ{"Seq # already seen<br>from this sender?"}
    SEQ -->|No| DSA["Deliver to serial,<br>send ACK"]
    SEQ -->|Yes| REACK["Send ACK again,<br>don't deliver"]
    REACK --> TTL    
    CMD -->|No| TTL{"ttl == 0?"}
    MNR --> TTL
    DSA --> TTL

    TTL -->|Yes| DR["Don't relay<br>(log ttl_expired)"]
    TTL -->|No| REL["ttl--, hop_count++<br>src_pseudo = mine, next_hop = 0<br>recompute link_tag<br>rebroadcast after RSSI jitter"]
```

When a frame arrives, the node first checks the `link_tag`. If it doesn't match, the frame came from outside the network, so it's logged and dropped. Then, the node checks the `msg_id` against its own seen cache. If it is a repeated ID, then it's logged as a duplicate and dropped, and if the node was waiting to relay that same frame, the duplicate counts towards k; once the count reaches k, the pending relay would be cancelled (see Section 5.3). The node would also cache the `msg_id` of every frame it sends itself, so that its own frames can't loop back and be relayed. A new `msg_id` is added to the cache, and the node tries to decrypt the frame. 

If decryption works, the frame is meant for that node. An ACK is matched to the node's "waiting for ACK" entry by any of its attempt `msg_id`s, which stops the retry timer and tells the laptop the message was delivered, with no reply. A second ACK for the same message finds no entry and is ignored. For a DATA frame, the node checks the sequence number. If it's new, the message gets delivered to the laptop and an ACK is sent back. If its been seen, the first ACK got lost, so the node only resends the ACK. Regardless of whether or not the frame was meant for this node, it goes to the TTL check next. At `ttl == 0` the node doesn't relay it and logs `ttl_expired`. Otherwise the node decrements `ttl`, increments `hop_count`, sets its own pseudonym in `src_pseudo`, sets `next_hop` to 0, and then recomputes `link_tag`. Finally, it rebroadcasts after a random wait (depending on the RSSI).

### 5.2 Send rules
```mermaid
%%{init: {"flowchart": {"nodeSpacing": 30, "rankSpacing": 35}}}%%
flowchart TD
    T1([Laptop sends cmd]) --> LEN{"Is length<br>> 153 bytes?"}
    T2([Receive path needs ACK]) --> NEW_MSG
    T3([Retry timer fired]) --> RETRY{"Retries left?"}

    RETRY --> |No| FAIL["Tell the laptop that message failed.<br>Clear the 'waiting for ACK'"]
    RETRY --> |Yes| NEW_MSG

    LEN --> |Yes| ER["Send error back to laptop<br>and stop."]
    LEN --> |No| NEW_MSG["Make a new random msg_id"]

    NEW_MSG --> BHD["Build the inner header:<br>real sender, recipient, timestamp,<br>sequence number (next one for new message,<br>original one for retry), & message length.<br>Also pad message to fixed size"]

    BHD --> ENC["Encrypt with the key shared with recipient<br>(producing nonce/ciphertext/aead_tag)"]

    ENC --> FILL["Fill the cleartext header.<br>ver_type = DATA or ACK, flags, msg_id,<br>ttl = default, hop_count = 0,<br>src_pseudo = pseudonym, next_hop = 0,<br>epoch = current"]

    FILL --> COMPUTE["Compute link_tag"]

    COMPUTE --> ADD["Add msg_id to seen-cache<br>(so that echo gets dropped)"]

    ADD --> DATA{"Is this DATA?"}

    DATA --> |Yes| REGISTER["Register or Update 'Waiting for ACK'<br>(store text, recipient, and sequence number<br>for retries) and restart retry timer<br>with the next backoff (1s / 2s / 4s)"]
    DATA --> |No| TRANSMIT
    REGISTER --> TRANSMIT["Transmit and log"]

    TRANSMIT --> FIRST{"New DATA,<br>first attempt?"}
    FIRST --> |Yes| SENT(["Tell laptop that the message was sent"])
    FIRST --> |No| DONE([Done])
```

A node sends a frame for one of 3 reasons: 
- The laptop sends a message
- The receive path needs to send an ACK
- A retry timer goes off

A message from the laptop that is over 153 bytes gets rejected with an error. If a retry has no retries left, the node tells the laptop the message failed and clears the "waiting for ACK" entry. Otherwise, every send builds a new frame with a fresh random `msg_id` (including retries), so that the relays don't drop them as duplicates. The node then builds the inner header (real sender, recipient, timestamp, sequence #, and length), pads the message to the fixed size, and encrypts it with the key shared with the recipient. A retry keeps the original sequence number so the recipient can tell it's the same message.

Next, the node fills in the cleartext header (`ver_type`, `flags`, `msg_id`, `ttl` = default, `hop_count` = 0, `src_pseudo` = its own pseudonym, `next_hop` = 0, current `epoch`) and computes the `link_tag` last, since it covers the finished header. It also **adds its own `msg_id` to the seen_cache** so that the echo gets dropped. A DATA frame registers or updates a "waiting for ACK" entry (storing the text, recipient, & sequence # for retries) and restarts the retry timer at the next backoff (1s / 2s / 4s). ACKs skip this, since they never get acknowledged. Finally, the frame is transmitted right away and logged, and only the first attempt of a new DATA message tells the laptop it was sent.


### 5.3 Relay timing

**Jitter:** Before rebroadcasting, a relay would wait a random time within the jitter window (where a weaker RSSI would mean a shorter wait, so farther nodes would relay first). _Exact RSSI-to-wait mapping: TBD._

**Rebroadcast suppression:** While a relay is pending, the node would count copies of the same `msg_id` that it hears from other nodes. The copy that started the timer wouldn't count though. If the count reaches a value of **k**, the node would cancel its relay. Otherwise it rebroadcasts when the timer hits. (This is inspired by [RFC 6206](https://www.rfc-editor.org/rfc/rfc6206))

**Timing rule:** The jitter window must be at least 2-3x the airtime of k frames, so that a node has time to hear k copies before the timer hits. This is inspired by [RFC 6206 Section 6.6](https://www.rfc-editor.org/rfc/rfc6206#section-6.6), where Trickle sets it up as the protocol having the minimum interval be at least 2-3 times as long as it takes to transmit k packets. 

### 5.4 Drop reasons

- Table of every drop or no-relay reason and its log name

## 6. Routing (v2: route learning)

_Owner: Rashad_

- HELLO beacons and the neighbor table
- Reverse-path route learning
- Directed forwarding with `next_hop`
- Flood fallback and self-healing
- Behaviour at epoch boundaries

## 7. Reliability

_Owner: Rashad (ACK contents: with Jose)_

- ACK contents and how an ACK travels back
- Retries and backoff
- Duplicate delivery on retry
- Delivery status reported to the chat client

## 8. Topology control

_Owner: Rashad_

- RSSI gate
- TX power
- Allowlist fallback and where it may be used

## 9. Security

_Owner: Jose_

- `link_tag`: key, coverage, per-hop recompute
- End-to-end encryption and trial decryption
- Replay protection
- Pseudonym and MAC rotation
- Signed BLOCK messages

## 10. Serial protocol (node ⇄ laptop)

_Owner: Yunus_

- Commands (laptop → node)
- Events (node → laptop)

## 11. Watchtower log schema

_Owner: Hannan (frozen at design freeze; everyone depends on it)_

- Field list with types (reference implementation: `ips/schema.py`)
- Meaning of `pseudo` (transmitter)
- Optional fields, such as sim ground-truth labels

## 12. Parameters

_Owner: Rashad + Jose_

| Parameter | Value | Notes |
|---|---|---|
| Default TTL (hardware) | TBD | |
| Default TTL (sim) | TBD | |
| Seen-cache size | TBD | |
| Seen-cache expiry | TBD | |
| Relay jitter window | TBD | Planned 10–50 ms. Must be at least 2–3× the airtime of k frames |
| Suppression threshold k | TBD | Proposed 2–3; settle by sim sweep |
| Frame airtime | TBD | Estimated ~3 ms per 240-byte frame at 1 Mbps; measure on hardware later |
| HELLO interval | TBD | |
| Neighbor expiry | TBD | |
| ACK timeout / retries / backoff | TBD | |
| Epoch length | TBD | |

## 13. Metric definitions

_Owner: Rashad_

- Transmission
- Delivery
- Reroute time
- Latency

## 14. Open questions

- Items still undecided, each with an owner

## 15. Decision log

- See [`docs/planning/project-breakdown.md` §4.7](docs/planning/project-breakdown.md) until decisions move here
