# Network #2 → AI/ML: answers to `IPS_DATA_NEEDS.md`

From: Jose (Network #2). To: Hannan (AI/ML).
Full detail and rationale: [`project-breakdown.md` §4.7](../docs/planning/project-breakdown.md) (what) and
[`protocol-design-motivation.md`](protocol-design-motivation.md) (why).

> **Status:** these are Network #2's decisions. The items marked **(needs team sign-off)** change the
> shared frame format or `ver_type` list, so they're final only once Rashad and Yunus agree.

---

## 1. Your Network #2 checklist

| Your item | Answer |
|---|---|
| Spec for each attack | Preliminary summary in §3 below. Rates, timings and intensities come with the attack-spec doc (task 11) |
| Start/stop time of every run + attacker identity | Yes. Every attack script will write a ground-truth label file with start/stop times on the **same Unix clock** as the watchtower log (§2.4). The attacker is always node **X** |
| Slow / subtle version of each attack | Yes, a loud and a subtle setting per attack (task 11). Your `synth.py` slow flood (8 pkt/s vs. the 15 pkt/s rule) is the model |
| ≥ 2 min per attack, more than one session | Yes, Wednesday's recordings |
| Epoch length and rotation | **60 s.** Epoch = `floor(unix_seconds / 60) mod 65536`, so **every node rotates its pseudonym *and* MAC at the same moment, on each Unix minute boundary**. Expect a short traffic gap at each boundary (the MAC change briefly restarts Wi-Fi). That's normal, not an attack |
| Can the watchtower map pseudonyms to real nodes? | **Yes.** The watchtower holds every node's pseudonym secret (not their encryption keys) and adds a field **`"node": "A"`…`"D"`, `"X"`, or `"?"`** to every log line. **Please group per-node features by `node` instead of `mac`**: identities stay continuous across rotations, so per-node baselines and RSSI history finally work. `"?"` (a pseudonym that matches no real node) is itself a signal |
| Replay window rules | §2.6 below |
| BLOCK signing | The **watchtower** holds the only Ed25519 private key; nodes have the public key. Details and the new command format in §2.7 |

---

## 2. Changes that affect the IPS

### 2.1 Watchtower log: new optional fields
All optional, so `schema.py`'s `parse_line` keeps working (unknown fields are ignored today).

| Field | Meaning | Use |
|---|---|---|
| `node` | Real node behind the transmitter: `A`–`D`, `X`, or `?` | Group features per node; `?` = outsider or spoof signal |
| `rx_us` | Radio receive timestamp, µs (board clock) | Fine inter-arrival timing for scripted senders. Keep `t` as the laptop timestamp for windows |
| `noise_floor` | Channel noise at receive, dBm | Jamming / channel saturation (Yunus will check accuracy on hardware) |
| `rate`, `sig_mode`, `mcs` | PHY rate / mode of the frame | Radio fingerprint: our firmware uses fixed settings, foreign firmware may not |
| `flags` | Cleartext flags byte (bit 0 = SOS) | Forged-flag detection |
| `epoch` | Frame's epoch field | Frames outside current ±1 epoch = replay or broken clock |
| `next_hop` | Directed-forwarding target (v2) | Routing-abuse features once route learning lands |
| `raw` | Hex of the full 240-byte frame | For my pcap/Wireshark tool; you can ignore it |

**Derived in the IPS, not logged by firmware:** relay-vs-originate behaviour per node. Use `msg_id` + `t` to tell
whether a node's frame is the first copy of a `msg_id` or a relay. A node that hears traffic but never relays
is a black-hole hint.

**Also new:** the watchtower can check that a frame's MAC matches its pseudonym (both are derived from
the same secret). A mismatch means someone copied a pseudonym from another radio. Yunus and I can add
this as a boolean field (`id_ok`?) if you want it; tell me.

### 2.2 Packet types (needs team sign-off)
`PACKET_TYPES` becomes **`{"DATA", "HELLO", "CTRL", "KEYS"}`**:
- **RREQ, RREP removed** (Nov 14 decision).
- **ACK no longer appears in cleartext.** ACKs are sent with `ver_type = DATA`, and the real type is encrypted, so sniffers can't count deliveries. You lose a cleartext ACK count.
- **BLOCK → CTRL**: one signed type for BLOCKs *and* the watchtower's time beacon.
- **KEYS (new)**: each node floods its next-epoch key about **6 times per minute**. Expected rate: ~0.1 originated KEYS/s per node, plus relayed copies.
- Expected **TIME** beacons: one CTRL from the watchtower **every 10 s**, plus relayed copies.

### 2.3 `pseudo` is the transmitter
Since the Nov 14 decision, `pseudo` (and `mac`) are the **last hop**, not the originator. The comment in
`schema.py` still says "sender pseudonym", so update it.

### 2.4 One clock
The mesh clock is **Unix time**. The IPS laptop sets the watchtower's time over serial, the watchtower
broadcasts signed time beacons, and nodes follow them. Your `t` (laptop receive time, Unix seconds) and
every block `until` use the same clock, and so will my attack label files.

### 2.5 What "normal" looks like now (so it isn't flagged)
- **The same `msg_id` from several transmitters is normal.** Every relay re-broadcasts it. Abnormal:
  - the same `msg_id` twice from the **same** transmitter;
  - a `msg_id` that reappears **> 60 s** after it was first seen;
  - **`hop` going down** for the same `msg_id`. In an honest flood, hop count only increases along the path.
- **Retries:** new `msg_id`, up to 4 attempts at about 0 / 1 / 3 / 7 s. They look like new messages, not replays.
- **ACKs:** look like DATA, sent 0–400 ms (random) after the DATA arrives.
- **HELLO:** 0.5 Hz per node, one hop (not relayed).
- **Minute boundaries:** every pseudonym and MAC changes at once; brief gap.

### 2.6 What the nodes already reject (don't double-count)
Nodes drop these themselves. The **watchtower is passive, so it still logs them**, which is useful as attack evidence:
1. Bad `link_tag` (outsiders) → you see `link_ok = false`.
2. Duplicate `msg_id` within 60 s (normal flooding) and **a 180 s `msg_id` cache** against replays.
3. `epoch` outside current ±1.
4. At the recipient only: inner timestamp older than **5 s** (`REPLAY_STALE`), or a repeated sequence number (not delivered twice).
5. Frames from a blocked identity (`BLOCKED`).

These drops happen inside nodes, not in the watchtower stream. If you want them as features, ask Yunus to
add node-side drop events to the serial output.

### 2.7 BLOCK command (laptop → watchtower)
Please change `make_block_cmd` to:
```json
{"cmd":"block", "node":"X", "reason":"flood", "until":1731264300.0}
{"cmd":"block", "node":"?", "pseudo":"a1b2c3d4", "mac":"02:..:..", "reason":"spoof", "until":1731264300.0}
```
- **Known node (`A`–`X`)**: just name it. The watchtower computes that node's pseudonym + MAC for the
  current and next epoch, signs the BLOCK, floods it, and **re-issues it every epoch** until `until`. So a
  block now **survives rotation**.
- **Unknown (`?`)**: give the observed `pseudo` and/or `mac`. That block lasts until the next rotation unless
  you re-send it.
- **`until`** stays Unix seconds (float), as in your code. The watchtower converts it.
- **Spoofs can now be blocked** without cutting off the victim. Nodes match a target on **pseudo AND MAC**
  (MAC optional). If the spoofer copied the victim's pseudonym but transmits from its own MAC, send
  `node:"?"` with the victim's `pseudo` and the **spoofer's `mac`**. If it copied both, keep `spoof` alert-only
  as `live.py` does now.
- **Unblock early / confirmation**: the watchtower will echo a `block_id`, and an unblock uses it. The exact
  event format belongs to Yunus (serial protocol §10), so treat this part as a proposal.

### 2.8 Datasets folder
`ips/data/` is in `.gitignore`, so labeled sessions saved there never reach the repo. Suggest
**`ips/datasets/`** (not ignored), with the naming from your doc (`YYYY-MM-DD_<type>_<nn>.jsonl`) plus a
matching `<same name>.labels.jsonl` from my attack scripts.

---

## 3. Attacks: preliminary summary (rates and timings follow in task 11)

Labels stay **`flood`, `replay`, `spoof`, `routing`** (as in `schema.py`). The attacker is node **X**.

| Attack | Who can do it now | What X does | Signals to expect |
|---|---|---|---|
| **flood** | Insider (valid `link_tag`) **or** outsider | High-rate DATA-looking frames (loud + slow versions) | Insider: per-node packet rate spike, relays amplify it. Outsider: `link_ok=false` burst, dropped at the first hop (watchtower still sees it) |
| **replay** | Outsider (no keys needed) | Re-sends captured frames unchanged | Same `msg_id` reappearing after > 60 s; `epoch` stale; frames carry the **original** transmitter's `pseudo` but come from X's radio, so **MAC ≠ pseudo** and an RSSI jump for that identity. Nodes drop them, but the watchtower logs them |
| **spoof** | **Insider only** (an outsider can't recompute `link_tag` after changing `src_pseudo`) | Transmits with a victim's current pseudonym (optionally its MAC too) | `node` attributes these frames to the **victim**, so the victim shows **two RSSI clusters**; MAC↔pseudo mismatch if the MAC wasn't copied |
| **routing** | **Insider only**, and **mostly meaningful once route learning (v2) exists** | Relays with forged low `hop` (or high `ttl`) to look like a short path | **`hop` decreasing for the same `msg_id`**; hop vs. RSSI inconsistency. Note: your `synth.py` fakes TTL 10 on HELLOs. Let's align once task 11 fixes the exact forgery |

**Possible extra insider variants** (new surfaces from our design; I'll say in task 11 whether we record them):
a flood of forged CTRL frames (nodes only relay CTRL frames whose signature checks out, and check at most ~2/s), or a flood of KEYS frames.
