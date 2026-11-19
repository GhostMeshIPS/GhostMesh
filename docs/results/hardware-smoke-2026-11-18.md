# Hardware smoke test, Wed Nov 18 (pre-merge check)

Owner: Yunus (Comp E). Firmware: `firmware-node-integration` after merging `main` (Rashad's LRU peer
eviction + jitter 50%) and the `RT_LOG_PEER_EVICTED` fix. Goal: confirm this exact code on hardware
before merging the PR.

**Result: the core works on hardware; two bugs found (§3). The PR was merged with these as known issues;
fixes and a short re-test follow in a separate PR (Thu Nov 19).**

## 1. Setup

- W on the laptop; A, B, C on power banks. D still not working; X not built.
- Auto traffic every 20 s: A → B, B → A, C → A.
- Log: `ips/data/raw/smoke_nov18.jsonl` on Yunus's laptop (gitignored; ask him for it). 2291 lines,
  1680 frames after W's clock was set, ~18 min with several W sessions between 20:44 and 21:06 EST.

## 2. What passed

| Check | Result |
|---|---|
| Sync from W's signed beacons alone | ✅ all three nodes, every session |
| Network key | ✅ `link_ok` true on all 1680 frames |
| PHY rate | ✅ 1 Mbps (`rate 0`, `sig_mode 0`) on every frame |
| Airtime per frame | 3151–3199 µs (Nov 17: 3279 µs) |
| MAC rotation, steady state | ✅ A, B, C each used **exactly 1 MAC per epoch over 14 epochs**, all locally administered, all matching their pseudonyms |
| Unknown transmitters after W's clock was set | ✅ none (the few `?` lines are frames heard before `set_time`) |
| Traffic mix | ✅ originated DATA/min: A 10.4 (own + ACKs for B and C), B 7.7 (own + ACKs for A), C 2.8 (own only) |
| Relaying | 431 of 647 `msg_id`s heard from all three nodes |

**Delivery (from the OLED `ok` / `x` counts):**

| Sender → target | Delivered | Failed | Rate |
|---|---|---|---|
| A → B | ~48 | 7 | ~87% |
| B → A | ~48 | 0 | 100% |
| C → A | ~48 | 2 | ~96% |
| **All** | | | **~95.6%** (G1 target ≥ 95%) |

Signal at W was weaker than on Nov 17 (averages A −70, B −75, C −81 dBm; minimums −87 to −89 dBm), so
A ↔ B may simply have been a marginal link. Not yet investigated.

## 3. Bugs found

### 3.1 Factory-MAC leak when a node takes its first beacon (Comp E, node layer)
At 20:44:34, right as W's first beacon reached freshly booted nodes, W logged 3 frames with **factory MACs**
(`3c:0f:02:e3:bb:00`, `3c:0f:02:e3:bd:dc`; no locally-administered bit) or a stale pseudonym, all carrying
the epoch from the nodes' saved state (31750) instead of the current one.

**Cause:** the first-beacon workaround in `gm_node_rx` (see the routing bug in the decision log) marks the
node synced immediately, but the epoch, pseudonym and MAC only switch on the next 100 ms `gm_tick`. Any
frame relayed in that window goes out under the board's real hardware MAC. This also explains the
"C factory MAC" frames of Nov 17 (it was not stale firmware on C).

**Fix (planned):** on the first beacon, switch epoch + pseudonym + MAC before returning to routing; add a
laptop test that starts nodes with factory-style MACs and fails if one ever reaches the air. Needs a reflash
of A–D.

### 3.2 Opening the watchtower's port still resets it on Windows (Comp E, tooling)
Opening the port with DTR/RTS low (`tools/chat_client.py`) does **not** stop the reset on Windows: the
driver toggles the lines anyway. At 21:02:08 the reopen rebooted W and wiped its clock; after a second
reopen, `/block C` failed with `clock_not_set` and `/unblock C` with `no_such_block`. **The block test did not
run** (it did on Nov 17). Nodes were unaffected and kept running on their own clocks.

**Fix (planned):** the chat client re-sends `set_time` whenever W reports `clock_not_set` (no reflash).
`ips/ingest.py` needs the same. Later: W keeps its clock across this kind of reset.

## 4. Next (Thu Nov 19)

1. Fix 3.1 (node layer + test) and 3.2 (chat client).
2. Reflash A–D; 5-minute re-test including `/block C` across an epoch change; check the log for any
   non-locally-administered MAC.
3. Merge the fix PR if clean.
4. Then: debug D, the A ↔ B delivery rate, the 3-board allowlist test (G1/G2).
