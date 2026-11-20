# GhostMesh IPS: the AI watchtower

The intrusion prevention system for GhostMesh. The watchtower board (W) hears every packet and streams
**metadata only** (which node transmitted, when, how strongly, TTL/hop, whether its MAC matches its
identity) to this laptop software. The software detects attacks inside the mesh and answers with a
**BLOCK**, which W signs and broadcasts. Message content is end-to-end encrypted and never used.

```
watchtower serial / recorded log ─▶ ingest.py ─▶ features.py ─▶ Random Forest ─▶ BLOCK / ALERT ─▶ watchtower
                                                       │                │
                                                       ▼                ▼
                                       rule + Isolation Forest     dashboard.py (+ local LLM explainer & chatbot)
                                       (logged for comparison)
```

For the step-by-step demo, see [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md).

## Quick start

```bash
cd ips
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-lock.txt      # exact tested versions (requirements.txt = loose)

python3 synth.py      # generate labelled synthetic sessions (fixed seeds, reproducible)
python3 detect.py     # train + score rule / Isolation Forest / Random Forest, save models

# Terminal 1
streamlit run dashboard.py                                    # http://localhost:8501
# Terminal 2: replay a session as if it were live (1 = real time, 10 = 10x faster)
python3 live.py --file test_session.jsonl --speed 10
# ...or the real watchtower over USB (find the port with: ls /dev/cu.*)
python3 live.py --port /dev/cu.usbserial-XXXX
# ...and record the session at the same time (same format as tools/chat_client.py --log)
python3 live.py --port /dev/cu.usbserial-XXXX --log datasets/2026-11-20_flood_01.jsonl
```

**Optional, plain-English explanations and chatbot:** install [Ollama](https://ollama.com), run
`ollama pull llama3.2:3b` and keep the app open. Without it, the IPS works the same and the
dashboard uses template sentences.

## What it detects

The attacks match Jose's attack scripts for X (`security/attacks/`, decision 20).

| Attack | What the attacker does | Main signals | Response |
|---|---|---|---|
| Flooding | Sends packets far faster than a normal node: 80, 15 or 8 per second as X, an outsider without the network key, or forged CTRL frames | New messages started per second, packet rate, failed link checks | BLOCK (60 s) |
| Identity-cycling flood | Floods with the network key under a new fake pseudonym + MAC every 5 frames | Many frames from pseudonyms matching no node, grouped as one "unknown keyed radio" (`?insider`) | **Alert only** (a BLOCK can't follow an identity that changes every 5 frames) |
| Routing abuse | Relays with a forged hop 0, to look like a shortcut (sometimes fixing TTL to hide it) | A copy claiming fewer hops than already heard; `ttl + hop` not adding up to the mesh's fixed sum (5) | BLOCK (60 s) |
| Replay | Re-sends frames heard 30 s to 4 min earlier | `msg_id` first heard > 20 s ago, MAC doesn't match identity (`id_ok`) | BLOCK the replaying radio; alert only if the identities have already expired |
| Spoofing | Uses another node's identity | Signal jump from that node's usual level, MAC doesn't match identity (`id_ok`) | **Alert only**, naming the node being impersonated (a block would cut off the real victim) |
| Missing KEYS | A jammer targets one node's key updates | A node (A–D) that is transmitting but sent 0 KEYS in 60 s | **Alert only** (a BLOCK can't stop a jammer) |

- An attack must be seen in **2 seconds in a row** before the IPS acts, so one odd second can't block a node.
- Blocks **expire after 60 s**, so a false alarm heals itself. An attacker that keeps going is blocked again.
- **Suspected impersonation (open issue O9):** if a node's signal suddenly jumps (> 6 dB), the IPS asks the
  operator instead of blocking the real node, and on confirm blocks only that exact radio.
- **The radio that transmits is blamed, not the identity it claims.** A frame carrying node A's pseudonym from
  another radio's MAC (`id_ok` false: a replay or spoof) is tracked under that MAC, so the real A is never blocked for it.
- **Auto-block switch** on the dashboard: off = every BLOCK waits for an operator click.
- **Trusted boards:** W is never blocked. If a mesh node doubles as W, start with `--trusted D`.

## Results

**Real hardware** (Nov 18 smoke test, A/B/C + W, 18 min, no attacks, `datasets/2026-11-18_normal_01.jsonl`):
the Random Forest raised **0 false alarms in 654 windows**, and the live pipeline raised 0 alerts.
**Real hardware with harmless events** (Nov 17 bench test: B unplugged, a block of C, a W outage, C moved;
`datasets/2026-11-17_mixed_01.jsonl`, never trained on): **0 false alarms in 1,231 windows**, 0 live alerts.

**Synthetic test session** (never used for training: 8/s flood, outsider and identity-cycling floods, forged CTRL,
forged-hop routing, 90 s replay, spoof, jammed KEYS, B unplugged):

| Detector | Attacks caught (recall) | Alarms correct (precision) | False alarms (FPR) |
|---|---|---|---|
| Rule baseline (`pkts > 15 or HELLOs > 1`) | 37% | 43% | 8.9% |
| Isolation Forest (unsupervised, trained on normal only) | 62% | 93% | 0.9% |
| **Random Forest** (supervised, names the attack) | **99%** | **100%** | **0.0%** |

The rule only sees packet rate: it misses the slow attacks, and it blames honest relays passing a fast flood along.
Rashad's simulator (2,641 normal windows): Random Forest 0% false alarms, Isolation Forest 10%.

- **Time to block:** 2 s to decide, plus up to 3 s for W to send it (W sends at most one CTRL frame per 3 s).
- ⚠️ The attacks are still **synthetic**. Real attack recordings from X are needed for a real "caught %".

## Files

| File | Role |
|---|---|
| `schema.py` | **The only file that knows the watchtower's JSON format** (frames, events, BLOCK / set_time commands) |
| `ingest.py` | Packets from a recorded `.jsonl` log or the live serial port. Sets W's clock and reconnects if the USB cable drops |
| `features.py` | Packets → one row per node per 1-second window (17 features) |
| `detect.py` | Rule baseline, Isolation Forest, Random Forest, scoring; saves models + benchmark |
| `live.py` | Live loop: windows → Random Forest → confirm → BLOCK / ALERT, with evidence |
| `explain.py` | Local LLM writes one plain sentence per alert; the exact numbers are added by code |
| `chat.py` | "Ask the watchtower" sidebar chatbot (read-only, grounded in live state + playbook) |
| `dashboard.py` | Streamlit dashboard |
| `retention.py` | Auto-delete: traffic logs keep 6 h, chat history 24 h |
| `synth.py` / `explore.py` | Synthetic labelled data (TTL 5, no HELLOs, X silent between attacks, attacks from decision 20) / data exploration |
| `datasets/` | Recorded real sessions kept in git (see [datasets/README.md](datasets/README.md)) |
| `data/` | Private live logs, git-ignored and auto-deleted |

## Design rules

- **Metadata only.** Never message content; it is encrypted end to end.
- **The model decides, the LLM only explains.** The language model never triggers or lifts a BLOCK, and never
  sees raw packet text (attackers choose their own pseudonym, which could carry prompt injection).
- **Train and test on different sessions**, never random splits of one session.
- **Local and private.** Everything runs on the laptop; live logs are pruned automatically.

## Contract with the firmware (PROTOCOL.md §10)

- Input: one JSON line per packet, e.g.
  `{"t":1795052674.387,"mac":"3c:..","pseudo":"23c91361","type":"DATA","msg_id":"..","ttl":3,"hop":2,"rssi":-73,"len":240,"link_ok":true,"node":"B","id_ok":true}`
  plus event lines like `{"ev":"block_sent",...}`. Frames from before W's clock is set are dropped.
- Output to the watchtower (which signs and broadcasts it):
  `{"cmd":"block","node":"X","reason":"flood","until":1795052734.0}` and `{"cmd":"set_time","unix_ms":...}`
