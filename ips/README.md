# GhostMesh IPS: the AI watchtower

The intrusion prevention system for GhostMesh. The watchtower node hears every packet and streams
**metadata only** (who transmitted, when, how strongly, TTL/hop) to this laptop software, which detects
attacks inside the mesh and answers with a signed **BLOCK**. Message content is end-to-end encrypted and
never used.

```
watchtower serial / replayed log ─▶ ingest.py ─▶ features.py ─▶ Random Forest ─▶ BLOCK ─▶ watchtower
                                                       │                 │
                                                       ▼                 ▼
                                            rule + Isolation Forest   dashboard.py (+ local LLM explainer & chatbot)
                                            (logged for comparison)
```

## Quick start

```bash
cd ips
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python3 synth.py      # generate labeled synthetic sessions (fixed seeds, reproducible)
python3 detect.py     # train + evaluate rule / Isolation Forest / Random Forest, save models

# Terminal 1
streamlit run dashboard.py                                 # http://localhost:8501
# Terminal 2: replay a recorded session as if it were live (1 = real time, 5 = 5x faster)
python3 live.py --file test_session.jsonl --speed 1
# ...or the real watchtower over USB:
python3 live.py --port /dev/tty.usbserial-XXXX
```

**Optional, plain-English explanations and chatbot:** install [Ollama](https://ollama.com), then
`ollama pull llama3.2:3b` and keep the app open. Without it, the IPS works the same and the
dashboard falls back to template text.

## What it detects

| Attack | What the attacker does | Signal | Response |
|---|---|---|---|
| Flooding | Spams packets | Packet rate per transmitter, gap between packets | BLOCK (60 s) |
| Routing abuse | Fake TTL / extra HELLO beacons to attract traffic | TTL, HELLO rate | BLOCK (60 s) |
| Replay _(planned)_ | Re-sends old captured packets | `msg_id` re-heard long after first seen | BLOCK |
| Spoofing _(planned)_ | Uses another node's identity | Two signal levels behind one identity | **Alert only** (blocking would cut off the real node) |

An attack must be seen in **2 consecutive 1-second windows** before the IPS acts, so one odd second
can't block a node. Blocks **expire after 60 s** so a false alarm heals itself; an attacker that keeps
going is re-blocked within 2 s.

## Results (synthetic data)

Scored on a session **none of the models trained on** (slow 8 pkt/s flood + routing abuse):

| Detector | Attacks caught (recall) | Alarms correct (precision) | False alarms (FPR) |
|---|---|---|---|
| Rule baseline (`pkt_count > 15`) | 0% | n/a | 0.0% |
| Isolation Forest (unsupervised, trained on normal only) | 98% | 80% | 2.5% |
| **Random Forest** (supervised, names the attack) | **100%** | **100%** | **0.0%** |

- **Time to block:** 2 s from the first malicious second.
- The "slow flood" stays under the rule threshold, so the rule never sees it, while the ML catches it.
- ⚠️ Synthetic normal traffic is simpler than the real mesh, so expect these numbers to drop on hardware data.
  Retraining on simulator/hardware captures is the next step.

## Files

| File | Role |
|---|---|
| `schema.py` | **The only file that knows the watchtower JSON format.** Firmware changes = edit this file only |
| `ingest.py` | Packets from a replayed `.jsonl` log or the live serial port (stamps laptop arrival time; the ESP32 has no real-time clock) |
| `features.py` | Packets → one row per transmitter per 1-second window |
| `detect.py` | Rule baseline, Isolation Forest, Random Forest, evaluation; saves models + benchmark |
| `live.py` | Live loop: windows → Random Forest → confirm → BLOCK / ALERT, with evidence |
| `explain.py` | Local LLM writes one plain sentence per alert; exact numbers are added by code |
| `chat.py` | "Ask the watchtower" sidebar chatbot (read-only, grounded in live state + playbook) |
| `retention.py` | Auto-delete: traffic logs keep 6 h, chat history 24 h |
| `dashboard.py` | Streamlit dashboard |
| `synth.py` / `explore.py` | Synthetic labeled data until hardware captures exist / data exploration |

## Design rules

- **Metadata only.** Never message content; it is encrypted end to end.
- **The model decides, the LLM only explains.** The language model never triggers or lifts a BLOCK, and never
  sees raw packet text (attackers choose their own pseudonym, which could carry prompt injection).
- **Train and test on different sessions**, never random splits of one session.
- **Local and private.** Everything runs on the laptop; logs are pruned automatically.

## Contract with the firmware

- Input: one JSON line per packet, e.g.
  `{"t":1731264000.123,"mac":"02:..","pseudo":"9f3a..","type":"DATA","msg_id":"..","ttl":4,"hop":1,"rssi":-52,"len":240,"link_ok":true}`
- Output to the watchtower (which signs and broadcasts it):
  `{"cmd":"block","mac":"..","pseudo":"..","reason":"flood","until":1731264152.0}`
