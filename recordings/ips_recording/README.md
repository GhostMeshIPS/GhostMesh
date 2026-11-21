# IPS recording

Taken from a live run on Nov 20, 2026: real boards A–D through the watchtower, with replay attacks from X. Browser bars are cropped out.

| File | What it shows |
|---|---|
| `screenshots/01_overview_normal_traffic.png` | Normal mesh traffic before any attack: 4 transmitters, 0 attacks stopped |
| `screenshots/02_replay_detected_and_blocked.png` | Replay attack (green bar) detected and blocked: 1 attack stopped, 4 s to block |
| `screenshots/03_mesh_map_and_rule_vs_ai.png` | Attacker blocked on the mesh map; Rule vs AI on real Nov 20 attacks: rule 0%, Isolation Forest 46%, Random Forest 100% caught |
| `screenshots/04_transmitters_and_activity_explanation.png` | Attacker marked BLOCKED; activity feed with the local LLM's plain-English explanation and "Rule: missed" badge |
| `screenshots/05_ask_the_watchtower_chatbot.png` | "Ask the watchtower" chatbot answering "Is the network safe right now?" |
| `screenshots/06_signal_strength_rssi.png` | Signal strength per radio; each board has a steady level, a new identity shows up at a different level |
| `screenshots/07_second_attacker_blocked.png` | A second replaying radio caught and blocked |
| `screenshots/08_about_this_ips_panel.png` | "About this IPS": model, 1 s windows, 2-window confirm, 60 s blocks, attacks it looks for, privacy |
| `screenshots/09_overview_after_two_attacks.png` | Overview after two attacks were stopped |

## Video

`6_Attack-IPS_FINAL.mp4` (15 s, 1080p, voiceover + captions): segment 6 of the demo video. A replay attack is detected and blocked in 4 s, and on real attacks from the boards the simple rule caught 0% while the Random Forest caught 100%.
