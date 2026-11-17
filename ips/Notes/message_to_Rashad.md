Hey Rashad, for the IPS I need:

1. You and Jose to agree on the packet types: DATA/ACK/HELLO/BLOCK (routing.h) vs DATA/HELLO/CTRL/KEYS (Jose's design). The IPS accepts both for now
2. The default TTL (still TBD in PROTOCOL.md §12)
3. Sim logs of normal traffic (chat, relays, ACKs) in the watchtower format, with `pseudo` = transmitter
4. An "unplug B" recording labelled normal, since it's on camera and must not get flagged
5. How fast nodes reroute after a BLOCK, for the video

Optional: node drop reasons (BAD_LINK_TAG, BLOCKED...) in the log. Thanks!
