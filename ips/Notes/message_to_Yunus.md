Hey Yunus, the watchtower firmware + §10 are great. The IPS now follows it: `live.py --port` opens W with DTR/RTS low, sends `set_time` on connect and again on `clock_not_set` (the Nov 18 open item), drops pre-clock lines, uses `id_ok`, and logs `block_sent`/errors. What I still need:

1. The Nov 18 smoke log `ips/data/raw/smoke_nov18.jsonl` (and Nov 17 if you have it). It's the first real data, so I can check the IPS against it today
2. A time slot with W plugged into my laptop to run `live.py --port` and test a real BLOCK end to end
3. Who is building X's attack firmware, and is it ready?
4. When A–D get reflashed with the factory-MAC fix (until then, first-sync frames show up as `?` radios)
5. Confirm we're using the dedicated W board, not D doubling as W (if D, I start the IPS with `--trusted D`)

Thanks!
