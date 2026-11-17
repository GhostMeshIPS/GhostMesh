Hey Jose, thanks for the notes, I've implemented them: tracking by `node`, your block format, the O9 rule (no auto-block of a whole node on spoof-like evidence), and `ips/datasets/` is ready. Yes please to `id_ok`. What I still need:

1. Task 11 attack specs (rates/timings, loud + quiet versions), especially the real routing attack (forged hop)
2. Labelled recordings for Wednesday in `ips/datasets/`. I proposed a labels format in `ips/datasets/README.md`, one line per run: `{"label":"flood","node":"X","start":...,"end":...}`. Does that work for your scripts?
3. Replay and spoof runnable on X
4. A question: a replayer sends frames with many different stolen pseudonyms, so a (pseudo AND mac) block barely stops it. Could a block for a `"?"` radio match on MAC only (pseudo = wildcard)?
