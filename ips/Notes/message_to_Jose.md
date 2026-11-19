Hey Jose, done on my side: IPS normal training with X powered off, spoof detection (signal jump + `id_ok` + MAC count, alert only), missing-KEYS alert (your 10e), and the O9 policy. What I still need:

1. Labelled attack recordings, even short ones (~2 min per attack) with a `.labels.jsonl`, in `ips/datasets/`. They're the only way to get real numbers for the video
2. A yes/no on the labels format in `ips/datasets/README.md`: one line per run, `{"label":"flood","node":"X","start":...,"end":...}`
3. Task 11 specs, especially the real routing attack (forged hop), so my training data matches
4. A question: a replayer uses many stolen pseudonyms, so a (pseudo AND mac) block barely stops it. Could a block for a `"?"` radio match on MAC only (pseudo = wildcard)?

Thanks!
