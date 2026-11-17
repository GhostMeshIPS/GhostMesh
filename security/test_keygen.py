#!/usr/bin/env python3
"""Tests for security/keygen.py (task 15). Runs keygen into a temp folder, never the real keys dir.

    python security/test_keygen.py

Checks the Python output (keys consistent, fingerprints right, roster holds no secrets,
overwrite protection), then compiles the generated headers against firmware/src/crypto
to prove two boards derive the same root key and the watchtower's signature verifies.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base
from nacl.signing import SigningKey

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
FW = REPO / "firmware"
KEYGEN = HERE / "keygen.py"

results = []
def ok(cond, name):
    results.append((bool(cond), name))

def fingerprint(key):
    h = hashlib.blake2b(b"GM-FP" + key, digest_size=4).hexdigest()
    return f"{h[:4]}-{h[4:]}"

def arrays(text):
    """name -> bytes for every 'static const uint8_t NAME[n] = {...};' in a header."""
    out = {}
    for m in re.finditer(r"static const uint8_t (\w+)\[\d+\] = \{([^}]*)\};", text):
        out[m.group(1)] = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", m.group(2)))
    return out

def peers(text):
    return [(int(m.group(1)), m.group(2), bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", m.group(3))))
            for m in re.finditer(r"\{ (\d+)u, '(\w)', \{([^}]*)\} \}", text)]

def keygen(*args):
    return subprocess.run([sys.executable, str(KEYGEN), *args], capture_output=True, text=True)

def find_cc():
    cc = os.environ.get("GM_CC") or shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if not cc and os.name == "nt" and Path(r"C:\msys64\ucrt64\bin\gcc.exe").exists():
        cc = r"C:\msys64\ucrt64\bin\gcc.exe"
    return cc

def compile_run(cc, src, keys_dir, work):
    env = dict(os.environ)
    env["PATH"] = str(Path(cc).parent) + os.pathsep + env.get("PATH", "")
    c = work / "prog.c"; c.write_text(src, encoding="utf-8")
    exe = work / ("prog.exe" if os.name == "nt" else "prog")
    lib, cr = FW / "lib" / "monocypher", FW / "src" / "crypto"
    r = subprocess.run([cc, "-std=c99", "-O1", "-Wall", "-Werror", "-Wno-unused-const-variable",
                        "-I", str(keys_dir), "-I", str(cr), "-I", str(FW / "src" / "routing"), "-I", str(lib),
                        str(c), str(cr / "gm_crypto.c"), str(cr / "gm_ratchet.c"), str(lib / "monocypher.c"),
                        str(lib / "monocypher-ed25519.c"), "-o", str(exe)], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr
    r = subprocess.run([str(exe)], env=env, capture_output=True, text=True)
    return r.stdout, r.stderr

NODE_PROG = r'''
#include <stdio.h>
#include "gm_crypto.h"
#include "keys_%s.h"
static void rng(void *c, uint8_t *o, size_t n) { (void)c; for (size_t i = 0; i < n; i++) o[i] = (uint8_t)i; }
int main(void) {
    gm_crypto_t g; char fp[10];
    gm_init(&g, GM_NODE_ID, GM_NETWORK_KEY, GM_PSEUDO_SECRET, GM_X25519_SK, GM_WATCHTOWER_PK, rng, NULL);
    for (int i = 0; i < GM_PEER_COUNT; i++) if (!gm_add_peer(&g, GM_PEERS[i].id, GM_PEERS[i].pk)) return 1;
    gm_fingerprint(g.x_pk, fp); printf("fp %%s\n", fp);
    gm_fingerprint(GM_NETWORK_KEY, fp); printf("net %%s\n", fp);
    for (int i = 0; i < GM_PEER_COUNT; i++) {
        printf("root %%u ", (unsigned)g.peers[i].node_id);
        for (int k = 0; k < 32; k++) printf("%%02x", g.peers[i].root[k]);
        printf("\n");
    }
    return 0;
}
'''

WT_PROG = r'''
#include <stdio.h>
#include "gm_crypto.h"
#include "keys_W.h"
static void rng(void *c, uint8_t *o, size_t n) { (void)c; for (size_t i = 0; i < n; i++) o[i] = (uint8_t)i; }
int main(void) {
    gm_crypto_t g; uint8_t region[GM_INNER_BYTES], st; uint64_t at; const uint8_t *pl; size_t pn; char fp[10];
    gm_init(&g, GM_NODE_ID, GM_NETWORK_KEY, GM_NETWORK_KEY, GM_NETWORK_KEY, GM_WATCHTOWER_PK, rng, NULL);
    gm_ctrl_sign(&g, GM_WATCHTOWER_SK, GM_CTRL_TIME, 1731264000000ull, NULL, 0, region);
    gm_fingerprint(GM_WATCHTOWER_PK, fp);
    printf("wt %s\nsig %d\n", fp, gm_ctrl_verify(&g, region, &st, &at, &pl, &pn) ? 1 : 0);
    return 0;
}
'''

def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        keys, roster_path, work = tmp / "keys", tmp / "roster.json", tmp / "work"
        work.mkdir()

        r = keygen("--out", str(keys), "--roster", str(roster_path))
        ok(r.returncode == 0, f"keygen runs ({r.stderr.strip()[:80]})")
        files = sorted(p.name for p in keys.glob("keys_*.h"))
        ok(files == ["keys_A.h", "keys_B.h", "keys_C.h", "keys_D.h", "keys_W.h", "keys_X.h"],
           "one header per board A-D, X, plus watchtower W")
        roster = json.loads(roster_path.read_text())
        rtext = roster_path.read_text().lower()

        H = {f[5]: keys.joinpath(f).read_text() for f in files}
        A = {n: arrays(H[n]) for n in H}
        net = A["A"]["GM_NETWORK_KEY"]
        ok(all(A[n]["GM_NETWORK_KEY"] == net for n in H), "every board has the same network key")
        ok(len({A[n]["GM_PSEUDO_SECRET"] for n in "ABCDX"}) == 5 and len({A[n]["GM_X25519_SK"] for n in "ABCDX"}) == 5,
           "pseudonym secrets and X25519 keys are all distinct")

        seed_pk = A["W"]["GM_WATCHTOWER_SK"]
        wt_pk = A["W"]["GM_WATCHTOWER_PK"]
        ok(bytes(SigningKey(seed_pk[:32]).verify_key) == wt_pk == seed_pk[32:], "watchtower SK = seed || PK, PK matches")
        ok(all(A[n]["GM_WATCHTOWER_PK"] == wt_pk for n in "ABCDX"), "every node has the watchtower's public key")
        ok("GM_X25519_SK" not in H["W"] and "GM_WATCHTOWER_SK" not in "".join(H[n] for n in "ABCDX"),
           "watchtower holds no X25519 key; nodes hold no signing key")

        wt_nodes = {name: ps for _, name, ps in peers(H["W"])}
        ok(all(wt_nodes.get(n) == A[n]["GM_PSEUDO_SECRET"] for n in "ABCDX"), "watchtower holds every node's pseudonym secret")

        by_name = {n["name"]: n for n in roster["nodes"]}
        for n in "ABCDX":
            pk = crypto_scalarmult_base(A[n]["GM_X25519_SK"])
            ok(by_name[n]["x25519_pk"] == pk.hex() and by_name[n]["fingerprint"] == fingerprint(pk),
               f"roster: {n}'s public key and fingerprint match its secret")
            pl = peers(H[n])
            ok(sorted(name for _, name, _ in pl) == sorted(set("ABCDX") - {n}) and
               all(ppk == crypto_scalarmult_base(A[name]["GM_X25519_SK"]) for _, name, ppk in pl),
               f"{n}'s peer list = every other node with the right public keys")
        ok(roster["watchtower"]["fingerprint"] == fingerprint(wt_pk) and roster["network_key_fingerprint"] == fingerprint(net),
           "roster: watchtower and network fingerprints")
        secrets_hex = [A[n][k].hex() for n in A for k in A[n] if k in ("GM_NETWORK_KEY", "GM_PSEUDO_SECRET", "GM_X25519_SK")]
        secrets_hex.append(seed_pk[:32].hex())
        ok(not any(s in rtext for s in secrets_hex), "roster.json contains no secret key material")
        ok(by_name["X"]["role"].startswith("attacker"), "X is listed as the insider attacker")

        r = keygen("--out", str(keys), "--roster", str(roster_path))
        ok(r.returncode != 0 and arrays(keys.joinpath("keys_A.h").read_text())["GM_NETWORK_KEY"] == net,
           "refuses to overwrite existing keys without --force")
        ok(keygen("--out", str(tmp / "k2"), "--roster", str(tmp / "r2.json"), "--nodes", "A,Q").returncode != 0,
           "rejects unknown board names")

        cc = find_cc()
        if not cc:
            ok(False, "C compiler found (needed for the header compile checks)")
        else:
            outA, err = compile_run(cc, NODE_PROG % "A", keys, work)
            outC, errC = compile_run(cc, NODE_PROG % "C", keys, work)
            ok(outA is not None and outC is not None, f"generated headers compile with gm_crypto ({(err or errC or '')[:120]})")
            if outA and outC:
                rootA = dict(re.findall(r"root (\d+) ([0-9a-f]{64})", outA))
                rootC = dict(re.findall(r"root (\d+) ([0-9a-f]{64})", outC))
                ok(rootA.get("3") and rootA.get("3") == rootC.get("1"), "board A and board C derive the same root key")
                ok(re.search(r"fp (\S+)", outA).group(1) == by_name["A"]["fingerprint"],
                   "board A's boot fingerprint (computed in C) matches the roster")
                ok(re.search(r"net (\S+)", outA).group(1) == roster["network_key_fingerprint"], "network fingerprint matches")
            outW, errW = compile_run(cc, WT_PROG, keys, work)
            ok(outW is not None and "sig 1" in outW, f"watchtower header signs a CTRL frame that verifies ({(errW or '')[:120]})")
            ok(outW is not None and f"wt {roster['watchtower']['fingerprint']}" in outW, "watchtower fingerprint matches")

        r = keygen("--out", str(keys), "--roster", str(roster_path), "--force")
        ok(r.returncode == 0 and arrays(keys.joinpath("keys_A.h").read_text())["GM_NETWORK_KEY"] != net,
           "--force re-keys everything with fresh keys")

    for good, name in results:
        print(f"{'PASS' if good else 'FAIL'}  {name}")
    bad = sum(1 for g, _ in results if not g)
    print(f"\n{len(results) - bad}/{len(results)} passed")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
