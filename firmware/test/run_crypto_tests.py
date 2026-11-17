#!/usr/bin/env python3
"""Build and run the gm_crypto host tests, then cross-check them in Python.

    python firmware/test/run_crypto_tests.py

Needs gcc (MSYS2 ucrt64, MinGW, Linux or macOS gcc/clang via GM_CC) and
`pip install pynacl cryptography`.

The Python half re-implements every formula from PROTOCOL.md §9 independently
(hashlib BLAKE2b, PyNaCl/libsodium, cryptography) and checks the C output byte
for byte. Those Python functions are also the reference for laptop tools
(keygen, pcap converter, IPS).
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from nacl.bindings import (crypto_aead_xchacha20poly1305_ietf_decrypt,
                           crypto_scalarmult, crypto_scalarmult_base)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

HERE = Path(__file__).resolve().parent
FW = HERE.parent
BUILD = HERE / "build"

# ---------------------------------------------------------------------------
# Reference implementation of PROTOCOL.md §9 (keep in sync with gm_crypto.c)
# ---------------------------------------------------------------------------

def be16(v): return v.to_bytes(2, "big")

def pseudonym(pseudo_secret, epoch):
    counter = 0
    while True:
        msg = b"GM-PSEUDO" + be16(epoch) + (bytes([counter]) if counter else b"")
        out = hashlib.blake2b(msg, key=pseudo_secret, digest_size=4).digest()
        if out not in (b"\x00" * 4, b"\xff" * 4):
            return out
        counter += 1

def mac(pseudo_secret, epoch):
    m = bytearray(hashlib.blake2b(b"GM-MAC" + be16(epoch), key=pseudo_secret, digest_size=6).digest())
    m[0] = (m[0] & 0xFC) | 0x02
    return bytes(m)

def link_tag(network_key, frame):
    return hashlib.blake2b(b"GM-LINK" + frame[:22] + frame[30:], key=network_key, digest_size=8).digest()

def root_key(my_sk, peer_pk):
    my_pk = crypto_scalarmult_base(my_sk)
    ss = crypto_scalarmult(my_sk, peer_pk)
    lo, hi = sorted([my_pk, peer_pk])
    return hashlib.blake2b(b"GM-ROOT" + ss + lo + hi, digest_size=32).digest()

def chain_start(root, epoch):
    return hashlib.blake2b(b"GM-RESYNC" + be16(epoch), key=root, digest_size=32).digest()

def message_key(ck):
    return hashlib.blake2b(b"GM-MSG", key=ck, digest_size=32).digest()

def ad(frame):
    return frame[0:10] + frame[20:22]

def inner_unpack(pt):
    return dict(sender=int.from_bytes(pt[0:4], "big"), recipient=int.from_bytes(pt[4:8], "big"),
                timestamp=int.from_bytes(pt[8:12], "big"), seq=int.from_bytes(pt[12:16], "big"),
                type=pt[16], len=pt[17], body=pt[18:18 + pt[17]], padding=pt[18 + pt[17]:])

def ctrl_message(region, payload_len):
    return b"GM-CTRL" + region[:9 + payload_len]

# ---------------------------------------------------------------------------
# Build + run the C tests
# ---------------------------------------------------------------------------

def find_cc():
    cc = os.environ.get("GM_CC") or shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if not cc and os.name == "nt" and Path(r"C:\msys64\ucrt64\bin\gcc.exe").exists():
        cc = r"C:\msys64\ucrt64\bin\gcc.exe"
    if not cc:
        sys.exit("No C compiler found. Install gcc (e.g. MSYS2 ucrt64) or set GM_CC.")
    return cc

def build_and_run():
    cc = find_cc()
    env = dict(os.environ)
    env["PATH"] = str(Path(cc).parent) + os.pathsep + env.get("PATH", "")   # MSYS2 gcc needs its DLLs
    BUILD.mkdir(exist_ok=True)
    exe = BUILD / ("test_crypto.exe" if os.name == "nt" else "test_crypto")
    cmd = [cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-pedantic", "-Werror",
           "-I", str(FW / "src" / "crypto"), "-I", str(FW / "src" / "routing"), "-I", str(FW / "lib" / "monocypher"),
           str(FW / "src" / "crypto" / "gm_crypto.c"), str(FW / "lib" / "monocypher" / "monocypher.c"),
           str(FW / "lib" / "monocypher" / "monocypher-ed25519.c"), str(HERE / "test_crypto.c"), "-o", str(exe)]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"Compile failed:\n{r.stdout}{r.stderr}")
    r = subprocess.run([str(exe)], env=env, capture_output=True, text=True)
    return r.returncode, r.stdout

# ---------------------------------------------------------------------------
# Cross-checks (same keys as test_crypto.c)
# ---------------------------------------------------------------------------

def fill(start, n=32): return bytes((start + i) & 0xFF for i in range(n))

def cross_check(vecs):
    results = []
    def ok(cond, name): results.append((bool(cond), name))

    NET, PS_A = fill(0x20), fill(0x00)
    SK_A, SK_C = fill(0x10), fill(0x70)
    pk_A, pk_C = crypto_scalarmult_base(SK_A), crypto_scalarmult_base(SK_C)

    ok(pseudonym(fill(0x00), 0x0102).hex() == "ac341587", "py: pseudonym vector")
    ok(mac(fill(0x00), 0x0102).hex() == "6aa707ca0edd", "py: MAC vector")
    ok(link_tag(fill(0x20), bytes(range(240))).hex() == "152ee8ad612ca586", "py: link_tag vector")

    root = root_key(SK_A, pk_C)
    ok(root == root_key(SK_C, pk_A), "py: root key is symmetric")
    ok(vecs["root_AC"] == root, "C == py: root[A,C]")
    mk = message_key(chain_start(root, 0x0102))
    ok(vecs["mk_AC_0102"] == mk, "C == py: message key for epoch 0x0102")

    f = vecs["frame_AC"]
    ok(link_tag(NET, f) == f[22:30], "C == py: link_tag of the encrypted frame")
    ok(f[12:16] == pseudonym(PS_A, 0x0102), "C == py: src_pseudo")
    nonce, ct, tag = f[30:54], f[54:224], f[224:240]
    try:
        pt = crypto_aead_xchacha20poly1305_ietf_decrypt(ct + tag, ad(f), nonce, mk)
        inner = inner_unpack(pt)
        ok(len(pt) == 170, "py: plaintext is 170 bytes")
        ok(inner["sender"] == 1 and inner["recipient"] == 3 and inner["seq"] == 7 and
           inner["timestamp"] == 123456789 and inner["type"] == 1 and inner["body"] == b"meet at 9",
           "py (libsodium) decrypts the C frame; inner header matches")
        ok(inner["padding"] == b"\x00" * (170 - 18 - 9), "py: body is zero-padded")
    except Exception as e:   # nacl raises CryptoError on a bad tag
        ok(False, f"py (libsodium) decrypts the C frame ({e})")

    region = vecs["ctrl_block"]
    wt = Ed25519PrivateKey.from_private_bytes(fill(0xA0))
    wt_pk = wt.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    msg = ctrl_message(region, 37)
    sig = region[9 + 37: 9 + 37 + 64]
    try:
        wt.public_key().verify(sig, msg)
        ok(True, "py (cryptography) verifies the C BLOCK signature")
    except InvalidSignature:
        ok(False, "py (cryptography) verifies the C BLOCK signature")
    ok(wt.sign(msg) == sig, "C == py: Ed25519 signature bytes (deterministic)")
    ok(region[1:9] == (1731264000456).to_bytes(8, "big"), "py: issued_at_ms is big-endian")
    ok(len(wt_pk) == 32, "py: watchtower public key derived")
    return results

def main():
    code, out = build_and_run()
    c_results = [(l.startswith("PASS"), l[5:]) for l in out.splitlines() if l.startswith(("PASS", "FAIL"))]
    vecs = {m.group(1): bytes.fromhex(m.group(2)) for m in re.finditer(r"^VEC (\S+) ([0-9a-f]+)$", out, re.M)}
    py_results = cross_check(vecs)

    for good, name in c_results + py_results:
        print(f"{'PASS' if good else 'FAIL'}  {name}")
    total = len(c_results) + len(py_results)
    bad = sum(1 for g, _ in c_results + py_results if not g)
    if "SUMMARY" not in out:
        print("C test binary did not finish (crash?)"); bad += 1
    print(f"\n{total - bad}/{total} passed")
    sys.exit(1 if bad or code else 0)

if __name__ == "__main__":
    main()
