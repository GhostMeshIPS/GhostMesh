# Monocypher 4.0.2 (vendored)

Crypto library for GhostMesh (decision 13 in `docs/planning/project-breakdown.md` §4.7). Unmodified upstream files.
Licence: dual 2-clause BSD / CC0 public domain, see `LICENCE.md`.

| File | Provides |
|---|---|
| `monocypher.c/.h` | keyed BLAKE2b (pseudonyms, `link_tag`, KDFs), XChaCha20-Poly1305 (`crypto_aead_lock`/`unlock`), X25519, `crypto_wipe` |
| `monocypher-ed25519.c/.h` | standard Ed25519 / SHA-512 (RFC 8032) for signed CTRL frames |

## Provenance

- Source: <https://monocypher.org/download/monocypher-4.0.2.tar.gz> (939,996 bytes)
- Tarball SHA-512 (matches `monocypher-4.0.2.tar.gz.sha512` published on monocypher.org):
  `bf275d4c53ff94af6cdc723a4e002e9f080f4d1436c86c76bb37870b34807f1d7b32331d8ff8a1aeb369e946f3769021e03e63efac25b82efc5abf54dc084714`
- Cross-checked against GitHub tag `4.0.2` (commit `0d85f98c`): the source files are identical except line 1's
  version stamp (`__git__` → `4.0.2`, added by the release script).
- File SHA-256 (as committed):

```
afe2b098c8569577a84488e0b98d276d1fba6506adea68bb9241a52111734c59  monocypher.c
f78bb31255cfb7beba66afd2137f5194c8a025cf40488b6cc1e295234d43f374  monocypher.h
7c9b16056cbd27521919e8a6f56a228808b9e718afc42e3d33f28c08e5abdee2  monocypher-ed25519.c
bd546edcd468d64e28caa3dbf4b1d6bfad7435c0ce994723fd81aae26405121b  monocypher-ed25519.h
5f8360e4c06ddcc584bdb4b210c6af824c4bb301e6a9a521869b6d90795ca4b3  LICENCE.md
```

## Verified on the laptop (2026-11-17)

- Upstream test suite (`tests/test.c` from the tarball) built with
  `gcc -std=c99 -O2 -Wall -Wextra -pedantic`: **0 warnings, "All tests OK!"**
- Interop with the Python tools: keyed BLAKE2b (our pseudonym and `link_tag` test vectors), XChaCha20-Poly1305
  with associated data (vs. PyNaCl/libsodium), X25519 (vs. PyNaCl) and Ed25519 (vs. `cryptography`):
  **all 8 outputs match byte for byte.** The interop test moves into the repo with task 14.

## Not yet done

- **ESP32-S3 build and benchmark:** waiting for Comp E's toolchain choice (Arduino-ESP32 vs. ESP-IDF).
  The code is plain C99 with no dependencies. With PlatformIO, `lib/` is picked up automatically; with ESP-IDF,
  wrap these files in a component.

## Updating

Replace all five files from a newer release, re-check its published SHA-512 and the GitHub tag, update the
hashes above, and re-run the tests. Never edit these files in place.
