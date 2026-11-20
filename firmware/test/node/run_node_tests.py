#!/usr/bin/env python3
"""Build and run the node integration test (routing + crypto + node glue, no hardware).

    python firmware/test/node/run_node_tests.py        # -v to print every event

Generates throwaway keys with security/keygen.py into a temp folder (never the real keys),
compiles board_keys.c once per board, and runs test_node.c. Needs gcc and pynacl.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FW = HERE.parent.parent
REPO = FW.parent
CC = os.environ.get("GM_CC", "gcc")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="gm_node_test_"))
    try:
        keys = tmp / "keys"
        subprocess.run([sys.executable, str(REPO / "security" / "keygen.py"), "--nodes", "A,B,C,D,X",
                        "--out", str(keys), "--roster", str(tmp / "roster.json")],
                       check=True, stdout=subprocess.DEVNULL)
        inc = ["-I", str(FW / "src" / "node"), "-I", str(FW / "src" / "watchtower"), "-I", str(FW / "src" / "routing"),
               "-I", str(FW / "src" / "crypto"), "-I", str(FW / "lib" / "monocypher"), "-I", str(keys)]
        flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g"]
        objs = []
        for board in "ABCDX":
            o = tmp / f"keys_{board}.o"
            subprocess.run([CC, *flags, *inc, f'-DGM_KEYS_FILE="keys_{board}.h"', f"-DGM_KEYS_FN=keys_{board}",
                            "-c", str(FW / "src" / "node" / "board_keys.c"), "-o", str(o)], check=True)
            objs.append(str(o))
        srcs = [HERE / "test_node.c", HERE / "wt_keys.c", FW / "src" / "node" / "gm_node.c",
                FW / "src" / "watchtower" / "gm_watch.c",
                FW / "src" / "routing" / "routing.c", FW / "src" / "crypto" / "gm_crypto.c",
                FW / "src" / "crypto" / "gm_ratchet.c", FW / "lib" / "monocypher" / "monocypher.c",
                FW / "lib" / "monocypher" / "monocypher-ed25519.c"]
        exe = tmp / "test_node"
        # Monocypher is vendored byte-exact, so don't hold it to -Werror -Wextra
        mono = [s for s in srcs if "monocypher" in str(s)]
        for s in mono:
            o = tmp / (s.stem + ".o")
            subprocess.run([CC, "-std=c11", "-O2", "-c", str(s), "-o", str(o)], check=True)
            objs.append(str(o))
        subprocess.run([CC, *flags, *inc, *[str(s) for s in srcs if s not in mono], *objs, "-o", str(exe)],
                       check=True)
        return subprocess.run([str(exe), *sys.argv[1:]]).returncode
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
