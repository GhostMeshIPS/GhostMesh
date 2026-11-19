"""
bindings.py - ctypes mirrors of routing.h and loading librouting.so.

Every Structure here must match routing.h exactly (fields, order, types).
check_sizes() compares them against sizeof() from C; it runs on every load.
"""
import ctypes
import subprocess
from ctypes import CFUNCTYPE, POINTER, c_bool, c_char_p, c_int, c_int8, c_size_t, c_uint8, c_uint16, c_uint32, c_void_p

from config import LIB_PATH, OUT_DIR, ROOT, ROUTING_DIR, RtConfig

SHIM = ROOT / "sim" / "shim.c"


# ---- Struct mirrors -------------------------------------------------------------

class RtFrame(ctypes.Structure):
    # rt_frame_t: 240 bytes, all byte arrays, offsets in PROTOCOL.md §9.4
    _fields_ = [
        ("ver_type",   c_uint8),
        ("flags",      c_uint8),
        ("msg_id",     c_uint8 * 8),
        ("ttl",        c_uint8),
        ("hop_count",  c_uint8),
        ("src_pseudo", c_uint8 * 4),
        ("next_hop",   c_uint8 * 4),
        ("epoch",      c_uint8 * 2),
        ("link_tag",   c_uint8 * 8),
        ("nonce",      c_uint8 * 24),
        ("ciphertext", c_uint8 * 170),
        ("aead_tag",   c_uint8 * 16),
    ]


class RtInner(ctypes.Structure):
    # rt_inner_t: the decrypted inner header + body
    _fields_ = [
        ("sender_id",    c_uint32),
        ("recipient_id", c_uint32),
        ("timestamp",    c_uint32),
        ("seq",          c_uint32),
        ("type",         c_uint8),
        ("len",          c_uint8),
        ("body",         c_uint8 * 152),
    ]


# platform callback signatures, in rt_platform_t order
TRANSMIT  = CFUNCTYPE(None,     c_void_p, POINTER(RtFrame))
NOW_MS    = CFUNCTYPE(c_uint32, c_void_p)
RANDOM    = CFUNCTYPE(c_uint32, c_void_p)
IS_SYNCED = CFUNCTYPE(c_bool,   c_void_p)
T_START   = CFUNCTYPE(None,     c_void_p, c_uint32, c_uint32)
T_CANCEL  = CFUNCTYPE(None,     c_void_p, c_uint32)
LINK_OK   = CFUNCTYPE(c_bool,   c_void_p, POINTER(RtFrame))
LINK_TAG  = CFUNCTYPE(None,     c_void_p, POINTER(RtFrame), POINTER(c_uint8))
ENCRYPT   = CFUNCTYPE(c_bool,   c_void_p, POINTER(RtInner), POINTER(RtFrame))
DECRYPT   = CFUNCTYPE(c_bool,   c_void_p, POINTER(RtFrame), POINTER(RtInner))
BLOCKED   = CFUNCTYPE(c_bool,   c_void_p, POINTER(RtFrame), POINTER(c_uint8))
KEYS      = CFUNCTYPE(None,     c_void_p, POINTER(RtFrame))
CTRL      = CFUNCTYPE(c_bool,   c_void_p, POINTER(RtFrame))
PSEUDO    = CFUNCTYPE(None,     c_void_p, POINTER(c_uint8))
EPOCH     = CFUNCTYPE(c_uint16, c_void_p)
DELIVER   = CFUNCTYPE(None,     c_void_p, POINTER(RtInner))
NOTIFY    = CFUNCTYPE(None,     c_void_p, c_uint32, c_int)
LOG       = CFUNCTYPE(None,     c_void_p, c_int, POINTER(RtFrame))


class RtPlatform(ctypes.Structure):
    # rt_platform_t: same 18 function pointers, same order
    _fields_ = [
        ("transmit", TRANSMIT), ("now_ms", NOW_MS), ("random_u32", RANDOM), ("is_synced", IS_SYNCED),
        ("timer_start", T_START), ("timer_cancel", T_CANCEL),
        ("link_tag_ok", LINK_OK), ("compute_link_tag", LINK_TAG), ("encrypt", ENCRYPT), ("try_decrypt", DECRYPT),
        ("is_blocked", BLOCKED), ("keys_receive", KEYS), ("ctrl_verify", CTRL),
        ("my_pseudonym", PSEUDO), ("current_epoch", EPOCH),
        ("deliver", DELIVER), ("notify", NOTIFY), ("log", LOG),
    ]


# rt_status_t values for notify()
STATUS_SENT, STATUS_DELIVERED, STATUS_FAILED = 0, 1, 2


# ---- Build + load ---------------------------------------------------------------

def _needs_build() -> bool:
    if not LIB_PATH.exists():
        return True
    built = LIB_PATH.stat().st_mtime
    sources = [ROUTING_DIR / "routing.c", ROUTING_DIR / "routing.h", SHIM]
    return any(s.stat().st_mtime > built for s in sources)


def build(force: bool = False) -> None:
    # compiles routing.c + shim.c into sim/out/librouting.so (only when sources changed)
    if not force and not _needs_build():
        return
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC", "-I", str(ROUTING_DIR),
                    str(ROUTING_DIR / "routing.c"), str(SHIM), "-o", str(LIB_PATH)], check=True)


def load() -> ctypes.CDLL:
    """Builds if needed, loads the library, sets argument types, and checks struct sizes."""
    build()
    lib = ctypes.CDLL(str(LIB_PATH))

    lib.sim_node_size.restype = c_size_t
    lib.sim_frame_size.restype = c_size_t
    lib.sim_inner_size.restype = c_size_t
    lib.sim_config_size.restype = c_size_t
    lib.sim_log_name.argtypes = [c_int]
    lib.sim_log_name.restype = c_char_p

    lib.rt_default_config.argtypes = [POINTER(RtConfig), c_uint32]
    lib.rt_init.argtypes = [c_void_p, POINTER(RtConfig), POINTER(RtPlatform), c_void_p]
    lib.rt_on_receive.argtypes = [c_void_p, POINTER(RtFrame), POINTER(c_uint8), c_int8]
    lib.rt_send.argtypes = [c_void_p, c_uint32, POINTER(c_uint8), c_uint8]
    lib.rt_send.restype = c_uint32
    lib.rt_on_timer.argtypes = [c_void_p, c_uint32]

    check_sizes(lib)
    return lib


def check_sizes(lib: ctypes.CDLL) -> None:
    # a size mismatch means a mirror above is out of date with routing.h
    pairs = [("rt_frame_t", RtFrame, lib.sim_frame_size()),
             ("rt_inner_t", RtInner, lib.sim_inner_size()),
             ("rt_config_t", RtConfig, lib.sim_config_size())]
    bad = [f"{name}: C {c} bytes, python {ctypes.sizeof(py)} bytes" for name, py, c in pairs if ctypes.sizeof(py) != c]
    if bad:
        raise RuntimeError("struct mirror out of date with routing.h:\n  " + "\n  ".join(bad))


def log_names(lib: ctypes.CDLL, count: int = 64) -> dict:
    # event number -> name, read from C
    names = {}
    for i in range(count):
        n = lib.sim_log_name(i).decode()
        if n != "UNKNOWN":
            names[i] = n
    return names
