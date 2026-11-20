"""Shared library for the attacker X scripts (decision 18). Network #2 / Jose.

X's firmware (firmware/src/attacker/main_x.cpp) is a radio passthrough with no keys. Everything an
insider can do happens here, on the laptop:

    keys     load_keys()            X's secrets from firmware/config/keys/keys_X.h (gitignored)
    crypto   pseudonym(), mac_for(), link_tag()     same formulas as gm_crypto (PROTOCOL §9.3–9.4)
    frames   Frame                  parse / build the 240-byte cleartext header, re-sign link_tag
    time     MeshClock              mesh clock + current epoch, learned from sniffed TIME beacons
    radio    XRadio                 serial link to X: sniff frames, transmit frames, set the MAC
             MockRadio              same interface, no hardware (tests, dry runs)
    pacing   paced()                send at a fixed rate for a fixed time (floods capped at 100/s, 16e)
    labels   LabelLog               ground truth for ips/datasets/*.labels.jsonl, on the mesh clock

Labels format (ips/datasets/README.md): {"label": "flood", "node": "X", "start": s, "end": s}, plus an
optional "variant". "label" stays one of flood / replay / spoof / routing so the IPS can use it.
"""
import hashlib
import hmac
import json
import os
import queue
import re
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
KEYS_DIR = REPO / "firmware" / "config" / "keys"

FRAME_BYTES = 240
DATA, HELLO, CTRL, KEYS = 1, 2, 3, 4
TYPE_NAMES = {DATA: "DATA", HELLO: "HELLO", CTRL: "CTRL", KEYS: "KEYS"}
CTRL_TIME, CTRL_BLOCK = 1, 2
EPOCH_MS = 60_000
DEFAULT_TTL = 5                 # boards: ttl + hop = 5 on every DATA/KEYS frame (routing.c, §12)
MAX_RATE_HZ = 100               # 16e: keep floods under what the watchtower's log can carry
LABELS = {"flood", "replay", "spoof", "routing"}


# ---- keys -------------------------------------------------------------------------------

@dataclass
class XKeys:
    name: str
    node_id: int
    network_key: bytes
    pseudo_secret: bytes
    x25519_sk: bytes
    watchtower_pk: bytes


def _c_arrays(text):
    out = {}
    for name, body in re.findall(r"static const uint8_t (GM_\w+)\[\d+\]\s*=\s*\{([^}]*)\}", text):
        out[name] = bytes(int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})", body))
    return out


def load_keys(path=None):
    """X's keys from the keygen header (default firmware/config/keys/keys_X.h)."""
    path = Path(path) if path else KEYS_DIR / "keys_X.h"
    text = path.read_text(encoding="utf-8")
    arr = _c_arrays(text)
    name = re.search(r'#define GM_NODE_NAME\s+"(\w)"', text)
    nid = re.search(r"#define GM_NODE_ID\s+(\d+)u", text)
    need = ("GM_NETWORK_KEY", "GM_PSEUDO_SECRET", "GM_X25519_SK", "GM_WATCHTOWER_PK")
    missing = [n for n in need if len(arr.get(n, b"")) != 32]
    if missing or not name or not nid:
        raise ValueError(f"{path}: not a node keys header (missing {missing or 'name/id'})")
    return XKeys(name.group(1), int(nid.group(1)), arr["GM_NETWORK_KEY"], arr["GM_PSEUDO_SECRET"],
                 arr["GM_X25519_SK"], arr["GM_WATCHTOWER_PK"])


# ---- crypto (must match firmware/src/crypto/gm_crypto.c) ----------------------------------

RESERVED_PSEUDOS = {0x00000000, 0xFFFFFFFF}


def pseudonym(pseudo_secret, epoch):
    """BLAKE2b(key=pseudo_secret, 4, "GM-PSEUDO" || epoch_be16 [|| counter]) as an int (§9.3)."""
    msg = b"GM-PSEUDO" + struct.pack(">H", epoch & 0xFFFF)
    counter = 0
    while True:
        m = msg + (bytes([counter]) if counter else b"")
        p = int.from_bytes(hashlib.blake2b(m, key=pseudo_secret, digest_size=4).digest(), "big")
        if p not in RESERVED_PSEUDOS:
            return p
        counter += 1


def mac_for(pseudo_secret, epoch):
    """Radio MAC for an epoch (§9.3): BLAKE2b(key, 6, "GM-MAC" || epoch_be16), locally administered."""
    m = bytearray(hashlib.blake2b(b"GM-MAC" + struct.pack(">H", epoch & 0xFFFF),
                                  key=pseudo_secret, digest_size=6).digest())
    m[0] = (m[0] & 0xFC) | 0x02
    return bytes(m)


def link_tag(network_key, frame):
    """BLAKE2b(key=network_key, 8, "GM-LINK" || frame[0:22] || frame[30:240]) (§9.4)."""
    return hashlib.blake2b(b"GM-LINK" + bytes(frame[0:22]) + bytes(frame[30:240]),
                           key=network_key, digest_size=8).digest()


def mac_str(mac):
    return ":".join(f"{b:02x}" for b in mac)


def mac_bytes(s):
    b = bytes(int(x, 16) for x in s.split(":"))
    if len(b) != 6:
        raise ValueError(f"bad MAC {s!r}")
    return b


# ---- frames -----------------------------------------------------------------------------

@dataclass
class Frame:
    """The 240-byte frame. Header fields are editable; `rest` is bytes 30..239 (nonce, body, tag)."""
    ver_type: int = DATA
    flags: int = 0
    msg_id: bytes = b"\0" * 8
    ttl: int = DEFAULT_TTL
    hop: int = 0
    src_pseudo: int = 0
    next_hop: int = 0
    epoch: int = 0
    tag: bytes = b"\0" * 8
    rest: bytes = b"\0" * 210

    @classmethod
    def parse(cls, raw):
        raw = bytes(raw)
        if len(raw) != FRAME_BYTES:
            raise ValueError(f"frame is {len(raw)} bytes, not 240")
        return cls(raw[0], raw[1], raw[2:10], raw[10], raw[11],
                   int.from_bytes(raw[12:16], "big"), int.from_bytes(raw[16:20], "big"),
                   int.from_bytes(raw[20:22], "big"), raw[22:30], raw[30:240])

    def to_bytes(self):
        b = (bytes([self.ver_type & 0xFF, self.flags & 0xFF]) + bytes(self.msg_id)
             + bytes([self.ttl & 0xFF, self.hop & 0xFF])
             + (self.src_pseudo & 0xFFFFFFFF).to_bytes(4, "big") + (self.next_hop & 0xFFFFFFFF).to_bytes(4, "big")
             + (self.epoch & 0xFFFF).to_bytes(2, "big") + bytes(self.tag) + bytes(self.rest))
        assert len(b) == FRAME_BYTES
        return b

    def sign(self, network_key):
        """Recompute link_tag over the current fields (do this LAST, after every edit)."""
        self.tag = link_tag(network_key, self.to_bytes())
        return self

    def link_ok(self, network_key):
        return hmac.compare_digest(link_tag(network_key, self.to_bytes()), bytes(self.tag))

    @property
    def type_name(self):
        return TYPE_NAMES.get(self.ver_type, str(self.ver_type))

    def ctrl_time_ms(self):
        """issued_at_ms of a CTRL TIME frame, else None (cleartext, §9.8)."""
        if self.ver_type == CTRL and self.rest[24] == CTRL_TIME:
            return int.from_bytes(self.rest[25:33], "big")
        return None


def random_data_frame(network_key, src_pseudo, epoch, ttl=DEFAULT_TTL, hop=0, flags=0):
    """A DATA frame no recipient can decrypt: random msg_id, nonce, ciphertext and tag, valid link_tag."""
    f = Frame(DATA, flags, os.urandom(8), ttl, hop, src_pseudo, 0, epoch, b"\0" * 8, os.urandom(210))
    return f.sign(network_key)


# ---- mesh clock ---------------------------------------------------------------------------

class MeshClock:
    """Mesh time = laptop time + offset, learned from sniffed TIME beacons (or set directly).

    The IPS laptop sets W's clock from its own time, so on that laptop the offset is ~0. On another
    laptop the TIME beacons give the offset (error ≈ flood delay, ~100 ms; fine for 60 s epochs and labels).
    """

    def __init__(self):
        self.offset_ms = None
        self._lock = threading.Lock()

    @staticmethod
    def laptop_ms():
        return time.time() * 1000.0

    def on_time_beacon(self, issued_at_ms, heard_at_laptop_ms=None):
        off = issued_at_ms - (heard_at_laptop_ms if heard_at_laptop_ms is not None else self.laptop_ms())
        with self._lock:
            self.offset_ms = off if self.offset_ms is None else max(self.offset_ms, off)

    def assume_laptop_clock(self):
        """Use when this laptop is the one that set W's clock (the IPS laptop)."""
        with self._lock:
            self.offset_ms = 0.0

    @property
    def synced(self):
        return self.offset_ms is not None

    def now_ms(self):
        if self.offset_ms is None:
            raise RuntimeError("mesh clock unknown: wait for a TIME beacon or call assume_laptop_clock()")
        return self.laptop_ms() + self.offset_ms

    def now_s(self):
        return self.now_ms() / 1000.0

    def epoch(self):
        return int(self.now_ms() // EPOCH_MS) & 0xFFFF


# ---- radio ------------------------------------------------------------------------------

@dataclass
class Heard:
    """One frame X heard."""
    raw: bytes
    mac: str
    rssi: int
    rx_us: int
    laptop_ms: float
    frame: Frame = field(init=False)

    def __post_init__(self):
        self.frame = Frame.parse(self.raw)


class _RadioBase:
    def __init__(self, clock=None):
        self.clock = clock or MeshClock()
        self.heard = queue.Queue(maxsize=5000)
        self.events = queue.Queue(maxsize=500)
        self._listeners = []
        self.sent = 0

    def on_frame(self, fn):
        """Call fn(Heard) for every frame X hears (on the reader thread; keep it quick)."""
        self._listeners.append(fn)

    def _deliver(self, h):
        t = h.frame.ctrl_time_ms()
        if t is not None:
            self.clock.on_time_beacon(t, h.laptop_ms)
        for fn in self._listeners:
            fn(h)
        try:
            self.heard.put_nowait(h)
        except queue.Full:
            try:
                self.heard.get_nowait()
            except queue.Empty:
                pass
            self.heard.put_nowait(h)

    def send(self, frame):
        raise NotImplementedError

    def set_mac(self, mac):
        raise NotImplementedError


class XRadio(_RadioBase):
    """Serial link to the X board (firmware/src/attacker/main_x.cpp)."""

    def __init__(self, port, clock=None):
        super().__init__(clock)
        import serial                                   # pyserial, only needed for real hardware
        self.ser = serial.Serial()
        self.ser.port, self.ser.baudrate, self.ser.timeout = port, 115200, 0.5
        self.ser.dtr = False                            # opening with DTR/RTS toggling resets an ESP32-S3
        self.ser.rts = False
        self.ser.open()
        self._wlock = threading.Lock()
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._reader, daemon=True)
        self._t.start()

    def _reader(self):
        while not self._stop.is_set():
            try:
                line = self.ser.readline()
            except Exception:
                if self._stop.is_set():
                    return
                time.sleep(0.2)
                continue
            if not line:
                continue
            try:
                ev = json.loads(line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if ev.get("ev") == "rx":
                try:
                    h = Heard(bytes.fromhex(ev["raw"]), ev.get("mac", ""), int(ev.get("rssi", 0)),
                              int(ev.get("rx_us", 0)), MeshClock.laptop_ms())
                except (KeyError, ValueError):
                    continue
                self._deliver(h)
            else:
                try:
                    self.events.put_nowait(ev)
                except queue.Full:
                    pass

    def _cmd(self, obj):
        line = json.dumps(obj, separators=(",", ":")) + "\n"     # compact: a tx line must stay < 512 bytes
        with self._wlock:
            self.ser.write(line.encode())

    def _wait_event(self, name, timeout):
        end = time.time() + timeout
        while time.time() < end:
            try:
                ev = self.events.get(timeout=max(0.01, end - time.time()))
            except queue.Empty:
                break
            if ev.get("ev") == name:
                return ev
            if ev.get("ev") == "error":
                raise RuntimeError(f"X reported an error: {ev}")
        raise TimeoutError(f"no '{name}' event from X within {timeout} s")

    def send(self, frame):
        raw = frame.to_bytes() if isinstance(frame, Frame) else bytes(frame)
        if len(raw) != FRAME_BYTES:
            raise ValueError("frames are 240 bytes")
        self._cmd({"cmd": "tx", "hex": raw.hex()})
        self.sent += 1

    def set_mac(self, mac):
        mac = mac if isinstance(mac, str) else mac_str(mac)
        self._cmd({"cmd": "set_mac", "mac": mac})
        return self._wait_event("mac", 3.0)

    def sniff(self, on=True):
        self._cmd({"cmd": "sniff", "on": bool(on)})
        return self._wait_event("status", 2.0)

    def status(self):
        self._cmd({"cmd": "status"})
        return self._wait_event("status", 2.0)

    def close(self):
        self._stop.set()
        try:
            self.ser.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class MockRadio(_RadioBase):
    """No hardware: records what would be sent; inject() plays frames as if X heard them."""

    def __init__(self, clock=None):
        super().__init__(clock)
        self.tx_log = []                    # (laptop_ms, raw bytes)
        self.mac = "02:00:00:00:00:58"

    def send(self, frame):
        raw = frame.to_bytes() if isinstance(frame, Frame) else bytes(frame)
        if len(raw) != FRAME_BYTES:
            raise ValueError("frames are 240 bytes")
        self.tx_log.append((MeshClock.laptop_ms(), raw))
        self.sent += 1

    def set_mac(self, mac):
        self.mac = mac if isinstance(mac, str) else mac_str(mac)
        return {"ev": "mac", "mac": self.mac, "outage_us": 0}

    def inject(self, raw, mac="02:00:00:00:00:01", rssi=-60, laptop_ms=None):
        self._deliver(Heard(bytes(raw), mac, rssi, 0, laptop_ms if laptop_ms is not None else MeshClock.laptop_ms()))

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass


# ---- pacing -----------------------------------------------------------------------------

def paced(radio, make_frame, rate_hz, duration_s, stop=None, allow_fast=False):
    """Send make_frame() every 1/rate_hz seconds for duration_s. Returns the number sent.

    Rates above MAX_RATE_HZ (100/s, decision 16e) are refused unless allow_fast=True, because the
    watchtower's log can't carry more and the IPS would lag.
    """
    if rate_hz <= 0 or duration_s < 0:
        raise ValueError("rate must be > 0 and duration >= 0")
    if rate_hz > MAX_RATE_HZ and not allow_fast:
        raise ValueError(f"{rate_hz}/s is above the {MAX_RATE_HZ}/s demo cap (16e); pass allow_fast=True")
    period = 1.0 / rate_hz
    t0 = time.perf_counter()
    n = 0
    while True:
        if stop is not None and stop.is_set():
            break
        due = t0 + n * period
        if due - t0 >= duration_s:
            break
        wait = due - time.perf_counter()
        if wait > 0.002:
            time.sleep(wait - 0.001)
        while time.perf_counter() < due:
            pass
        radio.send(make_frame())
        n += 1
    return n


# ---- labels -----------------------------------------------------------------------------

class LabelLog:
    """Writes ground-truth rows to a .labels.jsonl next to the recording, on the mesh clock."""

    def __init__(self, path, clock):
        self.path = Path(path)
        self.clock = clock

    def add(self, label, start_s, end_s, node="X", variant=None):
        if label not in LABELS:
            raise ValueError(f"label must be one of {sorted(LABELS)}")
        if end_s < start_s:
            raise ValueError("end before start")
        row = {"label": label, "node": node, "start": round(start_s, 3), "end": round(end_s, 3)}
        if variant:
            row["variant"] = variant
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        return row

    @contextmanager
    def run(self, label, node="X", variant=None):
        """with labels.run("flood", variant="loud"): ...attack...  -> one row covering the block."""
        if label not in LABELS:
            raise ValueError(f"label must be one of {sorted(LABELS)}")
        start = self.clock.now_s()
        try:
            yield
        finally:
            self.add(label, start, self.clock.now_s(), node, variant)
