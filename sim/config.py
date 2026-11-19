"""
config.py - every knob for a GhostMesh sim run, plus the named experiment sweeps.

    python sim/config.py                  # list experiments and how many runs each makes
    python sim/config.py --check-layout   # build routing.c and check RtConfig matches rt_config_t

One RunConfig = one independent sim run (one topology, one seed, one traffic pattern).
An experiment is just a list of RunConfigs, so it can be split across processes.
The runner / engine is not here; this file only describes runs.
"""
import ctypes
import dataclasses
import hashlib
import itertools
import json
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROUTING_DIR = ROOT / "firmware" / "src" / "routing"
OUT_DIR = ROOT / "sim" / "out"                       # gitignored
LIB_PATH = OUT_DIR / "librouting.so"

FRAME_BYTES = 240


# ---- Channel: bit rate, airtime, loss, collisions ----------------------------

@dataclass(frozen=True)
class ChannelConfig:
    bitrate_kbps: int = 1000          # ESP-NOW default is 1 Mbps; stress tests go slower
    overhead_bytes: int = 43          # 802.11 / ESP-NOW framing around our 240 bytes (estimate)
    collisions: bool = True           # overlapping transmissions a receiver can hear destroy each other
    carrier_sense: bool = True        # wait if the channel sounds busy (real Wi-Fi does)
    base_loss: float = 0.0            # random loss on top of collisions, 0..1
    preamble_us: int = 192            # 802.11b long preamble + PLCP header at 1 Mbps (fixed per frame)

    # RSSI model (log-distance path loss). assumptions, tune against the boards' calibration
    rssi_at_1m: float = -40.0
    path_loss_exp: float = 2.7
    rssi_noise_db: float = 3.0

    @property
    def airtime_ms(self) -> float:
        # preamble is a fixed time; the payload scales with bit rate (kbps = bits per ms)
        return self.preamble_us / 1000 + (FRAME_BYTES + self.overhead_bytes) * 8 / self.bitrate_kbps


# ---- Traffic: constant vs bursty at the same average --------------------------

@dataclass(frozen=True)
class TrafficConfig:
    pattern: str = "constant"         # "constant" or "bursty"
    avg_rate_mps: float = 1.0         # network-wide messages per second, averaged over the run
    burst_on_s: float = 2.0           # bursty: sending phase length
    burst_off_s: float = 8.0          # bursty: idle phase length
    msg_bytes: int = 32               # laptop message length (<= 152)
    duration_s: float = 120.0         # how long traffic is generated
    drain_s: float = 15.0             # extra time after traffic stops, so retries can finish
    conversations: int = 0            # 0 = random sender→recipient every message; N = only N fixed pairs, both ways

    @property
    def burst_rate_mps(self) -> float:
        # rate during ON phases so the average matches avg_rate_mps
        if self.pattern != "bursty":
            return self.avg_rate_mps
        return self.avg_rate_mps * (self.burst_on_s + self.burst_off_s) / self.burst_on_s


# ---- Topology: random geometric graph ------------------------------------------

@dataclass(frozen=True)
class TopologyConfig:
    n_nodes: int = 20
    target_avg_degree: float = 5.0    # keeps density the same as n changes
    require_connected: bool = True    # re-draw the graph until every node can reach every other

    @property
    def radio_range(self) -> float:
        # unit square, so expected degree ~ n * pi * r^2. solve for r
        return (self.target_avg_degree / (3.141592653589793 * self.n_nodes)) ** 0.5


# ---- Routing: mirrors rt_config_t (defaults = rt_default_config) ------------------

@dataclass(frozen=True)
class RoutingParams:
    default_ttl: int = 16              # still TBD at the freeze
    hop_pad_max: int = 2
    k: int = 2
    jitter_rand_pct: int = 50
    jitter_min_ms: int = 10
    jitter_max_ms: int = 50
    rssi_weak: int = -90
    rssi_strong: int = -40
    cache_expiry_ms: int = 60000
    long_cache_expiry_ms: int = 180000
    insert_limit_per_s: int = 20
    ack_delay_max_ms: int = 400
    fresh_ms: int = 5000
    seq_memory_ms: int = 15000
    retry_backoff_ms: tuple = (1000, 2000, 4000)
    # v2 route learning (PROTOCOL.md §6). route_learning = 0 is plain v1 flooding
    route_learning: int = 0
    scope_margin: int = 1
    hello_interval_ms: int = 0
    neighbor_expiry_ms: int = 6000
    route_expiry_ms: int = 30000


class RtConfig(ctypes.Structure):
    """Byte-for-byte mirror of rt_config_t in routing.h.
    Same fields, same order, same types. If routing.h changes, change this in the same commit
    and rerun --check-layout: a mismatch gives wrong values, not an error."""
    _fields_ = [
        ("node_id",              ctypes.c_uint32),
        ("default_ttl",          ctypes.c_uint8),
        ("hop_pad_max",          ctypes.c_uint8),
        ("k",                    ctypes.c_uint8),
        ("jitter_rand_pct",      ctypes.c_uint8),
        ("jitter_min_ms",        ctypes.c_uint16),
        ("jitter_max_ms",        ctypes.c_uint16),
        ("rssi_weak",            ctypes.c_int8),
        ("rssi_strong",          ctypes.c_int8),
        ("cache_expiry_ms",      ctypes.c_uint32),
        ("long_cache_expiry_ms", ctypes.c_uint32),
        ("insert_limit_per_s",   ctypes.c_uint16),
        ("ack_delay_max_ms",     ctypes.c_uint16),
        ("fresh_ms",             ctypes.c_uint32),
        ("seq_memory_ms",        ctypes.c_uint32),
        ("retry_backoff_ms",     ctypes.c_uint32 * 3),
        ("route_learning",       ctypes.c_uint8),
        ("scope_margin",         ctypes.c_uint8),
        ("hello_interval_ms",    ctypes.c_uint16),
        ("neighbor_expiry_ms",   ctypes.c_uint32),
        ("route_expiry_ms",      ctypes.c_uint32),
    ]


def to_rt_config(r: RoutingParams, node_id: int) -> RtConfig:
    # builds the C struct for one node from the run's routing params
    c = RtConfig()
    c.node_id = node_id
    for f in dataclasses.fields(r):
        if f.name == "retry_backoff_ms":
            for i, v in enumerate(r.retry_backoff_ms):
                c.retry_backoff_ms[i] = v
        else:
            setattr(c, f.name, getattr(r, f.name))
    return c


# ---- One run --------------------------------------------------------------------

@dataclass(frozen=True)
class RunConfig:
    experiment: str = "smoke"
    seed: int = 0
    mode: str = "flood"               # "flood" now, "route_learning" once v2 exists
    topology: TopologyConfig = field(default_factory=TopologyConfig)
    channel: ChannelConfig = field(default_factory=ChannelConfig)
    traffic: TrafficConfig = field(default_factory=TrafficConfig)
    routing: RoutingParams = field(default_factory=RoutingParams)

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["routing"]["retry_backoff_ms"] = list(self.routing.retry_backoff_ms)
        if not self.traffic.conversations:
            del d["traffic"]["conversations"]     # left out at its default, so older runs keep their run_ids
        return d

    @property
    def run_id(self) -> str:
        # same config -> same id, so reruns overwrite instead of piling up
        blob = json.dumps(self.to_dict(), sort_keys=True).encode()
        return hashlib.sha1(blob).hexdigest()[:10]

    @property
    def out_path(self) -> Path:
        # one file per run, so parallel processes never write to the same file
        return OUT_DIR / self.experiment / f"{self.run_id}.jsonl"


# ---- Experiments ----------------------------------------------------------------
# Sweep values below are starting points to edit, not results.

SEEDS = 10


def _grid(name: str, base: RunConfig, seeds: int, **axes) -> list:
    """Every combination of the axes x every seed. Axis keys look like 'channel.bitrate_kbps'."""
    keys = list(axes)
    runs = []
    for combo in itertools.product(*axes.values()):
        cfg = replace(base, experiment=name)
        for key, value in zip(keys, combo):
            part, attr = key.split(".")
            cfg = replace(cfg, **{part: replace(getattr(cfg, part), **{attr: value})})
        runs += [replace(cfg, seed=s) for s in range(seeds)]
    return runs


def experiments(seeds: int = SEEDS) -> dict:
    base = RunConfig()
    return {
        # one quick run to check the engine end to end
        "smoke": _grid("smoke", base, 1),

        # does flooding hold up as the mesh grows (density kept constant)
        "scaling": _grid("scaling", base, seeds,
                         **{"topology.n_nodes": [20, 30, 40, 50]}),

        # slower channels: find the delivery knee as offered load rises.
        # 250 / 500 are near ESP32 Long Range mode (check exact rates in Espressif docs)
        "capacity": _grid("capacity", replace(base, topology=TopologyConfig(n_nodes=30)), seeds,
                          **{"channel.bitrate_kbps": [250, 300, 500, 600, 900, 1000],
                             "traffic.avg_rate_mps": [0.5, 1, 2, 4, 8]}),

        # same average load, constant vs bursty, at a slow and the default rate
        "burstiness": _grid("burstiness", replace(base, topology=TopologyConfig(n_nodes=30)), seeds,
                            **{"traffic.pattern": ["constant", "bursty"],
                               "traffic.avg_rate_mps": [1, 2, 4],
                               "channel.bitrate_kbps": [300, 1000]}),

        # suppression threshold, and whether it still works on a slow channel (§5.3 timing rule)
        "k_sweep": _grid("k_sweep", replace(base, topology=TopologyConfig(n_nodes=50)), seeds,
                         **{"routing.k": [1, 2, 3],
                            "channel.bitrate_kbps": [300, 1000]}),

        # how much of the jitter window is random
        "jitter_sweep": _grid("jitter_sweep", replace(base, topology=TopologyConfig(n_nodes=50)), seeds,
                              **{"routing.jitter_rand_pct": [12, 25, 50]}),

        # does a bigger TTL fix delivery in big meshes? (default_ttl includes the +2 for hop padding)
        "ttl_sweep": _grid("ttl_sweep", base, seeds,
                           **{"topology.n_nodes": [20, 50],
                              "routing.default_ttl": [5, 8, 12, 14, 16]}),

        # v1 flooding vs v2 route learning (not deployed: scoped TTL leaks recipient distance, §6).
        # random pairs only save on the ACK; a few ongoing conversations show the most v2 could save
        "v2_compare": _grid("v2_compare", base, seeds,
                            **{"topology.n_nodes": [20, 30, 40, 50],
                               "routing.route_learning": [0, 1],
                               "traffic.conversations": [0, 5]}),
    }


# ---- Layout check -----------------------------------------------------------------

# fields where the sim deliberately uses a different default than the boards (rt_default_config).
# check_layout skips these; the rest still catch any shifted or wrong-size field
SIM_DIFFERS_FROM_HW = {
    "default_ttl": "sim uses 16 so 50-node meshes are reachable (ttl_sweep); boards keep 5",
}


def check_layout() -> bool:
    """Fills an RtConfig with C's rt_default_config and compares every field to RoutingParams.
    Every field has a distinct value, so a shifted or wrong-size field shows up as a mismatch.
    Fields in SIM_DIFFERS_FROM_HW are intentional differences and are skipped."""
    # same build the sim uses (routing.c + shim.c), so this check can never leave a
    # stripped-down librouting.so behind for the runner to pick up
    import bindings                                       # imported here: bindings imports this file
    bindings.build(force=True)
    lib = bindings.load()
    # run as a script, this file's RtConfig is a separate class from config.RtConfig, so set it here
    lib.rt_default_config.argtypes = [ctypes.POINTER(RtConfig), ctypes.c_uint32]
    c = RtConfig()
    lib.rt_default_config(ctypes.byref(c), 7)

    want = to_rt_config(RoutingParams(), 7)
    bad = []
    for name, _ in RtConfig._fields_:
        if name in SIM_DIFFERS_FROM_HW:
            continue
        got, exp = getattr(c, name), getattr(want, name)
        if name == "retry_backoff_ms":
            got, exp = list(got), list(exp)
        if got != exp:
            bad.append(f"{name}: C={got} python={exp}")
    print("layout OK" if not bad else "layout MISMATCH:\n  " + "\n  ".join(bad))
    return not bad


if __name__ == "__main__":
    if "--check-layout" in sys.argv:
        sys.exit(0 if check_layout() else 1)
    total = 0
    for name, runs in experiments().items():
        total += len(runs)
        print(f"{name:13s} {len(runs):5d} runs")
    print(f"{'total':13s} {total:5d} runs")
