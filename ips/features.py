from collections import deque
from statistics import median

import pandas as pd

from schema import UNKNOWN_NODE, WATCHTOWER

WINDOW = 1.0 # seconds per window
STALE_AFTER = 60   # a msg_id heard again after this many seconds is suspicious (seen-cache expiry)


def identity_of(pkt):
    """Who we track a single packet as: the node letter, or its MAC if there's no usable letter."""
    node = pkt.get("node")
    return node if node and node == node and node != UNKNOWN_NODE else pkt["mac"]   # node == node: not NaN


def add_identity(df):
    """Give every packet a stable `node` column: who we track it as.

    The watchtower tags each packet with the real node ("A".."D", "X") because it can
    work out pseudonyms. MAC and pseudonym rotate every 60 s; the node letter doesn't,
    so grouping by it lets the IPS follow one board across rotations.
    Fallback to the MAC when there's no usable letter:
      * the field is missing (older logs, or a sim without it),
      * it's "?" (no real node matches). Using the MAC keeps two different unknown
        radios apart instead of lumping them into one "?" identity.
    """
    df = df.copy()
    if "node" in df.columns:
        known = df["node"].notna() & (df["node"] != UNKNOWN_NODE)
        df["node"] = df["node"].where(known, df["mac"])
    else:
        df["node"] = df["mac"]
    return df


class PacketTracker:
    """Long-term memory the 10-second buffer can't hold. Stamps each packet with what it means.

    Fed packets one at a time, in arrival order (live.py on arrival, or a whole file offline),
    so training and live see exactly the same values.

    msg_id memory (replays come minutes later):
      first_copy      True if nobody transmitted this msg_id before -> this radio STARTED it
                      (False = it's relaying, or repeating, someone's message)
      msg_age         seconds since the msg_id was first heard (0 for a new one)
      same_tx_repeat  True if THIS radio already sent this msg_id. Honest relays send each
                      message once and retries use a new msg_id, so a repeat is a replay sign.
    Signal memory per identity (spoofing: a second radio using someone's identity):
      rssi_dev        dB between this packet's signal and that identity's usual level (median of
                      its last RSSI_HISTORY packets). Boards don't move, so honest values stay small.
    """
    MEMORY_S = 180      # same as the nodes' long replay cache (Jose, PROTOCOL.md 9.7)
    RSSI_HISTORY = 120  # packets per identity (~40 s of a busy node): long enough that a
                        # spoofer's own packets can't quickly drag the "usual level" towards it
    RSSI_MIN = 10       # need this many packets before judging deviations

    def __init__(self):
        self.seen = {}          # msg_id -> [first time heard, set of identities that sent it]
        self.rssi = {}          # identity -> its recent RSSI values
        self.last_prune = 0.0

    def annotate(self, pkt):
        t, mid, who = pkt["t"], pkt["msg_id"], identity_of(pkt)
        history = self.rssi.setdefault(who, deque(maxlen=self.RSSI_HISTORY))
        pkt["rssi_dev"] = abs(pkt["rssi"] - median(history)) if len(history) >= self.RSSI_MIN else 0.0
        history.append(pkt["rssi"])
        rec = self.seen.get(mid)
        if rec is None:
            pkt.update(first_copy=True, msg_age=0.0, same_tx_repeat=False)
            self.seen[mid] = [t, {who}]
        else:
            pkt.update(first_copy=False, msg_age=round(t - rec[0], 3), same_tx_repeat=who in rec[1])
            rec[1].add(who)
        if t - self.last_prune > 10:                      # forget msg_ids older than MEMORY_S
            self.seen = {m: r for m, r in self.seen.items() if t - r[0] <= self.MEMORY_S}
            self.last_prune = t
        return pkt


def annotate_packets(df):
    """Run the tracker over a whole recorded session (offline: training / evaluation)."""
    tracker = PacketTracker()
    rows = [tracker.annotate(dict(r)) for r in df.sort_values("t").to_dict("records")]
    return pd.DataFrame(rows, index=df.sort_values("t").index)


def build_features(df):
    df = df.sort_values("t")
    if "first_copy" not in df.columns:      # live.py stamps packets as they arrive; files get it here
        df = annotate_packets(df)
    df = add_identity(df)
    # The watchtower's own frames (its TIME beacons) aren't traffic to judge. They're dropped
    # only AFTER the msg_id stamping, so a node relaying a beacon still counts as a relay.
    df = df[df["node"] != WATCHTOWER].copy()

    # Which window each packet belongs to: whole seconds of the timestamp itself.
    # Absolute (not "since the first packet") so a window means the same second
    # whether we process a whole file or a live stream that started mid-session.
    df["window"] = (df["t"] // WINDOW).astype(int)

    # Time since this node's previous packet, computed across the whole session
    # (before windowing, so the first packet in a window still gets its gap).
    # Per node, not per MAC: with MACs rotating, a per-MAC gap would restart every minute.
    df["gap"] = df.groupby("node")["t"].diff()
    # TTL on HELLOs only (0 for other packets). Honest HELLOs are one-hop and always carry TTL 1,
    # whatever the network's default TTL is; DATA legitimately carries up to the default (16 in
    # Rashad's sim), which would hide a fake TTL of 10 inside ttl_max.
    df["hello_ttl"] = df["ttl"].where(df["type"] == "HELLO", 0)

    aggs = dict(
        pkt_count = ("t", "size"), #Packets this second
        hello_count = ("type", lambda s: (s == "HELLO").sum()), #HELLOs this second
        rssi_mean = ("rssi", "mean"),
        rssi_std = ("rssi", "std"),
        ttl_max = ("ttl", "max"),
        hello_ttl_max = ("hello_ttl", "max"),                       # 1 = honest; more = fake route advert
        hop_min = ("hop", "min"),
        gap_mean = ("gap", "mean"),
        link_fail = ("link_ok", lambda s: (~s.astype(bool)).sum()), #count of False
        orig_count = ("first_copy", "sum"),                         # messages it STARTED (not relays)
        stale_count = ("msg_age", lambda s: (s > STALE_AFTER).sum()),  # msg_ids first heard > 60 s ago
        dup_tx_count = ("same_tx_repeat", "sum"),                   # msg_ids it had already sent before
        rssi_dev_max = ("rssi_dev", "max"),                         # biggest jump from its usual signal (dB)
        mac_count = ("mac", "nunique"),                             # MACs using this identity this second
        # Not features (the model never sees them): the identity seen on air right now,
        # needed to block an unknown radio by its exact (pseudo, mac) pair.
        mac = ("mac", "last"),
        pseudo = ("pseudo", "last"),
    )
    # Labels only exist in synthetic/labeled data; live watchtower data has none
    if "label" in df.columns:
        aggs["label"] = ("label", lambda s: s[s != "normal"].iloc[0] if (s != "normal").any() else "normal")

    feats = df.groupby(["node", "window"]).agg(**aggs).reset_index() #turns node/window back into normal columns
    for col in ("orig_count", "dup_tx_count", "mac_count"):
        feats[col] = feats[col].astype(int)

    #std of 1 packet is undefined (NaN), so treat it as "no wobble"
    feats["rssi_std"] = feats["rssi_std"].fillna(0)
    #Each node's very first packet has no gap --> drop those rows
    feats = feats.dropna(subset=["gap_mean"])
    return feats

if __name__ == "__main__":
    # df = pd.read_json("normal_session1.jsonl", lines=True)   # clean data only
    from ingest import read_file
    df = read_file("flood_session1.jsonl")      # normal + flood
    feats = build_features(df)
    print(feats.head(10))
    print(feats.shape)
    print(feats.describe())
    print(feats.groupby("label")[["pkt_count", "orig_count", "gap_mean"]].agg(["mean", "count"]))
