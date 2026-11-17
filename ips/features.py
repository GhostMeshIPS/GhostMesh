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


class MsgIdTracker:
    """Remembers every msg_id for a few minutes and stamps each packet with what it means.

    Needs a longer memory than the IPS's 10-second buffer (replays come minutes later),
    so it's fed packets one at a time, in arrival order, and keeps its own history:
      first_copy      True if nobody transmitted this msg_id before -> this radio STARTED it
                      (False = it's relaying, or repeating, someone's message)
      msg_age         seconds since the msg_id was first heard (0 for a new one)
      same_tx_repeat  True if THIS radio already sent this msg_id. Honest relays send each
                      message once and retries use a new msg_id, so a repeat is a replay sign.
    """
    MEMORY_S = 180      # same as the nodes' long replay cache (Jose, PROTOCOL.md 9.7)

    def __init__(self):
        self.seen = {}          # msg_id -> [first time heard, set of identities that sent it]
        self.last_prune = 0.0

    def annotate(self, pkt):
        t, mid, who = pkt["t"], pkt["msg_id"], identity_of(pkt)
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


def annotate_msg_ids(df):
    """Run the tracker over a whole recorded session (offline: training / evaluation)."""
    tracker = MsgIdTracker()
    rows = [tracker.annotate(dict(r)) for r in df.sort_values("t").to_dict("records")]
    return pd.DataFrame(rows, index=df.sort_values("t").index)


def build_features(df):
    df = df.sort_values("t")
    if "first_copy" not in df.columns:      # live.py stamps packets as they arrive; files get it here
        df = annotate_msg_ids(df)
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

    aggs = dict(
        pkt_count = ("t", "size"), #Packets this second
        hello_count = ("type", lambda s: (s == "HELLO").sum()), #HELLOs this second
        rssi_mean = ("rssi", "mean"),
        rssi_std = ("rssi", "std"),
        ttl_max = ("ttl", "max"),
        hop_min = ("hop", "min"),
        gap_mean = ("gap", "mean"),
        link_fail = ("link_ok", lambda s: (~s.astype(bool)).sum()), #count of False
        orig_count = ("first_copy", "sum"),                         # messages it STARTED (not relays)
        stale_count = ("msg_age", lambda s: (s > STALE_AFTER).sum()),  # msg_ids first heard > 60 s ago
        dup_tx_count = ("same_tx_repeat", "sum"),                   # msg_ids it had already sent before
        # Not features (the model never sees them): the identity seen on air right now,
        # needed to block an unknown radio by its exact (pseudo, mac) pair.
        mac = ("mac", "last"),
        pseudo = ("pseudo", "last"),
    )
    # Labels only exist in synthetic/labeled data; live watchtower data has none
    if "label" in df.columns:
        aggs["label"] = ("label", lambda s: s[s != "normal"].iloc[0] if (s != "normal").any() else "normal")

    feats = df.groupby(["node", "window"]).agg(**aggs).reset_index() #turns node/window back into normal columns
    for col in ("orig_count", "dup_tx_count"):
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
