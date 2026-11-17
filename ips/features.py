import pandas as pd

from schema import UNKNOWN_NODE

WINDOW = 1.0 # seconds per window


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


def build_features(df):
    df = add_identity(df.sort_values("t"))

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
        link_fail = ("link_ok", lambda s: (~s).sum()), #count of False
        # Not features (the model never sees them): the identity seen on air right now,
        # needed to block an unknown radio by its exact (pseudo, mac) pair.
        mac = ("mac", "last"),
        pseudo = ("pseudo", "last"),
    )
    # Labels only exist in synthetic/labeled data; live watchtower data has none
    if "label" in df.columns:
        aggs["label"] = ("label", lambda s: s[s != "normal"].iloc[0] if (s != "normal").any() else "normal")

    feats = df.groupby(["node", "window"]).agg(**aggs).reset_index() #turns node/window back into normal columns

    #std of 1 packet is undefined (NaN), so treat it as "no wobble"
    feats["rssi_std"] = feats["rssi_std"].fillna(0)
    #Each node's very first packet has no gap --> drop those rows
    feats = feats.dropna(subset=["gap_mean"])
    return feats

if __name__ == "__main__":
    # df = pd.read_json("normal_session1.jsonl", lines=True)   # clean data only
    df = pd.read_json("flood_session1.jsonl", lines=True)      # normal + flood
    feats = build_features(df)
    print(feats.head(10))
    print(feats.shape)
    print(feats.describe())
    print(feats.groupby("label")[["pkt_count", "gap_mean"]].agg(["mean", "count"]))
