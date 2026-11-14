import pandas as pd

WINDOW = 1.0 # seconds per window

def build_features(df):
    df = df.sort_values("t").copy() # copy so we don't modify the original DataFrame

    # Which window each packet belongs to: whole seconds of the timestamp itself.
    # Absolute (not "since the first packet") so a window means the same second
    # whether we process a whole file or a live stream that started mid-session.
    df["window"] = (df["t"] // WINDOW).astype(int)

    # Time since this node's previous packet, computed across the whole session
    # (before windowing, so the first packet in a window still gets its gap)
    df["gap"] = df.groupby("mac")["t"].diff()

    aggs = dict(
        pkt_count = ("t", "size"), #Packets this second
        hello_count = ("type", lambda s: (s == "HELLO").sum()), #HELLOs this second
        rssi_mean = ("rssi", "mean"),
        rssi_std = ("rssi", "std"),
        ttl_max = ("ttl", "max"),
        hop_min = ("hop", "min"),
        gap_mean = ("gap", "mean"),
        link_fail = ("link_ok", lambda s: (~s).sum()), #count of False
    )
    # Labels only exist in synthetic/labeled data; live watchtower data has none
    if "label" in df.columns:
        aggs["label"] = ("label", lambda s: s[s != "normal"].iloc[0] if (s != "normal").any() else "normal")

    feats = df.groupby(["mac", "window"]).agg(**aggs).reset_index() #turns mac/window back into normal columns

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
