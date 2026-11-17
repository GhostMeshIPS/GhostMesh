import pandas as pd # pandas: library for working with tables of data

#Load the log into a DataFrame: one row per packet, one column per field
df = pd.read_json("normal_session1.jsonl", lines=True) #the lines=True means JSONL

# Show floats with 3 decimals instead of scientific notation (so t shows miliseconds)
pd.set_option("display.float_format", "{:.3f}".format)

#1. First look
print(df.head()) #first 5 rows: check the columns and values look right
print(df.shape) # (rows, columns): expect (597, 11)

#2. Packets per node - should be ~150 each
# groupby("node") splits the table into one group per node; .size() counts the number of rows in each group
print(df.groupby("node").size())

#3. RSSI per node -- mean should be near -48 / -60 / -67 / -75, std near 2
# For each node, take the rssi column and compute its average and spread
# mean = the node's typical signal strength; std = how much it wobbles.
print(df.groupby("node")["rssi"].agg(["mean", "std"]))

#4. Time between HELLOs per node -- should be ~2.0 s
# gap= this packet's time minus the same node's previous packet time.
# grouptby first so we never subtract a different node's packet
# Each node's first packet has no previous packet, so the gap is NaN (blank)
# This is our first feature: a flood would make gaps tiny.
df["gap"] = df.groupby("node")["t"].diff()

# Summarize gaps per node. min/max catch outlies the mean would hide
# Expect mean ~2.0, min >= 1.8, max <= 2.2 (HELLO_PERIOD +- JITTER in synth.py)
print(df.groupby("node")["gap"].agg(["mean", "std", "min", "max"]))