import json
import os
import joblib                         # saves/loads trained models to disk
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from features import build_features   # reuse the Step 3 feature builder
from ingest import read_file          # reads logs through schema.py, so every field keeps its exact type

# Baseline detector: fixed thresholds a human would write from the protocol spec.
# Normal nodes send ~1 packet per window, the flood ~30, so 15 sits safely between.
RATE_THRESHOLD = 15  # packets per window
# HELLOs are sent every 2 s (0.5/s), so 2+ in one second means someone is beaconing too fast.
HELLO_THRESHOLD = 1  # HELLOs per window
# No rule on ttl_max on purpose: real DATA packets legitimately carry TTL > 1, so a
# "ttl_max > 1" rule would only work on our HELLO-only synthetic data (unfair to the rule).
RULE_NAME = f"Rule (pkts > {RATE_THRESHOLD} or HELLOs > {HELLO_THRESHOLD})"

# Columns the ML models learn from: behaviour only. Left out on purpose:
#   mac, window -> identifiers, not behaviour (the model would memorise who/when)
#   label       -> the answer; using it would be cheating
#   pred_*      -> other detectors' outputs
FEATURES = ["pkt_count", "hello_count", "rssi_mean", "rssi_std",
            "ttl_max", "hop_min", "gap_mean", "link_fail",
            "hello_ttl_max",  # TTL on HELLOs: honest = 1 whatever the default TTL, so a fake route stands out
            "orig_count",     # messages it started itself: separates a flooder from the relays passing it on
            "stale_count",    # msg_ids first heard > 60 s ago: replay
            "dup_tx_count",   # msg_ids it had already sent: replay
            "rssi_dev_max",   # jump from this identity's usual signal: spoof (a second radio)
            "mac_count",      # MACs behind one identity in one second: spoof without a copied MAC
            "id_mismatch"]    # watchtower's id_ok = false: MAC doesn't belong to the pseudonym (spoof, replay)

RF_PATH = "models/rf.joblib"            # where the trained Random Forest is saved for live.py
IF_PATH = "models/iforest.joblib"       # trained Isolation Forest (for the rule-vs-AI comparison)
BENCH_PATH = "models/benchmark.json"    # test-session scores of all 3 detectors (for the dashboard)

# Real hardware recordings with NO attacks in them (git-ignored, ask the team for copies).
# Nov 18 smoke test: A, B, C + W, ~18 min, X never powered on. Missing files are skipped.
REAL_NORMAL_LOGS = ["data/raw/smoke_nov18.jsonl"]


def rule_detect(feats):
    """Flag every window that breaks either threshold (too many packets OR too many HELLOs).

    Vectorized: compares whole columns at once and returns a True/False Series
    (one value per window). `|` means OR, element by element.
    """
    return (feats["pkt_count"] > RATE_THRESHOLD) | (feats["hello_count"] > HELLO_THRESHOLD)


def evaluate(y_true, y_pred):
    """y_true: True/False 'is it really an attack'; y_pred: True/False 'did we flag it'."""
    # The four crosstab cells (& = AND, ~ = NOT, .sum() counts the Trues)
    tp = (y_true & y_pred).sum()         # attack AND flagged      -> caught
    fp = ((~y_true) & y_pred).sum()      # normal AND flagged      -> false alarm
    fn = (y_true & (~y_pred)).sum()      # attack AND not flagged  -> missed
    tn = ((~y_true) & (~y_pred)).sum()   # normal AND not flagged  -> correctly ignored

    # Precision: when we raise an alarm, how often is it a real attack?
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    # Recall: of all real attacks, how many did we catch?
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    # False-positive rate: of all normal windows, how many did we wrongly flag?
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    # (the "if ... else 0.0" guards against dividing by zero, e.g. a detector that flags nothing)

    return {"precision": precision, "recall": recall, "fpr": fpr,
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


def print_scores(name, scores):
    """Print one detector's scores on a single line."""
    print(f"{name:<8} precision {scores['precision']:.3f}   "
          f"recall {scores['recall']:.3f}   fpr {scores['fpr']:.3f}")


def train_iforest(train_feats):
    """Learn what 'normal' looks like from clean (attack-free) windows. No labels used."""
    model = IsolationForest(
        n_estimators=100,     # number of random trees in the forest
        contamination=0.01,   # expect ~1% of windows to look odd -> sets the alarm threshold
        random_state=42,      # same random cuts every run (like random.seed)
    )
    model.fit(train_feats[FEATURES])   # fit = train
    return model


def iforest_detect(model, feats):
    """Flag windows the model thinks don't fit 'normal'."""
    raw = model.predict(feats[FEATURES])   # sklearn's convention: 1 = normal, -1 = anomaly
    # Convert to True/False and keep the same row index as feats so it lines up
    return pd.Series(raw == -1, index=feats.index)


def train_rf(train_feats):
    """Supervised: learn to NAME the attack from labeled windows."""
    model = RandomForestClassifier(
        n_estimators=100,     # 100 decision trees that vote
        random_state=42,      # reproducible results
    )
    # Unlike the Isolation Forest, we pass the answers (labels) in as well
    model.fit(train_feats[FEATURES], train_feats["label"])
    return model


def rf_detect(model, feats):
    """Predicted class for each window: 'normal', 'flood' or 'routing'."""
    return pd.Series(model.predict(feats[FEATURES]), index=feats.index)


def flagged_table(feats, pred_col, who):
    """Truth vs. prediction: rows = real label, columns = what the detector said.
      flood/flagged  = attacks caught       flood/ignored  = attacks missed
      normal/ignored = correctly ignored    normal/flagged = false alarms
    """
    return pd.crosstab(
        feats["label"],
        feats[pred_col].map({True: "flagged", False: "ignored"}),  # True/False -> readable words
        rownames=["actual"],
        colnames=[f"{who} said"],
    )


if __name__ == "__main__":
    # --- Train the Isolation Forest ONCE, on clean normal traffic only ---
    # Training doesn't depend on which attack file we test, so it stays outside the loop.
    # Fake normal + real normal: fake-only flagged 17% of real traffic (real boards differ from
    # our simulation in small ways), real-only would make the fake benchmark below unfair.
    real_logs = [p for p in REAL_NORMAL_LOGS if os.path.exists(p)]
    real = (pd.concat([build_features(read_file(p)) for p in real_logs], ignore_index=True)
            if real_logs else None)
    train_feats = build_features(read_file("normal_session1.jsonl"))
    if real is not None:
        train_feats = pd.concat([train_feats, real], ignore_index=True)
    print(f"Isolation Forest trains on {len(train_feats)} normal windows "
          f"({len(real) if real is not None else 0} of them from real hardware)")
    model = train_iforest(train_feats)

    # --- Test both detectors on each attack session (data the model has never seen) ---
    for path in ["flood_session1.jsonl", "slowflood_session1.jsonl"]:
        feats = build_features(read_file(path))   # packets -> windows
        y_true = feats["label"] != "normal"                      # True = real attack window

        feats["pred_rule"] = rule_detect(feats)                  # threshold baseline
        feats["pred_iforest"] = iforest_detect(model, feats)     # ML anomaly detector

        print(f"\n=== {path} ===")
        flood = feats[feats["label"] == "flood"]
        print(f"flood windows: {len(flood)}   avg pkt_count: {flood['pkt_count'].mean():.1f}")
        print_scores("rule", evaluate(y_true, feats["pred_rule"]))
        print_scores("iforest", evaluate(y_true, feats["pred_iforest"]))
        print(flagged_table(feats, "pred_rule", "rule"))
        print(flagged_table(feats, "pred_iforest", "iforest"))

    # --- Step 9: Random Forest — train on one session, test on a DIFFERENT one ---
    train = build_features(read_file("train_session.jsonl"))
    test = build_features(read_file("test_session.jsonl"))
    rf = train_rf(train)
    test["pred_rf"] = rf_detect(rf, test)

    print("\n=== Random Forest: trained on train_session, tested on test_session ===")
    # Precision/recall for EACH class, not just attack vs. normal
    print(classification_report(test["label"], test["pred_rf"], digits=3))

    # Confusion table: rows = truth, columns = what the RF said
    print(pd.crosstab(test["label"], test["pred_rf"], rownames=["actual"], colnames=["rf said"]))

    # How much each feature helped the trees decide (sums to 1.0)
    print("\nfeature importance:")
    importance = pd.Series(rf.feature_importances_, index=FEATURES).sort_values(ascending=False)
    print(importance.round(3).to_string())

    # Save the trained models so live.py can load them instead of retraining every start
    os.makedirs("models", exist_ok=True)
    joblib.dump(rf, RF_PATH)
    joblib.dump(model, IF_PATH)
    print(f"\nsaved Random Forest -> {RF_PATH}, Isolation Forest -> {IF_PATH}")

    # --- Benchmark: all 3 detectors on the SAME unseen test session (slow flood, routing, replay, B unplugged) ---
    # Attack vs. normal for every detector, so the numbers are directly comparable.
    y_test = test["label"] != "normal"
    bench = {
        RULE_NAME: evaluate(y_test, rule_detect(test)),
        "Isolation Forest": evaluate(y_test, iforest_detect(model, test)),
        "Random Forest": evaluate(y_test, test["pred_rf"] != "normal"),
    }
    print("\n=== Benchmark on test_session (slow flood, routing abuse, replay, node B unplugged) ===")
    for who, s in bench.items():
        print_scores(who[:8], s)
    with open(BENCH_PATH, "w") as f:
        json.dump(bench, f, indent=2)
    print(f"saved benchmark -> {BENCH_PATH}")

    # --- Extra false-alarm check on Rashad's simulator (real routing.c, all-normal traffic) ---
    # Make logs with:  python sim/run.py smoke --watchtower   (from the repo root)
    # Not used for training yet: v1 routing only sends DATA (no HELLO/KEYS/CTRL), on random 20-50
    # node meshes, so it doesn't look like our 4-board demo. Every window should be "normal".
    import glob
    sim_logs = sorted(glob.glob("../sim/out/*/*.watchtower.jsonl"))
    if sim_logs:
        sim = pd.concat([build_features(read_file(p)) for p in sim_logs], ignore_index=True)
        print(f"\n=== False alarms on Rashad's sim traffic ({len(sim_logs)} runs, {len(sim)} windows, all normal) ===")
        for who, flagged in [(RULE_NAME, rule_detect(sim)), ("Isolation Forest", iforest_detect(model, sim)),
                             ("Random Forest", rf_detect(rf, sim) != "normal")]:
            print(f"{who[:8]:<8} false alarms {flagged.mean():.1%}  ({int(flagged.sum())} windows)")

    # --- False-alarm check on REAL hardware traffic (no attacks, so every flag is a false alarm) ---
    # The Random Forest never saw this data, so its number is a fair test. The Isolation Forest
    # trained on it, so its number only shows it has learned what the real boards look like.
    if real is not None:
        print(f"\n=== False alarms on real hardware ({', '.join(real_logs)}: {len(real)} windows, all normal) ===")
        for who, flagged in [(RULE_NAME, rule_detect(real)),
                             ("Isolation Forest (trained on this data)", iforest_detect(model, real)),
                             ("Random Forest", rf_detect(rf, real) != "normal")]:
            print(f"{who[:8]:<8} false alarms {flagged.mean():.1%}  ({int(flagged.sum())} windows)"
                  + ("   <- trained on this data" if "trained" in who else ""))
