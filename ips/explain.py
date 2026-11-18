"""Plain-English explanations of IPS alerts, written by a local LLM (Ollama).

Rules (from the project plan):
  * The LLM only EXPLAINS. It never decides and never triggers a BLOCK.
  * It only sees our own numbers and fixed labels: never message content, and never
    raw text from packets (an attacker chooses its own pseudonym, so text from packets
    could carry instructions aimed at the LLM: "prompt injection").
  * If Ollama isn't running, a template sentence is used instead, so the IPS and
    dashboard never depend on the LLM.

Try it:  python3 explain.py
"""
import json
import os
import urllib.request

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
TIMEOUT_S = 60

# Friendly names, keyed by the watchtower's `node` letter (stable across MAC rotation).
# Anything else is a MAC: a radio the watchtower couldn't match to a real node ("?").
NODE_NAMES = {"A": "Node A", "B": "Node B", "C": "Node C", "D": "Node D", "X": "Node X"}

# Our own fixed wording for each attack (never taken from packets)
ATTACK_TEXT = {
    "flood":   "flooding: sending packets far faster than a normal node, to drown out the mesh",
    "routing": ("routing abuse: advertising fake route information (a fake TTL and extra HELLO beacons) "
                "so it looks like the best path and other nodes send their messages through it"),
    "replay":  "replay: re-sending old captured packets",
    "spoof":   "spoofing: pretending to be another node",
}

# Features that make good evidence: plain-English name, number format, and which direction is
# SUSPICIOUS ("up" = higher than normal is bad, "down" = lower is bad). Only a change in the
# suspicious direction counts as evidence: "fewer HELLOs than normal" doesn't incriminate anyone.
EVIDENCE = {
    "pkt_count":    ("packets/s",                    "{:.0f}",   "up"),
    "orig_count":   ("new messages started/s",       "{:.0f}",   "up"),
    "hello_count":  ("HELLOs/s",                     "{:.0f}",   "up"),
    "ttl_max":      ("TTL",                          "{:.0f}",   "up"),
    "hello_ttl_max": ("TTL on its HELLO beacons",    "{:.0f}",   "up"),
    "hop_min":      ("hop count",                    "{:.0f}",   "down"),
    "gap_mean":     ("gap between packets",          "{:.2f} s", "down"),
    "link_fail":    ("failed link checks",           "{:.0f}",   "up"),
    "stale_count":  ("old messages re-sent/s",       "{:.0f}",   "up"),
    "dup_tx_count": ("its own messages repeated/s",  "{:.0f}",   "up"),
}


def display_name(node):
    """'Node A', or 'Unknown ·ab:cd' (last bytes of its MAC) for an unmatched radio."""
    return NODE_NAMES.get(node, f"Unknown ·{str(node)[-5:]}")


def top_evidence(features, baseline, top=3):
    """The `top` features that differ most from normal -> [(label, value_text, normal_text)].
    'Differ most' = biggest ratio between the attacker's value and the normal median."""
    scored = []
    for f, (label, fmt, bad_dir) in EVIDENCE.items():
        x, base = features.get(f), baseline.get(f)
        if x is None or base is None:
            continue
        if (x > base) != (bad_dir == "up"):
            continue                                            # changed, but in the harmless direction
        ratio = (max(x, base) + 0.1) / (min(x, base) + 0.1)    # +0.1 so zeros don't divide by zero
        if ratio > 1.5:
            scored.append((ratio, label, fmt.format(x), fmt.format(base)))
    scored.sort(reverse=True)
    return [(label, x, base) for _, label, x, base in scored[:top]]


def build_facts(event, baseline, block_seconds):
    """Turn an IPS event into a small, SAFE set of facts for the LLM.
    Only our own labels and numbers: the attacker can't put words in here."""
    ev = event["evidence"]
    return {
        "action": "blocked" if event["kind"] == "BLOCK" else "raised an alert about",
        "who": NODE_NAMES.get(event["node"], "an unknown radio"),   # never the raw pseudonym or MAC
        "attack": ATTACK_TEXT.get(event["attack"], "suspicious behaviour"),
        "evidence": [f"{label} was {x} (normal is {base})"
                     for label, x, base in top_evidence(ev["features"], baseline)],
        "ai_confidence_percent": round(ev["conf"] * 100),
        "simple_rule_would_have_caught_it": bool(ev["rule_caught"]),
        "block_lasts_seconds": block_seconds if event["kind"] == "BLOCK" else None,
    }


# Division of labour: the LLM writes ONE plain-English sentence (good with words);
# the code adds the exact evidence numbers afterwards (small LLMs garble numbers).
PROMPT = """You explain security alerts from GhostMesh, an encrypted off-grid mesh network,
to a non-technical audience watching a demo.

The watchtower {action} {who}. The attack: {attack}.

Write ONE short, plain sentence (max 30 words) saying what this radio was doing and that the
watchtower stopped it. Use everyday words. Do not include any numbers. Do not add effects,
causes or details that are not stated above. No quotes, no lists.

Sentence:"""


def evidence_sentence(facts):
    """The exact numbers, written by code so they are always correct."""
    text = ""
    if facts["evidence"]:
        text += " Evidence: " + "; ".join(facts["evidence"]) + "."
    text += f" The AI was {facts['ai_confidence_percent']}% sure"
    if not facts["simple_rule_would_have_caught_it"]:
        text += ", and a simple packet-rate rule would have missed it"
    return text + ". Only traffic patterns were used, never message content."


def ollama_explain(facts):
    """Ask the local LLM. Returns the text, or None if Ollama isn't available."""
    body = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": PROMPT.format(action=facts["action"], who=facts["who"], attack=facts["attack"]),
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 60},    # low temperature = steadier wording
    }).encode()
    req = urllib.request.Request(OLLAMA_URL, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            text = json.loads(resp.read())["response"].strip().strip('"').split("\n")[0]
            if not text:
                return None
            if not text.endswith((".", "!")):
                text += "."
            return text + evidence_sentence(facts)
    except Exception:
        return None                                            # not installed / not running / model missing


def template_explain(facts):
    """Fallback when there's no LLM: a fixed sentence built from the same facts."""
    return f"The watchtower {facts['action']} {facts['who']} for {facts['attack']}." + evidence_sentence(facts)


def explain(event, baseline, block_seconds):
    """-> (text, source) where source is the model name or 'template'."""
    facts = build_facts(event, baseline, block_seconds)
    text = ollama_explain(facts)
    return (text, OLLAMA_MODEL) if text else (template_explain(facts), "template")


if __name__ == "__main__":
    # Explain the most recent BLOCK from the last live.py run
    events = [json.loads(line) for line in open("data/live_events.jsonl")]
    blocks = [e for e in events if e["kind"] == "BLOCK"]
    if not blocks:
        raise SystemExit("No BLOCK events yet: run live.py first.")
    normal = {"pkt_count": 1, "hello_count": 1, "ttl_max": 1, "hop_min": 0, "gap_mean": 2.0, "link_fail": 0}
    text, source = explain(blocks[-1], normal, block_seconds=60)
    print(f"[{source}]\n{text}")
