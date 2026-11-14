"""Auto-delete old log lines so the laptop doesn't fill up (and keeps little history if seized).

    traffic windows  -> last 6 hours   (the big one: ~130 MB/day if kept forever)
    chat history     -> last 24 hours  (small, but private)
"""
import json
import os
import tempfile

WINDOWS_MAX_AGE_S = 6 * 3600
CHAT_MAX_AGE_S = 24 * 3600


def prune_jsonl(path, time_field, max_age_s, now):
    """Keep only lines whose `time_field` is within `max_age_s` of `now`. Returns lines removed.

    Writes to a temp file then swaps it in (os.replace is atomic), so a reader like the
    dashboard never sees a half-written file.
    """
    if not os.path.exists(path):
        return 0
    cutoff = now - max_age_s
    kept, removed = [], 0
    with open(path) as f:
        for line in f:
            try:
                if json.loads(line).get(time_field, now) >= cutoff:
                    kept.append(line)
                else:
                    removed += 1
            except json.JSONDecodeError:
                removed += 1                                  # drop corrupted lines too
    if removed:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".")
        with os.fdopen(fd, "w") as f:
            f.writelines(kept)
        os.replace(tmp, path)
    return removed
