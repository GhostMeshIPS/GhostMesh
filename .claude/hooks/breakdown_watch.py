"""SessionStart hook: flag changes to the team plan since this clone last saw it.

Compares docs/planning/project-breakdown.md on origin/main against the version
recorded in .git/ghostmesh-breakdown-seen (per-clone, never committed), and
hands any diff to Claude so it can tell the user what changed.
"""
import json, os, subprocess, sys

DOC = "docs/planning/project-breakdown.md"
MAX_LINES = 400


def git(*args, timeout=10):
    r = subprocess.run(["git", *args], capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip() if r.returncode == 0 else None


def emit(context, banner):
    print(json.dumps({
        "systemMessage": banner,
        "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": context},
    }))


def main():
    os.chdir(os.environ.get("CLAUDE_PROJECT_DIR", "."))
    try:
        git("fetch", "-q", "origin", "main", timeout=8)
    except subprocess.TimeoutExpired:
        pass  # offline: compare against the last fetched origin/main
    new = git("rev-parse", f"origin/main:{DOC}")
    git_dir = git("rev-parse", "--git-dir")
    if not new or not git_dir:
        return
    seen_path = os.path.join(git_dir, "ghostmesh-breakdown-seen")
    seen = open(seen_path).read().strip() if os.path.exists(seen_path) else None
    if seen == new:
        return
    behind = git("rev-parse", f"HEAD:{DOC}") != new
    pull = " The user's checkout is behind origin/main for this file; tell them to run `git pull`." if behind else ""

    if seen is None:
        emit(
            f"{DOC} is the team's source of truth for GhostMesh and is now watched for changes. "
            "This is the first check on this machine, so there is no earlier version to diff. "
            "In your first reply, briefly tell the user it is being watched and summarize each entry "
            f"in its '4.7 Decision log' section, including what it asks of their role.{pull}",
            "GhostMesh: project-breakdown.md is now watched for team changes.",
        )
    else:
        diff = git("diff", "--no-color", "-U2", seen, new) or ""
        lines = diff.splitlines()
        if len(lines) > MAX_LINES:
            diff = "\n".join(lines[:MAX_LINES]) + f"\n[... {len(lines) - MAX_LINES} more lines; read the file for the rest]"
        emit(
            f"{DOC} (the team's source of truth) changed on origin/main since this user's last session. "
            "In your first reply, before anything else, flag the MAJOR changes in a few bullets: decisions, "
            "frame format or protocol fields, the watchtower log schema, interfaces between roles, "
            "deadlines, and ownership. Say which roles each change affects. Skip typo and wording fixes. "
            f"If nothing is major, say so in one line.{pull}\n\nDiff:\n{diff}",
            "GhostMesh: project-breakdown.md changed since your last session.",
        )
    with open(seen_path, "w") as f:
        f.write(new + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(0)  # never block a session over this
