"""Usage log + decay report.

Why: the failure mode for a suite like this is not being wrong, it is quietly
accumulating checks nobody runs. `/Volumes/T7/scopeguard` and
`/Volumes/T7/scopeguard-cli` are two forks of the same tool 27 minutes apart,
both still on disk a month later, neither on PATH. That is the base rate. So
every invocation is logged, and `cc decay` names the checks that have not fired
so you can DELETE them. A check that never runs is not free - it is a claim of
coverage you do not have. (¬‿¬)

The log lives under ~/.cache (not on T7) so a decay report still works when the
drive is unmounted, and it records only check name / exit code / timestamp -
never target names, hosts, paths or findings, because those are the things that
must not accumulate on disk.
"""

from __future__ import annotations

import datetime as _dt
import json
import os

_DEFAULT = os.path.join(
    os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"),
    "crosscheck",
    "usage.jsonl",
)


def log_path() -> str:
    return os.environ.get("CROSSCHECK_USAGE_LOG") or _DEFAULT


def record(check: str, code: int) -> None:
    """Best-effort. A logging failure must never change a security verdict."""
    p = log_path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {"ts": _dt.datetime.now().isoformat(timespec="seconds"), "check": check, "code": code}
                )
                + "\n"
            )
    except OSError:
        pass


def read(limit: int = 100000) -> list[dict]:
    p = log_path()
    if not os.path.isfile(p):
        return []
    rows = []
    try:
        with open(p, "r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rows.append(json.loads(ln))
                except ValueError:
                    continue
                if len(rows) >= limit:
                    break
    except OSError:
        return []
    return rows


def decay_report(all_checks: list[str], days: int = 60, today: _dt.date | None = None) -> dict:
    today = today or _dt.date.today()
    rows = read()
    last: dict[str, _dt.date] = {}
    fired: dict[str, int] = {}
    findings: dict[str, int] = {}
    for row in rows:
        c = row.get("check")
        if not c:
            continue
        fired[c] = fired.get(c, 0) + 1
        if row.get("code") == 2:
            findings[c] = findings.get(c, 0) + 1
        try:
            d = _dt.datetime.fromisoformat(row["ts"]).date()
        except (KeyError, ValueError):
            continue
        if c not in last or d > last[c]:
            last[c] = d

    dead, cold, live = [], [], []
    for c in all_checks:
        if c not in fired:
            dead.append({"check": c, "runs": 0, "last": None, "verdict": "NEVER RUN - delete it or wire it in"})
            continue
        age = (today - last[c]).days if c in last else None
        row = {"check": c, "runs": fired[c], "findings": findings.get(c, 0), "last": str(last.get(c, "?")), "age_days": age}
        if age is not None and age > days:
            row["verdict"] = f"cold for {age}d - delete unless you can name the next run"
            cold.append(row)
        else:
            live.append(row)
    return {"log": log_path(), "total_runs": len(rows), "dead": dead, "cold": cold, "live": live}
