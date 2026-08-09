"""vrp - is this class of finding fileable HERE, before you build the PoC.

This is the module that maps to the largest realized loss in the corpus: three
PoC-confirmed osv-scalibr findings and a HIGH-severity go-cloud credential leak,
all closed $0 - not because they were wrong, but because the program's severity
bar and ineligible-class list excluded them. The PoC work was already done.

So the question this answers is deliberately asked EARLY: given a program and a
vuln class, is this above the bar, below it, explicitly ineligible, or inside a
dated exclusion window? Cheap to ask before a weekend of work, expensive to
learn after.

Judgment calls:
1. Missing policy is INVALID: "I have no idea what this program pays for" is
   not the same as "go ahead".
2. A STALE policy is JUDGMENT(4), not INVALID. A cache-age number must never
   hard-stop a pipeline on a non-security fact - that is the rule everyone
   routes around by week two, and a rule routed around is worse than none.
3. An unknown vuln class is JUDGMENT, not CLEAN. We say we do not have a
   ruling, rather than implying eligibility.
4. Every ruling prints the quoted policy line it came from, so you can check
   the transcription instead of trusting it.
"""

from __future__ import annotations

import datetime as _dt
import json
import os

from ..result import Result, Finding
from .scope import load_policy, policy_dir

CHECK = "vrp"

DEFAULT_MAX_AGE_DAYS = 90


def _parse_date(s: str):
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return _dt.datetime.strptime(s, fmt).date()
        except (ValueError, TypeError):
            continue
    return None


def _norm(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum() or ch == " ").strip()


def check(
    program: str,
    vuln_class: str,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    today: _dt.date | None = None,
) -> Result:
    r = Result(check=CHECK)
    today = today or _dt.date.today()

    pol, err = load_policy(program)
    if err:
        return Result.invalid(
            CHECK,
            err,
            f"write {os.path.join(policy_dir(), program.lower() + '.json')} "
            f"with severity_bar / ineligible_classes before spending PoC effort",
        )

    r.data.update({"program": program, "vuln_class": vuln_class})

    # ---- freshness: a note or a judgment, never a hard stop --------------
    fetched = _parse_date(pol.get("fetched_at", "") or "")
    if not fetched:
        r.add(
            Finding(
                what="policy has no fetched_at date - age is unknown",
                fix="add \"fetched_at\": \"YYYY-MM-DD\" when you transcribe the program page",
                severity="judgment",
            )
        )
    else:
        age = (today - fetched).days
        r.data["policy_age_days"] = age
        if age > max_age_days:
            r.add(
                Finding(
                    what=f"policy transcript is {age} days old (limit {max_age_days})",
                    detail=f"fetched_at {fetched}; program terms change without notice",
                    fix=f"re-read {pol.get('policy_url', 'the program page')} and re-stamp fetched_at",
                    severity="judgment",
                )
            )
        else:
            r.note(f"policy is {age} days old (fetched {fetched})")

    # ---- dated exclusion windows ----------------------------------------
    for win in pol.get("exclusion_windows", []) or []:
        start = _parse_date(win.get("from", "") or "")
        end = _parse_date(win.get("until", "") or "")
        classes = [_norm(c) for c in (win.get("classes") or [])]
        hits = (not classes) or any(c in _norm(vuln_class) or _norm(vuln_class) in c for c in classes)
        if not hits:
            continue
        active = (start is None or today >= start) and (end is None or today <= end)
        if active:
            r.add(
                Finding(
                    what="an exclusion window is ACTIVE for this class",
                    detail=f"{win.get('from', '?')} .. {win.get('until', '?')}: {win.get('quote', '')}",
                    fix="hold the report until the window closes, or pick another class",
                )
            )
        elif end and today > end:
            r.note(f"an exclusion window for this class EXPIRED on {end} - no longer blocking")

    # ---- explicitly ineligible classes ----------------------------------
    nv = _norm(vuln_class)
    for row in pol.get("ineligible_classes", []) or []:
        name = row.get("class", "") if isinstance(row, dict) else str(row)
        quote = row.get("quote", "") if isinstance(row, dict) else ""
        n = _norm(name)
        if not n:
            continue
        if n in nv or nv in n:
            r.add(
                Finding(
                    what=f"'{name}' is explicitly INELIGIBLE for {program}",
                    detail=quote or "(no quote transcribed - verify on the program page)",
                    fix="do not build the PoC; this closes informative/N-A at best",
                )
            )

    # ---- severity bar ----------------------------------------------------
    bar = pol.get("severity_bar")
    if bar:
        r.note(f"severity bar: {bar}")
        r.data["severity_bar"] = bar
    below = [_norm(c) for c in (pol.get("below_bar_classes") or [])]
    if below and any(c in nv or nv in c for c in below):
        r.add(
            Finding(
                what=f"'{vuln_class}' historically lands BELOW {program}'s severity bar",
                detail=f"bar: {bar or 'unstated'}",
                fix="escalate the impact into a chain that clears the bar, or pick another target",
            )
        )

    known = [_norm(row.get("class", "") if isinstance(row, dict) else str(row))
             for row in (pol.get("ineligible_classes") or [])]
    known += below + [_norm(c) for c in (pol.get("eligible_classes") or [])]
    if not any(k and (k in nv or nv in k) for k in known):
        r.add(
            Finding(
                what=f"no ruling on record for '{vuln_class}' at {program}",
                detail="absence of a rule is not permission",
                fix="read the program page for this class before investing PoC time",
                severity="judgment",
            )
        )

    if not r.findings:
        r.note(f"'{vuln_class}' is not excluded by {program}'s transcribed policy - proceed, PoC first")
    return r
