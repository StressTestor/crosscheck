#!/usr/bin/env python3
"""crosscheck - the mechanical half of the security work you keep re-remembering.

Runs standalone, in CI, or from an agent. Deterministic checks only: anything
that needs a model lives in the crosscheck skill and the crosscheck-adjudicate
workflow, and this CLI routes to it rather than guessing.

Exit codes (1 is reserved for an uncaught crash, so it can never read as a verdict):
    0 CLEAN     nothing to act on
    2 FINDING   something is wrong, named, with a fix
    3 INVALID   could not evaluate - never confuse this with clean
    4 JUDGMENT  a model or a human has to look; route it

Worst-of aggregation across checks: 3 > 2 > 4 > 0.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cc.result import Result, emit, worst, EXIT_INVALID  # noqa: E402
from cc import usage  # noqa: E402
from cc.checks import baseline, prbranch, prbody, ci, scope, secrets, vrp  # noqa: E402

ALL_CHECKS = ["baseline", "pr-branch", "pr-body", "ci", "scope", "secrets", "vrp"]

# Profiles are sequencing, not new checks. Each is "what do I run before X".
PROFILES = {
    "oss-pr": ["pr-branch", "pr-body", "ci"],
    "odysseus-pr": ["pr-branch", "pr-body", "ci"],
    "bounty-presubmit": ["secrets", "vrp"],
    "repo-audit": ["ci", "secrets"],
}


def _p(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cc", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="machine-readable envelope (same shape for every check)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baseline", help="dirty-vs-clean failing-set diff: settle 'that failure is pre-existing'")
    b.add_argument("repo")
    b.add_argument("--timeout", type=int, default=900)
    b.add_argument("suite", nargs=argparse.REMAINDER, help="-- <suite command>")

    pb = sub.add_parser("pr-branch", help="catch replayed/stray commits before you push")
    pb.add_argument("repo")
    pb.add_argument("--branch")
    pb.add_argument("--remote")
    pb.add_argument("--base", help="override the resolved default branch")
    pb.add_argument("--max-commits", type=int, default=prbranch.SANE_COMMIT_CEILING)

    pd = sub.add_parser("pr-body", help="run the target repo's OWN description checker on your draft")
    pd.add_argument("repo")
    pd.add_argument("body", help="path to the drafted PR body markdown")
    pd.add_argument("--title")
    pd.add_argument("--strict-title", action="store_true")

    c = sub.add_parser("ci", help="Actions supply-chain pass (delegates to zizmor/actionlint), routes deep review")
    c.add_argument("repo")
    c.add_argument("--changed", default="", help="comma-separated changed files, to trigger routing")
    c.add_argument("--require-sast", action="store_true", help="INVALID if no Actions SAST is installed")
    c.add_argument("--no-audit", action="store_true")

    s = sub.add_parser("scope", help="is this host inside the program's declared scope (suffix-anchored)")
    s.add_argument("program")
    s.add_argument("hosts", nargs="+")

    sec = sub.add_parser("secrets", help="aim gitleaks at report drafts / evidence dirs / vault-bound notes")
    sec.add_argument("paths", nargs="+")
    sec.add_argument("--allow", action="append", default=[], help="file allowed to contain the finding (the report itself)")
    sec.add_argument("--history", action="store_true", help="also scan git history")

    v = sub.add_parser("vrp", help="is this vuln class fileable here - ask BEFORE building the PoC")
    v.add_argument("program")
    v.add_argument("vuln_class")
    v.add_argument("--max-age-days", type=int, default=vrp.DEFAULT_MAX_AGE_DAYS)

    rp = sub.add_parser("run", help="a named profile (sequencing only, no new checks)")
    rp.add_argument("profile", choices=sorted(PROFILES))
    rp.add_argument("repo", nargs="?", default=".")
    rp.add_argument("--body")
    rp.add_argument("--title")
    rp.add_argument("--program")
    rp.add_argument("--vuln-class")
    rp.add_argument("--changed", default="")
    rp.add_argument("--paths", nargs="*", default=[])

    d = sub.add_parser("decay", help="which checks have not fired - delete them")
    d.add_argument("--days", type=int, default=60)

    sub.add_parser("checks", help="list check names")
    return ap


def dispatch(a) -> list[Result]:
    if a.cmd == "baseline":
        argv = [x for x in (a.suite or []) if x != "--"]
        return [baseline.check(_p(a.repo), argv, timeout=a.timeout)]
    if a.cmd == "pr-branch":
        return [prbranch.check(_p(a.repo), a.branch, a.remote, a.base, a.max_commits)]
    if a.cmd == "pr-body":
        return [prbody.check(_p(a.repo), _p(a.body), a.title, a.strict_title)]
    if a.cmd == "ci":
        changed = [x.strip() for x in a.changed.split(",") if x.strip()]
        return [ci.check(_p(a.repo), changed, a.require_sast, not a.no_audit)]
    if a.cmd == "scope":
        return [scope.check(a.program, a.hosts)]
    if a.cmd == "secrets":
        return [secrets.check([_p(x) for x in a.paths], a.allow, a.history)]
    if a.cmd == "vrp":
        return [vrp.check(a.program, a.vuln_class, a.max_age_days)]
    if a.cmd == "run":
        return run_profile(a)
    raise ValueError(a.cmd)


def run_profile(a) -> list[Result]:
    out: list[Result] = []
    repo = _p(a.repo)
    changed = [x.strip() for x in a.changed.split(",") if x.strip()]
    for name in PROFILES[a.profile]:
        if name == "pr-branch":
            out.append(prbranch.check(repo))
        elif name == "pr-body":
            if not a.body:
                out.append(Result.invalid("pr-body", "profile needs --body <draft.md>"))
            else:
                out.append(prbody.check(repo, _p(a.body), a.title, False))
        elif name == "ci":
            out.append(ci.check(repo, changed))
        elif name == "secrets":
            paths = [_p(x) for x in a.paths] or [repo]
            out.append(secrets.check(paths, [_p(a.body)] if a.body else []))
        elif name == "vrp":
            if not (a.program and a.vuln_class):
                out.append(Result.invalid("vrp", "profile needs --program and --vuln-class"))
            else:
                out.append(vrp.check(a.program, a.vuln_class))
    return out


def main(argv=None) -> int:
    ap = build_parser()
    a = ap.parse_args(argv)

    if a.cmd == "checks":
        for c in ALL_CHECKS:
            print(c)
        return 0

    if a.cmd == "decay":
        rep = usage.decay_report(ALL_CHECKS, days=a.days)
        if a.json:
            import json as _j
            print(_j.dumps(rep, indent=2))
            return 0
        print(f"usage log: {rep['log']}  ({rep['total_runs']} runs)")
        for row in rep["dead"]:
            print(f"  DEAD  {row['check']:<12} {row['verdict']}")
        for row in rep["cold"]:
            print(f"  COLD  {row['check']:<12} {row['verdict']}")
        for row in rep["live"]:
            print(f"  live  {row['check']:<12} runs={row['runs']} findings={row.get('findings', 0)} last={row['last']}")
        return 0

    try:
        results = dispatch(a)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_INVALID

    for r in results:
        usage.record(r.check, r.code)
    return emit(results, a.json)


if __name__ == "__main__":
    sys.exit(main())
