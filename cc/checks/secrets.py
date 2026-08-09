"""secrets - point the scanners you already have at the stuff nobody scans.

gitleaks and trufflehog are installed and Joe runs them by hand on targets. The
gap is not detection, it is aim: report drafts, evidence directories and
vault-bound notes never get scanned, and the vault auto-commit hook pushes to
GitHub on every write. A live key pasted into an evidence note leaves the
machine before anyone re-reads it. XX

So this module reimplements nothing. It shells out to the installed scanners
and aims them at the surfaces that actually leak.

Judgment calls:
1. No scanner installed is INVALID, never CLEAN. An unrun scanner prints the
   same nothing as a clean scan.
2. Directories are scanned with `--no-git` so an evidence dir that is not a
   repo still gets read.
3. Findings are reported with the secret REDACTED. This tool must never be the
   thing that copies a live key into a log or a JSON envelope.
4. One file may be nominated as the submission target (--allow), because the
   report itself legitimately quotes the finding. Everything else is hostile
   territory.
"""

from __future__ import annotations

import json
import os

from ..result import Result, Finding
from ..run import run, have

CHECK = "secrets"


def _gitleaks_dir(path: str, r: Result) -> int:
    """Scan a directory tree. Returns number of findings added."""
    out_json = os.path.join(
        os.environ.get("TMPDIR", "/tmp"), f"cc-gitleaks-{abs(hash(path)) % 10**8}.json"
    )
    p = run(
        [
            "gitleaks", "dir", path,
            "--no-banner", "--redact", "--exit-code", "2",
            "--report-format", "json", "--report-path", out_json,
        ],
        timeout=600,
    )
    if p.timed_out:
        r.add(Finding(what="gitleaks timed out", where=path, severity="invalid"))
        return 0
    n = 0
    if os.path.isfile(out_json):
        try:
            with open(out_json, "r", encoding="utf-8") as fh:
                rows = json.load(fh) or []
            for row in rows:
                n += 1
                r.add(
                    Finding(
                        what=f"possible secret: {row.get('RuleID', 'unknown rule')}",
                        where=f"{row.get('File', '?')}:{row.get('StartLine', '?')}",
                        detail=(row.get("Match") or "")[:120],  # gitleaks --redact already masked it
                        fix="remove it, rotate it, and keep it out of anything the vault hook pushes",
                    )
                )
        except (OSError, ValueError) as e:
            r.add(Finding(what=f"could not read gitleaks report: {e}", severity="invalid"))
        finally:
            try:
                os.unlink(out_json)
            except OSError:
                pass
    elif p.code not in (0, 2):
        r.add(
            Finding(
                what=f"gitleaks exited {p.code}",
                where=path,
                detail=p.text().strip()[:250],
                severity="invalid",
            )
        )
    return n


def check(paths: list[str], allow: list[str] | None = None, history: bool = False) -> Result:
    r = Result(check=CHECK)
    allow = [os.path.abspath(a) for a in (allow or [])]

    if not paths:
        return Result.invalid(CHECK, "no paths given", "cc secrets <dir-or-file> [...] [--allow report.md]")

    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        return Result.invalid(CHECK, f"path does not exist: {', '.join(missing)}")

    if not have("gitleaks"):
        return Result.invalid(
            CHECK,
            "gitleaks is not installed - refusing to report a clean scan that never ran",
            "brew install gitleaks",
        )

    r.data["scanned"] = [os.path.abspath(p) for p in paths]
    r.data["allowed"] = allow

    total = 0
    for p in paths:
        ap = os.path.abspath(p)
        before = len(r.findings)
        if os.path.isdir(ap):
            total += _gitleaks_dir(ap, r)
            if history and os.path.isdir(os.path.join(ap, ".git")):
                g = run(["gitleaks", "git", ap, "--no-banner", "--redact", "--exit-code", "2"], timeout=900)
                if g.code == 2:
                    r.add(
                        Finding(
                            what="secret found in git HISTORY (deleting the file does not remove it)",
                            where=ap,
                            detail=g.text().strip()[-300:],
                            fix="rotate the credential; rewriting history is not enough once it is pushed",
                        )
                    )
        else:
            total += _gitleaks_dir(os.path.dirname(ap) or ".", r)

        # Drop findings that live in the nominated submission file - the report
        # is allowed to quote its own finding.
        if allow:
            kept = []
            for f in r.findings[before:]:
                fp = os.path.abspath(f.where.rsplit(":", 1)[0]) if f.where else ""
                if fp in allow:
                    r.note(f"allowed (submission target): {f.where}")
                else:
                    kept.append(f)
            r.findings = r.findings[:before] + kept

    # Recompute the code after any allow-list pruning, so an allowed-only run
    # is genuinely CLEAN rather than stuck at FINDING.
    from ..result import EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID
    if any(f.severity == "invalid" for f in r.findings):
        r.code = EXIT_INVALID
    elif r.findings:
        r.code = EXIT_FINDING
    else:
        r.code = EXIT_CLEAN
        r.note(f"gitleaks found nothing across {len(paths)} path(s)")

    if have("trufflehog"):
        r.note("trufflehog is installed; run it for verified-live keys: trufflehog filesystem <dir> --only-verified")
    return r
