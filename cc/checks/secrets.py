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
import tempfile

from ..result import Result, Finding
from ..run import run, have

CHECK = "secrets"


def _gitleaks_dir(path: str, r: Result) -> int:
    """Scan a directory tree. Returns number of findings added."""
    # mkstemp, not a guessable name in a shared TMPDIR. A predictable path is a
    # symlink target, and this tool writes a report about secrets into it -
    # exactly the primitive you would not want to hand someone. (Also `hash()`
    # is per-process randomized, so the old name was not even stable.) XX
    fd, out_json = tempfile.mkstemp(prefix="cc-gitleaks-", suffix=".json")
    os.close(fd)
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
    if os.path.isfile(out_json) and os.path.getsize(out_json) > 0:
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
    else:
        try:
            os.unlink(out_json)
        except OSError:
            pass
    if not os.path.isfile(out_json) and p.code not in (0, 2):
        r.add(
            Finding(
                what=f"gitleaks exited {p.code}",
                where=path,
                detail=p.text().strip()[:250],
                severity="invalid",
            )
        )
    return n


def _resolve_allow(allow: list[str], paths: list[str], r: Result) -> list[str]:
    """Resolve --allow against the SCANNED roots, not the process cwd.

    `cc secrets ./evidence --allow report.md` from anywhere but the scan
    directory silently allow-listed a path that did not exist, so the report's
    own legitimate finding was never suppressed - and the CLI help demonstrates
    exactly that bare-relative form. An --allow that matches nothing is a loud
    note, never a silent no-op.
    """
    out = []
    for a in allow:
        if os.path.isabs(a):
            out.append(os.path.realpath(a))
            continue
        cands = [os.path.realpath(a)]
        for p in paths:
            base = p if os.path.isdir(p) else os.path.dirname(p)
            cands.append(os.path.realpath(os.path.join(base, a)))
        hit = next((c for c in cands if os.path.exists(c)), None)
        if hit:
            out.append(hit)
        else:
            r.note(f"--allow {a!r} matched no file under the scanned paths - it is NOT suppressing anything")
    return out


def check(paths: list[str], allow: list[str] | None = None, history: bool = False) -> Result:
    r = Result(check=CHECK)
    allow = _resolve_allow(list(allow or []), [os.path.abspath(p) for p in paths], r)

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
            # Scan the FILE, not its parent. `gitleaks dir` takes a single file
            # fine. Scanning the parent meant `cc secrets ~/report.md` swept all
            # of $HOME, attributed strangers' files to your run, and put their
            # paths into a JSON envelope headed for an agent transcript - while
            # `data.scanned` claimed only the one file. >:[
            total += _gitleaks_dir(ap, r)

        # Drop findings that live in the nominated submission file - the report
        # is allowed to quote its own finding.
        if allow:
            kept = []
            for f in r.findings[before:]:
                fp = os.path.realpath(f.where.rsplit(":", 1)[0]) if f.where else ""
                if fp in allow:
                    r.note(f"allowed (submission target): {f.where}")
                else:
                    kept.append(f)
            r.findings = r.findings[:before] + kept

    # Recompute the code after allow-list pruning so an allowed-only run is
    # genuinely CLEAN. Rebuild through Result.add rather than re-deriving the
    # mapping here - the private copy did not know about "judgment" and coded
    # it as FINDING, which is exactly the drift a second implementation buys.
    from ..result import EXIT_CLEAN
    kept = list(r.findings)
    r.findings = []
    r.code = EXIT_CLEAN
    for f in kept:
        r.add(f)
    if not r.findings:
        r.note(f"gitleaks found nothing across {len(paths)} path(s)")

    if have("trufflehog"):
        r.note("trufflehog is installed; run it for verified-live keys: trufflehog filesystem <dir> --only-verified")
    return r
