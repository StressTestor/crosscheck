"""Result contract shared by every crosscheck check.

Judgment calls, written down because every module depends on them:

1. Four exit codes, not two. A security tool that can only say pass/fail has to
   lie when it cannot decide. CLEAN(0) / FINDING(2) / INVALID(3) / JUDGMENT(4).
   1 stays free so an uncaught Python traceback (which exits 1) can never be
   mistaken for a real verdict.
2. Aggregation is worst-of with INVALID loudest: 3 > 2 > 4 > 0. A run that
   could not evaluate one of its checks is worse than one that found a problem,
   because a skipped check reads as silence and silence reads as clean.
3. JUDGMENT(4) outranks CLEAN but not FINDING. It means "a model has to look at
   this", never "probably fine".
4. There is no code path that downgrades INVALID. If a check cannot run, it
   says so. It never returns CLEAN with a warning nobody reads.
5. FOREIGN TEXT NEVER LANDS IN `what`. `what` is always crosscheck's own words.
   Anything produced by the thing under test - a repo's PR bot, zizmor output,
   a foreign test id, a probe's stderr - goes in `foreign`, where it is capped
   and tagged at the single serialisation point below.

   Why: `--json` is read by agents. Uncapped, unlabelled text from an untrusted
   repo flowing into the same field crosscheck writes its own verdicts into is
   a prompt-injection channel wearing a trusted envelope. The reader cannot
   tell our sentence from theirs, which is the whole trick. >:[
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field, asdict
from typing import Any

# Exit codes. 1 is deliberately unused -> reserved for an uncaught crash.
EXIT_CLEAN = 0
EXIT_FINDING = 2
EXIT_INVALID = 3
EXIT_JUDGMENT = 4

# Foreign text is capped at emission. Long enough for a real message, short
# enough that a wall of crafted text cannot bury the verdict around it.
MAX_FOREIGN_BYTES = 600

# Loudness order for worst-of aggregation. Higher wins. (¬‿¬) INVALID on top.
_RANK = {EXIT_CLEAN: 0, EXIT_JUDGMENT: 1, EXIT_FINDING: 2, EXIT_INVALID: 3}

_NAME = {
    EXIT_CLEAN: "CLEAN",
    EXIT_FINDING: "FINDING",
    EXIT_INVALID: "INVALID",
    EXIT_JUDGMENT: "JUDGMENT",
}


def name_for(code: int) -> str:
    return _NAME.get(code, f"UNKNOWN({code})")


def worst(codes) -> int:
    """Worst-of aggregation. Empty means nothing ran, which is INVALID, not clean.

    A run with no checks is the exact shape of a silent misconfiguration, so it
    fails loud rather than reporting a green zero. XX
    """
    codes = list(codes)
    if not codes:
        return EXIT_INVALID
    for c in codes:
        if c not in _RANK:
            raise ValueError(f"not a crosscheck exit code: {c!r}")
    return max(codes, key=lambda c: _RANK[c])


@dataclass
class Finding:
    """One thing worth a human's attention. `where` is file:line when we have it.

    `what` / `detail` / `fix` are crosscheck's own words. Text that came out of
    the thing under test goes in `foreign` via `with_foreign()`, never here.
    """

    what: str
    where: str = ""
    detail: str = ""
    fix: str = ""
    severity: str = "finding"  # finding | judgment | invalid
    # {"source": str, "text": str, "bytes": int, "truncated": bool}
    foreign: dict | None = None

    def with_foreign(self, source: str, text: str) -> "Finding":
        """Attach text produced by the target. Capped and tagged here, once."""
        raw = text or ""
        # Cap BYTES, not code points. Slicing the str and reporting len(raw) as
        # "bytes" meant 600 emoji were ~2400 UTF-8 bytes while the envelope
        # claimed 600 and truncated:false. Decode with errors="ignore" so a cut
        # through a multi-byte sequence cannot raise or emit a replacement char.
        blob = raw.encode("utf-8")
        capped = blob[:MAX_FOREIGN_BYTES].decode("utf-8", errors="ignore")
        self.foreign = {
            "source": source,
            "text": capped,
            "bytes": len(blob),
            "truncated": len(blob) > MAX_FOREIGN_BYTES,
        }
        return self

    def line(self) -> str:
        head = f"{self.where}: {self.what}" if self.where else self.what
        if self.detail:
            head += f"\n    {self.detail}"
        if self.foreign:
            f = self.foreign
            tail = " [truncated]" if f["truncated"] else ""
            # Marked on every line so a multi-line payload cannot walk out of
            # its own quoting and impersonate crosscheck's voice.
            body = "\n".join(
                f"    | {ln}" for ln in f["text"].splitlines()[:12]
            ) or "    | (empty)"
            head += f"\n    untrusted output from {f['source']} ({f['bytes']} bytes{tail}):\n{body}"
        if self.fix:
            head += f"\n    fix: {self.fix}"
        return head


@dataclass
class Result:
    check: str
    code: int = EXIT_CLEAN
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Free-form, per-check. Always JSON-serialisable.
    data: dict[str, Any] = field(default_factory=dict)

    # -- constructors, so callers never hand-pick an exit code -------------
    @classmethod
    def clean(cls, check: str, **kw) -> "Result":
        return cls(check=check, code=EXIT_CLEAN, **kw)

    @classmethod
    def invalid(cls, check: str, why: str, fix: str = "", **kw) -> "Result":
        return cls(
            check=check,
            code=EXIT_INVALID,
            findings=[Finding(what=why, fix=fix, severity="invalid")],
            **kw,
        )

    def add(self, f: Finding) -> "Result":
        """Adding a finding escalates the code. It can never de-escalate."""
        self.findings.append(f)
        want = EXIT_JUDGMENT if f.severity == "judgment" else EXIT_FINDING
        if f.severity == "invalid":
            want = EXIT_INVALID
        self.code = worst([self.code, want])
        return self

    def fail(self, why: str, fix: str = "") -> "Result":
        """Escalate THIS result to INVALID, keeping findings already collected.

        `Result.invalid()` builds a fresh object, so calling it late in a check
        silently discarded everything found earlier - the exit code stayed
        right but the --json findings list lost real results. Use this whenever
        the check has already added something. XX
        """
        return self.add(Finding(what=why, fix=fix, severity="invalid"))

    def note(self, msg: str) -> "Result":
        self.notes.append(msg)
        return self

    @property
    def ok(self) -> bool:
        return self.code == EXIT_CLEAN

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "code": self.code,
            "status": name_for(self.code),
            "findings": [asdict(f) for f in self.findings],
            "notes": self.notes,
            "data": self.data,
        }


def emit(results, as_json: bool, stream=None) -> int:
    """Print results, return the aggregate exit code.

    Single output path for every subcommand so `--json` is always the same
    envelope shape and never a per-check improvisation.
    """
    stream = stream or sys.stdout
    results = [results] if isinstance(results, Result) else list(results)
    code = worst([r.code for r in results])

    if as_json:
        json.dump(
            {
                "status": name_for(code),
                "code": code,
                "results": [r.to_dict() for r in results],
            },
            stream,
            indent=2,
        )
        stream.write("\n")
        return code

    for r in results:
        print(f"[{name_for(r.code)}] {r.check}", file=stream)
        for n in r.notes:
            print(f"    - {n}", file=stream)
        for f in r.findings:
            print(f"  {f.line()}", file=stream)
    print(f"\n=> {name_for(code)} ({code})", file=stream)
    return code
