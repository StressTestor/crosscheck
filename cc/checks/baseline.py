"""baseline - settle "that failure is pre-existing" with a run, not an assertion.

Why this exists: calling a failure pre-existing when it is not corrupts every
gate downstream. adv-gate, presubmission-gate and verify-change all accept
"pre-existing" as an input and reason on top of it. One wrong call there and
three expensive gates agree on the wrong thing. XX

The method is a set difference, so the answer is not arguable:
  run suite on the dirty tree -> F_dirty
  stash EVERYTHING (tracked + untracked) -> run again -> F_clean
  restore
  introduced  = F_dirty - F_clean   <- your change did this
  pre-existing= F_dirty & F_clean   <- only these may be called pre-existing
  fixed       = F_clean - F_dirty

Judgment calls:
1. Untracked files are stashed too (-u). A new untracked test file is exactly
   the thing that makes a "clean" run lie.
2. If the stash cannot be taken or cannot be restored, we abort LOUD (INVALID)
   and print the recovery command. Never leave the tree half-stashed quietly.
3. A suite that exits non-zero without any parseable failure names is a harness
   error, not a test failure. That is INVALID, not FINDING - "the runner
   crashed" must never be laundered into "your change broke a test".
4. Interpreter/toolchain versions are recorded for both runs so a local-only
   failure reads as an env hypothesis rather than a finding.
5. Every "can we protect this tree?" question is answered BEFORE the suite is
   executed even once. Dirty submodules abort the run outright - `git stash`
   does not recurse into them, so a suite that writes there destroys work with
   no stash to recover from. Warning about it afterwards is an obituary. XX
"""

from __future__ import annotations

import re

from ..result import Result, Finding
from ..run import run, have
from .. import gitutil as G

CHECK = "baseline"

# Failure-name extraction, per ecosystem. First pattern that yields hits wins.
# Deliberately conservative: a name we cannot parse is better than a wrong set.
_PATTERNS = [
    # pytest:  FAILED tests/test_x.py::test_y - AssertionError
    # The `[^\s(]` first char is load-bearing: unittest ends its run with
    # `FAILED (failures=2)`, and capturing THAT as a test name makes the set
    # difference compare failure COUNTS instead of test names - so a run with
    # 2 failures vs 1 would report a fabricated "introduced" failure. >:[
    re.compile(r"^(?:FAILED|ERROR)\s+([^\s(]\S*)(?:\s+-.*)?$", re.M),
    # unittest: FAIL: test_y (tests.test_x.Klass)
    re.compile(r"^(?:FAIL|ERROR):\s+(\S+\s*\([^)]+\))", re.M),
    # go test:  --- FAIL: TestThing (0.00s)
    re.compile(r"^\s*---\s+FAIL:\s+(\S+)", re.M),
    # cargo:    test module::thing ... FAILED   /  failures:\n    module::thing
    re.compile(r"^test\s+(\S+)\s+\.\.\.\s+FAILED", re.M),
    # jest/vitest: ✕ name   or   × name
    re.compile(r"^\s*[✕×]\s+(.+?)(?:\s+\(\d+\s*ms\))?$", re.M),
]


def parse_failures(text: str) -> set[str]:
    for pat in _PATTERNS:
        hits = {m.strip() for m in pat.findall(text) if m and m.strip()}
        if hits:
            return hits
    return set()


def _toolchain() -> dict:
    """Record what actually ran. A local-only failure is an env hypothesis."""
    info = {}
    for tool, argv in (
        ("python", ["python3", "--version"]),
        ("node", ["node", "--version"]),
        ("go", ["go", "version"]),
        ("cargo", ["cargo", "--version"]),
    ):
        if have(argv[0]):
            p = run(argv, timeout=30)
            if p.ok:
                info[tool] = p.text().strip().splitlines()[0]
    return info


def check(repo: str, suite_argv: list[str], timeout: int = 900, as_dict=None) -> Result:
    r = Result(check=CHECK)

    if not suite_argv:
        return Result.invalid(CHECK, "no suite command given", "cc baseline <repo> -- pytest -q")
    if not G.is_repo(repo):
        return Result.invalid(CHECK, f"not a git repo: {repo}")

    r.data["toolchain"] = _toolchain()
    r.data["suite"] = suite_argv

    # ---- run 1: the tree as it is now -------------------------------------
    dirty_list = G.dirty_files(repo)
    r.data["dirty_files"] = dirty_list
    if not dirty_list:
        r.note("working tree is clean - nothing to compare, both runs would be identical")
        return Result.invalid(
            CHECK,
            "working tree has no uncommitted changes",
            "baseline compares dirty vs clean; with a clean tree use verify-change instead",
        )

    # ---- prove we can protect the tree BEFORE running anything -----------
    # Ordering is the whole point. Everything below used to be discovered
    # after the suite had already executed against the real working tree, at
    # which point the warning is an obituary. >:[
    dirty_subs = G.dirty_submodules(repo)
    if dirty_subs:
        return Result.invalid(
            CHECK,
            f"submodule(s) hold uncommitted work that `git stash` cannot protect: {', '.join(dirty_subs)}",
            "commit or stash inside the submodule first - otherwise baseline would run your "
            "suite over them with no way to restore",
            data={"dirty_submodules": dirty_subs},
        )

    ign = G.git(repo, "status", "--porcelain", "--ignored=matching")
    ignored = [ln[3:].strip() for ln in ign.out.splitlines() if ln.startswith("!!")] if ign.ok else []
    if ignored:
        r.data["ignored_unprotected"] = ignored[:50]
        r.note(
            f"{len(ignored)} gitignored path(s) are NOT covered by the stash - "
            f"if your suite writes to them, those writes are not reverted"
        )

    p1 = run(suite_argv, cwd=repo, timeout=timeout)
    if p1.timed_out:
        return Result.invalid(CHECK, f"suite timed out on the dirty tree after {timeout}s")
    f_dirty = parse_failures(p1.text())
    if p1.code != 0 and not f_dirty:
        # Non-zero with nothing parseable == harness error. Do NOT call this a
        # test failure; that is how "your change broke it" gets fabricated.
        return Result.invalid(
            CHECK,
            f"suite exited {p1.code} on the dirty tree but no test-failure names were parsed",
            "looks like a harness/collection error, not a test failure - fix the runner first",
            data={"stderr_tail": p1.text()[-1500:]},
        )

    # ---- stash, run 2, restore -------------------------------------------
    # Everything from here until the pop is a window where the user's work
    # lives only in a stash. Any exception in that window has to name the
    # recovery command, not vanish into a generic traceback. 💀
    try:
        stash = G.git(repo, "stash", "push", "--include-untracked", "-m", "crosscheck-baseline", timeout=120)
    except BaseException as e:  # noqa: BLE001
        return Result.invalid(
            CHECK,
            f"interrupted while stashing: {e!r}",
            f"check for a stray stash: git -C {repo} stash list",
        )
    if not stash.ok:
        return Result.invalid(
            CHECK,
            "could not stash the working tree",
            f"git said: {stash.text().strip()[:300]}",
        )
    if "No local changes" in stash.text():
        return Result.invalid(CHECK, "git reported nothing to stash despite a dirty status")

    # The clean-tree run must never be able to skip the restore, and the
    # restore must never be able to swallow an exception from the run (a
    # `return` inside `finally` would do exactly that). So: capture, restore,
    # then decide. >:[
    p2 = None
    run_exc = None
    try:
        p2 = run(suite_argv, cwd=repo, timeout=timeout)
    except BaseException as e:  # noqa: BLE001 - re-raised below, never swallowed
        run_exc = e

    try:
        restore = G.git(repo, "stash", "pop", timeout=120)
    except BaseException as e:  # noqa: BLE001
        # The pop itself was interrupted. This is the worst moment to be quiet:
        # the tree is stashed and the user does not know it.
        return Result.invalid(
            CHECK,
            f"INTERRUPTED WHILE RESTORING - your changes are in a stash: {e!r}",
            f"run: git -C {repo} stash pop",
            data={"stash_restore_failed": True},
        )

    if not restore.ok:
        # Loudest possible failure: the user's work is sitting in a stash.
        # Reported even if the suite itself also blew up - losing the tree is
        # the worse problem, and the exception is re-raised after this only if
        # the restore succeeded.
        return Result.invalid(
            CHECK,
            "YOUR CHANGES ARE STILL IN THE STASH - restore failed",
            "run: git -C %s stash pop   (conflict? resolve, then commit or re-stash)" % repo,
            data={
                "git": restore.text().strip()[:500],
                "stash_restore_failed": True,
                "suite_exception": repr(run_exc) if run_exc else None,
            },
        )
    if run_exc is not None:
        raise run_exc

    if p2.timed_out:
        return Result.invalid(CHECK, f"suite timed out on the clean tree after {timeout}s")
    f_clean = parse_failures(p2.text())
    if p2.code != 0 and not f_clean:
        return Result.invalid(
            CHECK,
            f"suite exited {p2.code} on the clean tree but no failure names were parsed",
            "harness error on the baseline run - the comparison would be meaningless",
            data={"stderr_tail": p2.text()[-1500:]},
        )

    introduced = sorted(f_dirty - f_clean)
    pre_existing = sorted(f_dirty & f_clean)
    fixed = sorted(f_clean - f_dirty)

    r.data.update(
        {
            "introduced": introduced,
            "pre_existing": pre_existing,
            "fixed": fixed,
            "dirty_exit": p1.code,
            "clean_exit": p2.code,
        }
    )
    r.note(f"dirty run: {len(f_dirty)} failing / clean run: {len(f_clean)} failing")
    if pre_existing:
        r.note(f"pre-existing (present in BOTH runs, safe to call pre-existing): {len(pre_existing)}")
        for t in pre_existing[:20]:
            r.note(f"    pre-existing: {t}")
    if fixed:
        r.note(f"your change FIXES {len(fixed)}: {', '.join(fixed[:10])}")

    for t in introduced:
        r.add(
            Finding(
                what="test fails only with your changes applied",
                where=t,
                detail="absent from the stashed-clean run, so it is NOT pre-existing",
                fix="fix it, or prove it is environmental by re-running on another machine",
            )
        )
    if not introduced:
        r.note("no failure is attributable to the working-tree changes")
    return r
