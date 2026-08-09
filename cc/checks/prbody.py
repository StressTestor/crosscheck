"""pr-body - run the target repo's OWN description checker against your draft.

The template is prose; the bot is the gate. Re-deriving the bot's rules from
the template drifts the moment a maintainer edits one and not the other, and
odysseus is a live example: the template shows an end-to-end checkbox the bot
never inspects. So we do not re-derive. We execute the maintainer's checker
with stubbed github/context/core and report exactly what it would have posted.

Zero maintenance, exactly correct, and it generalises to any repo carrying a
description bot. Repos with no bot fall back to template-section matching,
which is explicitly reported as the weaker check so a PASS there is not read as
the same guarantee.

Judgment calls:
1. A repo with a checker we cannot execute (no node) is INVALID, never CLEAN.
   "I could not check" and "there is nothing wrong" are different answers.
2. The fallback only asserts that every `##` heading in the template appears in
   the draft with non-placeholder content. It cannot know the bot's thresholds.
3. Conventional-Commits title validation runs only when the repo actually
   enforces it (a workflow mentioning it) or when --strict-title is passed. We
   do not impose our own conventions on someone else's repo.
"""

from __future__ import annotations

import json
import os
import re

from ..result import Result, Finding
from ..run import run, have

CHECK = "pr-body"

_HARNESS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "harness", "pr_check_harness.js")

# Where description bots actually live, in observed order of likelihood.
_CHECKER_GLOBS = (
    ".github/scripts/check-pr-description.js",
    ".github/scripts/check-pr-body.js",
    ".github/scripts/pr-description.js",
    ".github/scripts/check-description.js",
)

_TEMPLATES = (
    ".github/pull_request_template.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "docs/pull_request_template.md",
    ".github/PULL_REQUEST_TEMPLATE/pull_request_template.md",
)

# Conventional Commits, matching the shape odysseus enforces in CI.
_CC_RE = re.compile(
    r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([\w .\/-]+\))?!?: .+"
)


def find_checker(repo: str) -> str | None:
    for rel in _CHECKER_GLOBS:
        p = os.path.join(repo, rel)
        if os.path.isfile(p):
            return p
    # Anything else that looks like one.
    d = os.path.join(repo, ".github", "scripts")
    if os.path.isdir(d):
        for fn in sorted(os.listdir(d)):
            if re.match(r"check.*(pr|description).*\.js$", fn, re.I):
                return os.path.join(d, fn)
    return None


def find_template(repo: str) -> str | None:
    for rel in _TEMPLATES:
        p = os.path.join(repo, rel)
        if os.path.isfile(p):
            return p
    return None


def _strip_comments(text: str) -> str:
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


def _flatten(text: str) -> str:
    """Lowercase, drop punctuation, collapse whitespace. Used on BOTH sides."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", text.lower())).strip()


def enforces_conventional_title(repo: str) -> bool:
    wf = os.path.join(repo, ".github", "workflows")
    if not os.path.isdir(wf):
        return False
    for fn in os.listdir(wf):
        if not fn.endswith((".yml", ".yaml")):
            continue
        try:
            with open(os.path.join(wf, fn), "r", encoding="utf-8", errors="replace") as fh:
                if "Conventional Commits" in fh.read():
                    return True
        except OSError:
            continue
    return False


def _template_sections(path: str) -> list[str]:
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                m = re.match(r"^#{1,6}\s+(.+?)\s*$", ln)
                if m:
                    out.append(m.group(1).strip())
    except OSError:
        return []
    return out


_SANDBOX_PROBE_CACHE: dict[str, bool] = {}


def _node_supports_permission() -> bool:
    """Does this node have the permission model? Probed once, then cached."""
    if "ok" not in _SANDBOX_PROBE_CACHE:
        p = run(["node", "--permission", "-e", "0"], timeout=30)
        _SANDBOX_PROBE_CACHE["ok"] = p.ok
    return _SANDBOX_PROBE_CACHE["ok"]


def _sandbox_args(repo: str, body_path: str) -> list[str] | None:
    """node flags confining an untrusted checker. None when unsupported."""
    if not _node_supports_permission():
        return None
    # BOTH the logical and the resolved path go in the allowlist. On macOS a
    # temp dir is /var/folders/... which is a symlink to /private/var/... and
    # node checks the RESOLVED path - allowlisting only one silently denies the
    # legitimate checker, which then reads as INVALID forever. XX
    reads = set()
    for p in (repo, os.path.dirname(_HARNESS), body_path):
        for form in (os.path.abspath(p), os.path.realpath(p)):
            reads.add(form)

    argv = ["--permission"]
    for p in sorted(reads):
        argv.append(f"--allow-fs-read={p}")
        if os.path.isdir(p):
            argv.append(f"--allow-fs-read={p}/*")
    return argv


def check(
    repo: str,
    body_path: str,
    title: str | None = None,
    strict_title: bool = False,
    trust_repo: bool = False,
) -> Result:
    r = Result(check=CHECK)

    if not os.path.isdir(repo):
        return Result.invalid(CHECK, f"no such repo path: {repo}")
    if not os.path.isfile(body_path):
        return Result.invalid(CHECK, f"no such draft body file: {body_path}")

    try:
        with open(body_path, "r", encoding="utf-8", errors="replace") as fh:
            body = fh.read()
    except OSError as e:
        return Result.invalid(CHECK, f"cannot read draft body: {e}")

    if not body.strip():
        r.add(Finding(what="draft PR body is empty", fix="write the description before pushing"))
        return r

    # ---- title -----------------------------------------------------------
    want_title = strict_title or enforces_conventional_title(repo)
    r.data["title_enforced_by_repo"] = want_title
    if want_title:
        if not title:
            r.add(
                Finding(
                    what="repo enforces Conventional Commits PR titles but no --title was given",
                    fix='cc pr-body <repo> <body.md> --title "fix(scope): summary"',
                    severity="invalid",
                )
            )
        elif not _CC_RE.match(title):
            r.add(
                Finding(
                    what="PR title is not Conventional Commits",
                    where=title[:120],
                    detail="expected type(scope): summary - feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert",
                    fix='e.g. "fix(search): handle empty query"',
                )
            )

    # ---- the real gate: the repo's own checker ---------------------------
    checker = find_checker(repo)
    r.data["checker"] = checker
    if checker:
        if not have("node"):
            return r.fail(
                f"{os.path.relpath(checker, repo)} exists but node is not installed",
                "brew install node - without it we cannot run the repo's real gate",
            )
        if not os.path.isfile(_HARNESS):
            return r.fail(f"harness missing: {_HARNESS}")

        # We are about to execute JavaScript that came out of a cloned repo.
        # For odysseus that is fine; for a repo you cloned an hour ago to audit
        # it is arbitrary attacker code running as you.
        #
        # Two boundaries, and only one of them is real:
        #   - node's --permission model (OS-level): no fs writes, no
        #     child_process, no worker threads. This one HOLDS.
        #   - the vm context's require-guard and process stub (in-process):
        #     defence in depth ONLY. `this.constructor.constructor('return
        #     process')()` walks straight out of a vm context - node's own docs
        #     say vm is not a security mechanism, and it was demonstrated
        #     against this harness.
        #
        # So the env is not "stubbed", it is NOT PASSED: inherit_env=False
        # means a full vm escape reaches a process whose environment holds
        # PATH and the three CC_* values we chose. Nothing to steal. 👻
        sandbox = _sandbox_args(repo, body_path)
        if sandbox is None and not trust_repo:
            return r.fail(
                "cannot sandbox the repo's checker (node is too old for --permission)",
                "upgrade node, or re-run with --trust-repo if you genuinely trust this repo's .github/scripts",
            )
        env = {"CC_PR_TITLE": title or ""}
        argv = ["node"] + (sandbox or []) + [_HARNESS, checker, body_path]
        p = run(argv, cwd=repo, timeout=90, env=env, inherit_env=False)
        if sandbox:
            r.note("ran the checker sandboxed: no fs writes, no subprocesses, no inherited environment")
        else:
            r.note("SANDBOX DISABLED via --trust-repo - the repo's JS ran with your privileges")
        if p.timed_out:
            return r.fail("the repo's checker timed out")
        # A dead checker is not a passing checker. The harness exits 0 on every
        # path it controls, so a non-zero code means the process died - an
        # uncaught async throw is ordinary Actions-bot code - and empty stdout
        # means it produced no verdict at all. Either way there is nothing to
        # read, and "nothing to read" must never reach the CLEAN path. XX
        if p.code != 0:
            return r.fail(
                f"the repo's checker process exited {p.code} - it produced no verdict",
                p.text().strip()[-400:] or "(no output)",
            )
        if not p.out.strip():
            return r.fail(
                "the repo's checker produced no output",
                p.text().strip()[-400:] or "(no output)",
            )
        try:
            payload = json.loads(p.out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return r.fail("could not parse harness output", p.text().strip()[:400])

        if payload.get("error"):
            return r.fail(
                f"the repo's checker raised: {payload['error']}",
                "the harness stubs github/context/core; this checker may need more surface",
            )

        r.note(f"ran the repo's own checker: {os.path.relpath(checker, repo)}")
        for w in payload.get("warnings", [])[:5]:
            r.note(f"checker warning: {w}")
        problems = payload.get("problems", [])
        r.data["problems"] = problems
        r.data["failed"] = bool(payload.get("failed"))
        for prob in problems:
            r.add(
                Finding(
                    what=re.sub(r"\*\*(.+?)\*\*", r"\1", prob),
                    detail="reported by the repo's own PR-description bot",
                    fix="fix the draft before pushing - this bot runs on your PR",
                )
            )
        if payload.get("failed") and not problems:
            # The checker failed the draft but rendered nothing we could parse.
            # Plenty of bots just call core.setFailed() and let the job status
            # carry the message. Reporting CLEAN here would be the exact
            # failure this tool exists to prevent: the check RAN, and FAILED.
            r.add(
                Finding(
                    what="the repo's checker FAILED this draft: "
                         + (payload.get("message") or "(no message given)"),
                    detail="it failed without emitting parseable bullets, so the specific rules are unknown",
                    fix=f"read {os.path.relpath(checker, repo)} and fix the draft by hand",
                    severity="judgment",
                )
            )
        elif not problems:
            r.note("the repo's description bot would pass this draft")
        return r

    # ---- fallback: template sections (weaker, and says so) ---------------
    tpl = find_template(repo)
    if not tpl:
        r.note("repo has neither a description bot nor a PR template - nothing to enforce")
        return r

    r.note(f"no description bot found; falling back to template sections ({os.path.relpath(tpl, repo)})")
    r.note("WEAKER CHECK: section presence only, not the bot's thresholds")
    r.data["template"] = tpl

    stripped = _strip_comments(body)
    # Normalize BOTH sides identically. Stripping punctuation from only the
    # template heading meant "Visual / UI changes" became "visual  ui changes"
    # and could never match the draft's un-stripped text - so every punctuated
    # heading reported missing even when copied verbatim. >:[
    low = _flatten(stripped)
    missing = []
    for sec in _template_sections(tpl):
        key = _flatten(sec)
        if not key or len(key) < 3:
            continue
        if key not in low:
            missing.append(sec)
    r.data["missing_sections"] = missing
    for sec in missing:
        r.add(
            Finding(
                what="template section missing from the draft",
                where=sec,
                fix=f"add a '{sec}' section",
            )
        )
    if not missing:
        r.note("every template section appears in the draft")
    return r
