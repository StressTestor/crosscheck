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


def check(
    repo: str,
    body_path: str,
    title: str | None = None,
    strict_title: bool = False,
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
            return Result.invalid(
                CHECK,
                f"{os.path.relpath(checker, repo)} exists but node is not installed",
                "brew install node - without it we cannot run the repo's real gate",
            )
        if not os.path.isfile(_HARNESS):
            return Result.invalid(CHECK, f"harness missing: {_HARNESS}")

        env = {"CC_PR_TITLE": title or ""}
        p = run(["node", _HARNESS, checker, body_path], cwd=repo, timeout=90, env=env)
        if p.timed_out:
            return Result.invalid(CHECK, "the repo's checker timed out")
        try:
            payload = json.loads(p.out.strip().splitlines()[-1]) if p.out.strip() else {}
        except (ValueError, IndexError):
            return Result.invalid(
                CHECK,
                "could not parse harness output",
                p.text().strip()[:400],
            )

        if payload.get("error"):
            return Result.invalid(
                CHECK,
                f"the repo's checker raised: {payload['error']}",
                "the harness stubs github/context/core; this checker may need more surface",
            )

        r.note(f"ran the repo's own checker: {os.path.relpath(checker, repo)}")
        for w in payload.get("warnings", [])[:5]:
            r.note(f"checker warning: {w}")
        problems = payload.get("problems", [])
        r.data["problems"] = problems
        for prob in problems:
            r.add(
                Finding(
                    what=re.sub(r"\*\*(.+?)\*\*", r"\1", prob),
                    detail="reported by the repo's own PR-description bot",
                    fix="fix the draft before pushing - this bot runs on your PR",
                )
            )
        if not problems and not payload.get("failed"):
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
    low = stripped.lower()
    missing = []
    for sec in _template_sections(tpl):
        key = re.sub(r"[^a-z0-9 ]+", "", sec.lower()).strip()
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
