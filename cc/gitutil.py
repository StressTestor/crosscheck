"""git helpers. The important one is: never assume the default branch is main.

Real bases seen in this corpus: `master` (star-map), `dev`, `main`. Guessing
wrong turns a branch check into a 600-commit false positive, which is how you
teach yourself to ignore the tool. (｡◕‿↼)
"""

from __future__ import annotations

import os

from .run import run, Proc

# Order matters: whatever the remote itself says wins over any local guess.
_FALLBACK_BRANCHES = ("main", "master", "dev", "develop", "trunk")


def is_repo(path: str) -> bool:
    p = run(["git", "-C", path, "rev-parse", "--git-dir"], timeout=20)
    return p.ok


def git(path: str, *args: str, timeout: int = 60) -> Proc:
    return run(["git", "-C", path, *args], timeout=timeout)


def remotes(path: str) -> list[str]:
    p = git(path, "remote")
    return [ln.strip() for ln in p.out.splitlines() if ln.strip()] if p.ok else []


def pick_remote(path: str, preferred: str | None = None) -> str | None:
    """upstream beats origin: on a fork, origin is yours and upstream is theirs."""
    rs = remotes(path)
    if preferred:
        return preferred if preferred in rs else None
    for cand in ("upstream", "origin"):
        if cand in rs:
            return cand
    return rs[0] if rs else None


def default_branch(path: str, remote: str) -> str | None:
    """Resolve the remote's real default branch. Returns None when unknowable.

    None is a legitimate answer and callers must treat it as INVALID rather
    than substituting 'main' - a wrong base is worse than no answer.
    """
    # 1. The symbolic ref the remote itself published.
    p = git(path, "symbolic-ref", "--quiet", f"refs/remotes/{remote}/HEAD")
    if p.ok and p.out.strip():
        return p.out.strip().rsplit("/", 1)[-1]

    # 2. Ask the remote directly (needs network; may be denied offline).
    p = git(path, "ls-remote", "--symref", remote, "HEAD", timeout=45)
    if p.ok:
        for ln in p.out.splitlines():
            if ln.startswith("ref:") and "HEAD" in ln:
                return ln.split()[1].rsplit("/", 1)[-1]

    # 3. Only now fall back, and only to a ref that actually exists locally.
    for cand in _FALLBACK_BRANCHES:
        if git(path, "rev-parse", "--verify", "--quiet", f"refs/remotes/{remote}/{cand}").ok:
            return cand
    return None


def current_branch(path: str) -> str | None:
    p = git(path, "rev-parse", "--abbrev-ref", "HEAD")
    b = p.out.strip() if p.ok else ""
    return b if b and b != "HEAD" else None


def commits_ahead(path: str, branch: str, base_ref: str) -> list[dict] | None:
    """Commits on `branch` not reachable from `base_ref`, newest first.

    Returns None when git could not answer (unknown revision, corrupt repo).
    Returning [] there would be indistinguishable from "zero commits, verified"
    - which read as CLEAN "nothing to push" for a mistyped branch name. 💀
    """
    sep = "\x1f"
    fmt = sep.join(["%H", "%an", "%ae", "%s"])
    p = git(path, "log", f"--format={fmt}", f"{base_ref}..{branch}")
    if not p.ok:
        return None
    out = []
    for ln in p.out.splitlines():
        if not ln.strip():
            continue
        parts = ln.split(sep)
        if len(parts) != 4:
            continue
        sha, an, ae, subj = parts
        out.append({"sha": sha, "author": an, "email": ae, "subject": subj})
    return out


def commit_files(path: str, sha: str) -> list[str]:
    p = git(path, "show", "--name-only", "--format=", sha)
    return [ln.strip() for ln in p.out.splitlines() if ln.strip()] if p.ok else []


def identities(path: str) -> set[str]:
    """Emails that count as 'you' - local config plus the known noreply form."""
    ids = set()
    for scope in ("--local", "--global"):
        p = git(path, "config", scope, "user.email")
        if p.ok and p.out.strip():
            ids.add(p.out.strip().lower())
    env = os.environ.get("CROSSCHECK_IDENTITIES", "")
    for e in env.split(","):
        if e.strip():
            ids.add(e.strip().lower())
    return ids


def same_person(email: str, known: set[str]) -> bool:
    """Is this email one of yours, allowing for GitHub's noreply forms?

    A commit you made through the GitHub web editor is authored as
    `<id>+<user>@users.noreply.github.com`. Calling that "written by someone
    else - replayed" is a false accusation, and this operator has already been
    bitten by exactly this identity split once. So compare the noreply LOCAL
    part too, not just the whole address.
    """
    e = (email or "").strip().lower()
    if e in known:
        return True
    handle = _noreply_handle(e)
    if not handle:
        return False
    return any(_noreply_handle(k) == handle for k in known)


def _noreply_handle(email: str) -> str | None:
    """`1234+joe@users.noreply.github.com` -> `joe`. None when not a noreply."""
    if not email.endswith("@users.noreply.github.com"):
        return None
    local = email.split("@", 1)[0]
    return local.split("+", 1)[1] if "+" in local else local


def dirty_files(path: str) -> list[str]:
    """Everything not committed, tracked or not. Used to decide stashability."""
    p = git(path, "status", "--porcelain", "--untracked-files=all")
    return [ln[3:].strip() for ln in p.out.splitlines() if ln.strip()] if p.ok else []
