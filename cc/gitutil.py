"""git helpers. The important one is: never assume the default branch is main.

Real bases seen in this corpus: `master` (star-map), `dev`, `main`. Guessing
wrong turns a branch check into a 600-commit false positive, which is how you
teach yourself to ignore the tool. (｡◕‿↼)
"""

from __future__ import annotations

import os
import re

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


def plausible_base(path: str, remote: str, branch: str, declared: str | None) -> tuple[str | None, list[dict]]:
    """Pick the base this branch is ACTUALLY cut from, not the declared default.

    A repo can publish `dev` as its default while contribution branches are cut
    from `main`. Diffing against the declared default then yields a nonsense
    set - odysseus produced 1925 "ahead" and ~40 commits by other authors, all
    of them ordinary `main` history that `dev` simply does not contain. The
    check reported them as replayed strays. That is precisely the false
    positive this module exists to avoid, arrived at from the other direction:
    not by guessing `main`, but by trusting a default that was not the base. >:[

    So: score every plausible base by how far ahead the branch is, and take the
    nearest. Ties keep the declared default. Returns (base, all_candidates).
    """
    seen, cands = [], []
    for cand in ([declared] if declared else []) + list(_FALLBACK_BRANCHES):
        if not cand or cand in seen:
            continue
        seen.append(cand)
        ref = f"{remote}/{cand}"
        if not git(path, "rev-parse", "--verify", "--quiet", ref).ok:
            continue
        p = git(path, "rev-list", "--left-right", "--count", f"{ref}...{branch}")
        if not p.ok or len(p.out.split()) != 2:
            continue
        behind, ahead = (int(x) for x in p.out.split())
        cands.append({"branch": cand, "ahead": ahead, "behind": behind, "declared": cand == declared})
    if not cands:
        return None, []
    # Score on TOTAL divergence (ahead + behind), not `ahead` alone. Two
    # candidates can be equally far ahead while one of them is also 3 commits
    # behind - and a base you are behind is not a base you were cut from.
    # Total divergence is the merge-base distance; ties keep the declared
    # default so we never wander off it without a reason. (｡◕‿↼)
    best = min(cands, key=lambda c: (c["ahead"] + c["behind"], c["ahead"], not c["declared"]))
    return best["branch"], cands


_REPO_DIR_ENV = "CROSSCHECK_REPOS"
_DEFAULT_REPO_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "repos"
)


def repo_dir() -> str:
    return os.environ.get(_REPO_DIR_ENV) or _DEFAULT_REPO_DIR


def remote_url(path: str, remote: str) -> str:
    p = git(path, "remote", "get-url", remote)
    return p.out.strip() if p.ok else ""


def repo_policy(path: str, remote: str) -> dict | None:
    """Hand-transcribed per-repo branch policy, matched on the remote URL.

    The git graph can tell you which branch you ARE on. It cannot tell you which
    branch this KIND of work belongs on - that is a decision a project states in
    prose, somewhere the tool cannot see. odysseus's owner put it in a chat
    room: dev for normal work, main for security fixes and narrow hotfixes. A
    divergence heuristic will happily bless a security fix cut from dev, because
    dev is genuinely nearest. So the policy is data, and we surface it at the
    moment the base is chosen. (｡◕‿↼)
    """
    import json as _json

    url = remote_url(path, remote)
    if not url:
        return None
    d = repo_dir()
    if not os.path.isdir(d):
        return None
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".json") or fn.startswith("_"):
            continue
        try:
            with open(os.path.join(d, fn), "r", encoding="utf-8") as fh:
                pol = _json.load(fh)
        except (OSError, ValueError):
            continue
        m = pol.get("match", "")
        if m and m in url:
            return pol
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
    fmt = sep.join(["%H", "%an", "%ae", "%s", "%b"])
    p = git(path, "log", f"--format={fmt}", f"{base_ref}..{branch}")
    if not p.ok:
        return None
    out = []
    for ln in p.out.splitlines():
        if not ln.strip():
            continue
        parts = ln.split(sep)
        if len(parts) < 4:
            continue
        sha, an, ae, subj = parts[0], parts[1], parts[2], parts[3]
        body = parts[4] if len(parts) > 4 else ""
        out.append(
            {"sha": sha, "author": an, "email": ae, "subject": subj,
             "coauthors": _coauthors(body)}
        )
    return out


_COAUTHOR_RE = re.compile(r"^\s*co-authored-by:.*?<([^>]+)>", re.I | re.M)


def _coauthors(body: str) -> list[str]:
    """Emails from Co-authored-by trailers - GitHub's own pairing convention."""
    return [m.strip().lower() for m in _COAUTHOR_RE.findall(body or "")]


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


def submodule_paths(path: str) -> list[str]:
    """Submodule paths, recursively. Empty when there are none."""
    p = git(path, "submodule", "status", "--recursive")
    if not p.ok:
        return []
    out = []
    for ln in p.out.splitlines():
        # " <sha> <path> (<describe>)" - the leading char is a status flag.
        parts = ln.strip().split()
        if len(parts) >= 2:
            out.append(parts[1])
    return out


def dirty_submodules(path: str) -> list[str]:
    """Submodules holding uncommitted content.

    `git stash --include-untracked` does NOT recurse into submodules, so any
    work in here is invisible to the stash-and-restore contract. Discovering
    that after running a suite that writes into one costs the user the work,
    with no stash to recover from. Ask BEFORE running anything. 💀
    """
    dirty = []
    for sub in submodule_paths(path):
        full = os.path.join(path, sub)
        if not os.path.isdir(full):
            continue
        st = git(full, "status", "--porcelain", "--untracked-files=all")
        if st.ok and st.out.strip():
            dirty.append(sub)
    return dirty


def dirty_files(path: str) -> list[str]:
    """Everything not committed, tracked or not. Used to decide stashability."""
    p = git(path, "status", "--porcelain", "--untracked-files=all")
    return [ln[3:].strip() for ln in p.out.splitlines() if ln.strip()] if p.ok else []
