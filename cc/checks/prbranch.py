"""pr-branch - catch a branch that replays commits before you push it.

The real cost, from the corpus: rustsec#1604 was closed by the maintainer with
"this PR seems to replay all commits or something", and tex-fmt#141 was
self-closed to cut losses. Both were a stale branch rebased instead of
refreshed. The fix is `git checkout -B <branch> upstream/<default>` then
cherry-pick your own commits - never a bare rebase of a branch that is hundreds
of commits behind.

This check is a set difference against the remote's REAL default branch and an
author filter. Anything on your branch that you did not write, or that does not
touch your fix surface, is a replayed stray.

Judgment calls:
1. The base is resolved from the remote, never assumed. If it cannot be
   resolved we return INVALID - guessing `main` on a `master` repo produces a
   600-commit false positive and trains you to ignore the tool.
2. `upstream` is preferred over `origin`. On a fork, origin is yours; the thing
   you are diffing against is theirs.
3. Author identity comes from git config plus $CROSSCHECK_IDENTITIES. An
   unrecognised author is reported, not silently allowed.
4. We do NOT auto-fetch. A check that mutates your repo to make itself pass is
   its own bug; if the remote ref is stale we say so and tell you to fetch.
"""

from __future__ import annotations

from ..result import Result, Finding
from .. import gitutil as G

CHECK = "pr-branch"

# More than this many commits ahead is almost never a real contribution branch.
SANE_COMMIT_CEILING = 25


def check(
    repo: str,
    branch: str | None = None,
    remote: str | None = None,
    base: str | None = None,
    max_commits: int = SANE_COMMIT_CEILING,
) -> Result:
    r = Result(check=CHECK)

    if not G.is_repo(repo):
        return Result.invalid(CHECK, f"not a git repo: {repo}")

    branch = branch or G.current_branch(repo)
    if not branch:
        return Result.invalid(CHECK, "detached HEAD - check out the branch you intend to push")

    rem = G.pick_remote(repo, remote)
    if not rem:
        return Result.invalid(CHECK, "no git remote configured", "git remote add upstream <url>")

    if base:
        base_branch = base
    else:
        declared = G.default_branch(repo, rem)
        base_branch, cands = G.plausible_base(repo, rem, branch, declared)
        if not base_branch:
            return Result.invalid(
                CHECK,
                f"could not resolve any base branch on remote '{rem}'",
                f"git fetch {rem}, or pass --base",
            )
        r.data["base_candidates"] = cands
        if declared and base_branch != declared:
            # Say it out loud. Silently picking a different base than the repo
            # declares is the kind of helpfulness that hides a wrong answer.
            near = next(c for c in cands if c["branch"] == base_branch)
            far = next((c for c in cands if c["branch"] == declared), None)
            r.note(
                f"base: using {base_branch} ({near['ahead']} ahead), not the declared default "
                f"{declared}" + (f" ({far['ahead']} ahead) - this branch is not cut from it" if far else "")
            )

    base_ref = f"{rem}/{base_branch}"
    if not G.git(repo, "rev-parse", "--verify", "--quiet", base_ref).ok:
        return Result.invalid(
            CHECK,
            f"{base_ref} does not exist locally",
            f"git fetch {rem}",
        )

    r.data.update({"branch": branch, "remote": rem, "base": base_ref})

    commits = G.commits_ahead(repo, branch, base_ref)
    if commits is None:
        # git could not answer. "zero commits" and "unanswerable" must not
        # share the CLEAN 'nothing to push' path - that let a mistyped
        # --branch report clean. >:[
        return Result.invalid(
            CHECK,
            f"git could not resolve {base_ref}..{branch}",
            f"check the branch name exists: git -C {repo} rev-parse --verify {branch}",
        )
    r.data["ahead"] = len(commits)
    behind = G.git(repo, "rev-list", "--count", f"{branch}..{base_ref}")
    if behind.ok and behind.out.strip().isdigit():
        r.data["behind"] = int(behind.out.strip())

    if not commits:
        r.note(f"{branch} has no commits beyond {base_ref} - nothing to push")
        return r

    r.note(f"{branch} is {len(commits)} commit(s) ahead of {base_ref}")

    mine = G.identities(repo)
    r.data["identities"] = sorted(mine)
    if not mine:
        r.add(
            Finding(
                what="no git identity configured, cannot tell your commits from replayed ones",
                fix="git config user.email <you>   or set CROSSCHECK_IDENTITIES=a@b,c@d",
                severity="invalid",
            )
        )
        return r

    # A pair-programmed commit authored by a collaborator but crediting you via
    # a Co-authored-by trailer is YOURS. Telling someone to cherry-pick "only
    # your shas" would have them drop it.
    strays = [
        c for c in commits
        if not G.same_person(c["email"], mine)
        and not any(G.same_person(e, mine) for e in c.get("coauthors", []))
    ]
    r.data["foreign_commits"] = strays

    if len(commits) > max_commits:
        r.add(
            Finding(
                what=f"{len(commits)} commits ahead of {base_ref} - far past a normal contribution branch",
                detail=f"ceiling is {max_commits}; this is the shape of a bare rebase onto a stale base",
                fix=f"git checkout -B {branch} {base_ref} && git cherry-pick <your shas>",
            )
        )

    for c in strays:
        r.add(
            Finding(
                what="commit on your branch is not authored by a known identity of yours",
                where=c["sha"][:12],
                detail=f"{c['author']} <{c['email']}>: {c['subject'][:110]}",
                fix=(
                    f"if that address IS yours, register it: "
                    f"CROSSCHECK_IDENTITIES={c['email']} - otherwise it is replayed: "
                    f"git checkout -B {branch} {base_ref} && git cherry-pick <only your shas>"
                ),
            )
        )

    if not strays and len(commits) <= max_commits:
        r.note("every commit ahead is authored by you - branch shape looks clean")
    return r
