"""pr-branch: replayed commits, against a real two-repo git setup.

The base-branch resolution tests matter most: guessing `main` on a `master`
repo turns this check into a several-hundred-commit false positive, which is
how a tool teaches you to ignore it.
"""

import os
import subprocess
import tempfile
import unittest

from cc.checks import prbranch
from cc import gitutil as G
from cc.result import EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID


def git(d, *a, check=True):
    return subprocess.run(["git", "-C", d, *a], check=check, capture_output=True, text=True)


class TestPrBranch(unittest.TestCase):
    def setUp(self):
        # upstream repo whose default branch is `master`, not `main`.
        self.up = tempfile.mkdtemp()
        git(self.up, "init", "-q", "--initial-branch=master")
        git(self.up, "config", "user.email", "maintainer@upstream.tld")
        git(self.up, "config", "user.name", "Maintainer")
        with open(os.path.join(self.up, "a.txt"), "w") as fh:
            fh.write("1\n")
        git(self.up, "add", "-A")
        git(self.up, "commit", "-qm", "upstream base")

        self.repo = tempfile.mkdtemp()
        subprocess.run(["git", "clone", "-q", self.up, self.repo], check=True, capture_output=True)
        git(self.repo, "remote", "rename", "origin", "upstream")
        git(self.repo, "config", "user.email", "me@mine.tld")
        git(self.repo, "config", "user.name", "Me")
        git(self.repo, "checkout", "-qb", "fix/thing")

    def _commit(self, name, email, fname):
        with open(os.path.join(self.repo, fname), "w") as fh:
            fh.write("x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "-c", f"user.name={name}", "-c", f"user.email={email}",
            "commit", "-qm", f"work on {fname}")

    def test_resolves_master_not_main(self):
        self.assertEqual(G.default_branch(self.repo, "upstream"), "master")

    def test_own_commits_are_clean(self):
        self._commit("Me", "me@mine.tld", "mine.txt")
        r = prbranch.check(self.repo)
        self.assertEqual(r.code, EXIT_CLEAN, [f.what for f in r.findings])
        self.assertEqual(r.data["ahead"], 1)

    def test_foreign_commit_is_flagged_as_replayed(self):
        self._commit("Me", "me@mine.tld", "mine.txt")
        self._commit("Someone Else", "other@elsewhere.tld", "theirs.txt")
        r = prbranch.check(self.repo)
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertEqual(len(r.data["foreign_commits"]), 1)
        self.assertIn("not authored by a known identity", r.findings[0].what)

    def test_commit_ceiling_fires(self):
        for i in range(4):
            self._commit("Me", "me@mine.tld", f"f{i}.txt")
        r = prbranch.check(self.repo, max_commits=2)
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertTrue(any("past a normal contribution branch" in f.what for f in r.findings))

    def test_identity_from_env_is_honoured(self):
        self._commit("Alt", "alt@mine.tld", "alt.txt")
        os.environ["CROSSCHECK_IDENTITIES"] = "alt@mine.tld"
        try:
            r = prbranch.check(self.repo)
            self.assertEqual(r.code, EXIT_CLEAN, [f.what for f in r.findings])
        finally:
            os.environ.pop("CROSSCHECK_IDENTITIES", None)

    def test_github_noreply_identity_is_recognised_as_yours(self):
        # A commit made through GitHub's web editor is authored as
        # <id>+<user>@users.noreply.github.com. Calling that "replayed" is a
        # false accusation - this operator has been bitten by it before.
        os.environ["CROSSCHECK_IDENTITIES"] = "212606152+StressTestor@users.noreply.github.com"
        try:
            self._commit("Me", "99999+StressTestor@users.noreply.github.com", "web-edit.txt")
            r = prbranch.check(self.repo)
            self.assertEqual(r.code, EXIT_CLEAN, [f.detail for f in r.findings])
        finally:
            os.environ.pop("CROSSCHECK_IDENTITIES", None)

    def test_coauthored_by_trailer_is_evidence_not_proof(self):
        # SECURITY: a Co-authored-by trailer is commit-BODY text. Anyone can
        # write your email into their own commit. Treating it as identity proof
        # (as this check briefly did) is an attacker-controlled bypass of the
        # only authorship signal there is. It must be surfaced, never trusted.
        with open(os.path.join(self.repo, "pair.txt"), "w") as fh:
            fh.write("x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "-c", "user.name=Mallory", "-c", "user.email=mallory@evil.tld",
            "commit", "-qm", "looks helpful\n\nCo-authored-by: Me <me@mine.tld>")
        r = prbranch.check(self.repo)
        self.assertEqual(r.code, EXIT_FINDING, "a self-asserted trailer suppressed a foreign commit")
        self.assertTrue(
            any("NOT proof" in (f.detail or "") for f in r.findings),
            [f.detail for f in r.findings],
        )
        # And the attacker-controlled text must be quarantined, not inlined.
        self.assertTrue(any((f.foreign or {}).get("source") == "commit" for f in r.findings))
        for f in r.findings:
            self.assertNotIn("mallory@evil.tld", f.what + (f.fix or ""))

    def test_uncredited_foreign_commit_still_flagged(self):
        # Discriminating: the co-author path must not blanket-allow everything.
        with open(os.path.join(self.repo, "theirs.txt"), "w") as fh:
            fh.write("x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "-c", "user.name=Other", "-c", "user.email=other@elsewhere.tld",
            "commit", "-qm", "their work\n\nCo-authored-by: Someone <someone@else.tld>")
        r = prbranch.check(self.repo)
        self.assertEqual(r.code, EXIT_FINDING)

    def test_unresolvable_branch_is_invalid_not_clean(self):
        # git could not answer != "zero commits, nothing to push".
        r = prbranch.check(self.repo, branch="no-such-branch")
        self.assertEqual(r.code, EXIT_INVALID)

    def test_no_commits_ahead_is_clean(self):
        r = prbranch.check(self.repo)
        self.assertEqual(r.code, EXIT_CLEAN)

    def test_base_is_the_branch_actual_base_not_the_declared_default(self):
        # odysseus publishes `dev` as its default while contribution branches
        # are cut from `main`. Diffing against the declared default produced
        # 1925 "ahead" and ~40 other-authored commits reported as replayed
        # strays - all of it ordinary main history dev lacks.
        # Build that shape: a divergent `dev`, a branch cut from `master`.
        git(self.up, "checkout", "-qb", "dev")
        for i in range(3):
            with open(os.path.join(self.up, f"dev{i}.txt"), "w") as fh:
                fh.write("x\n")
            git(self.up, "add", "-A")
            git(self.up, "commit", "-qm", f"dev only {i}")
        git(self.up, "checkout", "-q", "master")
        git(self.repo, "fetch", "-q", "upstream")
        # Make the remote *declare* dev as its default.
        git(self.repo, "symbolic-ref", "refs/remotes/upstream/HEAD", "refs/remotes/upstream/dev")

        self._commit("Me", "me@mine.tld", "mine.txt")
        declared = G.default_branch(self.repo, "upstream")
        self.assertEqual(declared, "dev", "fixture did not set the declared default")

        base, cands = G.plausible_base(self.repo, "upstream", "fix/thing", declared)
        self.assertEqual(base, "master", f"picked the declared default over the real base: {cands}")

        r = prbranch.check(self.repo)
        self.assertEqual(r.data["base"], "upstream/master")
        self.assertEqual(r.code, EXIT_CLEAN, [f.detail for f in r.findings])
        self.assertTrue(
            any("not the declared default" in n for n in r.notes),
            f"picked a different base silently: {r.notes}",
        )

    def test_a_branch_cut_from_the_maintainer_branch_resolves_to_it(self):
        # odysseus runs two long-lived branches: `dev` is the maintainer /
        # integration branch and is the declared default, while contribution
        # branches are cut from `main`. BOTH modes have to resolve correctly -
        # a heuristic that always prefers the contribution base would be just as
        # wrong for maintainer work as trusting the default was for contributions.
        git(self.up, "checkout", "-qb", "dev")
        for i in range(3):
            with open(os.path.join(self.up, f"dev{i}.txt"), "w") as fh:
                fh.write("x\n")
            git(self.up, "add", "-A")
            git(self.up, "commit", "-qm", f"maintainer work {i}")
        git(self.up, "checkout", "-q", "master")
        git(self.repo, "fetch", "-q", "upstream")
        git(self.repo, "symbolic-ref", "refs/remotes/upstream/HEAD", "refs/remotes/upstream/dev")

        # Cut a branch from dev, the way direct repo work would.
        git(self.repo, "checkout", "-qB", "maint/thing", "upstream/dev")
        with open(os.path.join(self.repo, "m.txt"), "w") as fh:
            fh.write("x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "maintainer change")

        base, cands = G.plausible_base(self.repo, "upstream", "maint/thing", "dev")
        self.assertEqual(base, "dev", f"maintainer branch did not resolve to dev: {cands}")

        r = prbranch.check(self.repo, branch="maint/thing")
        self.assertEqual(r.data["base"], "upstream/dev")
        self.assertEqual(r.code, EXIT_CLEAN, [f.detail for f in r.findings])
        self.assertFalse(
            any("not the declared default" in n for n in r.notes),
            "warned about a base change that did not happen",
        )

    def test_declared_default_wins_when_it_is_the_nearest(self):
        # Discriminating: do not wander off the declared default for no reason.
        self._commit("Me", "me@mine.tld", "mine.txt")
        base, _ = G.plausible_base(self.repo, "upstream", "fix/thing", "master")
        self.assertEqual(base, "master")

    def test_repo_branch_policy_is_surfaced_when_transcribed(self):
        # The git graph says which branch you ARE on. It cannot say which branch
        # this KIND of work belongs on - that is prose a project states
        # elsewhere. odysseus's owner: dev for normal work, main for security
        # fixes. A divergence heuristic would bless a security fix cut from dev.
        import json as _json
        rd = tempfile.mkdtemp()
        os.environ["CROSSCHECK_REPOS"] = rd
        try:
            url = git(self.repo, "remote", "get-url", "upstream").stdout.strip()
            with open(os.path.join(rd, "fixture.json"), "w") as fh:
                _json.dump({
                    "repo": "fixture",
                    "match": os.path.basename(url),
                    "branch_policy": {
                        "quote": "dev for normal work, main for security fixes",
                        "rules": [{"base": "master", "for": "security", "note": "security fixes belong here"}],
                    },
                    "push_policy": {"push_to_origin": False, "note": "we push nothing here"},
                }, fh)
            self._commit("Me", "me@mine.tld", "mine.txt")
            r = prbranch.check(self.repo)
            joined = " ".join(r.notes)
            self.assertIn("dev for normal work, main for security fixes", joined)
            self.assertIn("security fixes belong here", joined)
            self.assertIn("we push nothing here", joined)
        finally:
            os.environ.pop("CROSSCHECK_REPOS", None)

    def test_no_policy_file_means_no_policy_noise(self):
        # Discriminating: a repo with no transcribed policy must stay quiet.
        rd = tempfile.mkdtemp()
        os.environ["CROSSCHECK_REPOS"] = rd
        try:
            self._commit("Me", "me@mine.tld", "mine.txt")
            r = prbranch.check(self.repo)
            self.assertFalse(any("policy:" in n for n in r.notes), r.notes)
        finally:
            os.environ.pop("CROSSCHECK_REPOS", None)

    def test_not_a_repo_is_invalid(self):
        self.assertEqual(prbranch.check(tempfile.mkdtemp()).code, EXIT_INVALID)

    def test_unknown_base_is_invalid_not_guessed(self):
        # Explicitly asking for a branch that does not exist must not silently
        # fall back to some other base.
        r = prbranch.check(self.repo, base="does-not-exist")
        self.assertEqual(r.code, EXIT_INVALID)

    def test_no_remote_is_invalid(self):
        solo = tempfile.mkdtemp()
        git(solo, "init", "-q")
        git(solo, "config", "user.email", "a@b.c")
        git(solo, "config", "user.name", "a")
        with open(os.path.join(solo, "x"), "w") as fh:
            fh.write("1")
        git(solo, "add", "-A")
        git(solo, "commit", "-qm", "x")
        self.assertEqual(prbranch.check(solo).code, EXIT_INVALID)


if __name__ == "__main__":
    unittest.main()
