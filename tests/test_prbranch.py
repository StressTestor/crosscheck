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

    def test_unresolvable_branch_is_invalid_not_clean(self):
        # git could not answer != "zero commits, nothing to push".
        r = prbranch.check(self.repo, branch="no-such-branch")
        self.assertEqual(r.code, EXIT_INVALID)

    def test_no_commits_ahead_is_clean(self):
        r = prbranch.check(self.repo)
        self.assertEqual(r.code, EXIT_CLEAN)

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
