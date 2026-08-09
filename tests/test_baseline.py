"""baseline: failure parsing and the stash-restore contract.

The restore-failure path gets a test before the happy path, because that is the
one where a bug costs the user their working tree.
"""

import os
import subprocess
import tempfile
import unittest

from cc.checks import baseline
from cc.result import EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID


class TestParseFailures(unittest.TestCase):
    def test_pytest(self):
        out = "FAILED tests/test_a.py::test_one - AssertionError\nFAILED tests/test_b.py::test_two\n1 passed"
        self.assertEqual(
            baseline.parse_failures(out), {"tests/test_a.py::test_one", "tests/test_b.py::test_two"}
        )

    def test_unittest(self):
        out = "FAIL: test_thing (tests.test_mod.Klass)\nERROR: test_other (tests.test_mod.Klass)"
        got = baseline.parse_failures(out)
        self.assertTrue(any("test_thing" in g for g in got), got)

    def test_go(self):
        self.assertEqual(baseline.parse_failures("--- FAIL: TestThing (0.00s)"), {"TestThing"})

    def test_cargo(self):
        self.assertEqual(baseline.parse_failures("test mod::thing ... FAILED"), {"mod::thing"})

    def test_clean_output_yields_nothing(self):
        self.assertEqual(baseline.parse_failures("5 passed in 0.2s"), set())

    def test_unparseable_is_empty_not_a_guess(self):
        # An empty set here is what drives the "harness error" INVALID path.
        self.assertEqual(baseline.parse_failures("Segmentation fault"), set())


def _git(d, *a):
    subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)


class TestBaselineIntegration(unittest.TestCase):
    """Real git repo, real subprocess. These are the semantics that matter."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        _git(self.d, "init", "-q")
        _git(self.d, "config", "user.email", "t@t.t")
        _git(self.d, "config", "user.name", "t")
        # A fake suite whose output we control via a file in the tree.
        with open(os.path.join(self.d, "suite.sh"), "w") as fh:
            fh.write('#!/bin/sh\ncat "$(dirname "$0")/out.txt" 2>/dev/null; exit "$(cat "$(dirname "$0")/code.txt" 2>/dev/null || echo 0)"\n')
        os.chmod(os.path.join(self.d, "suite.sh"), 0o755)
        self._write("out.txt", "1 passed\n")
        self._write("code.txt", "0\n")
        _git(self.d, "add", "-A")
        _git(self.d, "commit", "-qm", "init")

    def _write(self, name, text):
        with open(os.path.join(self.d, name), "w") as fh:
            fh.write(text)

    def _suite(self):
        return [os.path.join(self.d, "suite.sh")]

    def test_clean_tree_is_invalid_not_clean(self):
        # Nothing to compare -> saying CLEAN would be a lie.
        r = baseline.check(self.d, self._suite())
        self.assertEqual(r.code, EXIT_INVALID)

    def test_introduced_failure_is_attributed(self):
        # Dirty tree fails; stashed clean tree passes -> introduced.
        self._write("out.txt", "FAILED tests/test_x.py::test_new\n")
        self._write("code.txt", "1\n")
        r = baseline.check(self.d, self._suite())
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertIn("tests/test_x.py::test_new", r.data["introduced"])
        self.assertEqual(r.data["pre_existing"], [])

    def test_pre_existing_failure_is_not_attributed(self):
        # Commit the failure first, then dirty the tree with something else.
        self._write("out.txt", "FAILED tests/test_x.py::test_old\n")
        self._write("code.txt", "1\n")
        _git(self.d, "add", "-A")
        _git(self.d, "commit", "-qm", "failing")
        self._write("unrelated.txt", "dirty\n")
        r = baseline.check(self.d, self._suite())
        self.assertEqual(r.code, EXIT_CLEAN, r.findings and r.findings[0].what)
        self.assertIn("tests/test_x.py::test_old", r.data["pre_existing"])
        self.assertEqual(r.data["introduced"], [])

    def test_harness_error_is_invalid_not_a_test_failure(self):
        # Non-zero exit with nothing parseable must never become "you broke it".
        self._write("out.txt", "ImportError: cannot import name 'x'\n")
        self._write("code.txt", "2\n")
        r = baseline.check(self.d, self._suite())
        self.assertEqual(r.code, EXIT_INVALID)

    def test_working_tree_is_restored_afterwards(self):
        self._write("out.txt", "FAILED a::b\n")
        self._write("code.txt", "1\n")
        baseline.check(self.d, self._suite())
        with open(os.path.join(self.d, "out.txt")) as fh:
            self.assertEqual(fh.read(), "FAILED a::b\n", "the dirty tree must come back")
        st = subprocess.run(["git", "-C", self.d, "stash", "list"], capture_output=True, text=True)
        self.assertEqual(st.stdout.strip(), "", "no stash may be left behind")

    def test_untracked_files_are_stashed_too(self):
        # An untracked new test is exactly what makes a "clean" run lie.
        self._write("out.txt", "FAILED only::when::dirty\n")
        self._write("code.txt", "1\n")
        self._write("brand_new_untracked.txt", "x\n")
        r = baseline.check(self.d, self._suite())
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertTrue(os.path.exists(os.path.join(self.d, "brand_new_untracked.txt")))

    def test_not_a_repo_is_invalid(self):
        d = tempfile.mkdtemp()
        self.assertEqual(baseline.check(d, ["true"]).code, EXIT_INVALID)

    def test_no_suite_command_is_invalid(self):
        self.assertEqual(baseline.check(self.d, []).code, EXIT_INVALID)


if __name__ == "__main__":
    unittest.main()
