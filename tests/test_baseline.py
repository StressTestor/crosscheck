"""baseline: failure parsing and the stash-restore contract.

The restore-failure path gets a test before the happy path, because that is the
one where a bug costs the user their working tree.
"""

import os
import subprocess
import tempfile
import unittest

from cc.checks import baseline
from cc.result import EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID, EXIT_JUDGMENT


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

    def test_unittest_summary_line_is_not_a_test_name(self):
        # Regression: unittest ends with `FAILED (failures=2)`. Capturing that
        # made the set difference compare failure COUNTS, so a 2-vs-1 run
        # fabricated an "introduced" failure out of nothing.
        out = (
            "FAIL: test_thing (tests.test_mod.Klass.test_thing)\n"
            "----\n"
            "Ran 73 tests in 7.0s\n"
            "FAILED (failures=1)\n"
        )
        got = baseline.parse_failures(out)
        self.assertNotIn("(failures=1)", got)
        self.assertTrue(any("test_thing" in g for g in got), got)

    def test_differing_failure_counts_do_not_fabricate_attribution(self):
        dirty = "FAIL: test_a (m.K.test_a)\nFAIL: test_b (m.K.test_b)\nFAILED (failures=2)\n"
        clean = "FAIL: test_a (m.K.test_a)\nFAILED (failures=1)\n"
        introduced = baseline.parse_failures(dirty) - baseline.parse_failures(clean)
        self.assertEqual(len(introduced), 1)
        self.assertTrue(any("test_b" in i for i in introduced), introduced)


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
        r = baseline.check(self.d, self._suite())
        # The result is asserted too: an implementation that returned before
        # stashing would leave the file "restored" and the stash empty while
        # reporting the failure as pre-existing. Both halves have to hold.
        self.assertEqual(r.code, EXIT_FINDING, [f.what for f in r.findings])
        self.assertIn("a::b", r.data["introduced"])
        with open(os.path.join(self.d, "out.txt")) as fh:
            self.assertEqual(fh.read(), "FAILED a::b\n", "the dirty tree must come back")
        st = subprocess.run(["git", "-C", self.d, "stash", "list"], capture_output=True, text=True)
        self.assertEqual(st.stdout.strip(), "", "no stash may be left behind")

    def test_untracked_files_are_stashed_too(self):
        # The suite fails IFF the untracked file is present, so this can only
        # pass if the stash actually removed it for the clean run. The old
        # fixture created an untracked file the suite never read - remove
        # --include-untracked from the stash and that test still passed.
        with open(os.path.join(self.d, "suite.sh"), "w") as fh:
            fh.write(
                '#!/bin/sh\nd="$(dirname "$0")"\n'
                'if [ -f "$d/brand_new_untracked.txt" ]; then echo "FAILED only::when::dirty"; exit 1; fi\n'
                'echo "1 passed"\nexit 0\n'
            )
        os.chmod(os.path.join(self.d, "suite.sh"), 0o755)
        _git(self.d, "add", "-A")
        _git(self.d, "commit", "-qm", "suite keyed on the untracked file")
        self._write("brand_new_untracked.txt", "x\n")
        r = baseline.check(self.d, self._suite())
        self.assertEqual(r.code, EXIT_FINDING, [f.what for f in r.findings])
        self.assertIn("only::when::dirty", r.data["introduced"])
        self.assertTrue(os.path.exists(os.path.join(self.d, "brand_new_untracked.txt")))

    def test_dirty_submodule_aborts_before_running_the_suite(self):
        # Data loss, reproduced: `git stash -u` does not recurse into
        # submodules, so a suite writing there destroyed uncommitted work with
        # no stash to recover from - and the tool only noticed AFTER running.
        inner = tempfile.mkdtemp()
        _git(inner, "init", "-q")
        _git(inner, "config", "user.email", "t@t.t")
        _git(inner, "config", "user.name", "t")
        with open(os.path.join(inner, "inner.txt"), "w") as fh:
            fh.write("original\n")
        _git(inner, "add", "-A")
        _git(inner, "commit", "-qm", "init")

        subprocess.run(
            ["git", "-C", self.d, "-c", "protocol.file.allow=always",
             "submodule", "add", "-q", inner, "sub"],
            check=True, capture_output=True,
        )
        _git(self.d, "add", "-A")
        _git(self.d, "commit", "-qm", "add sub")

        precious = os.path.join(self.d, "sub", "inner.txt")
        with open(precious, "w") as fh:
            fh.write("MY IMPORTANT UNCOMMITTED WORK\n")

        # A suite that would clobber it.
        with open(os.path.join(self.d, "suite.sh"), "w") as fh:
            fh.write('#!/bin/sh\necho clobbered > "$(dirname "$0")/sub/inner.txt"\necho "1 passed"\n')
        os.chmod(os.path.join(self.d, "suite.sh"), 0o755)

        r = baseline.check(self.d, [os.path.join(self.d, "suite.sh")])
        self.assertEqual(r.code, EXIT_INVALID)
        self.assertIn("sub", r.data.get("dirty_submodules", []))
        with open(precious) as fh:
            self.assertIn("MY IMPORTANT UNCOMMITTED WORK", fh.read(),
                          "baseline ran the suite over unprotected submodule work")

    def test_suite_creating_a_gitignored_file_aborts_attribution(self):
        # The stash does not touch ignored files, so an artifact the dirty run
        # generates survives into the "clean" run. A warning was the old
        # answer; an attribution computed over poisoned state is not one.
        self._write(".gitignore", "gen.out\n")
        _git(self.d, "add", "-A")
        _git(self.d, "commit", "-qm", "ignore gen.out")
        with open(os.path.join(self.d, "suite.sh"), "w") as fh:
            fh.write('#!/bin/sh\necho data > "$(dirname "$0")/gen.out"\necho "1 passed"\nexit 0\n')
        os.chmod(os.path.join(self.d, "suite.sh"), 0o755)
        r = baseline.check(self.d, self._suite())
        self.assertEqual(r.code, EXIT_INVALID, [f.what for f in r.findings])
        self.assertIn("gen.out", r.data.get("ignored_created", []))
        # Aborted BEFORE the stash: the tree is untouched and nothing is stranded.
        st = subprocess.run(["git", "-C", self.d, "stash", "list"], capture_output=True, text=True)
        self.assertEqual(st.stdout.strip(), "", "aborting must not leave a stash behind")

    def test_suite_modifying_existing_ignored_state_is_judgment(self):
        # The file existed before the run, so the set did not change - but its
        # content did, and whether it feeds the suite is a human question.
        self._write(".gitignore", "state.db\n")
        _git(self.d, "add", "-A")
        _git(self.d, "commit", "-qm", "ignore state.db")
        self._write("state.db", "seed\n")
        with open(os.path.join(self.d, "suite.sh"), "w") as fh:
            fh.write('#!/bin/sh\necho row >> "$(dirname "$0")/state.db"\necho "1 passed"\nexit 0\n')
        os.chmod(os.path.join(self.d, "suite.sh"), 0o755)
        r = baseline.check(self.d, self._suite())
        self.assertEqual(r.code, EXIT_JUDGMENT, [f.what for f in r.findings])
        self.assertIn("state.db", r.data.get("ignored_modified", []))

    def test_pycache_churn_is_not_poisoning(self):
        # CPython owns pyc invalidation; flagging __pycache__ writes would
        # make every Python baseline INVALID forever and get routed around.
        self._write(".gitignore", "__pycache__/\n")
        _git(self.d, "add", "-A")
        _git(self.d, "commit", "-qm", "ignore pycache")
        with open(os.path.join(self.d, "suite.sh"), "w") as fh:
            fh.write(
                '#!/bin/sh\nd="$(dirname "$0")"\nmkdir -p "$d/__pycache__"\n'
                'echo bytecode > "$d/__pycache__/m.cpython-313.pyc"\necho "1 passed"\nexit 0\n'
            )
        os.chmod(os.path.join(self.d, "suite.sh"), 0o755)
        r = baseline.check(self.d, self._suite())
        self.assertEqual(r.code, EXIT_CLEAN, [f.what for f in r.findings])

    def test_not_a_repo_is_invalid(self):
        d = tempfile.mkdtemp()
        self.assertEqual(baseline.check(d, ["true"]).code, EXIT_INVALID)

    def test_no_suite_command_is_invalid(self):
        self.assertEqual(baseline.check(self.d, []).code, EXIT_INVALID)


if __name__ == "__main__":
    unittest.main()
