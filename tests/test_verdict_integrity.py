"""False-CLEAN regressions found by an external reviewer.

Every case here was REPRODUCED against the shipped tree before it was fixed.
They share one shape: the tool learned something bad and then reported CLEAN
anyway — a scanner failed, a probe never executed, a spec was malformed, a
commit vouched for itself, a tier was misspelled.

These use mocked `Proc` rather than the real binaries on purpose. Coverage of a
false-CLEAN regression must not depend on whether a scanner happens to be
installed on the machine running the suite.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from cc.checks import secrets, enforce, vrp, scope
from cc.result import Finding, EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID, EXIT_JUDGMENT
from cc.run import Proc


def _proc(code=0, out="", err="", timed_out=False):
    return Proc(argv=["fake"], code=code, out=out, err=err, timed_out=timed_out)


class TestSecretsNeverLaunders(unittest.TestCase):
    """--allow nominates a file that may quote a secret. It is not a mute button."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.report = os.path.join(self.d, "report.md")
        with open(self.report, "w") as fh:
            fh.write("# report\n")

    def test_timeout_on_an_allowed_file_is_invalid_not_clean(self):
        # The allow-list used to delete findings AFTER the scan and rebuild the
        # exit code, which erased the scanner's own INVALID along with them.
        with patch.object(secrets, "have", lambda t: True), \
             patch.object(secrets, "run", lambda *a, **k: _proc(code=124, timed_out=True)):
            r = secrets.check([self.d], allow=["report.md"])
        self.assertEqual(r.code, EXIT_INVALID, [f.what for f in r.findings])

    def test_finding_exit_with_no_readable_report_is_invalid(self):
        # gitleaks said it found secrets and we have nothing to show for it.
        with patch.object(secrets, "have", lambda t: True), \
             patch.object(secrets, "run", lambda *a, **k: _proc(code=2)):
            r = secrets.check([self.d])
        self.assertEqual(r.code, EXIT_INVALID)
        self.assertTrue(any("no usable redacted report" in f.what for f in r.findings))

    def test_history_scan_failure_is_invalid_not_clean(self):
        os.makedirs(os.path.join(self.d, ".git"), exist_ok=True)

        def fake(argv, **k):
            if "git" in argv:
                return _proc(code=124, timed_out=True)
            return _proc(code=0)

        with patch.object(secrets, "have", lambda t: True), patch.object(secrets, "run", fake):
            r = secrets.check([self.d], history=True)
        self.assertEqual(r.code, EXIT_INVALID)
        self.assertTrue(any("history scan did not complete" in f.what for f in r.findings))

    def test_allowed_row_is_suppressed_but_a_sibling_row_is_not(self):
        # Discriminating: suppression must happen at the ROW, not the verdict.
        rows = [
            {"File": "report.md", "StartLine": 1, "RuleID": "rsa", "Match": "REDACTED"},
            {"File": "other.txt", "StartLine": 2, "RuleID": "rsa", "Match": "REDACTED"},
        ]

        def fake(argv, **k):
            out = argv[argv.index("--report-path") + 1]
            with open(out, "w") as fh:
                json.dump(rows, fh)
            return _proc(code=2)

        with patch.object(secrets, "have", lambda t: True), patch.object(secrets, "run", fake):
            r = secrets.check([self.d], allow=["report.md"])
        self.assertEqual(r.code, EXIT_FINDING)
        wheres = " ".join(f.where for f in r.findings)
        self.assertIn("other.txt", wheres)
        self.assertNotIn("report.md", wheres)


class TestEnforceNeverBlessesANonRun(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.specs = tempfile.mkdtemp()
        os.environ[enforce.SPEC_DIR_ENV] = self.specs
        os.environ[enforce.AUDIT_LOG_ENV] = os.path.join(tempfile.mkdtemp(), "a.jsonl")

    def tearDown(self):
        os.environ.pop(enforce.SPEC_DIR_ENV, None)
        os.environ.pop(enforce.AUDIT_LOG_ENV, None)

    def _spec(self, ctrl, name):
        with open(os.path.join(self.specs, f"{name}.json"), "w") as fh:
            json.dump({"target": name, "cwd": self.d, "controls": [ctrl]}, fh)
        return name

    def _ctrl(self, **over):
        c = {"name": "c", "declares": "d", "probe": ["/bin/echo", "hi"],
             "expect": "refused", "refused_when": {"exit_code_not_in": [0]}}
        c.update(over)
        return c

    def test_dry_run_is_not_a_verdict(self):
        r = enforce.check(self._spec(self._ctrl(), "dry"), dry_run=True)
        self.assertNotEqual(r.code, EXIT_CLEAN, "dry-run evaluated nothing and called it clean")
        self.assertEqual(r.code, EXIT_JUDGMENT)

    def test_malformed_expect_is_invalid_not_allowed(self):
        # A typo used to fall through to the allowed branch and report ENFORCED.
        r = enforce.check(self._spec(self._ctrl(expect="alllowed"), "typo"))
        self.assertEqual(r.code, EXIT_INVALID)

    def test_a_probe_that_never_executed_is_not_a_refusal(self):
        # exit 127 satisfies `exit_code_not_in:[0]` while nothing ran.
        missing = os.path.join(self.d, "definitely-not-here")
        r = enforce.check(self._spec(self._ctrl(probe=[missing]), "missing"))
        self.assertEqual(r.code, EXIT_INVALID)
        self.assertEqual(r.data["verdicts"]["c"], enforce.UNTESTABLE)

    def test_only_with_an_unknown_name_is_invalid(self):
        # Silently skipping a control you asked for reads exactly like passing.
        r = enforce.check(self._spec(self._ctrl(), "only"), only=["c", "no-such-control"])
        self.assertEqual(r.code, EXIT_INVALID)


class TestVrpTierVocabulary(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        os.environ[scope.POLICY_DIR_ENV] = self.d
        with open(os.path.join(self.d, "p.json"), "w") as fh:
            json.dump({
                "program": "p", "fetched_at": "2026-08-09", "in_scope": ["x.com"],
                "eligible_classes": ["product vulnerability"],
                "floor": {
                    "verified": True,
                    "tiers": {"OT0": "flagship", "OT2": "standard"},
                    "unrewarded": [{"tier": "OT2", "classes": ["product vulnerability"], "quote": "q"}],
                },
            }, fh)

    def tearDown(self):
        os.environ.pop(scope.POLICY_DIR_ENV, None)

    def test_unknown_tier_is_invalid_not_rewarded_by_absence(self):
        # OT22 used to be "not on the unrewarded list" -> proceed, PoC first.
        r = vrp.check("p", "product vulnerability", tier="OT22")
        self.assertEqual(r.code, EXIT_INVALID)

    def test_the_real_tier_still_fires(self):
        r = vrp.check("p", "product vulnerability", tier="OT2")
        self.assertEqual(r.code, EXIT_FINDING)


class TestForeignByteCap(unittest.TestCase):
    def test_cap_counts_utf8_bytes_not_code_points(self):
        # 600 emoji is ~2400 bytes. The cap sliced characters and reported the
        # character count as "bytes", so the envelope claimed 600/untruncated.
        f = Finding(what="ours").with_foreign("t", "\U0001F600" * 600)
        self.assertEqual(f.foreign["bytes"], 2400)
        self.assertTrue(f.foreign["truncated"])
        self.assertLessEqual(len(f.foreign["text"].encode("utf-8")), 600)

    def test_ascii_still_behaves(self):
        f = Finding(what="ours").with_foreign("t", "A" * 100)
        self.assertEqual(f.foreign["bytes"], 100)
        self.assertFalse(f.foreign["truncated"])


if __name__ == "__main__":
    unittest.main()
