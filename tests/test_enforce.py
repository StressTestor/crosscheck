"""enforce: does a declared control engage, and does the target admit it.

The fixture targets reproduce the shape of codecalc #62 - a ceiling that does
not bind, with a self-report that still lists it as applied. The three-way
split (ENFORCED / UNENFORCED / UNENFORCED-SILENT) is the whole reason this
module exists, so all three get a test.
"""

import json
import os
import tempfile
import unittest

from cc.checks import enforce
from cc.result import EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID

# A target that refuses the probe and reports honestly.
TARGET_ENFORCED = """#!/bin/sh
echo "refused: limit applied" >&2
echo '{"unenforced": []}'
exit 1
"""

# A target that does NOT refuse, and honestly says the control did not apply.
TARGET_UNENFORCED_HONEST = """#!/bin/sh
echo "ok, did the thing"
echo '{"unenforced": ["nproc"]}' > report.json
exit 0
"""

# codecalc #62: does NOT refuse, and the self-report still claims it applied.
TARGET_UNENFORCED_SILENT = """#!/bin/sh
echo "ok, did the thing"
echo '{"unenforced": []}' > report.json
exit 0
"""


class TestEnforce(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.specs = tempfile.mkdtemp()
        os.environ[enforce.SPEC_DIR_ENV] = self.specs

    def tearDown(self):
        os.environ.pop(enforce.SPEC_DIR_ENV, None)

    def _target(self, body, name="target.sh"):
        p = os.path.join(self.d, name)
        with open(p, "w") as fh:
            fh.write(body)
        os.chmod(p, 0o755)
        return p

    def _spec(self, control, name="t"):
        doc = {"target": name, "cwd": self.d, "controls": [control]}
        p = os.path.join(self.specs, f"{name}.json")
        with open(p, "w") as fh:
            json.dump(doc, fh)
        return name

    def _nproc_control(self, target, **over):
        c = {
            "name": "nproc",
            "declares": "RLIMIT_NPROC is applied per execution",
            "probe": [target],
            "expect": "refused",
            "refused_when": {"exit_code_not_in": [0]},
            "self_report": {
                "from": "file",
                "file": "report.json",
                "path": "unenforced",
                "claims_applied_when": "absent_from",
                "key": "nproc",
            },
        }
        c.update(over)
        return c

    def test_enforced_control_is_clean(self):
        t = self._target(TARGET_ENFORCED)
        c = self._nproc_control(t)
        c["self_report"] = {"from": "stdout_json", "path": "unenforced",
                            "claims_applied_when": "absent_from", "key": "nproc"}
        r = enforce.check(self._spec(c))
        self.assertEqual(r.code, EXIT_CLEAN, [f.what for f in r.findings])
        self.assertEqual(r.data["verdicts"]["nproc"], enforce.ENFORCED)

    def test_unenforced_but_honest_is_a_finding(self):
        t = self._target(TARGET_UNENFORCED_HONEST)
        r = enforce.check(self._spec(self._nproc_control(t)))
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertEqual(r.data["verdicts"]["nproc"], enforce.UNENFORCED)

    def test_unenforced_and_reported_as_applied_is_the_worst_class(self):
        # codecalc #62 exactly: the ceiling did not bind, and `unenforced` does
        # not say so, so a caller reads the result as "the ceiling applied".
        t = self._target(TARGET_UNENFORCED_SILENT)
        r = enforce.check(self._spec(self._nproc_control(t)))
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertEqual(r.data["verdicts"]["nproc"], enforce.UNENFORCED_SILENT)
        self.assertTrue(
            any("reports it AS applied" in f.what for f in r.findings),
            [f.what for f in r.findings],
        )
        self.assertTrue(any("WORST CLASS" in n for n in r.notes), r.notes)

    def test_untestable_is_invalid_never_clean(self):
        # No refused_when rule: we cannot recognise a refusal, so we must not
        # claim the control holds.
        t = self._target(TARGET_ENFORCED)
        c = self._nproc_control(t)
        del c["refused_when"]
        r = enforce.check(self._spec(c))
        self.assertEqual(r.code, EXIT_INVALID)
        self.assertEqual(r.data["verdicts"]["nproc"], enforce.UNTESTABLE)

    def test_exit_code_alone_never_decides_a_refusal(self):
        # A target that dies for an unrelated reason must not read as refused.
        t = self._target("#!/bin/sh\necho 'ImportError: boom' >&2\nexit 1\n")
        c = self._nproc_control(t)
        c["refused_when"] = {"exit_code_not_in": [0], "stderr_contains": "refused"}
        r = enforce.check(self._spec(c))
        # Died, but not with a refusal -> control did not hold.
        self.assertEqual(r.data["verdicts"]["nproc"], enforce.UNENFORCED)

    def test_pinned_allowed_case_catches_over_blocking(self):
        # A refusal harness with no allowed-cases rewards a target that refuses
        # everything.
        t = self._target(TARGET_ENFORCED)
        c = self._nproc_control(t)
        c["expect"] = "allowed"
        r = enforce.check(self._spec(c))
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertTrue(any("pins as ALLOWED was refused" in f.what for f in r.findings))

    def test_probe_must_be_an_argv_list(self):
        c = self._nproc_control("x")
        c["probe"] = "sh -c 'echo hi'"
        r = enforce.check(self._spec(c))
        self.assertEqual(r.code, EXIT_INVALID)

    def test_dry_run_executes_nothing(self):
        marker = os.path.join(self.d, "fired")
        t = self._target(f"#!/bin/sh\ntouch {marker}\nexit 0\n")
        r = enforce.check(self._spec(self._nproc_control(t)), dry_run=True)
        self.assertFalse(os.path.exists(marker), "dry-run fired the probe")
        self.assertTrue(any("WOULD RUN" in n for n in r.notes), r.notes)

    def test_missing_spec_is_invalid(self):
        self.assertEqual(enforce.check("nope").code, EXIT_INVALID)

    def test_spec_name_traversal_is_refused(self):
        r = enforce.check(".." + os.sep + "somewhere")
        self.assertEqual(r.code, EXIT_INVALID)

    def test_spec_with_no_controls_is_invalid(self):
        p = os.path.join(self.specs, "empty.json")
        with open(p, "w") as fh:
            json.dump({"target": "x", "controls": []}, fh)
        self.assertEqual(enforce.check("empty").code, EXIT_INVALID)

    def test_only_filters_controls(self):
        t = self._target(TARGET_ENFORCED)
        c = self._nproc_control(t)
        c["self_report"] = {}
        r = enforce.check(self._spec(c), only=["nproc"])
        self.assertIn("nproc", r.data["verdicts"])
        r2 = enforce.check(self._spec(c), only=["nothing-matches"])
        self.assertEqual(r2.code, EXIT_INVALID)


if __name__ == "__main__":
    unittest.main()
