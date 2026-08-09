"""The result contract. Everything downstream depends on these exact semantics."""

import io
import json
import unittest

from cc.result import (
    Result, Finding, worst, emit,
    EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID, EXIT_JUDGMENT,
)


class TestWorst(unittest.TestCase):
    def test_invalid_is_loudest(self):
        # The whole point: "could not evaluate" must beat "found a problem",
        # because a skipped check reads as silence and silence reads as clean.
        self.assertEqual(worst([EXIT_FINDING, EXIT_INVALID]), EXIT_INVALID)
        self.assertEqual(worst([EXIT_CLEAN, EXIT_JUDGMENT, EXIT_FINDING, EXIT_INVALID]), EXIT_INVALID)

    def test_finding_beats_judgment(self):
        self.assertEqual(worst([EXIT_JUDGMENT, EXIT_FINDING]), EXIT_FINDING)

    def test_judgment_beats_clean(self):
        self.assertEqual(worst([EXIT_CLEAN, EXIT_JUDGMENT]), EXIT_JUDGMENT)

    def test_all_clean_is_clean(self):
        self.assertEqual(worst([EXIT_CLEAN, EXIT_CLEAN]), EXIT_CLEAN)

    def test_empty_is_invalid_not_clean(self):
        # A run where nothing executed is a silent misconfiguration.
        self.assertEqual(worst([]), EXIT_INVALID)

    def test_exit_one_is_never_a_verdict(self):
        # 1 is reserved for an uncaught crash.
        with self.assertRaises(ValueError):
            worst([1])


class TestResult(unittest.TestCase):
    def test_add_escalates_never_downgrades(self):
        r = Result(check="x")
        self.assertEqual(r.code, EXIT_CLEAN)
        r.add(Finding(what="bad"))
        self.assertEqual(r.code, EXIT_FINDING)
        r.add(Finding(what="needs a look", severity="judgment"))
        self.assertEqual(r.code, EXIT_FINDING, "judgment must not downgrade an existing finding")

    def test_invalid_finding_forces_invalid(self):
        r = Result(check="x")
        r.add(Finding(what="cannot run", severity="invalid"))
        self.assertEqual(r.code, EXIT_INVALID)

    def test_invalid_constructor_carries_the_reason(self):
        r = Result.invalid("x", "no policy", "write one")
        self.assertEqual(r.code, EXIT_INVALID)
        self.assertEqual(len(r.findings), 1)
        self.assertIn("no policy", r.findings[0].what)

    def test_json_envelope_is_stable(self):
        r = Result.clean("x")
        r.note("hello")
        buf = io.StringIO()
        code = emit([r], as_json=True, stream=buf)
        payload = json.loads(buf.getvalue())
        self.assertEqual(code, EXIT_CLEAN)
        self.assertEqual(payload["status"], "CLEAN")
        self.assertEqual(payload["results"][0]["check"], "x")
        self.assertIn("findings", payload["results"][0])
        self.assertIn("data", payload["results"][0])

    def test_emit_returns_worst_across_results(self):
        a = Result.clean("a")
        b = Result.invalid("b", "nope")
        buf = io.StringIO()
        self.assertEqual(emit([a, b], as_json=True, stream=buf), EXIT_INVALID)


class TestCliContract(unittest.TestCase):
    def test_usage_error_is_invalid_not_finding(self):
        # argparse exits 2 by default - the same number as EXIT_FINDING. That
        # made "you typed it wrong" (no check ran) indistinguishable from "a
        # real finding was evaluated and found".
        import subprocess, sys as _s, os as _o
        root = _o.path.dirname(_o.path.dirname(_o.path.abspath(__file__)))
        for argv in (["scope"], ["nosuchcommand"], ["baseline"], []):
            p = subprocess.run([_s.executable, _o.path.join(root, "crosscheck.py"), *argv],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, EXIT_INVALID, f"{argv} -> {p.returncode}")

    def test_help_still_exits_zero(self):
        import subprocess, sys as _s, os as _o
        root = _o.path.dirname(_o.path.dirname(_o.path.abspath(__file__)))
        p = subprocess.run([_s.executable, _o.path.join(root, "crosscheck.py"), "--help"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
