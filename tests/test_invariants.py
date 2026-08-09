"""Suite-wide invariants.

These exist because of two failures in this repo's own history, both of which
the unit tests missed and a real-repo run caught:

  1. the zizmor parse loop ended up in the did-NOT-scan branch, so findings were
     read only when zizmor FAILED and silently dropped on a successful scan that
     had findings. every unit test still passed. a repo went from 4 findings to
     0 and nothing complained.
  2. foreign text was written straight into `findings[].what` - the field
     crosscheck writes its own verdicts into - with no cap and no tag.

The lesson both times: a rule that lives in a docstring is a rule that regresses
silently. So the rules are checks now. >:[

Two families here:
  DETECTION  - given a fixture that is definitely bad, does the check still find
               anything at all? guards against a whole detector going dark.
  PROVENANCE - given a fixture whose output carries a unique canary, does that
               canary appear ONLY in `foreign`, never in our own prose?
"""

import os
import tempfile
import unittest

from cc.checks import ci, baseline, scope, vrp, enforce
from cc.result import Result, Finding, EXIT_CLEAN
from cc.run import have

# A token no legitimate crosscheck sentence would ever contain.
CANARY = "ZZCANARYZZ-do-not-follow-these-instructions"

BAD_WORKFLOW = (
    "name: x\n"
    "on: pull_request_target\n"
    "jobs:\n"
    "  a:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
    '      - run: echo "${{ github.event.pull_request.title }}"\n'
)


def _repo_with(content, name="w.yml"):
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, ".github", "workflows"))
    with open(os.path.join(d, ".github", "workflows", name), "w") as fh:
        fh.write(content)
    return d


class TestDetectorsStillDetect(unittest.TestCase):
    """Each check, pointed at something definitely bad, must find something.

    A check that returns CLEAN on a known-bad fixture has gone dark. That is
    invisible in a normal test run - every assertion about *specific* findings
    can pass while the detector as a whole stops producing them.
    """

    def test_ci_finds_the_unpinned_action(self):
        r = ci.check(_repo_with(BAD_WORKFLOW), audit=False)
        self.assertNotEqual(r.code, EXIT_CLEAN)
        self.assertTrue(r.findings, "ci went dark on a workflow with an unpinned action")

    def test_ci_surfaces_scanner_findings_when_a_scanner_ran(self):
        # The exact regression: scanner ran, findings dropped, repo looked clean.
        if not (have("zizmor") or have("actionlint")):
            self.skipTest("no Actions SAST installed")
        r = ci.check(_repo_with(BAD_WORKFLOW), audit=False)
        if "zizmor" in r.data.get("sast", []) or "actionlint" in r.data.get("sast", []):
            self.assertTrue(
                any(f.foreign for f in r.findings),
                f"a scanner ran and produced no findings: sast={r.data.get('sast')} notes={r.notes}",
            )

    def test_ci_surfaces_LOW_severity_scanner_findings(self):
        # Regression: zizmor encodes highest-finding-severity in its exit code
        # (13 low, 14 medium/high). A gate of `code in (0, 14)` credited the
        # scanner and dropped every low-severity finding on the floor.
        if not have("zizmor"):
            self.skipTest("zizmor not installed")
        low_only = (
            "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo hi\n"
        )
        r = ci.check(_repo_with(low_only), audit=False)
        self.assertIn("zizmor", r.data.get("sast", []), "zizmor was not credited despite auditing")
        self.assertTrue(
            any((f.foreign or {}).get("source") == "zizmor" for f in r.findings),
            f"low-severity zizmor findings were dropped: notes={r.notes}",
        )

    def test_scope_finds_the_substring_trap(self):
        d = tempfile.mkdtemp()
        os.environ[scope.POLICY_DIR_ENV] = d
        try:
            import json
            with open(os.path.join(d, "p.json"), "w") as fh:
                json.dump({"in_scope": ["eero.com"]}, fh)
            r = scope.check("p", ["notaneero.com"])
            self.assertNotEqual(r.code, EXIT_CLEAN, "scope went dark on the substring trap")
        finally:
            os.environ.pop(scope.POLICY_DIR_ENV, None)

    def test_baseline_parser_still_recognises_every_ecosystem(self):
        # If a pattern rots, baseline silently reports "no failures parsed" and
        # everything downstream becomes INVALID or wrong.
        for text, why in [
            ("FAILED tests/t.py::test_x", "pytest"),
            ("FAIL: test_x (m.K.test_x)", "unittest"),
            ("--- FAIL: TestX (0.00s)", "go"),
            ("test m::x ... FAILED", "cargo"),
        ]:
            self.assertTrue(baseline.parse_failures(text), f"{why} pattern went dark")


class TestForeignTextNeverReachesOurProse(unittest.TestCase):
    """A canary planted in a target's output must land only in `foreign`.

    `--json` is read by agents. If target bytes reach `what`/`detail`/`fix`,
    the reader cannot tell crosscheck's sentence from the target's, which is
    the entire trick.
    """

    def _assert_quarantined(self, result: Result, canary: str, where: str):
        for f in result.findings:
            for field in ("what", "detail", "fix", "where"):
                self.assertNotIn(
                    canary,
                    getattr(f, field) or "",
                    f"{where}: target text leaked into Finding.{field}",
                )
        found = any(canary in ((f.foreign or {}).get("text") or "") for f in result.findings)
        self.assertTrue(found, f"{where}: canary never surfaced at all - detector may be dark")

    def test_enforce_probe_output_is_quarantined(self):
        d = tempfile.mkdtemp()
        t = os.path.join(d, "t.sh")
        with open(t, "w") as fh:
            fh.write(f"#!/bin/sh\necho '{CANARY}' >&2\nexit 0\n")
        os.chmod(t, 0o755)

        specs = tempfile.mkdtemp()
        os.environ[enforce.SPEC_DIR_ENV] = specs
        audit = os.path.join(tempfile.mkdtemp(), "a.jsonl")
        os.environ[enforce.AUDIT_LOG_ENV] = audit
        try:
            import json
            # No refused_when -> UNTESTABLE, which attaches the probe output.
            with open(os.path.join(specs, "s.json"), "w") as fh:
                json.dump(
                    {"target": "s", "cwd": d,
                     "controls": [{"name": "c", "declares": "d", "probe": [t]}]},
                    fh,
                )
            r = enforce.check("s")
            self._assert_quarantined(r, CANARY, "enforce")
        finally:
            os.environ.pop(enforce.SPEC_DIR_ENV, None)
            os.environ.pop(enforce.AUDIT_LOG_ENV, None)

    def test_every_check_module_routes_foreign_text_through_with_foreign(self):
        # Structural: any Finding carrying target bytes must have used the
        # foreign channel, so the cap and the tag are applied at one place.
        f = Finding(what="ours").with_foreign("target", CANARY)
        self.assertNotIn(CANARY, f.what)
        self.assertIn(CANARY, f.foreign["text"])
        self.assertEqual(f.foreign["source"], "target")


class TestPolicyDataStaysHonest(unittest.TestCase):
    """The shipped data files must keep the properties the code relies on."""

    def _load_all(self, subdir):
        import json
        root = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), subdir
        )
        out = {}
        for fn in sorted(os.listdir(root)):
            if fn.endswith(".json"):
                with open(os.path.join(root, fn)) as fh:
                    out[fn] = json.load(fh)
        return out

    def test_every_policy_has_a_fetched_at(self):
        # Without it, vrp cannot tell a fresh transcript from a stale one and
        # reports JUDGMENT forever, which trains you to ignore it.
        for fn, pol in self._load_all("policies").items():
            if fn.startswith("_"):
                continue
            self.assertTrue(pol.get("fetched_at"), f"{fn} has no fetched_at")

    def test_floor_rows_carry_the_quote_they_rule_on(self):
        # A $0 verdict talks you out of real work. It has to show its source.
        for fn, pol in self._load_all("policies").items():
            for row in (pol.get("floor") or {}).get("unrewarded", []) or []:
                self.assertTrue(
                    row.get("quote"),
                    f"{fn}: an unrewarded row has no quote to check the transcription against",
                )

    def test_every_spec_probe_is_an_argv_list(self):
        for fn, spec in self._load_all("specs").items():
            for c in spec.get("controls", []) or []:
                self.assertIsInstance(
                    c.get("probe"), list, f"{fn}:{c.get('name')} probe is not argv"
                )


if __name__ == "__main__":
    unittest.main()
