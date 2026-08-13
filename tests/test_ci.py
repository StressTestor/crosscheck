"""ci: Actions supply-chain checks.

(This file also held pr-body's tests until pr-body was deleted; see the
deletion commit for why and for the sandbox design that went with it.)
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from cc.checks import ci
from cc.result import EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID, EXIT_JUDGMENT
from cc.run import Proc


def _proc(code=0, out="", err="", timed_out=False):
    return Proc(argv=["fake"], code=code, out=out, err=err, timed_out=timed_out)

UNPINNED = """
name: x
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""

PINNED = """
name: x
on: [push]
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
"""


class TestCi(unittest.TestCase):
    def _repo(self, content, name="w.yml"):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, ".github", "workflows"))
        with open(os.path.join(d, ".github", "workflows", name), "w") as fh:
            fh.write(content)
        return d

    def test_unpinned_action_is_a_finding(self):
        r = ci.check(self._repo(UNPINNED), audit=False)
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertTrue(any("mutable tag" in f.what for f in r.findings))

    def test_missing_permissions_block_is_a_finding(self):
        r = ci.check(self._repo(UNPINNED), audit=False)
        self.assertTrue(any("no permissions block" in f.what for f in r.findings))

    def test_pinned_and_scoped_has_no_pin_or_permission_finding(self):
        r = ci.check(self._repo(PINNED), audit=False)
        pin_or_perm = [f for f in r.findings if "mutable tag" in f.what or "no permissions block" in f.what]
        self.assertEqual(pin_or_perm, [], [f.what for f in pin_or_perm])

    def test_no_workflows_still_audits_dependencies(self):
        # A repo with no CI can still ship a vulnerable requirements.txt. The
        # old early-return made that indistinguishable from an empty dir.
        # The old version of this test passed audit=False, so it would have
        # survived the whole dependency block being deleted. Now the mocked
        # scan must actually be invoked or the assertion fails.
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "requirements.txt"), "w") as fh:
            fh.write("requests==2.19.0\n")
        calls = []

        def fake_run(argv, **k):
            calls.append(argv[0])
            return _proc(code=0, out=json.dumps({"dependencies": []}))

        with patch.object(ci, "have", lambda t: t == "pip-audit"), \
             patch.object(ci, "run", fake_run):
            r = ci.check(d)
        self.assertIn("pip-audit", calls, "no workflows and the dependency audit never ran")
        self.assertEqual(r.code, EXIT_CLEAN, [f.what for f in r.findings])

    def test_uppercase_sha_pin_is_not_a_finding(self):
        d = self._repo(PINNED.replace("9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
                                      "9C091BB21B7C1C1D1991BB908D89E4E9DDDFE3E0"))
        r = ci.check(d, audit=False)
        self.assertFalse(any("mutable tag" in f.what for f in r.findings), [f.what for f in r.findings])

    def test_no_sast_installed_is_not_clean(self):
        # Only two greps ran; claiming CLEAN would mean "we looked".
        d = self._repo(PINNED)
        real = ci.have
        ci.have = lambda t: False
        try:
            r = ci.check(d, audit=False)
            self.assertNotEqual(r.code, EXIT_CLEAN)
            self.assertTrue(any("no Actions SAST actually ran" in f.what for f in r.findings))
        finally:
            ci.have = real

    def test_require_sast_keeps_findings_already_collected(self):
        # A late INVALID must not discard real findings from --json output.
        d = self._repo(UNPINNED)
        real = ci.have
        ci.have = lambda t: False
        try:
            r = ci.check(d, require_sast=True, audit=False)
            self.assertEqual(r.code, EXIT_INVALID)
            self.assertTrue(any("mutable tag" in f.what for f in r.findings), [f.what for f in r.findings])
        finally:
            ci.have = real

    def test_touching_a_workflow_routes_to_gha_review(self):
        # The routing contract is the `route` payload plus a judgment-severity
        # finding. The aggregate code may legitimately be FINDING instead of
        # JUDGMENT when the installed SAST also has something to say - findings
        # outrank judgments - so assert the contract, not the aggregate.
        d = self._repo(PINNED)
        r = ci.check(d, changed=[".github/workflows/w.yml"], audit=False)
        self.assertEqual(r.data["route"]["gate"], "gha-security-review")
        self.assertEqual(r.data["route"]["workflowFiles"], [".github/workflows/w.yml"])
        self.assertTrue(any(f.severity == "judgment" for f in r.findings))
        self.assertIn(r.code, (EXIT_JUDGMENT, EXIT_FINDING))

    def test_broken_scanner_config_cannot_buy_a_clean(self):
        # The audited repo owns .github/actionlint.yaml and .github/zizmor.yml.
        # Crediting a config-errored scanner as "ran" let a repo ship two junk
        # files and suppress both --require-sast and the no-SAST fallback.
        d = self._repo(
            "name: x\non: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n"
        )
        for fn in ("actionlint.yaml", "zizmor.yml"):
            with open(os.path.join(d, ".github", fn), "w") as fh:
                fh.write("not: [valid\n  yaml: {{{\n")
        r = ci.check(d, require_sast=True, audit=False)
        self.assertNotEqual(r.code, EXIT_CLEAN, r.notes)
        self.assertFalse(
            any("clean under" in n for n in r.notes),
            f"claimed clean under scanners that never ran: {r.notes}",
        )

    def test_scanner_findings_actually_surface(self):
        # Regression: the zizmor parse loop briefly sat in the did-NOT-scan
        # branch, so findings were read only on failure and silently dropped on
        # a successful scan that HAD findings. The repo looked clean.
        d = self._repo(
            "name: x\non: pull_request_target\npermissions: {}\njobs:\n  a:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            '      - run: echo "${{ github.event.pull_request.title }}"\n'
        )
        if not (ci.have("zizmor") or ci.have("actionlint")):
            self.skipTest("no Actions SAST installed")
        r = ci.check(d, audit=False)
        self.assertTrue(
            any(f.foreign for f in r.findings),
            f"a scanner ran but produced no findings: notes={r.notes} sast={r.data.get('sast')}",
        )
        self.assertEqual(r.code, EXIT_FINDING)

    def test_no_changed_files_means_no_route(self):
        r = ci.check(self._repo(PINNED), audit=False)
        self.assertNotIn("route", r.data)

    def test_actionlint_self_diagnostics_are_not_findings(self):
        # "no project was found in any parent directories" is actionlint
        # talking about itself. Reporting it as a security finding is how a
        # tool earns a mute.
        d = self._repo(PINNED)
        r = ci.check(d, audit=False)
        self.assertFalse(
            any("no project was found" in (f.detail or "") for f in r.findings),
            [f.detail for f in r.findings],
        )

    def test_require_sast_without_tools_is_invalid(self):
        d = self._repo(PINNED)
        real = ci.have
        ci.have = lambda t: False  # simulate a machine with no SAST installed
        try:
            r = ci.check(d, require_sast=True, audit=False)
            self.assertEqual(r.code, EXIT_INVALID)
        finally:
            ci.have = real

    def test_composite_action_pins_are_scanned(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, ".github", "workflows"))
        with open(os.path.join(d, ".github", "workflows", "w.yml"), "w") as fh:
            fh.write(PINNED)
        os.makedirs(os.path.join(d, ".github", "actions", "thing"))
        with open(os.path.join(d, ".github", "actions", "thing", "action.yml"), "w") as fh:
            fh.write("runs:\n  steps:\n    - uses: some/action@v1\n")
        r = ci.check(d, audit=False)
        self.assertTrue(any("action.yml" in f.where for f in r.findings), [f.where for f in r.findings])


class TestDependencyAuditNeverFakesAScan(unittest.TestCase):
    """A failed or empty dependency scan is INVALID, never zero findings.

    Empty scanner stdout used to become `{}`, which "parsed", and once it
    parsed the nonzero exit was ignored for both pip-audit and npm - a failed
    scan returned code 0 with no findings. Mocked `Proc` on purpose: coverage
    of a false-CLEAN must not depend on which scanners this machine has.
    """

    def _pyrepo(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "requirements.txt"), "w") as fh:
            fh.write("requests==2.19.0\n")
        return d

    def _npmrepo(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "package-lock.json"), "w") as fh:
            fh.write("{}")
        return d

    def _check(self, repo, tool, proc):
        with patch.object(ci, "have", lambda t: t == tool), \
             patch.object(ci, "run", lambda *a, **k: proc):
            return ci.check(repo)

    def test_failed_pip_audit_is_invalid_not_clean(self):
        r = self._check(self._pyrepo(), "pip-audit", _proc(code=1, err="boom"))
        self.assertEqual(r.code, EXIT_INVALID, [f.what for f in r.findings])
        self.assertTrue(any("no usable report" in f.what for f in r.findings))

    def test_pip_audit_empty_object_is_invalid_even_on_exit_zero(self):
        # `{}` has no 'dependencies' list - that is not a scan result, whatever
        # the exit code says.
        r = self._check(self._pyrepo(), "pip-audit", _proc(code=0, out="{}"))
        self.assertEqual(r.code, EXIT_INVALID)

    def test_pip_audit_advisories_still_surface(self):
        # Discriminating: the INVALID gate must not eat real advisories.
        doc = {"dependencies": [{"name": "requests", "version": "2.19.0",
                                 "vulns": [{"id": "PYSEC-1", "aliases": [],
                                            "fix_versions": ["2.20.0"]}]}]}
        r = self._check(self._pyrepo(), "pip-audit", _proc(code=1, out=json.dumps(doc)))
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertTrue(any("vulnerable python dependency" in f.what for f in r.findings))

    def test_failed_npm_audit_is_invalid_not_clean(self):
        r = self._check(self._npmrepo(), "npm", _proc(code=1, err="npm ERR! network"))
        self.assertEqual(r.code, EXIT_INVALID, [f.what for f in r.findings])
        self.assertTrue(any("no usable report" in f.what for f in r.findings))

    def test_npm_error_envelope_is_invalid_even_when_it_parses(self):
        # npm error output IS valid JSON - it just is not an audit report.
        r = self._check(self._npmrepo(), "npm",
                        _proc(code=1, out=json.dumps({"error": {"code": "EAUDITNOLOCK"}})))
        self.assertEqual(r.code, EXIT_INVALID)

    def test_npm_advisories_still_surface(self):
        doc = {"vulnerabilities": {"lodash": {}},
               "metadata": {"vulnerabilities": {"high": 1, "critical": 0}}}
        r = self._check(self._npmrepo(), "npm", _proc(code=1, out=json.dumps(doc)))
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertTrue(any("high/critical advisory" in f.what for f in r.findings))

    def test_npm_clean_report_is_clean(self):
        doc = {"vulnerabilities": {},
               "metadata": {"vulnerabilities": {"high": 0, "critical": 0}}}
        r = self._check(self._npmrepo(), "npm", _proc(code=0, out=json.dumps(doc)))
        self.assertEqual(r.code, EXIT_CLEAN, [f.what for f in r.findings])


if __name__ == "__main__":
    unittest.main()
