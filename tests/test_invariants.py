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

import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cc.checks import ci, baseline, prbranch, scope, secrets, vrp, enforce
from cc.result import Result, EXIT_CLEAN, EXIT_FINDING
from cc.run import Proc, have


def _proc(code=0, out="", err="", timed_out=False):
    return Proc(argv=["fake"], code=code, out=out, err=err, timed_out=timed_out)

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

    def test_audited_repo_cannot_suppress_its_own_audit(self):
        # The audited repo owns .github/zizmor.yml and .github/actionlint.yaml.
        # A VALID ignore-everything config used to suppress the analysis, and
        # ci then printed "clean under ... zizmor" - vouching for a
        # pull_request_target + template-injection workflow. Malformed config
        # was already caught; this is the same hole through the supported path.
        if not have("zizmor"):
            self.skipTest("zizmor not installed")
        d = _repo_with(
            "name: x\non: pull_request_target\npermissions: {}\njobs:\n  a:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            '      - run: echo "${{ github.event.pull_request.title }}"\n',
            name="danger.yml",
        )
        with open(os.path.join(d, ".github", "zizmor.yml"), "w") as fh:
            fh.write(
                "rules:\n  template-injection:\n    ignore:\n      - danger.yml\n"
                "  dangerous-triggers:\n    ignore:\n      - danger.yml\n"
            )
        r = ci.check(d, require_sast=True, audit=False)
        self.assertNotEqual(r.code, EXIT_CLEAN, r.notes)
        self.assertTrue(
            any((f.foreign or {}).get("source") == "zizmor" for f in r.findings),
            f"the repo's own ignore config suppressed the gate: notes={r.notes}",
        )
        # A suppression is an accepted risk on your own repo...
        self.assertTrue(any("SUPPRESSED by this repo" in f.what for f in r.findings))
        # ...and a FINDING when you are auditing someone else's.
        strict = ci.check(d, require_sast=True, audit=False, strict_suppressions=True)
        self.assertEqual(strict.code, EXIT_FINDING)

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

    def _assert_quarantined(self, result: Result, canary: str, where: str,
                            expect_in_findings: bool = True):
        for f in result.findings:
            for field in ("what", "detail", "fix", "where"):
                self.assertNotIn(
                    canary,
                    getattr(f, field) or "",
                    f"{where}: target text leaked into Finding.{field}",
                )
        for n in result.notes:
            if canary in n:
                self.assertTrue(
                    n.startswith("untrusted from"),
                    f"{where}: foreign text sits in an untagged note: {n!r}",
                )
        if expect_in_findings:
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

    # The old test here ("every check module routes foreign text through
    # with_foreign") exercised the HELPER, not the producers - it passed while
    # four modules f-stringed target text straight into trusted fields. These
    # are per-producer canaries instead: mocked Proc throughout, so they run
    # on any machine and cannot be satisfied by anything but the producer
    # itself doing the routing.

    def test_ci_uses_ref_is_quarantined(self):
        # The `uses:` value is workflow-controlled; it used to sit in `detail`
        # and get interpolated into `fix`.
        d = _repo_with(
            "name: x\non: [push]\npermissions: {}\njobs:\n  a:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            f"      - uses: evil/{CANARY}@v1\n"
        )
        with patch.object(ci, "have", lambda t: False):
            r = ci.check(d, audit=False)
        self._assert_quarantined(r, CANARY, "ci pins grep")

    def test_ci_scanner_self_output_is_quarantined_in_notes(self):
        # actionlint talking about itself is scanner text; it went into a
        # trusted note verbatim.
        d = _repo_with(BAD_WORKFLOW)
        with patch.object(ci, "have", lambda t: t == "actionlint"), \
             patch.object(ci, "run", lambda *a, **k: _proc(code=3, out=f"actionlint: {CANARY}")):
            r = ci.check(d, audit=False)
        self._assert_quarantined(r, CANARY, "ci actionlint self-output", expect_in_findings=False)
        self.assertTrue(any(CANARY in n for n in r.notes),
                        "the scanner's words vanished entirely - not quarantine, amnesia")

    def test_ci_dependency_scanner_output_is_quarantined(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "requirements.txt"), "w") as fh:
            fh.write("requests==2.19.0\n")
        with patch.object(ci, "have", lambda t: t == "pip-audit"), \
             patch.object(ci, "run", lambda *a, **k: _proc(code=1, err=CANARY)):
            r = ci.check(d)
        self._assert_quarantined(r, CANARY, "ci pip-audit failure output")

    def test_secrets_gitleaks_paths_are_quarantined(self):
        # gitleaks File/Match come out of the scanner's report - a crafted
        # filename used to sit in trusted `where`.
        d = tempfile.mkdtemp()
        rows = [{"File": f"{CANARY}.txt", "StartLine": 3,
                 "RuleID": "rsa", "Match": f"key {CANARY}"}]

        def fake(argv, **k):
            out = argv[argv.index("--report-path") + 1]
            with open(out, "w") as fh:
                json.dump(rows, fh)
            return _proc(code=2)

        with patch.object(secrets, "have", lambda t: t == "gitleaks"), \
             patch.object(secrets, "run", fake):
            r = secrets.check([d])
        self._assert_quarantined(r, CANARY, "secrets gitleaks row")

    def test_baseline_test_ids_are_quarantined_in_notes(self):
        # A "test name" is arbitrary text to a hostile harness. Pre-existing
        # ids used to be f-stringed into trusted notes.
        d = tempfile.mkdtemp()

        def git(*a):
            subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)

        git("init", "-q")
        git("config", "user.email", "t@t.t")
        git("config", "user.name", "t")
        with open(os.path.join(d, "suite.sh"), "w") as fh:
            fh.write(f'#!/bin/sh\necho "FAILED zz::{CANARY}"\nexit 1\n')
        os.chmod(os.path.join(d, "suite.sh"), 0o755)
        git("add", "-A")
        git("commit", "-qm", "init")
        with open(os.path.join(d, "unrelated.txt"), "w") as fh:
            fh.write("dirty\n")

        # Fails identically on both runs -> pre-existing -> notes, not findings.
        r = baseline.check(d, [os.path.join(d, "suite.sh")])
        self._assert_quarantined(r, CANARY, "baseline pre-existing ids", expect_in_findings=False)
        self.assertTrue(any(CANARY in n for n in r.notes),
                        f"the pre-existing id vanished entirely: {r.notes}")

    def test_prbranch_commit_headers_are_quarantined(self):
        # Commit author/subject are attacker-authored on a replayed branch.
        up = tempfile.mkdtemp()

        def git(where, *a, env=None):
            subprocess.run(["git", "-C", where, *a], check=True, capture_output=True, env=env)

        git(up, "init", "-q", "--initial-branch=main")
        git(up, "config", "user.email", "maint@up.tld")
        git(up, "config", "user.name", "Maint")
        with open(os.path.join(up, "a.txt"), "w") as fh:
            fh.write("1\n")
        git(up, "add", "-A")
        git(up, "commit", "-qm", "base")

        repo = tempfile.mkdtemp()
        subprocess.run(["git", "clone", "-q", up, repo], check=True, capture_output=True)
        git(repo, "config", "user.email", "me@mine.tld")
        git(repo, "config", "user.name", "Me")
        git(repo, "checkout", "-qb", "feature")
        with open(os.path.join(repo, "b.txt"), "w") as fh:
            fh.write("x\n")
        git(repo, "add", "-A")
        git(repo, "-c", f"user.name={CANARY}", "-c", "user.email=mallory@evil.tld",
            "commit", "-qm", f"subject {CANARY}")

        os.environ["CROSSCHECK_IDENTITIES"] = "me@mine.tld"
        try:
            r = prbranch.check(repo)
        finally:
            os.environ.pop("CROSSCHECK_IDENTITIES", None)
        self.assertEqual(r.code, EXIT_FINDING, [f.what for f in r.findings])
        self._assert_quarantined(r, CANARY, "pr-branch stray commit")
        # data travels into agent transcripts: capped header fields only,
        # never whole commit objects.
        for c in r.data.get("foreign_commits", []):
            self.assertLessEqual(len(c.get("subject", "")), 200)
            self.assertNotIn("body", c, "raw commit bodies do not belong in data")

    def test_scope_rejected_input_is_quarantined(self):
        d = tempfile.mkdtemp()
        os.environ[scope.POLICY_DIR_ENV] = d
        try:
            with open(os.path.join(d, "p.json"), "w") as fh:
                json.dump({"in_scope": ["eero.com"], "fetched_at": "2026-08-01"}, fh)
            r = scope.check("p", [f"evil.com\nIN {CANARY} (matches 'eero.com')"])
            self._assert_quarantined(r, CANARY, "scope rejected input")
        finally:
            os.environ.pop(scope.POLICY_DIR_ENV, None)


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

    def test_at_least_one_real_policy_ships(self):
        # The provenance tests below iterate over whatever exists - delete
        # every policy and they all pass over nothing. The dataset existing at
        # all is itself a property the code relies on: scope and vrp are dead
        # weight without one real program transcribed.
        real = {fn: p for fn, p in self._load_all("policies").items()
                if not fn.startswith("_")}
        self.assertTrue(real, "no real policy ships - every scope/vrp run would be INVALID")
        self.assertTrue(
            any((p.get("floor") or {}).get("unrewarded") for p in real.values()),
            "no policy carries a floor table - the floor-quote invariant is ruling on air",
        )

    def test_at_least_one_real_spec_ships(self):
        real = {
            fn: s for fn, s in self._load_all("specs").items()
            if not fn.startswith(("_", ".")) and s and isinstance(s, dict) and s.get("controls")
        }
        self.assertTrue(real, "no real enforce spec ships - the probe invariant is ruling on air")

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
