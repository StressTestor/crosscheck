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
from unittest.mock import patch

from cc.checks import enforce
from cc.result import EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID, EXIT_JUDGMENT
from cc.run import Proc

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

    def test_enforced_verdict_is_reached_but_unproven_until_a_red_run(self):
        # The control genuinely refuses, so the VERDICT is ENFORCED - but the
        # exit code stays JUDGMENT until the rule has been seen to go red,
        # because a rule that only ever passed may be matching for an
        # unrelated reason. Both halves are asserted on purpose.
        t = self._target(TARGET_ENFORCED)
        c = self._nproc_control(t)
        c["self_report"] = {"from": "stdout_json", "path": "unenforced",
                            "claims_applied_when": "absent_from", "key": "nproc"}
        r = enforce.check(self._spec(c))
        self.assertEqual(r.data["verdicts"]["nproc"], enforce.ENFORCED)
        self.assertEqual(r.code, EXIT_JUDGMENT)
        self.assertTrue(any("never been seen to FAIL" in f.what for f in r.findings))

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
        # everything. TARGET_ENFORCED refuses (recognisably), so the pinned
        # negative broke: over-block, a real finding.
        t = self._target(TARGET_ENFORCED)
        c = self._nproc_control(t)
        c["expect"] = "allowed"
        c["allowed_when"] = {"exit_code_in": [0]}
        r = enforce.check(self._spec(c))
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertTrue(any("pins as ALLOWED was refused" in f.what for f in r.findings))

    def test_allowed_without_allowed_when_is_invalid_before_the_probe_fires(self):
        # "Allowed" used to mean merely "not refused", so a crashed
        # allowed-case read as successfully allowed. A spec that cannot name
        # what success looks like has not pinned anything.
        marker = os.path.join(self.d, "fired")
        t = self._target(f"#!/bin/sh\ntouch {marker}\nexit 0\n")
        c = self._nproc_control(t)
        c["expect"] = "allowed"
        r = enforce.check(self._spec(c))
        self.assertEqual(r.code, EXIT_INVALID)
        self.assertEqual(r.data["verdicts"]["nproc"], enforce.UNTESTABLE)
        self.assertFalse(os.path.exists(marker), "a malformed spec earned an execution")

    def test_crashed_allowed_case_is_untestable_not_allowed(self):
        # Exit 3 with no refusal marker satisfies neither allowed_when nor
        # refused_when: a crash decides nothing, in either direction.
        t = self._target("#!/bin/sh\necho 'Traceback: boom' >&2\nexit 3\n")
        c = self._nproc_control(t)
        c["expect"] = "allowed"
        c["allowed_when"] = {"exit_code_in": [0]}
        c["refused_when"] = {"exit_code_not_in": [0], "stderr_contains": "refused"}
        c["self_report"] = {}
        r = enforce.check(self._spec(c))
        self.assertEqual(r.code, EXIT_INVALID)
        self.assertEqual(r.data["verdicts"]["nproc"], enforce.UNTESTABLE)

    def test_allowed_case_that_succeeds_is_enforced(self):
        # Discriminating: the positive predicate must not over-block the
        # legitimate case it exists to protect.
        t = self._target("#!/bin/sh\necho 'ok, did the thing'\nexit 0\n")
        c = self._nproc_control(t)
        c["expect"] = "allowed"
        c["allowed_when"] = {"exit_code_in": [0], "stdout_contains": "ok"}
        c["self_report"] = {}
        r = enforce.check(self._spec(c))
        self.assertEqual(r.data["verdicts"]["nproc"], enforce.ENFORCED)

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

    def test_enforced_without_a_recorded_red_run_is_not_trusted(self):
        # The failure this repo actually shipped: a refusal rule that has only
        # ever passed may be matching for an unrelated reason. A README
        # paragraph is not a check, so this is one.
        t = self._target(TARGET_ENFORCED)
        c = self._nproc_control(t)
        c["self_report"] = {}
        r = enforce.check(self._spec(c))
        self.assertNotEqual(r.code, EXIT_CLEAN)
        self.assertTrue(
            any("never been seen to FAIL" in f.what for f in r.findings),
            [f.what for f in r.findings],
        )

    def test_recording_a_red_run_makes_the_verdict_count(self):
        # Round trip: prove it goes red against a broken target, then the same
        # control's ENFORCED on a working target is trusted.
        broken = self._target(TARGET_UNENFORCED_HONEST, name="broken.sh")
        c_broken = self._nproc_control(broken)
        c_broken["self_report"] = {}
        red = enforce.check(self._spec(c_broken, name="red"), record_red=True)
        self.assertEqual(red.data["verdicts"]["nproc"], enforce.UNENFORCED)

        # Same probe argv + rule, now against a target that refuses.
        good = self._target(TARGET_ENFORCED, name="broken.sh")  # overwrite, same path
        c_good = self._nproc_control(good)
        c_good["self_report"] = {}
        self.assertEqual(
            enforce.control_fingerprint(c_broken),
            enforce.control_fingerprint(c_good),
            "fingerprint must not depend on target behaviour",
        )
        r = enforce.check(self._spec(c_good, name="good"))
        self.assertEqual(r.code, EXIT_CLEAN, [f.what for f in r.findings])

    def test_fingerprint_changes_when_the_refusal_rule_changes(self):
        # Editing the rule invalidates the proof - that is the point.
        t = self._target(TARGET_ENFORCED)
        a = self._nproc_control(t)
        b = self._nproc_control(t)
        b["refused_when"] = {"exit_code_not_in": [0], "stderr_contains": "refused"}
        self.assertNotEqual(enforce.control_fingerprint(a), enforce.control_fingerprint(b))

    def test_fingerprint_ignores_unrelated_controls(self):
        t = self._target(TARGET_ENFORCED)
        a = self._nproc_control(t)
        b = self._nproc_control(t)
        b["declares"] = "totally different prose"
        self.assertEqual(enforce.control_fingerprint(a), enforce.control_fingerprint(b))

    def test_fingerprint_covers_cwd_env_and_allowed_when(self):
        # All three change what executes or how the outcome is read, so an old
        # proof must not survive a change to any of them.
        t = self._target(TARGET_ENFORCED)
        a = self._nproc_control(t)
        self.assertNotEqual(
            enforce.control_fingerprint(a, cwd="/somewhere"),
            enforce.control_fingerprint(a, cwd="/elsewhere"),
            "cwd changes which program a relative probe path names",
        )
        b = self._nproc_control(t)
        b["env"] = {"MODE": "prod"}
        self.assertNotEqual(enforce.control_fingerprint(a), enforce.control_fingerprint(b))
        c = self._nproc_control(t)
        c["allowed_when"] = {"exit_code_in": [0]}
        self.assertNotEqual(enforce.control_fingerprint(a), enforce.control_fingerprint(c))

    def test_every_fired_probe_is_audited_with_a_hash_chain(self):
        import tempfile as _tf
        log = os.path.join(_tf.mkdtemp(), "probe-audit.jsonl")
        os.environ[enforce.AUDIT_LOG_ENV] = log
        try:
            t = self._target(TARGET_ENFORCED)
            c = self._nproc_control(t)
            c["self_report"] = {}
            enforce.check(self._spec(c, name="a"))
            enforce.check(self._spec(c, name="b"))
            rows = [json.loads(l) for l in open(log) if l.strip()]
            self.assertEqual(len(rows), 2)
            for row in rows:
                self.assertEqual(row["argv"], [t])
                self.assertIn("sentinel", row)
                self.assertIn("spec_sha", row)
            # chain links: each entry hashes the previous chain value
            import hashlib as _h
            prev = "0" * 64
            for row in rows:
                body = {k: v for k, v in row.items() if k != "chain"}
                want = _h.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()
                self.assertEqual(row["chain"], want, "audit chain does not verify")
                prev = row["chain"]
        finally:
            os.environ.pop(enforce.AUDIT_LOG_ENV, None)

    def test_dry_run_writes_no_audit_entry(self):
        import tempfile as _tf
        log = os.path.join(_tf.mkdtemp(), "probe-audit.jsonl")
        os.environ[enforce.AUDIT_LOG_ENV] = log
        try:
            t = self._target(TARGET_ENFORCED)
            enforce.check(self._spec(self._nproc_control(t)), dry_run=True)
            self.assertFalse(os.path.exists(log), "dry-run wrote an audit entry")
        finally:
            os.environ.pop(enforce.AUDIT_LOG_ENV, None)

    def test_unwritable_audit_log_refuses_to_fire(self):
        # An unrecorded probe is a probe that fired silently. Fail closed.
        marker = os.path.join(self.d, "fired")
        t = self._target(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
        os.environ[enforce.AUDIT_LOG_ENV] = os.path.join(self.d, "target.sh", "nope.jsonl")
        try:
            r = enforce.check(self._spec(self._nproc_control(t)))
            self.assertEqual(r.code, EXIT_INVALID)
            self.assertFalse(os.path.exists(marker), "probe fired despite an unwritable audit log")
        finally:
            os.environ.pop(enforce.AUDIT_LOG_ENV, None)

    def test_pinned_allowed_controls_can_also_be_proven(self):
        # The expect:allowed branch used to `continue` past the recorder, so a
        # pinned negative could never be proven and reported unproven forever.
        t = self._target(TARGET_ENFORCED)
        c = self._nproc_control(t)
        c["expect"] = "allowed"
        c["allowed_when"] = {"exit_code_in": [0]}
        c["self_report"] = {}
        r = enforce.check(self._spec(c, name="al"), record_red=True)
        self.assertEqual(r.data["verdicts"]["nproc"], enforce.UNENFORCED)
        self.assertIn(enforce.control_fingerprint(c, cwd=self.d), enforce._load_ledger())

    def test_unwritable_ledger_makes_record_red_invalid(self):
        # A red run that was observed but never recorded proves nothing next
        # run - and the old code said "recorded" anyway.
        broken = self._target(TARGET_UNENFORCED_HONEST)
        c = self._nproc_control(broken)
        c["self_report"] = {}
        # A DIRECTORY at the ledger path fails the write even when running as
        # root, where a chmod-based fixture would silently pass.
        os.makedirs(os.path.join(self.specs, ".redruns.json"))
        r = enforce.check(self._spec(c), record_red=True)
        self.assertEqual(r.code, EXIT_INVALID, [f.what for f in r.findings])
        self.assertTrue(any("could NOT be recorded" in f.what for f in r.findings))

    def test_missing_spec_is_invalid(self):
        self.assertEqual(enforce.check("nope").code, EXIT_INVALID)

    def test_spec_name_traversal_is_refused(self):
        r = enforce.check(".." + os.sep + "somewhere")
        self.assertEqual(r.code, EXIT_INVALID)

    def test_explicit_spec_paths_are_refused(self):
        # A spec is arbitrary argv. load_spec used to accept any filesystem
        # path, so any json anywhere on disk could become an execution plan,
        # sidestepping the review that specs/ diffs get.
        outside = os.path.join(self.d, "outside.json")
        with open(outside, "w") as fh:
            json.dump({"target": "x", "cwd": self.d,
                       "controls": [self._nproc_control("/bin/true")]}, fh)
        r = enforce.check(outside)
        self.assertEqual(r.code, EXIT_INVALID)
        self.assertTrue(any("paths are refused" in f.what for f in r.findings),
                        [f.what for f in r.findings])

    def test_bare_name_with_json_suffix_still_loads(self):
        # `cc enforce foo.json` is a habit, not an attack. It resolves to the
        # same specs/foo.json a bare name would.
        t = self._target(TARGET_ENFORCED)
        r = enforce.check(self._spec(self._nproc_control(t)) + ".json")
        self.assertIn("nproc", r.data["verdicts"])

    def _deny_run(self):
        real_run = enforce.run

        def fake(argv, **k):
            if argv and argv[0] == "sentinel":
                return Proc(argv=argv, code=2, out="", err="deny", timed_out=False)
            return real_run(argv, **k)

        return fake

    def test_sentinel_deny_fails_closed_without_the_override(self):
        # A probe firing PAST a guard refusal, silently, was the accepted
        # limit here. Now it is INVALID and the probe does not fire.
        marker = os.path.join(self.d, "fired")
        t = self._target(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
        c = self._nproc_control(t)
        with patch.object(enforce, "have", lambda tool: tool == "sentinel"), \
             patch.object(enforce, "run", self._deny_run()):
            r = enforce.check(self._spec(c))
        self.assertEqual(r.code, EXIT_INVALID, [f.what for f in r.findings])
        self.assertEqual(r.data["verdicts"]["nproc"], enforce.UNTESTABLE)
        self.assertFalse(os.path.exists(marker), "the probe fired past a guard DENY")

    def test_override_sentinel_fires_and_stamps_the_audit_log(self):
        # Discrimination preserved: the override runs the probe, and the
        # audit row says a DENY was overridden - it can be answered for.
        log = os.path.join(tempfile.mkdtemp(), "probe-audit.jsonl")
        os.environ[enforce.AUDIT_LOG_ENV] = log
        try:
            t = self._target(TARGET_ENFORCED)
            c = self._nproc_control(t)
            c["self_report"] = {}
            with patch.object(enforce, "have", lambda tool: tool == "sentinel"), \
                 patch.object(enforce, "run", self._deny_run()):
                r = enforce.check(self._spec(c), override_sentinel=True)
            self.assertEqual(r.data["verdicts"]["nproc"], enforce.ENFORCED)
            rows = [json.loads(ln) for ln in open(log, encoding="utf-8") if ln.strip()]
            self.assertTrue(rows, "the overridden probe fired without an audit row")
            self.assertIs(rows[-1].get("sentinel_overridden"), True)
        finally:
            os.environ.pop(enforce.AUDIT_LOG_ENV, None)

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
