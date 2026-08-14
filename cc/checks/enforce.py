"""enforce - does a declared control actually engage, and does the target
tell the truth about it when it doesn't.

Every other check in this suite reads artifacts. This one RUNS the thing under
test and throws input at it that should be refused. That is a deliberate break
in the tool's otherwise-static posture, so it is its own subcommand: invoking
`cc enforce` IS the consent to execute probes. Nothing else in crosscheck
executes a target, and nothing here ever touches a remote host.

## the class this exists for

"Control declared, control not applied, success reported anyway." Four
independent instances drove this module:

  - codecalc #62: RLIMIT_NPROC does not bind at uid 0 and `unenforced` does not
    say so, so a caller reads the result as "the process ceiling was applied".
  - codecalc #61: execute_code_stream cannot apply the memory/CPU ceilings
    execute_code declares.
  - crosscheck's own `ci`: a SAST scanner was credited as having run when a
    malformed config - living INSIDE the audited repo - made it analyze
    nothing, and then the output asserted the workflows were clean under it.
  - crosscheck's own `pr-body`: a checker that crashed was reported as passing.

Reading code finds these sometimes. Running a probe that should be refused
finds them every time.

## verdicts, and why there are four

  ENFORCED           the probe was refused. the control is real.
  UNENFORCED         the probe succeeded. the control is not applied.
  UNENFORCED-SILENT  the probe succeeded AND the target's own self-report
                     still claims the control applied. strictly worse than
                     UNENFORCED: a caller who reads the report is now
                     confidently wrong, and this is the exact shape of #62.
  UNTESTABLE         the probe could not be run at all. INVALID, never CLEAN -
                     "I could not test it" and "it holds" are different
                     sentences, and conflating them is the bug this whole
                     suite is about. XX

Judgment calls:
1. Probes are argv lists, never shell strings. The suite obeys the sink rule it
   enforces on everyone else, and that rule matters most in the one module
   whose job is running hostile input.
2. Specs are hand-written versioned data, exactly like `policies/`. There is no
   spec generator: a probe nobody read is a probe nobody should fire.
3. A missing or malformed spec is INVALID. There is no default spec and no
   "probably fine" path.
4. `expect: "allowed"` exists so a spec can pin a NEGATIVE - proof that a
   legitimate operation still works after a control is added. A refusal harness
   with no allowed-cases silently rewards a target that refuses everything.
5. We never assert on exit code alone. A target that dies for an unrelated
   reason looks exactly like a target that refused, so a spec must say how a
   refusal is recognised.
"""

from __future__ import annotations

import hashlib
import json
import os

from ..result import Result, Finding
from ..run import run, have

CHECK = "enforce"

SPEC_DIR_ENV = "CROSSCHECK_SPECS"
_DEFAULT_SPEC_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "specs"
)

ENFORCED = "ENFORCED"
UNENFORCED = "UNENFORCED"
UNENFORCED_SILENT = "UNENFORCED-SILENT"
UNTESTABLE = "UNTESTABLE"


def spec_dir() -> str:
    return os.environ.get(SPEC_DIR_ENV) or _DEFAULT_SPEC_DIR


def ledger_path() -> str:
    return os.path.join(spec_dir(), ".redruns.json")


def control_fingerprint(control: dict, cwd: str | None = None) -> str:
    """Hash the parts of a control that decide its verdict.

    Keyed on everything that changes WHAT EXECUTES or HOW the outcome is
    read - name, probe, both recognition rules, expect, env, and the cwd the
    probes run in - NOT the whole spec, so editing an unrelated control does
    not invalidate this one's proof. cwd and env used to be omitted, which
    left an old proof valid for a different executable behaviour: the same
    relative probe path in a different directory is a different program. XX
    """
    payload = json.dumps(
        {
            "name": control.get("name"),
            "probe": control.get("probe"),
            "refused_when": control.get("refused_when"),
            "allowed_when": control.get("allowed_when"),
            "expect": control.get("expect", "refused"),
            "env": control.get("env"),
            "cwd": cwd,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _load_ledger() -> dict:
    try:
        with open(ledger_path(), "r", encoding="utf-8") as fh:
            return json.load(fh) or {}
    except (OSError, ValueError):
        return {}


def _record_red(control: dict, verdict: str, cwd: str | None = None) -> str | None:
    """Remember that this exact control has been SEEN TO FAIL.

    A control that has never gone red is a control nobody has tested. The
    first spec in this repo reported ENFORCED against a deliberately broken
    build because its refusal rule matched for an unrelated reason - and the
    mitigation shipped as a paragraph in a README, which is the same shape as
    every mitigation that quietly stops happening by week two. So it is a
    machine check now. (¬‿¬)

    This is a discipline ledger, not a security boundary: anyone who can edit
    the spec can edit this. It exists to stop honest mistakes, and it says so.

    Returns an error string when the write failed, None on success. The old
    version swallowed OSError while the caller claimed "recorded red run"
    unconditionally - a proof that never landed, narrated as landed. XX
    """
    led = _load_ledger()
    led[control_fingerprint(control, cwd)] = {
        "name": control.get("name"),
        "verdict": verdict,
    }
    try:
        os.makedirs(os.path.dirname(ledger_path()), exist_ok=True)
        with open(ledger_path(), "w", encoding="utf-8") as fh:
            json.dump(led, fh, indent=2, sort_keys=True)
        return None
    except OSError as e:
        return str(e)


AUDIT_LOG_ENV = "CROSSCHECK_PROBE_AUDIT"
_DEFAULT_AUDIT = os.path.join(os.path.expanduser("~"), ".crosscheck", "probe-audit.jsonl")


def audit_path() -> str:
    return os.environ.get(AUDIT_LOG_ENV) or _DEFAULT_AUDIT


def _sentinel_verdict(argv: list[str]) -> str:
    """Ask the local guard what it thinks of this probe. NON-BLOCKING.

    enforce's probes are subprocess argv, so sentinel/ghost - a PreToolUse hook
    on the agent's Bash tool - never sees them. That is a blind spot in the one
    module built to run hostile input, so we hand the guard the argv on the way
    past and RECORD its opinion.

    Deliberately an oracle, never a veto: a guard that can refuse probes turns
    every DENY into UNTESTABLE-forever, which is the exact defect that killed
    the guard-corpus module. Recording preserves discrimination; blocking
    destroys it. (¬‿¬)
    """
    if not have("sentinel"):
        return "unavailable"
    p = run(["sentinel", "check", "--", *argv], timeout=30)
    if p.timed_out:
        return "timeout"
    if p.code == 0:
        return "allow"
    return f"deny({p.code})"


def _audit(argv: list[str], cwd: str | None, spec_sha: str, verdict: str) -> str | None:
    """Hash-chained append-only record. Returns an error string, or None.

    Tamper-EVIDENCE and legibility, NOT an authorization boundary: this runs as
    the same user that could rewrite the file. It exists so a probe that fired
    cannot fire silently, and so an unexpected argv is visible after the fact.
    An agent that authors a hostile spec AND commits it defeats it entirely -
    ordinary review of spec diffs is the only control on that, and the docs say
    so rather than implying coverage. XX
    """
    path = audit_path()
    try:
        prev = "0" * 64
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                for ln in fh:
                    if ln.strip():
                        last = ln
                try:
                    prev = json.loads(last).get("chain", prev)
                except (ValueError, UnboundLocalError):
                    pass
        entry = {
            "ts": _now_iso(),
            "argv": argv,
            "cwd": cwd or "",
            "spec_sha": spec_sha,
            "sentinel": verdict,
        }
        entry["chain"] = hashlib.sha256(
            (prev + json.dumps(entry, sort_keys=True)).encode()
        ).hexdigest()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # O_APPEND so concurrent runs cannot interleave a partial line.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(entry) + "\n").encode())
        finally:
            os.close(fd)
        return None
    except OSError as e:
        return str(e)


def _now_iso() -> str:
    import datetime as _dt

    return _dt.datetime.now().isoformat(timespec="seconds")


def load_spec(path_or_name: str) -> tuple[dict | None, str | None]:
    """A path, or a bare name resolved inside specs/. No traversal."""
    if os.sep in path_or_name or path_or_name.endswith(".json"):
        path = os.path.abspath(os.path.expanduser(path_or_name))
    else:
        root = os.path.realpath(spec_dir())
        path = os.path.realpath(os.path.join(root, f"{path_or_name}.json"))
        if path != root and not path.startswith(root + os.sep):
            return None, f"spec name {path_or_name!r} escapes the spec directory"
    if not os.path.isfile(path):
        return None, f"no spec at {path}"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh), None
    except (OSError, ValueError) as e:
        return None, f"spec {path} is unreadable/malformed: {e}"


def _dig(doc, path: str):
    """Walk a dotted path. Returns (found, value) so absent != None."""
    cur = doc
    for part in [p for p in path.split(".") if p]:
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return False, None
    return True, cur


def _rule_holds(rule: dict | None, p) -> tuple[bool | None, str]:
    """Does a recognition rule hold for this probe outcome? None = cannot tell.

    Shared by refused_when and allowed_when, because both answer the same
    question: is this outcome the one the spec named? Exit code alone is never
    enough - a target that dies for an unrelated reason looks identical to one
    that refused, and a target that crashes looks identical to one that ran.
    """
    rule = rule or {}
    if not rule:
        return None, "no recognition rule was given"

    text = p.text()
    checks = []

    if "stdout_contains" in rule:
        checks.append(rule["stdout_contains"] in (p.out or ""))
    if "stderr_contains" in rule:
        checks.append(rule["stderr_contains"] in (p.err or ""))
    if "output_contains" in rule:
        checks.append(rule["output_contains"] in text)
    if "exit_code_in" in rule:
        checks.append(p.code in rule["exit_code_in"])
    if "exit_code_not_in" in rule:
        checks.append(p.code not in rule["exit_code_not_in"])

    if not checks:
        return None, "the rule has no recognised keys"
    # All stated conditions must hold. A partial match is not a match.
    return all(checks), ""


def _refused(control: dict, p) -> tuple[bool | None, str]:
    """Was the probe refused? None means we cannot tell -> UNTESTABLE."""
    rule = control.get("refused_when") or {}
    if not rule:
        return None, "spec gives no refused_when rule, so a refusal cannot be recognised"
    held, why = _rule_holds(rule, p)
    if held is None:
        return None, "refused_when has no recognised keys"
    return held, ""


def _claims_applied(control: dict, p, cwd: str | None) -> tuple[bool | None, str]:
    """Does the target's own self-report claim this control was applied?

    None when there is no self-report to consult - that is not a failure, it
    just means the SILENT variant cannot be distinguished.
    """
    sr = control.get("self_report") or {}
    if not sr:
        return None, ""

    src = sr.get("from", "stdout_json")
    if src == "stdout_json":
        raw = p.out
    elif src == "file":
        fp = sr.get("file", "")
        if cwd and not os.path.isabs(fp):
            fp = os.path.join(cwd, fp)
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as e:
            return None, f"self-report file unreadable: {e}"
    else:
        return None, f"unknown self_report.from {src!r}"

    try:
        doc = json.loads(raw) if (raw or "").strip() else None
    except ValueError:
        return None, "self-report is not parseable JSON"
    if doc is None:
        return None, "self-report produced no JSON"

    path = sr.get("path", "")
    found, value = _dig(doc, path) if path else (True, doc)
    mode = sr.get("claims_applied_when", "absent_from")
    key = sr.get("key", control.get("name", ""))

    if mode == "absent_from":
        # The codecalc shape: a control is claimed applied when its name does
        # NOT appear in the `unenforced` list.
        if not found:
            return None, f"self-report has no {path!r} to read"
        seq = value if isinstance(value, (list, tuple)) else [value]
        return not any(key in str(x) for x in seq), ""
    if mode == "present_in":
        if not found:
            return False, ""
        seq = value if isinstance(value, (list, tuple)) else [value]
        return any(key in str(x) for x in seq), ""
    if mode == "equals":
        return (found and value == sr.get("value")), ""
    return None, f"unknown claims_applied_when {mode!r}"


def check(
    spec_ref: str,
    only: list[str] | None = None,
    dry_run: bool = False,
    timeout: int = 120,
    record_red: bool = False,
) -> Result:
    r = Result(check=CHECK)

    spec, err = load_spec(spec_ref)
    if err:
        return Result.invalid(
            CHECK,
            err,
            f"write a spec in {spec_dir()} - see specs/README.md; there is no default",
        )

    controls = spec.get("controls") or []
    if not controls:
        return Result.invalid(CHECK, f"spec {spec_ref!r} declares no controls")

    cwd = spec.get("cwd")
    if cwd:
        cwd = os.path.abspath(os.path.expanduser(cwd))
        if not os.path.isdir(cwd):
            return Result.invalid(CHECK, f"spec cwd does not exist: {cwd}")

    r.data.update({"spec": spec.get("target", spec_ref), "cwd": cwd, "dry_run": dry_run})
    if spec.get("description"):
        r.note(spec["description"])

    wanted = set(only or [])
    matched: set[str] = set()
    dry_ran = False
    verdicts = {}
    ledger = _load_ledger()
    spec_sha = hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:16]
    r.data["spec_sha"] = spec_sha

    for control in controls:
        name = control.get("name") or "(unnamed)"
        if wanted and name not in wanted:
            continue
        matched.add(name)
        declares = control.get("declares", "")
        probe = control.get("probe")
        expect = control.get("expect", "refused")

        if not isinstance(probe, list) or not probe:
            r.add(
                Finding(
                    what=f"{name}: probe is not an argv list",
                    detail="probes are argv lists, never shell strings",
                    severity="invalid",
                )
            )
            verdicts[name] = UNTESTABLE
            continue

        if expect not in ("refused", "allowed"):
            # A typo used to fall through to the allowed branch, so
            # expect:"alllowed" reported ENFORCED/CLEAN on a ledger hit.
            r.add(
                Finding(
                    what=f"{name}: expect must be 'refused' or 'allowed'",
                    detail=f"got {expect!r}",
                    fix="fix the spec before running it",
                    severity="invalid",
                )
            )
            verdicts[name] = UNTESTABLE
            continue

        if expect == "allowed" and not (control.get("allowed_when") or {}):
            # "Allowed" was implemented as merely "not refused", so a crashed
            # allowed-case whose output missed the refusal marker counted as
            # successfully allowed. Success needs its own positive rule, and a
            # spec that cannot state one has not pinned anything. Checked
            # BEFORE the probe fires - a malformed spec earns no execution. XX
            r.add(
                Finding(
                    what=f"{name}: expect:'allowed' has no allowed_when rule",
                    detail="absence of a refusal is not proof of success - a crashed allowed-case would read as allowed",
                    fix="add allowed_when naming how success is recognised (same keys as refused_when)",
                    severity="invalid",
                )
            )
            verdicts[name] = UNTESTABLE
            continue

        if dry_run:
            r.note(f"WOULD RUN [{name}] expect={expect}: {' '.join(probe)}")
            verdicts[name] = "DRY-RUN"
            dry_ran = True
            continue

        verdict = _sentinel_verdict(probe)
        audit_err = _audit(probe, cwd, spec_sha, verdict)
        if audit_err:
            # Fail closed on audit failure ONLY. An unrecorded probe is a probe
            # that fired silently, which is the thing this is for.
            r.add(
                Finding(
                    what=f"{name}: refusing to fire - the probe audit log could not be written",
                    detail=f"{audit_path()}: {audit_err}",
                    fix="fix the log path or permissions; enforce will not execute unrecorded",
                    severity="invalid",
                )
            )
            verdicts[name] = UNTESTABLE
            continue
        if verdict.startswith("deny"):
            r.note(f"{name}: sentinel would DENY this probe (recorded, not blocked)")

        # inherit_env=False is the one thing that ported out of pr-body's
        # sandbox when it was deleted: a probe gets PATH and whatever the spec
        # names, never the operator's environment. The rest of that sandbox
        # (node --permission, the vm require-guard) was JS-runtime containment
        # and has nothing to contain here - enforce fires argv subprocesses.
        p = run(
            probe,
            cwd=cwd,
            timeout=control.get("timeout", timeout),
            env=control.get("env") or None,
            inherit_env=False,
        )
        if p.timed_out:
            r.add(
                Finding(
                    what=f"{name}: probe timed out - the control is UNTESTABLE",
                    detail=f"declared: {declares}",
                    fix="raise the probe timeout, or fix the target so it answers",
                    severity="invalid",
                )
            )
            verdicts[name] = UNTESTABLE
            continue

        if p.code in (126, 127):
            # 127 = not found, 126 = not executable. Either satisfies a rule
            # like exit_code_not_in:[0] while the target never ran at all.
            r.add(
                Finding(
                    what=f"{name}: the probe never executed (exit {p.code})",
                    detail="126=not executable, 127=not found - this is not a refusal",
                    fix="fix the probe path before trusting any verdict from it",
                    severity="invalid",
                ).with_foreign("probe output", p.text())
            )
            verdicts[name] = UNTESTABLE
            continue

        if expect == "refused":
            refused, why = _refused(control, p)
            if refused is None:
                r.add(
                    Finding(
                        what=f"{name}: cannot tell whether the probe was refused - UNTESTABLE",
                        detail=why or "refused_when did not resolve",
                        fix="give the control a refused_when rule that names how a refusal looks",
                        severity="invalid",
                    ).with_foreign("probe output", p.text())
                )
                verdicts[name] = UNTESTABLE
                continue
            held = refused
        else:
            # expect == "allowed": success is a POSITIVE match on allowed_when.
            # Not-allowed then splits on whether the outcome is a recognisable
            # refusal (the pinned negative broke: over-block, a real finding)
            # or something else entirely (a crash - which is not an allowance
            # and not a refusal, so it decides nothing). XX
            allowed, why = _rule_holds(control.get("allowed_when"), p)
            if allowed is None:
                r.add(
                    Finding(
                        what=f"{name}: allowed_when did not resolve - UNTESTABLE",
                        detail=why or "allowed_when has no recognised keys",
                        fix="give allowed_when at least one recognisable condition",
                        severity="invalid",
                    ).with_foreign("probe output", p.text())
                )
                verdicts[name] = UNTESTABLE
                continue
            if allowed:
                held = True
            else:
                refused, _why = _rule_holds(control.get("refused_when"), p)
                if refused is not True:
                    r.add(
                        Finding(
                            what=f"{name}: the allowed-case probe neither succeeded nor was recognisably refused - UNTESTABLE",
                            detail="it most likely crashed; a crash is not an allowance and not a refusal",
                            fix="fix the probe, or the allowed_when/refused_when rules, before trusting any verdict",
                            severity="invalid",
                        ).with_foreign("probe output", p.text())
                    )
                    verdicts[name] = UNTESTABLE
                    continue
                held = False

        if held:
            verdicts[name] = ENFORCED
            if control_fingerprint(control, cwd) in ledger:
                r.note(f"{ENFORCED}  {name} - {declares or 'control holds'}")
            else:
                # An ENFORCED from a control never seen to fail is not evidence.
                # This is the bug that shipped in this repo's first spec, and a
                # README paragraph is not a check. >:[
                r.add(
                    Finding(
                        what=f"{name}: ENFORCED, but this control has never been seen to FAIL",
                        detail=(
                            "a refusal rule that has only ever passed may be matching for an "
                            "unrelated reason - the first spec in this repo did exactly that"
                        ),
                        fix=(
                            "break the control on a throwaway copy and re-run with --record-red, "
                            "then this verdict counts"
                        ),
                        severity="judgment",
                    )
                )
            continue

        claims, claim_note = _claims_applied(control, p, cwd)
        if claim_note:
            r.note(f"{name}: {claim_note}")

        # Record the red HERE - before the expect:allowed branch, which used to
        # `continue` past the recorder and left pinned-negative controls
        # permanently unprovable. Any outcome where the control did not hold is
        # a red run, whichever direction it was pinned in. >:[
        if record_red:
            rec_err = _record_red(control, UNENFORCED_SILENT if claims is True else UNENFORCED, cwd)
            if rec_err:
                # The red run was OBSERVED but the proof never landed. Saying
                # "recorded" here would bless the control's next ENFORCED off
                # evidence that does not exist.
                r.add(
                    Finding(
                        what=f"{name}: red run observed but could NOT be recorded",
                        detail=f"{ledger_path()}: {rec_err}",
                        fix="fix the ledger path/permissions and re-run --record-red",
                        severity="invalid",
                    )
                )
            else:
                r.note(f"recorded red run for {name} - its ENFORCED verdicts now count")

        if expect == "allowed":
            # A pinned negative broke: a legitimate operation is now refused.
            verdicts[name] = UNENFORCED
            r.add(
                Finding(
                    what=f"{name}: an operation the spec pins as ALLOWED was refused",
                    detail=f"declared: {declares}",
                    fix="the control over-blocks - check it before shipping it",
                )
            )
            continue

        if claims is True:
            verdicts[name] = UNENFORCED_SILENT
            r.add(
                Finding(
                    what=f"{name}: control NOT applied, and the target reports it AS applied",
                    detail=(
                        f"declared: {declares}. the probe succeeded, and the self-report still "
                        f"claims the control engaged - a caller reading that result is confidently wrong"
                    ),
                    fix="apply the control, or record it in the target's unenforced/failed list",
                )
            )
        else:
            verdicts[name] = UNENFORCED
            r.add(
                Finding(
                    what=f"{name}: control is NOT applied",
                    detail=f"declared: {declares}. the probe succeeded when it should have been refused",
                    fix="apply the control, or stop declaring it",
                )
            )

    missing = sorted(wanted - matched)
    if missing:
        r.add(
            Finding(
                what=f"--only named control(s) that do not exist in this spec: {', '.join(missing)}",
                fix="check the control names; a silently skipped control reads as passing",
                severity="invalid",
            )
        )

    if dry_ran:
        # Nothing was evaluated. CLEAN would mean "we looked".
        r.add(
            Finding(
                what="--dry-run evaluated nothing - this is not a verdict",
                fix="re-run without --dry-run to get one",
                severity="judgment",
            )
        )

    r.data["verdicts"] = verdicts
    silent = [k for k, v in verdicts.items() if v == UNENFORCED_SILENT]
    if silent:
        r.note(f"WORST CLASS - not applied AND reported as applied: {', '.join(silent)}")
    if not verdicts:
        return Result.invalid(CHECK, "no controls matched --only", "check the control names in the spec")
    return r
