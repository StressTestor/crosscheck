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
from ..run import run

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


def control_fingerprint(control: dict) -> str:
    """Hash the parts of a control that decide its verdict.

    Keyed on name + probe + refused_when + expect, NOT the whole spec, so
    editing an unrelated control does not invalidate this one's proof.
    """
    payload = json.dumps(
        {
            "name": control.get("name"),
            "probe": control.get("probe"),
            "refused_when": control.get("refused_when"),
            "expect": control.get("expect", "refused"),
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


def _record_red(control: dict, verdict: str) -> None:
    """Remember that this exact control has been SEEN TO FAIL.

    A control that has never gone red is a control nobody has tested. The
    first spec in this repo reported ENFORCED against a deliberately broken
    build because its refusal rule matched for an unrelated reason - and the
    mitigation shipped as a paragraph in a README, which is the same shape as
    every mitigation that quietly stops happening by week two. So it is a
    machine check now. (¬‿¬)

    This is a discipline ledger, not a security boundary: anyone who can edit
    the spec can edit this. It exists to stop honest mistakes, and it says so.
    """
    led = _load_ledger()
    led[control_fingerprint(control)] = {
        "name": control.get("name"),
        "verdict": verdict,
    }
    try:
        os.makedirs(os.path.dirname(ledger_path()), exist_ok=True)
        with open(ledger_path(), "w", encoding="utf-8") as fh:
            json.dump(led, fh, indent=2, sort_keys=True)
    except OSError:
        pass


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


def _refused(control: dict, p) -> tuple[bool | None, str]:
    """Was the probe refused? None means we cannot tell -> UNTESTABLE.

    Exit code alone is never enough: a target that dies for an unrelated reason
    looks identical to one that refused.
    """
    rule = control.get("refused_when") or {}
    if not rule:
        return None, "spec gives no refused_when rule, so a refusal cannot be recognised"

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
        return None, "refused_when has no recognised keys"
    # All stated conditions must hold. A partial match is not a refusal.
    return all(checks), ""


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
    verdicts = {}
    ledger = _load_ledger()

    for control in controls:
        name = control.get("name") or "(unnamed)"
        if wanted and name not in wanted:
            continue
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

        if dry_run:
            r.note(f"WOULD RUN [{name}] expect={expect}: {' '.join(probe)}")
            verdicts[name] = "DRY-RUN"
            continue

        p = run(probe, cwd=cwd, timeout=control.get("timeout", timeout))
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

        refused, why = _refused(control, p)
        if refused is None:
            r.add(
                Finding(
                    what=f"{name}: cannot tell whether the probe was refused - UNTESTABLE",
                    detail=why or "refused_when did not resolve",
                    fix="give the control a refused_when rule that names how a refusal looks",
                    severity="invalid",
                )
            )
            verdicts[name] = UNTESTABLE
            continue

        held = refused if expect == "refused" else (not refused)

        if held:
            verdicts[name] = ENFORCED
            if control_fingerprint(control) in ledger:
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

        if record_red:
            _record_red(control, UNENFORCED_SILENT if claims is True else UNENFORCED)
            r.note(f"recorded red run for {name} - its ENFORCED verdicts now count")

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

    r.data["verdicts"] = verdicts
    silent = [k for k, v in verdicts.items() if v == UNENFORCED_SILENT]
    if silent:
        r.note(f"WORST CLASS - not applied AND reported as applied: {', '.join(silent)}")
    if not verdicts:
        return Result.invalid(CHECK, "no controls matched --only", "check the control names in the spec")
    return r
