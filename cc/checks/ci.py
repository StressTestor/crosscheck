"""ci - the mechanical supply-chain pass on a repo's own GitHub Actions.

This module is deliberately thin. zizmor and actionlint already decide Actions
semantics correctly (template injection, credential persistence, over-broad
tokens, unpinned actions, shell bugs inside run:). Reimplementing that with
regexes over YAML - no stdlib YAML parser, `permissions:` nesting per job,
`uses:` inside composite action.yml - would be a worse copy that rots. So:

  - delegate semantics to zizmor + actionlint,
  - keep only the two cheap greps they do not phrase the way you need,
  - and ROUTE workflow-file changes to gha-security-review rather than
    pretending six adversarial lenses fit in a linter.

Judgment calls:
1. Missing SAST is INVALID under --require-sast, never a silent skip. A skipped
   scanner that prints nothing looks exactly like a clean scan. 💀
2. The SHA-pin scan covers composite `action.yml` too, not just
   .github/workflows/**, because that is where a pinned-looking repo hides an
   unpinned dependency.
3. Actions published by GitHub itself (actions/*, github/*) are still reported
   when unpinned - the 2025-era tag-mutation incidents were first-party too.
4. We never write to the repo. No autofix, no reformat.
"""

from __future__ import annotations

import json
import os
import re

from ..result import Result, Finding
from ..run import run, have

CHECK = "ci"

# git resolves object ids case-insensitively, so an uppercase 40-hex pin is
# exactly as pinned as a lowercase one. Matching only lowercase reported a
# correctly-hardened workflow as unpinned. XX
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
# `uses: owner/repo@ref` (with optional subpath). Docker/local refs are skipped.
_USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)['\"]?")
_PERMS_RE = re.compile(r"^\s*permissions:\s*(.*)$")
# actionlint -oneline emits `path:line:col: message [rule]`. Anything else on
# that stream is actionlint talking about itself, not about the workflow.
_ACTIONLINT_RE = re.compile(r"^([^\s:]+:\d+:\d+):\s+\S")


def _workflow_files(repo: str) -> list[str]:
    out = []
    wf = os.path.join(repo, ".github", "workflows")
    if os.path.isdir(wf):
        for fn in sorted(os.listdir(wf)):
            if fn.endswith((".yml", ".yaml")):
                out.append(os.path.join(wf, fn))
    return out


def _composite_actions(repo: str) -> list[str]:
    out = []
    base = os.path.join(repo, ".github", "actions")
    if os.path.isdir(base):
        for root, _dirs, files in os.walk(base):
            for fn in files:
                if fn in ("action.yml", "action.yaml"):
                    out.append(os.path.join(root, fn))
    for fn in ("action.yml", "action.yaml"):
        p = os.path.join(repo, fn)
        if os.path.isfile(p):
            out.append(p)
    return out


def _scan_pins(path: str, repo: str, r: Result) -> None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as e:
        r.add(Finding(what=f"cannot read workflow: {e}", where=path, severity="invalid"))
        return

    rel = os.path.relpath(path, repo)
    for i, ln in enumerate(lines, 1):
        m = _USES_RE.match(ln)
        if not m:
            continue
        ref = m.group(1)
        if ref.startswith(("./", "../", "docker://")):
            continue  # local or docker action, no SHA to pin
        if "@" not in ref:
            r.add(
                Finding(
                    what="action used with no ref at all",
                    where=f"{rel}:{i}",
                    detail=ref,
                    fix="pin to a full 40-char commit SHA",
                )
            )
            continue
        _name, _, pin = ref.rpartition("@")
        if not _SHA_RE.match(pin):
            r.add(
                Finding(
                    what="third-party action pinned to a mutable tag, not a commit SHA",
                    where=f"{rel}:{i}",
                    detail=ref,
                    fix=f"pin to the 40-hex SHA: {_name}@<sha>  # {pin}",
                )
            )


def _scan_permissions(path: str, repo: str, r: Result) -> None:
    rel = os.path.relpath(path, repo)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return
    if not any(_PERMS_RE.match(ln) for ln in text.splitlines()):
        r.add(
            Finding(
                what="workflow declares no permissions block - inherits the repo default token scope",
                where=rel,
                fix="add `permissions: {}` at the top and let each job opt in to what it needs",
            )
        )


def check(
    repo: str,
    changed: list[str] | None = None,
    require_sast: bool = False,
    audit: bool = True,
) -> Result:
    r = Result(check=CHECK)

    if not os.path.isdir(repo):
        return Result.invalid(CHECK, f"no such repo path: {repo}")

    wfs = _workflow_files(repo)
    acts = _composite_actions(repo)
    r.data["workflows"] = [os.path.relpath(p, repo) for p in wfs]

    # No workflows is NOT "nothing to audit" - a repo with no CI can still ship
    # a vulnerable requirements.txt. The dependency pass below runs regardless.
    if not wfs and not acts:
        r.note("no GitHub Actions workflows in this repo")

    for p in wfs + acts:
        _scan_pins(p, repo, r)
    for p in wfs:
        _scan_permissions(p, repo, r)

    # ---- delegate the semantics ------------------------------------------
    sast_ran = []
    if wfs and have("actionlint"):
        p = run(["actionlint", "-no-color", "-oneline"], cwd=repo, timeout=180)
        # A scanner only counts as having RUN if it actually analyzed the
        # workflows. Crediting a timeout - or a config error - suppressed both
        # --require-sast and the no-SAST fallback, and the audited repo owns
        # `.github/actionlint.yaml`, so a repo could ship one junk config file
        # and buy itself a CLEAN. The input disabling the audit must never come
        # from the thing being audited. 💀
        #
        # actionlint exits 3 for BOTH real findings and "no project was found",
        # so the exit code cannot decide this; the output has to.
        al_findings = [ln.strip() for ln in p.text().splitlines() if _ACTIONLINT_RE.match(ln.strip())]
        al_self = [
            ln.strip() for ln in p.text().splitlines()
            if "no project was found" in ln or "could not parse" in ln or ln.strip().startswith("actionlint:")
        ]
        if p.timed_out:
            r.note("actionlint timed out - NOT counted as a scanner that ran")
        elif al_findings or (p.code == 0 and not al_self):
            sast_ran.append("actionlint")
        else:
            # Not credited. The verdict is carried by sast_ran staying empty,
            # which drives the judgment Finding / --require-sast gate below -
            # so a repo cannot disable the audit by shipping a junk config,
            # and a plain non-git directory does not become a hard error.
            r.note(
                f"actionlint exited {p.code} WITHOUT linting: "
                + ((al_self[0] if al_self else p.text().strip()[-200:]) or "(no output)")
            )
        # actionlint exits 1 when it has findings; that is data, not an error.
        # But its OWN diagnostics ("no project was found in any parent
        # directories...") come out on the same stream, and reporting those as
        # security findings is how a tool earns a mute. Only accept the real
        # `file:line:col: message` shape. XX
        saw_real = False
        for ln in ([] if p.timed_out else p.text().splitlines()):
            ln = ln.strip()
            if not ln:
                continue
            m = _ACTIONLINT_RE.match(ln)
            if m:
                saw_real = True
                r.add(
                    Finding(
                        what="actionlint reported a workflow issue",
                        where=m.group(1),
                    ).with_foreign("actionlint", ln)
                )
            elif "no project was found" in ln or ln.startswith("actionlint:"):
                r.note(f"actionlint: {ln}")
        if not saw_real and p.code not in (0, 1):
            r.note(f"actionlint exited {p.code} with no parseable findings")
    if wfs and have("zizmor"):
        p = run(
            ["zizmor", "--offline", "--min-severity=low", "--format=plain", ".github/workflows/"],
            cwd=repo,
            timeout=300,
        )
        # zizmor: 0 = clean, 14 = findings. Anything else (1 = invalid config,
        # which the AUDITED repo controls via .github/zizmor.yml) means it did
        # not scan, and must not be credited as a scanner that ran.
        if p.timed_out:
            r.note("zizmor timed out - NOT counted as a scanner that ran")
        elif p.code in (0, 14):
            sast_ran.append("zizmor")
            # Parse in the RAN branch. This loop briefly lived under `else`,
            # which meant findings were read only when zizmor FAILED and
            # silently dropped on exit 14 - the exact false-CLEAN this module
            # exists to prevent, reintroduced during a refactor. XX
            for ln in p.text().splitlines():
                s = ln.strip()
                if re.match(r"^(error|warning|note)\[", s):
                    r.add(
                        Finding(what="zizmor reported a workflow issue").with_foreign("zizmor", s)
                    )
        else:
            r.note(f"zizmor exited {p.code} WITHOUT scanning: " + (p.text().strip()[-200:] or "(no output)"))
    r.data["sast"] = sast_ran

    if require_sast and not sast_ran:
        return r.fail(
            "--require-sast given but no Actions SAST produced an analysis (not installed, or exited without scanning)",
            "pipx install zizmor==1.25.2 && brew install actionlint",
        )
    if wfs and not sast_ran:
        # Reporting CLEAN here would mean "we looked" when only two greps ran.
        # The tool's own rule: a check that could not run must never look like
        # a check that passed. So say so in the exit code, not in a note. >:[
        r.add(
            Finding(
                what="no Actions SAST actually ran - only pin/permission greps did, semantics unchecked",
                detail="zizmor and actionlint decide template injection, credential persistence and token scope; neither produced an analysis (not installed, or exited without scanning - see notes)",
                fix="pipx install zizmor==1.25.2 && brew install actionlint, and check .github/zizmor.yml / .github/actionlint.yaml parse",
                severity="judgment",
            )
        )

    # ---- dependency advisories on your own manifests ---------------------
    if audit:
        req = [
            f for f in ("requirements.txt", "requirements-optional.txt", "requirements-dev.txt")
            if os.path.isfile(os.path.join(repo, f))
        ]
        if req and have("pip-audit"):
            argv = ["pip-audit", "--format", "json", "--progress-spinner", "off"]
            for f in req:
                argv += ["-r", f]
            p = run(argv, cwd=repo, timeout=600)
            if p.timed_out:
                r.add(Finding(what="pip-audit timed out - dependencies NOT scanned", severity="invalid"))
            else:
                # Structured output. Grepping GHSA|PYSEC|CVE out of prose meant
                # a formatting change silently emptied the findings list.
                try:
                    doc = json.loads(p.out) if p.out.strip() else {}
                except ValueError:
                    doc = None
                if doc is None:
                    if p.code != 0:
                        r.add(
                            Finding(
                                what="pip-audit failed and its output could not be parsed",
                                detail=p.text().strip()[-300:],
                                severity="invalid",
                            )
                        )
                else:
                    for dep in doc.get("dependencies", []) or []:
                        for v in dep.get("vulns", []) or []:
                            ids = ", ".join([v.get("id", "?")] + (v.get("aliases") or [])[:2])
                            fixes = ", ".join(v.get("fix_versions") or []) or "no fixed version published"
                            r.add(
                                Finding(
                                    what="vulnerable python dependency",
                                    where=f"{dep.get('name', '?')}=={dep.get('version', '?')}",
                                    fix=f"upgrade to: {fixes}",
                                ).with_foreign("pip-audit", ids)
                            )
        elif req:
            r.add(
                Finding(
                    what="python requirements present but pip-audit is not installed - dependencies UNSCANNED",
                    detail=", ".join(req),
                    fix="pipx install pip-audit==2.10.0",
                    severity="judgment",
                )
            )

        has_lock = os.path.isfile(os.path.join(repo, "package-lock.json"))
        if has_lock and not have("npm"):
            r.add(
                Finding(
                    what="package-lock.json present but npm is not installed - dependencies UNSCANNED",
                    fix="brew install node",
                    severity="judgment",
                )
            )
        if has_lock and have("npm"):
            # --json, not a grep over prose: npm prints the SINGULAR
            # "1 critical severity vulnerability" for exactly one, and the
            # human format changes between majors.
            p = run(["npm", "audit", "--json", "--audit-level=high"], cwd=repo, timeout=420)
            if p.timed_out:
                r.add(Finding(what="npm audit timed out - dependencies NOT scanned", severity="invalid"))
            else:
                try:
                    doc = json.loads(p.out) if p.out.strip() else {}
                except ValueError:
                    doc = None
                if doc is None:
                    if p.code != 0:
                        r.add(
                            Finding(
                                what="npm audit failed and its output could not be parsed",
                                detail=p.text().strip()[-300:],
                                severity="invalid",
                            )
                        )
                else:
                    meta = (doc.get("metadata") or {}).get("vulnerabilities") or {}
                    high = int(meta.get("high", 0) or 0) + int(meta.get("critical", 0) or 0)
                    if high:
                        names = sorted((doc.get("vulnerabilities") or {}).keys())[:8]
                        r.add(
                            Finding(
                                what=f"npm audit: {high} high/critical advisory(ies)",
                                fix="npm audit fix, or pin the transitive dep",
                            ).with_foreign("npm audit", ", ".join(names))
                        )

    # ---- route, do not re-lens -------------------------------------------
    if changed:
        touched = [c for c in changed if "/.github/workflows/" in f"/{c}" or c.startswith(".github/workflows/") or os.path.basename(c) in ("action.yml", "action.yaml")]
        if touched:
            r.data["route"] = {"gate": "gha-security-review", "workflowFiles": touched}
            r.add(
                Finding(
                    what="this change touches CI workflow files - run the adversarial GHA review",
                    detail=", ".join(touched[:8]),
                    fix="Workflow {name:'gha-security-review', args:{workflowFiles:[...], repoPath:'%s'}}" % repo,
                    severity="judgment",
                )
            )

    if not r.findings:
        scope_txt = ", ".join(["pins", "permissions"] + sast_ran)
        r.note(f"{len(wfs)} workflow(s) clean under: {scope_txt}")
    return r
