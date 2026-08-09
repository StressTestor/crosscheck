# architecture — crosscheck

## project overview

stdlib-only Python CLI that runs the deterministic security pre-flight checks
Joe already does by hand across three lanes: odysseus, general open-source
contribution, and bug bounties. it is the *mechanical* half only. anything that
needs a model routes to an existing gate or to the `crosscheck-adjudicate`
workflow.

designed from a mining pass over 2,511 indexed agent sessions (2,142 Claude
local + 363 codex + 6 kimi, plus 291 Claude sessions on the zo box). 49
candidate checks were proposed by 8 lane miners, 32 survived an adversarial
refute pass, and an architect critique then cut 6 modules that did not hold up
against the machine. what shipped is what survived both.

## stack and dependencies

| layer | technology | version |
|-------|------------|---------|
| language | Python | 3.11+ (developed on 3.14.6) |
| deps | stdlib only | — |
| tests | unittest | stdlib |
| optional: Actions SAST | zizmor / actionlint | 1.25.2 / 1.7.12 |
| optional: dep advisories | pip-audit / npm | 2.10.0 / any |
| optional: secret scanning | gitleaks | any |

optional tools are *delegated to, never reimplemented*. when one is missing the
affected check degrades to a documented weaker form, or to `INVALID` under
`--require-sast` — never to a silent pass.

versions match what odysseus CI pins, so a local run reproduces the CI verdict.

## directory structure

```
crosscheck/
  crosscheck.py           # dispatcher + profiles; the only entrypoint
  cc/
    result.py             # Finding/Result, the four exit codes, worst-of, --json envelope
    run.py                # argv-only subprocess runner (no shell, always a timeout)
    gitutil.py            # git helpers; resolves the REAL default branch
    usage.py              # usage log + `cc decay` (deletes dead checks)
    checks/
      baseline.py         # dirty-vs-clean failing-set diff
      prbranch.py         # replayed/stray commits vs upstream default
      ci.py               # Actions pins/permissions + SAST delegation + routing
      scope.py            # suffix-anchored host-in-scope matcher
      secrets.py          # aims gitleaks at drafts/evidence/vault-bound notes
      vrp.py              # program eligibility BEFORE PoC effort
      enforce.py          # RUNS a local target: declared-vs-applied control parity
  policies/               # hand-transcribed program policy JSON (see its README)
  specs/                  # hand-written enforce specs + fixtures (see its README)
                          #   .redruns.json = proof each control has been seen to FAIL
  tests/                  # unittest; 134 tests, incl. suite-wide detector + provenance invariants
  install.sh              # ~/.local/bin/cc launcher + optional pre-push hook
```

agent surface, outside this repo:

```
~/.claude/skills/crosscheck/SKILL.md          # when to run what, how to read exit codes
~/.claude/workflows/crosscheck-adjudicate.js  # the judgment half (5 lenses + adjudicator)
~/.claude/workflows/mine-sec-suite.js         # the mining pass that produced this design
```

## key patterns

**foreign text never lands in `what`.** `--json` is read by agents, so text
produced by the thing under test — a scanner's output, a foreign test id, a
probe's stderr — goes in a separate `foreign` field, capped at 600 bytes and
tagged `{source, bytes, truncated}` at the single serialisation point in
`result.py`. `what`/`detail`/`fix` are always crosscheck's own words. Human
output prefixes every foreign line with `|` so a multi-line payload cannot walk
out of its quoting and impersonate a verdict. Uncapped, unlabelled repo text
flowing into the same field crosscheck writes its verdicts into is a
prompt-injection channel wearing a trusted envelope.

**four exit codes, not two.** `0 CLEAN / 2 FINDING / 3 INVALID / 4 JUDGMENT`.
`1` is reserved so an uncaught traceback can never read as a verdict.
worst-of aggregation is `3 > 2 > 4 > 0` — INVALID is loudest because a check
that could not run prints the same nothing as a clean one.

**delegate, don't reimplement.** zizmor/actionlint own Actions semantics,
gitleaks owns secret detection, pip-audit/npm own dependency advisories.
crosscheck's value is aiming them at the things nobody aims them at, and
reading their exit codes honestly — including refusing to credit one that
analyzed nothing.

**never guess in the permissive direction.** no policy for a program is
`INVALID`, never "probably in scope". an unknown vuln class is `JUDGMENT`,
never `CLEAN`. absence of a rule is not permission.

**staleness is a nudge, not a wall.** an old policy transcript is `JUDGMENT`,
not `INVALID`. a rule that hard-stops a pipeline on a cache age gets routed
around within a week, and a rule routed around once is gone.

**data over code.** `policies/` are versioned JSON. adding a program is a data
change with a test, not a code change.

**one module executes the target, and it says so.** Every check except
`enforce` reads artifacts and never runs the thing under test. `cc enforce`
launches a LOCAL target and feeds it probes that should be refused — invoking
that subcommand IS the consent. It still never touches a remote host, and
`--dry-run` prints the exact argv first. It exists because "control declared,
control not applied, success reported anyway" recurred four times across two
independent targets (codecalc #61/#62, and two of crosscheck's own review
blockers), and reading code catches that class only sometimes.

**the suite obeys its own rules.** `run.py` is argv-only with no `shell=True`,
because `ci` flags shell sinks in other people's code.

## exit-code table

| code | name | meaning |
|------|------|---------|
| 0 | CLEAN | nothing to act on |
| 2 | FINDING | named problem with a fix |
| 3 | INVALID | could not evaluate — **never** treat as clean |
| 4 | JUDGMENT | needs a model or a human; route it |
| 1 | *(reserved)* | uncaught crash only |

## environment variables

| var | purpose |
|-----|---------|
| `CROSSCHECK_POLICIES` | override the `policies/` directory |
| `CROSSCHECK_IDENTITIES` | extra emails that count as "you" for `pr-branch` |
| `CROSSCHECK_USAGE_LOG` | override the decay log path |
| `CROSSCHECK_BIN_DIR` | where `install.sh` puts the `cc` launcher |

## commands

| action | command |
|--------|---------|
| install | `./install.sh` (adds `~/.local/bin/cc`) |
| install pre-push in a repo | `./install.sh --hook <repo>` |
| run tests | `python3 -m unittest discover -s tests -t .` |
| list checks | `cc checks` |
| find dead checks | `cc decay` |

## CI

`.github/workflows/ci.yml`. Runs the suite on python 3.11 and 3.13 (proving the
floor this doc claims rather than asserting it), then points crosscheck at
itself: `cc ci . --require-sast`, `cc secrets . --history`, and a step that
**requires the deliberately-bad fixture under `specs/fixtures/` to still fail**
— a self-audit that only ever passes proves nothing. Actions are pinned to full
SHAs and the token starts at `permissions: {}`, because this repo flags others
for exactly those.

## gotchas

| problem | cause | fix |
|---------|-------|-----|
| `cc` exits 3 saying "suite not found" | `/Volumes/T7` unmounted | mount the drive. the launcher is a stub on the main disk so this is one sentence instead of a stack trace |
| `pr-branch` reports hundreds of stray commits | the resolved base is wrong | `git remote set-head <remote> --auto`, or pass `--base`. the tool refuses to guess `main` |
| `ci` finds nothing on a bad repo | no SAST installed | `pipx install zizmor==1.25.2 && brew install actionlint`, or pass `--require-sast` to make the gap loud |
| `baseline` says INVALID on a clean tree | nothing to compare | that is correct; use `verify-change` for a committed change |
| `baseline` refuses over a dirty submodule | `git stash` does not recurse into submodules | commit or stash inside the submodule first — the alternative is running your suite over work nothing can restore |
| `ci` says a scanner "exited WITHOUT scanning" | malformed `.github/zizmor.yml` / `.github/actionlint.yaml`, or not a git repo | fix the config. it is deliberately not credited as a scan — the audited repo must not be able to disable its own audit |
| `baseline` says changes are in the stash | `git stash pop` hit a conflict | resolve it by hand; the tool reports loudly rather than swallowing it |
| `scope`/`vrp` INVALID for a program | no policy file | `cp policies/_template.json policies/<program>.json` and transcribe by hand |
| `cc enforce` says UNTESTABLE | the spec has no `refused_when`, or it did not resolve | a refusal must be recognisable; exit code alone is not enough |
| `enforce` says ENFORCED but exits JUDGMENT | that control has never been seen to FAIL, so its rule is unproven | break it on a throwaway copy and `cc enforce <spec> --record-red`. see `specs/README.md` |
| a `vrp` ruling looks wrong | policy is a hand transcript | every ruling prints its source quote — check the transcription, then the page |
| actionlint noise about "no project found" | actionlint talking about itself outside a repo | already filtered; only `file:line:col:` findings are reported |

## what this deliberately does NOT do

each of these is owned by something that already exists, and duplicating it
would mean two answers that drift:

| not here | owned by |
|----------|----------|
| PR diff review | `presubmission-gate` |
| build / repro / RED / suite proof | `verify-change`, `adv-gate` |
| duplicate-risk scoring | `dupe-gate` |
| the six adversarial GHA lenses | `gha-security-review` |
| filesystem path boundaries | `scopeguard` (`/Volumes/T7/scopeguard`) |
| running a repo's own PR-description bot | the repo's CI, which already runs it |
| running recon | `scopecreep` |
| repo liveness / anti-AI-policy scan | `oss-scout-nonsec` |
| touching a **bounty/scan target** | no subcommand ever sends a packet to a target host. two documented exceptions, both to infrastructure you already trust: `pr-branch` may run `git ls-remote` against your configured remote (pass `--base` to avoid it), and `cc ci`'s dependency audit queries the npm/PyPI advisory APIs (pass `--no-audit` to avoid it) |

also deliberately cut after the design critique, with reasons in the git
history: a codex prior-scan index (its artifacts live in a purged `$TMPDIR`),
a rules-of-engagement manifest (one observed instance), an IP-classifier
interpreter matrix (ran once, every interpreter agreed), and a guard-corpus
regression runner (ghost blocks its own tester from inside an agent).

## last updated

2026-08-09 — 7 checks, 134 tests, skill + adjudicate workflow, own CI.
`enforce` added after the codecalc audit showed declared-vs-applied recurring across targets.
Four adversarial review rounds + marko applied (32 defects fixed, incl. 10 false-CLEAN
paths, a false-INELIGIBLE in `vrp`, and one unrecoverable data-loss path in `baseline`).

**Known, accepted limits** (documented rather than papered over):
- **`cc enforce` executes probes in a blind spot the local PreToolUse guard
  cannot see.** sentinel/ghost inspects the *agent's Bash tool* command line;
  enforce's probes are subprocess argv from inside python, so their argv is
  never shown to it. Verified: a probe attempting to read `/etc/shadow` reached
  the target and ran, in a session where the same guard blocked the agent five
  separate times for less (`specs/_guard-canary.json` is the standing
  regression). Mitigation is **instrumentation, not containment**: every probe
  is put past `sentinel check` as a NON-BLOCKING oracle and appended to a
  hash-chained log at `~/.crosscheck/probe-audit.jsonl` before it fires, and an
  unwritable log refuses the run. That is tamper-evidence and legibility, **not
  an authorization boundary** — it runs as the same user who could rewrite the
  file. An agent that authors a hostile spec *and commits it* defeats it
  entirely; ordinary review of spec diffs is the only control on that case.
- **`specs/.redruns.json` is a discipline record, not a security boundary.**
  Anyone who can edit a spec can edit it. It exists to stop honest mistakes.
- `ci`'s `uses:`/`permissions:` greps are line-oriented, not YAML-aware; a
  `uses:` string inside a `run: |` block can be misread. zizmor/actionlint are
  the YAML-aware authority and run alongside.
- the payout `floor` for `google-oss-vrp` was transcribed from Google-domain
  search summaries, **not machine-read** from the published table (both primary
  pages are JS-rendered and return title-only to a fetch). Re-verify before
  letting a `$0` verdict talk you out of real work.
