The code matters more than the lack of real-task use right now. Dogfooding would have exposed several problems, but today the tool can manufacture CLEAN after a scanner failed, after a foreign commit vouched for itself, after a misspelled VRP tier, and even when `enforce` ran nothing. Fix those before treating the 255 construction runs as evidence.

The single highest-value change is in `secrets`: stop deleting findings after the scanner has already classified them. Then delete `scope`; its one real policy cannot be represented by its matcher.

## 1. highest-value improvement

Change the `secrets` allow-list from post-hoc finding deletion to source-level suppression of parsed secret rows.

Currently, after a scan, every finding whose `where` resolves to an allowed path is removed, regardless of whether it is a secret, a timeout, a launch failure, or malformed scanner output. The code then resets the result to CLEAN and rebuilds it from whatever survived: [cc/checks/secrets.py:168-189](/Volumes/T7/crosscheck/cc/checks/secrets.py:168).

I reproduced this exact outcome with a mocked gitleaks timeout on an allowed file:

```text
code=0
findings=[]
notes=[
  "allowed (submission target): /evidence/report.md",
  "gitleaks found nothing across 1 path(s)"
]
```

That directly reverses the result contract. The scanner path correctly added an INVALID; the allow-list silently erased it.

The concrete change:

- Pass the normalized allow-file set into `_gitleaks_dir()` at [cc/checks/secrets.py:36](/Volumes/T7/crosscheck/cc/checks/secrets.py:36).
- While iterating parsed gitleaks rows at [cc/checks/secrets.py:56-71](/Volumes/T7/crosscheck/cc/checks/secrets.py:56), resolve only that row’s reported file against the scanned root. If, and only if, that file is allow-listed, skip adding that one `possible secret` finding.
- Require allow targets to be regular files under one of the scanned roots. An absolute directory should not be an allow target.
- Delete the entire post-scan pruning and code-recomputation block at [cc/checks/secrets.py:168-189](/Volumes/T7/crosscheck/cc/checks/secrets.py:168). Scanner failures and history findings must never be removable by `--allow`.
- When gitleaks returns the configured finding code `2` but produces no nonempty, parseable report, preserve the evidence that gitleaks said it found something and escalate to INVALID. The current code accepts that as zero findings at [cc/checks/secrets.py:44-84](/Volumes/T7/crosscheck/cc/checks/secrets.py:44).

The discriminating tests should be:

- allowed secret row only → CLEAN;
- timeout on allowed file → INVALID;
- fatal exit on allowed file → INVALID;
- history finding under an allowed path → FINDING;
- exit 2 plus empty report → INVALID containing a generic “gitleaks reported findings but emitted no usable redacted report” finding.

This one change removes both a false-CLEAN and an authorization mistake: `--allow report.md` would mean “this known report may quote a secret,” not “suppress anything the scanner says about this path.”

## 2. correctness defects

These are confirmed or directly reachable verdict failures, ordered roughly by consequence.

| check | defect | current false result | concrete correction |
|---|---|---|---|
| `secrets` | The directory scanner treats gitleaks exit `2` plus an absent or empty report as zero findings because only codes outside `(0, 2)` are rejected: [cc/checks/secrets.py:44-84](/Volumes/T7/crosscheck/cc/checks/secrets.py:44). | CLEAN when gitleaks explicitly said FINDING. | Exit 2 requires at least one valid redacted report row; otherwise retain a generic finding and escalate INVALID. |
| `secrets --history` | Only exit `2` is handled. Timeout, launch failure, and every other nonzero exit are ignored: [cc/checks/secrets.py:149-159](/Volumes/T7/crosscheck/cc/checks/secrets.py:149). I reproduced a history timeout returning CLEAN plus “gitleaks found nothing.” | CLEAN when history was not scanned. | Handle `0=CLEAN`, `2=FINDING`, timeout/anything else=`INVALID`. |
| `ci` | Empty scanner stdout becomes `{}`. Once that empty object “parses,” the nonzero exit is ignored for both pip-audit and npm: [cc/checks/ci.py:265-289](/Volumes/T7/crosscheck/cc/checks/ci.py:265), [cc/checks/ci.py:317-340](/Volumes/T7/crosscheck/cc/checks/ci.py:317). I reproduced failed pip-audit and npm calls returning code 0 with no findings. | CLEAN when the dependency scan found advisories or failed operationally. | Validate exit semantics and JSON schema together. Empty objects and error envelopes are INVALID. A vulnerability exit is accepted only alongside the expected dependency/advisory structure. |
| `ci` | The scanner invocations still honor configuration and ignore rules owned by the audited repository. The actionlint invocation supplies no neutral `-config-file`, and zizmor supplies neither `--no-config` nor `--no-ignores`: [cc/checks/ci.py:155-179](/Volumes/T7/crosscheck/cc/checks/ci.py:155), [cc/checks/ci.py:197-216](/Volumes/T7/crosscheck/cc/checks/ci.py:197). The code guards malformed configuration, but a valid ignore-everything configuration can still suppress analysis. | Potential CLEAN when the audited repo validly disables findings. | Run the security gate with neutral configuration, `zizmor --no-config --no-ignores`, and an explicit neutral actionlint config. Report repository suppressions separately if they are useful evidence. |
| `pr-branch` | A commit-controlled `Co-authored-by` trailer is treated as identity proof. Any foreign committer can put the operator’s email in its body; `_coauthors()` trusts it at [cc/gitutil.py:168-194](/Volumes/T7/crosscheck/cc/gitutil.py:168), and the stray filter exempts it at [cc/checks/prbranch.py:143-150](/Volumes/T7/crosscheck/cc/checks/prbranch.py:143). I reproduced a Mallory-authored commit returning CLEAN after claiming the operator as coauthor. | CLEAN when a foreign commit self-asserts the operator’s identity. | Never use an unsigned commit-body trailer to suppress a foreign-author finding. Present it as foreign evidence for adjudication or require an explicit SHA allow-list/signed provenance. |
| `pr-branch` | The module claims anything outside the fix surface is a stray at [cc/checks/prbranch.py:10-12](/Volumes/T7/crosscheck/cc/checks/prbranch.py:10), but the implementation checks only authorship and a count ceiling. Any unrelated operator-authored commits under the ceiling are declared clean at [cc/checks/prbranch.py:146-177](/Volumes/T7/crosscheck/cc/checks/prbranch.py:146). | CLEAN outside the advertised detection scope. | Either add deterministic patch-equivalence/surface evidence, or narrow the command’s claim to “foreign-author or oversized branch detector.” Do not imply general stray detection. |
| `vrp` | Supplied tiers are never validated against `floor.tiers`. Any unmatched string is called “not on the unrewarded list”: [cc/checks/vrp.py:119-133](/Volumes/T7/crosscheck/cc/checks/vrp.py:119). The shipped policy declares only OT0–OT3 at [policies/google-oss-vrp.json:18-23](/Volumes/T7/crosscheck/policies/google-oss-vrp.json:18). `OT22` currently returns CLEAN and “proceed, PoC first.” | CLEAN for a typo whose intended OT2 truth is FINDING. | Normalize and require tier membership. Unknown tier is INVALID or JUDGMENT, never rewarded-by-absence. |
| `enforce` | `_refused()` accepts exit-code-only rules despite the module saying exit code alone is never enough: [cc/checks/enforce.py:250-277](/Volumes/T7/crosscheck/cc/checks/enforce.py:250). With a ledger entry, a missing executable returning 127 can satisfy `exit_code_not_in:[0]` and become CLEAN/ENFORCED. | CLEAN when the target never executed. | Reject 126/127 before refusal matching. Require at least one non-exit refusal signal. |
| `enforce` | `expect:"allowed"` is implemented as merely `not refused`: [cc/checks/enforce.py:450-474](/Volumes/T7/crosscheck/cc/checks/enforce.py:450). A crash or missing target whose output does not match the refusal marker can therefore count as successfully allowed. | CLEAN when an allowed-case probe crashed. | Add a separate required `allowed_when` predicate. Absence of refusal is not proof of successful allowance. |
| `enforce` | Any `expect` value other than the exact string `"refused"` is initially treated like allowed at [cc/checks/enforce.py:375-377](/Volumes/T7/crosscheck/cc/checks/enforce.py:375) and [cc/checks/enforce.py:450](/Volumes/T7/crosscheck/cc/checks/enforce.py:450). I reproduced `expect:"alllowed"` returning CLEAN/ENFORCED with an existing ledger proof. | CLEAN for malformed spec data. | Validate `expect in {"refused", "allowed"}` before executing anything; anything else is INVALID. |
| `enforce --only` | Unknown requested names are silently ignored if at least one other requested control matches. Only the all-miss case is rejected: [cc/checks/enforce.py:365-374](/Volumes/T7/crosscheck/cc/checks/enforce.py:365), [cc/checks/enforce.py:522-527](/Volumes/T7/crosscheck/cc/checks/enforce.py:522). | CLEAN after silently skipping a requested control. | Compute `wanted - matched` and return INVALID if nonempty. |
| `enforce --dry-run` | Dry-run records `"DRY-RUN"` verdicts but leaves the result at code 0: [cc/checks/enforce.py:390-393](/Volumes/T7/crosscheck/cc/checks/enforce.py:390). The live `crosscheck-self --dry-run --json` returned `"status":"CLEAN"` despite executing no control. | CLEAN when nothing was evaluated. | Make dry-run a non-verdict output mode, or JUDGMENT. It cannot be CLEAN under the project’s own doctrine. |
| `baseline` | Ignored paths are explicitly recognized as unstashed, but only a note is emitted: [cc/checks/baseline.py:122-129](/Volumes/T7/crosscheck/cc/checks/baseline.py:122). The dirty suite runs at line 131, its ignored artifacts survive the stash, and the clean suite reuses them at line 173. | A newly introduced failure can reproduce from dirty-generated cache/build/database state in the “clean” run, be labelled pre-existing at [cc/checks/baseline.py:218-249](/Volumes/T7/crosscheck/cc/checks/baseline.py:218), and return CLEAN. | Isolate both runs in separate disposable worktrees/build roots, or return INVALID when the run changes ignored state. A warning is not enough for an attribution check. |

I did not find a compelling case where an unparseable underlying finding should be force-labelled FINDING instead of INVALID. When the tool knows a scanner reported something but cannot safely recover the details, the right aggregate remains INVALID because it outranks FINDING. The defect is dropping that evidence and returning CLEAN.

### foreign text still reaches trusted fields

The documented invariant says `what`, `detail`, and `fix` are crosscheck’s own words and target text appears only under the capped, tagged `foreign` field: [ARCHITECTURE.md:72-80](/Volumes/T7/crosscheck/ARCHITECTURE.md:72). That invariant is not true.

Concrete counterexamples:

- Workflow-controlled `uses:` values enter trusted `detail` and `fix`: [cc/checks/ci.py:73-107](/Volumes/T7/crosscheck/cc/checks/ci.py:73).
- Raw actionlint/zizmor failure output enters uncapped `notes`: [cc/checks/ci.py:192-195](/Volumes/T7/crosscheck/cc/checks/ci.py:192), [cc/checks/ci.py:228](/Volumes/T7/crosscheck/cc/checks/ci.py:228).
- Raw pip-audit/npm failure output enters trusted `detail`: [cc/checks/ci.py:272-276](/Volumes/T7/crosscheck/cc/checks/ci.py:272), [cc/checks/ci.py:324-328](/Volumes/T7/crosscheck/cc/checks/ci.py:324).
- Commit-controlled author, email, and subject enter trusted `detail` and `fix`, while the complete foreign commit objects are stored uncapped in `data`: [cc/checks/prbranch.py:151-173](/Volumes/T7/crosscheck/cc/checks/prbranch.py:151).
- Gitleaks-controlled paths and error output enter trusted `where` and `detail`: [cc/checks/secrets.py:63-73](/Volumes/T7/crosscheck/cc/checks/secrets.py:63), [cc/checks/secrets.py:84-91](/Volumes/T7/crosscheck/cc/checks/secrets.py:84), [cc/checks/secrets.py:149-158](/Volumes/T7/crosscheck/cc/checks/secrets.py:149).
- Baseline correctly puts introduced test IDs under `foreign`, but pre-existing/fixed test IDs are interpolated directly into `notes`: [cc/checks/baseline.py:231-237](/Volumes/T7/crosscheck/cc/checks/baseline.py:231).
- `scope` accepts arbitrary bracket contents as an “IPv6 literal” without validating IPv6 at [cc/checks/scope.py:58-60](/Volumes/T7/crosscheck/cc/checks/scope.py:58), then puts it in `where`. A newline-bearing input emitted an unquoted extra line in human output at [cc/checks/scope.py:173-176](/Volumes/T7/crosscheck/cc/checks/scope.py:173).

There is also no 600-byte cap. `with_foreign()` slices Python characters and stores `len(raw)` as bytes: [cc/result.py:90-99](/Volumes/T7/crosscheck/cc/result.py:90). Six hundred emoji are roughly 2,400 UTF-8 bytes while the envelope reports 600 and `truncated:false`.

The correction should be API-level, not another convention:

- Any repository, scanner, test, probe, policy-page, or user-derived value must be a `ForeignText`/provenance value.
- `Finding` locations and diagnostics need the same quarantine as message bodies.
- `Result.notes` and `Result.data` need either trusted-only typed constructors or explicit foreign subfields.
- Human rendering must prefix every line of every foreign value.
- Cap `text.encode("utf-8")`, then decode the bounded byte sequence safely.

## 3. what to delete

Delete `scope`.

Its apparent one-program coverage is actually zero-program coverage.

The only non-template policy stores GitHub owner paths:

```json
"github.com/google"
"github.com/GoogleCloudPlatform"
```

Those are at [policies/google-oss-vrp.json:7-8](/Volumes/T7/crosscheck/policies/google-oss-vrp.json:7). But `normalize_host()` deliberately discards everything after the first slash at [cc/checks/scope.py:48-65](/Volumes/T7/crosscheck/cc/checks/scope.py:48), and `host_matches()` then performs DNS-host equality/suffix matching at [cc/checks/scope.py:68-75](/Volumes/T7/crosscheck/cc/checks/scope.py:68).

I ran the shipped policy:

```text
https://github.com/google/osv-scalibr
    -> normalized to github.com
    -> FINDING / OUT

https://github.com/GoogleCloudPlatform/go-cloud
    -> normalized to github.com
    -> FINDING / OUT
```

The unmatched branch is [cc/checks/scope.py:158-180](/Volumes/T7/crosscheck/cc/checks/scope.py:158). So the author’s hypothesis is too generous: `scope` is not inert except for one program. It has no usable real policy.

The deletion is specific:

- Remove the import and `ALL_CHECKS` entry at [crosscheck.py:27-29](/Volumes/T7/crosscheck/crosscheck.py:27).
- Remove the parser at [crosscheck.py:94-96](/Volumes/T7/crosscheck/crosscheck.py:94).
- Remove dispatch at [crosscheck.py:142-143](/Volumes/T7/crosscheck/crosscheck.py:142).
- Delete `cc/checks/scope.py`.
- Delete [tests/test_scope.py](/Volumes/T7/crosscheck/tests/test_scope.py:1).
- Delete the synthetic scope detector invariant at [tests/test_invariants.py:95-105](/Volumes/T7/crosscheck/tests/test_invariants.py:95).
- Move `load_policy()` and `policy_dir()` into `vrp.py` or a small policy-data helper because [cc/checks/vrp.py:32](/Volumes/T7/crosscheck/cc/checks/vrp.py:32) currently imports them from `scope`.

Do not turn it into a generalized URL/repository matcher to save it. That is new machinery for one hand-transcribed program. `vrp` has realized-loss evidence; `scope` has no usable dataset.

## 4. the four accepted limits

| limit | verdict | why |
|---|---|---|
| `enforce` runs behind the PreToolUse guard | **Rationalisation.** | `load_spec()` accepts arbitrary JSON paths at [cc/checks/enforce.py:219-234](/Volumes/T7/crosscheck/cc/checks/enforce.py:219); the spec controls cwd, argv, and environment at [cc/checks/enforce.py:355-359](/Volumes/T7/crosscheck/cc/checks/enforce.py:355) and [cc/checks/enforce.py:418-424](/Volumes/T7/crosscheck/cc/checks/enforce.py:418). A Sentinel denial is reduced to a note and the command still executes at [cc/checks/enforce.py:395-424](/Volumes/T7/crosscheck/cc/checks/enforce.py:395). Clearing inherited environment variables removes one source of secrets; it does not contain filesystem, Keychain, network, or subprocess access. The log records intent, not outcome, and does not mitigate execution. Default behavior should be Sentinel denial → INVALID, with a separate explicit reviewed override, or execution inside an actual external containment boundary. |
| `.redruns.json` is a discipline record | **Acceptable in principle; defective as implemented.** | It is honest to say it does not resist someone editing both spec and ledger. But `_record_red()` swallows write errors at [cc/checks/enforce.py:112-135](/Volumes/T7/crosscheck/cc/checks/enforce.py:112), while the caller claims “recorded red run” unconditionally at [cc/checks/enforce.py:480-486](/Volumes/T7/crosscheck/cc/checks/enforce.py:480). Also, the fingerprint omits cwd and env at [cc/checks/enforce.py:86-101](/Volumes/T7/crosscheck/cc/checks/enforce.py:86), even though both affect execution at lines 355–359 and 418–424. Changing either can leave an old proof valid for a different executable behavior and turn ENFORCED into CLEAN at [cc/checks/enforce.py:452-471](/Volumes/T7/crosscheck/cc/checks/enforce.py:452). |
| CI greps are line-oriented but real linters run alongside | **Rationalisation.** | The regex matches become authoritative FINDINGs at [cc/checks/ci.py:73-125](/Volumes/T7/crosscheck/cc/checks/ci.py:73). If `uses:` appears inside a `run: |` scalar, a correct YAML-aware result cannot cancel the regex result because FINDING remains louder under [cc/result.py:44-45](/Volumes/T7/crosscheck/cc/result.py:44). “Authority runs alongside” is not mitigation when the authority cannot override the duplicate. Delete the regex findings and rely on strict, non-suppressible YAML-aware scans; absence of those scans is already non-CLEAN at [cc/checks/ci.py:231-247](/Volumes/T7/crosscheck/cc/checks/ci.py:231). |
| Google payout floor came from search summaries | **Rationalisation.** | The policy admits the weak provenance at [policies/google-oss-vrp.json:1-3](/Volumes/T7/crosscheck/policies/google-oss-vrp.json:1), but `_floor_verdict()` converts it into a normal FINDING and says “do NOT spend PoC time here” at [cc/checks/vrp.py:119-132](/Volumes/T7/crosscheck/cc/checks/vrp.py:119). Source uncertainty must affect the machine verdict. Add `"verified": false` and make matching rows JUDGMENT until primary verification, or remove those rows. A prose warning cannot repair a hard programmatic verdict. |

## 5. where the tests give false confidence

These are tests that survive the behavior they claim to prevent.

1. **The dependency-audit regression test disables dependency auditing.**

   `test_no_workflows_still_audits_dependencies` calls `ci.check(..., audit=False)` and asserts only that one obsolete note is absent: [tests/test_ci.py:60-67](/Volumes/T7/crosscheck/tests/test_ci.py:60). Delete the entire pip/npm block at [cc/checks/ci.py:249-340](/Volumes/T7/crosscheck/cc/checks/ci.py:249) and it still passes.

2. **The suite-wide provenance invariant never runs a check.**

   The test named `test_every_check_module_routes_foreign_text_through_with_foreign` constructs one already-correct synthetic `Finding` and tests `with_foreign()` itself: [tests/test_invariants.py:164-170](/Volumes/T7/crosscheck/tests/test_invariants.py:164). Every producer can leak foreign text and this stays green. That is already the current state in `pr-branch`, `ci`, `secrets`, and `baseline`.

   Delete this test and replace it with per-producer canaries. The canary must be planted in commit author/subject, workflow refs, scanner fatal output, test IDs, filenames, notes, and data, then asserted to appear only in tagged foreign fields.

3. **The CI darkness invariant has multiple escape hatches.**

   The “unpinned action” fixture also lacks permissions and may trigger scanner judgments; the test merely asserts non-CLEAN and any finding: [tests/test_invariants.py:62-65](/Volumes/T7/crosscheck/tests/test_invariants.py:62). `_scan_pins()` can go dark and the permissions detector still saves it.

   The scanner-specific invariant asserts only if the scanner has already credited itself: [tests/test_invariants.py:67-76](/Volumes/T7/crosscheck/tests/test_invariants.py:67). If invocation or crediting regresses and `sast=[]`, the test performs no assertion.

   The broken-config test also uses a workflow with no permissions and only asserts not-CLEAN: [tests/test_ci.py:111-127](/Volumes/T7/crosscheck/tests/test_ci.py:111). The original scanner-credit bug can return while the unrelated permissions finding keeps this test green.

4. **The scope tests prove an imaginary policy, not the shipped one.**

   The happy path manufactures host-only `acme.com` data at [tests/test_scope.py:51-71](/Volumes/T7/crosscheck/tests/test_scope.py:51). No test sends a known Google repository through the only real policy, despite the policy instructions explicitly requiring that smoke test at [policies/README.md:19-24](/Volumes/T7/crosscheck/policies/README.md:19). That missing test conceals the zero-program mismatch above.

5. **The untracked-baseline test does not make the untracked file affect the suite.**

   The test changes tracked `out.txt` and `code.txt`, which already create the dirty-vs-clean difference, then creates an unrelated untracked file that the suite never reads: [tests/test_baseline.py:133-140](/Volumes/T7/crosscheck/tests/test_baseline.py:133). Remove `--include-untracked` from the stash and the test still passes. The untracked fixture must itself determine the suite result.

   Similarly, the restore test ignores the returned result; an implementation that returns before stashing leaves the file unchanged and the stash empty, satisfying both assertions: [tests/test_baseline.py:124-131](/Volumes/T7/crosscheck/tests/test_baseline.py:124).

6. **The enforce test named “exit code alone never decides” does not test that.**

   It supplies both an exit predicate and a stderr predicate, proving only that stated predicates are conjunctive: [tests/test_enforce.py:123-130](/Volumes/T7/crosscheck/tests/test_enforce.py:123). The shared fixture itself uses exit code alone at [tests/test_enforce.py:62-69](/Volumes/T7/crosscheck/tests/test_enforce.py:62), which production accepts.

   Add a nonexistent executable with an exit-only rule and require UNTESTABLE/INVALID. Add a crashing allowed-case target and require INVALID. Also assert dry-run is not CLEAN; the current dry-run test checks only that the marker was not written and a `WOULD RUN` note exists: [tests/test_enforce.py:148-153](/Volumes/T7/crosscheck/tests/test_enforce.py:148).

7. **The shipped-data invariants are vacuous when data disappears.**

   `test_every_policy_has_a_fetched_at` iterates existing files but never asserts at least one real policy exists; `test_floor_rows_carry_the_quote_they_rule_on` passes over zero floor rows: [tests/test_invariants.py:188-203](/Volumes/T7/crosscheck/tests/test_invariants.py:188). Delete `google-oss-vrp.json` and both tests pass while every real `vrp` invocation becomes INVALID.

   The spec invariant has the same issue: delete every shipped spec and `test_every_spec_probe_is_an_argv_list` passes over nothing at [tests/test_invariants.py:205-210](/Volumes/T7/crosscheck/tests/test_invariants.py:205).

8. **The byte-cap test uses only ASCII.**

   `"A" * N` makes characters equal bytes, so [tests/test_emission.py:20-25](/Volumes/T7/crosscheck/tests/test_emission.py:20) cannot detect that production counts code points rather than UTF-8 bytes at [cc/result.py:90-99](/Volumes/T7/crosscheck/cc/result.py:90). Add multibyte input.

9. **The VRP rewarded-tier test codifies permissive absence.**

   Its synthetic floor omits the `tiers` vocabulary, then calls OT0 “rewarded” solely because it is absent from `unrewarded`: [tests/test_vrp.py:115-140](/Volumes/T7/crosscheck/tests/test_vrp.py:115). That is why OT22 is also currently rewarded. Put an explicit tier set in the fixture and require unknown tiers to be non-CLEAN.

10. **No secrets test enters the history branch.**

    The entire file stops without one `history=True` case: [tests/test_secrets.py:24-73](/Volumes/T7/crosscheck/tests/test_secrets.py:24). The positive detector tests also skip when gitleaks is absent. Scanner exit behavior should be unit-tested with deterministic mocked `Proc` and report data; installed-tool availability should not decide whether false-CLEAN regressions are covered.

## the author’s hypothesis

Confirmed as an operational problem, rejected as the current highest-value improvement.

The usage log cannot even distinguish construction runs from task runs because it intentionally stores only timestamp, check name, and code: [cc/usage.py:34-44](/Volumes/T7/crosscheck/cc/usage.py:34). The shipped `scope` mismatch is exactly the kind of defect one real invocation would have caught immediately. Synthetic tests and construction loops optimized internal mechanics without ever closing the loop on actual inputs.

But real use is not a substitute for correcting known false-CLEAN paths. Run one real task per lane after the verdict fixes, not before:

- one dirty working-tree baseline on an actual change;
- one real PR branch plus CI/dependency scan;
- one current bounty VRP decision using freshly verified policy data.

Do not add another module. Do not bulk-transcribe programs “just in case.” Add policy data only when a real task needs it, and make that first real invocation a required smoke fixture.

## verification

- I read the requested files in order, then the supporting policy/spec/usage files.
- The full 139-test command was attempted. In this managed read-only environment, 100 integration tests errored in fixture setup because `tempfile.mkdtemp()` had no writable directory. That is an environment failure, not a repository test verdict.
- The 34 pure/read-only tests passed.
- Read-only call-level reproductions confirmed CLEAN for:
  - failed pip-audit with no usable output;
  - gitleaks timeout erased by `--allow`;
  - gitleaks history timeout;
  - foreign commit self-vouching via `Co-authored-by`;
  - malformed `scope` port normalized to an allowed host;
  - unknown VRP tier;
  - misspelled `enforce.expect`.
- Direct commands confirmed:
  - both shipped Google owner paths are classified OUT by `scope`;
  - `cc enforce crosscheck-self --dry-run --json` reports CLEAN.
- No repository files were changed.

The security-audit workflow materially changed the deletion call: rather than delete something merely because it had low or construction-only usage, I exercised the only shipped policy and found that `scope`’s data model cannot consume it. That is evidence for deletion, not taste.