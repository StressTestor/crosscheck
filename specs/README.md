# specs

one json per target. `cc enforce` reads these and **nothing else**.

a spec says: here is a control the target DECLARES, here is a probe that should
be REFUSED, and here is how i will recognise a refusal.

these are hand-written on purpose, like `policies/`. there is no spec generator,
because `cc enforce` is the one subcommand that **executes the thing under
test** — a probe nobody read is a probe nobody should fire.

## verdicts

```
ENFORCED           the probe was refused. the control is real.
UNENFORCED         the probe succeeded. the control is not applied.
UNENFORCED-SILENT  the probe succeeded AND the target's own self-report still
                   claims the control applied. strictly worse: whoever reads
                   that report is now confidently wrong.
UNTESTABLE         the probe could not be run, or a refusal could not be
                   recognised. INVALID (3), never CLEAN.
```

`UNENFORCED-SILENT` is the whole reason this module exists. codecalc #62 is the
canonical example: `RLIMIT_NPROC` does not bind at uid 0, and the `unenforced`
array does not say so, so a caller reads the result as "the ceiling applied".

## the trap: a refusal rule that passes for the wrong reason

**Exit code alone is almost never enough.** A target that dies for an unrelated
reason looks exactly like one that refused.

This bit the very first spec written for this repo. `crosscheck-self` probes
`cc ci --require-sast` against a fixture with malformed scanner configs, and the
rule was just:

```json
"refused_when": { "exit_code_not_in": [0] }
```

That passed whether or not the control existed — the fixture *also* trips an
unrelated `permissions:` finding, so the exit code is non-zero either way. The
spec reported ENFORCED against a deliberately re-broken build. It only became a
real test once the rule named the specific signal:

```json
"refused_when": {
  "exit_code_not_in": [0],
  "output_contains": "no Actions SAST produced an analysis"
}
```

**This is now a machine check, not a rule you have to remember.** A control
whose verdict is ENFORCED but which has never been *seen to fail* reports
`JUDGMENT (4)`, not CLEAN — because a refusal rule that has only ever passed may
be matching for an unrelated reason.

To prove one, break the control on a throwaway copy and run:

```
cc enforce <name> --record-red
```

Any control that comes back UNENFORCED there is recorded in `specs/.redruns.json`,
keyed by a fingerprint of `name + probe + refused_when + expect`. Editing the
refusal rule changes the fingerprint and invalidates the proof, which is the
point. Editing an unrelated control does not.

Prune stale entries when you change a rule: a proof recorded against an old
`refused_when` would otherwise bless that rule again if someone reverted it.
Fingerprints not present in any current spec are dead weight at best.

The ledger is a **discipline record, not a security boundary** — anyone who can
edit a spec can edit it. It exists to stop honest mistakes, which is exactly the
class of mistake that shipped here first.

Why a check and not a paragraph: the original mitigation for this WAS a
paragraph, and a documentation requirement is the same shape as every
mitigation that quietly stops happening by week two.

## format

```json
{
  "target": "codecalc",
  "description": "one line, printed as a note",
  "cwd": "/absolute/path/the/probes/run/in",
  "controls": [
    {
      "name": "nproc",
      "declares": "RLIMIT_NPROC is applied per execution",
      "probe": ["./target", "--spawn", "200"],
      "expect": "refused",
      "refused_when": {
        "exit_code_not_in": [0],
        "stderr_contains": "resource temporarily unavailable"
      },
      "self_report": {
        "from": "file",
        "file": "report.json",
        "path": "unenforced",
        "claims_applied_when": "absent_from",
        "key": "nproc"
      },
      "timeout": 60
    }
  ]
}
```

| field | meaning |
|---|---|
| `probe` | **argv list, never a shell string.** the suite obeys the sink rule it enforces on others, and it matters most here |
| `expect` | `refused` (default) or `allowed` |
| `refused_when` | how a refusal is recognised. keys: `exit_code_in`, `exit_code_not_in`, `stdout_contains`, `stderr_contains`, `output_contains`. **all stated conditions must hold** |
| `self_report` | optional. lets `UNENFORCED` be upgraded to `UNENFORCED-SILENT` |
| `self_report.from` | `stdout_json` or `file` (+ `file:`) |
| `self_report.claims_applied_when` | `absent_from` (the codecalc shape), `present_in`, or `equals` (+ `value:`) |

## pin your negatives

Use `"expect": "allowed"` for operations that must keep working. A refusal
harness with no allowed-cases silently rewards a target that refuses
everything, and "we hardened it" then means "we broke it".

`crosscheck-self.json` carries one: a genuinely clean, fully-pinned repo must
still return CLEAN under `--require-sast`.

## the guard does not see these probes

`cc enforce` is the one subcommand that executes the target, and its probes run
as subprocesses from inside python — **not** as agent Bash calls. The local
sentinel/ghost PreToolUse hook only inspects the agent's command line, so it
never sees a probe's argv.

Verified, not assumed: `_guard-canary.json` fires an attack-shaped probe
(attempts to read `/etc/shadow`, exits 7 with a marker). It reaches the target
and runs, in sessions where that same guard blocks the agent for far less.

Good news for enforce — it will not report UNTESTABLE forever the way a
guard-tested module would. But read the other direction too: **a spec is
execution the guard will not review.** Hand-writing them is the point, not a
formality. `--dry-run` before every change to a spec, every time.

## running

```
cc enforce <name> --dry-run          # print the probes, execute nothing
cc enforce <name>                    # fire them
cc enforce <name> --only nproc       # one control
```

`--dry-run` first, every time you touch a spec. It prints the exact argv.
