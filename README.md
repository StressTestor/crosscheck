# crosscheck

i kept doing the same handful of checks by hand before every PR, every push,
every bounty submission. and then forgetting one.

the branch
that replays 13 of someone else's commits because it got rebased instead of
refreshed. the failing test called "pre-existing" without ever stashing and
re-running. three PoC-confirmed findings that closed $0 because the program's
severity bar excluded the class - after the PoC work was done.

crosscheck runs the mechanical half of that memory. stdlib python, real exit
codes, works from your shell, from CI, or from an agent.

one module, `enforce`, actually runs the thing under test - everything else
just reads artifacts. it exists because "control declared, control not applied,
success reported anyway" showed up four times across two different targets.

it does not review diffs, prove fixes, score duplicate risk, or re-lens GitHub
Actions workflows. adv-gate, verify-change, dupe-gate and gha-security-review
already do those, and this routes to them instead of copying them.

## install

```
git clone <this> /Volumes/T7/crosscheck   # it already lives there
cd /Volumes/T7/crosscheck && ./install.sh
```

that puts a `cc` launcher in `~/.local/bin`. the suite stays on the external
drive; the launcher does not, so when the drive is unmounted you get one clear
sentence and exit 3 instead of a stack trace.

optional, and worth it - these are what the checks delegate to:

```
brew install actionlint gitleaks node
pipx install zizmor==1.25.2
pipx install pip-audit==2.10.0
```

versions match odysseus CI's pins, so a local run reproduces the CI verdict.

## exit codes

```
0  CLEAN      nothing to act on
2  FINDING    named problem, with a fix
3  INVALID    could not evaluate  <- not a pass. ever.
4  JUDGMENT   needs a model or a human
```

1 is reserved for an uncaught crash so it can never be mistaken for a verdict.
worst-of aggregation is `3 > 2 > 4 > 0`.

INVALID being louder than FINDING is the whole design in one line. a check that
didn't run prints the same nothing as a check that passed.

## the checks

| check | question it answers |
|-------|--------------------|
| `baseline` | is that failure actually pre-existing, or did i cause it |
| `pr-branch` | is my branch about to replay someone else's commits |
| `ci` | are the actions pinned, the tokens scoped, the deps clean |
| `scope` | is this host really inside the program's scope |
| `secrets` | is a live key sitting in my evidence dir or a vault-bound note |
| `vrp` | is this class of bug even fileable here, before i build the PoC |
| `enforce` | does a declared control actually engage - and does the target admit it when it doesn't |

## use it

```bash
# the two that pay for themselves
cc baseline ~/repo -- pytest -q
cc pr-branch ~/repo

# actions supply chain, delegating to zizmor + actionlint
cc ci ~/repo --changed core/x.py,.github/workflows/ci.yml

# bounty side
cc scope acme api.acme.com notanacme.com
cc vrp google-oss-vrp "product vulnerability" --tier OT2   # $0? ask BEFORE the PoC
cc secrets ./evidence --allow ./report.md

# whole sweeps
cc run oss-pr ~/repo
cc run bounty-presubmit --program acme --vuln-class ssrf --paths ./evidence

# does a declared control actually hold? RUNS the target. --dry-run first.
cc enforce codecalc --dry-run
cc enforce codecalc

# every check speaks json, same envelope shape
cc --json ci ~/repo
```

## make it actually fire

a rule that lives in a doc is a rule you have to remember. wire the branch check
into git instead:

```
./install.sh --hook ~/repo     # pre-push; bypass with git push --no-verify
```

## delete things

```
cc decay
```

lists checks that have never fired, or have gone cold. a check nobody runs isn't
free - it's a claim of coverage you don't have. delete it.

## policies

`scope` and `vrp` read hand-transcribed json in `policies/`. there is no
fetcher on purpose: a scraped policy that silently drifts is how you probe an
out-of-scope host with a green exit code. no policy for a program means exit 3,
never "probably fine". see `policies/README.md`.

## from an agent

there's a `crosscheck` skill and a `crosscheck-adjudicate` workflow for the
judgment half - claim honesty, reachability, maintainer intent, confinement,
rules of engagement. the CLI finds; the workflow reasons; neither pretends to be
the other.

## tests

```
python3 -m unittest discover -s tests -t .
```

200 tests. real git repos, real subprocesses, and the adversarial cases are the
point - `notaneero.com` and `eero.com.attacker.net` both have to come back OUT,
and so does `github.com/google-not` under a `github.com/google` policy. a
canary token planted in scanner output, commit headers, test ids or workflow
refs must surface ONLY in tagged `foreign` fields, never in crosscheck's own
prose - one test per producer, mocked scanners throughout.
