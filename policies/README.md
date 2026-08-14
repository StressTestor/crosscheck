# policies

one json per program. `cc scope` and `cc vrp` read these and **nothing else**.

these are hand-transcribed on purpose. there is no fetcher, because a scraped
policy that silently drifts is how you probe an out-of-scope host while holding
a green exit code.

rules the code enforces, so you can rely on them:

- no policy file -> `INVALID (3)`. never "probably in scope".
- policy older than `--max-age-days` -> `JUDGMENT (4)`, not invalid. a cache age
  must never hard-stop a pipeline on a non-security fact.
- a class with no ruling -> `JUDGMENT (4)`. absence of a rule is not permission.
- `out_of_scope` beats an `in_scope` wildcard.
- a scope entry may carry a path (`github.com/google` = the org, not the host).
  matching is host suffix-anchored AND whole path segments - `/google` covers
  `/google/osv-scalibr`, never `/google-not` or `/notgoogle`.
- a `floor` block rules `FINDING` only when it carries `"verified": true`,
  meaning someone read the primary page. rows transcribed from summaries rule
  `JUDGMENT (4)` - an unverified $0 must not talk you out of real work.

files starting with `_` are templates/examples, not real programs.

## adding a program

1. `cp _template.json <program>.json`
2. open the program page, paste real quotes into `ineligible_classes` / `exclusion_windows`
3. stamp `fetched_at` with today
4. `python3 crosscheck.py scope <program> <a-known-in-scope-host>` and confirm IN
