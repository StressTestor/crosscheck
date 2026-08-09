"""scope - decide whether a host is inside a bounty program's declared scope.

Wrong ALLOW is the critical error, exactly as in scopeguard - except scopeguard
draws a filesystem boundary and this draws a DNS one. Probing an out-of-scope
host is the one bug-bounty mistake that is not merely wasted effort.

The bug this exists to make unreachable is substring matching. `notaneero.com`
contains `eero.com`. `eero.com.attacker.net` contains `eero.com`. Neither is in
scope for eero. Matching is suffix-anchored on a label boundary, always:

    host == domain   OR   host.endswith("." + domain)

Judgment calls:
1. No policy for the program is INVALID. There is no code path that defaults a
   host to in-scope because the rules could not be found. >:[
2. Explicit out-of-scope entries beat in-scope wildcards. `*.example.com` in
   scope plus `internal.example.com` out means internal is OUT.
3. Hosts are lowercased and one trailing dot is stripped (`a.com.` == `a.com`).
   A leading `*.` in a policy entry means "subdomains and the apex".
4. A port, scheme or path on the input is stripped before matching; we compare
   hosts, not URLs. An input that is not a parseable host is INVALID.
5. IDN/punycode is compared as given. We do not transcode, because a silent
   transcode is a way to match something the operator did not read.
"""

from __future__ import annotations

import json
import os
import re

from ..result import Result, Finding

CHECK = "scope"

POLICY_DIR_ENV = "CROSSCHECK_POLICIES"
_DEFAULT_POLICY_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "policies"
)

_HOST_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_\-\.]*[a-z0-9_])?$")


def policy_dir() -> str:
    return os.environ.get(POLICY_DIR_ENV) or _DEFAULT_POLICY_DIR


def normalize_host(raw: str) -> str | None:
    """URL or bare host -> comparable host. None when it is not a host."""
    if not raw or not raw.strip():
        return None
    h = raw.strip()
    h = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", h)  # scheme
    h = h.split("/", 1)[0]                               # path
    h = h.split("?", 1)[0].split("#", 1)[0]
    if "@" in h:                                          # userinfo
        h = h.rsplit("@", 1)[1]
    if h.startswith("["):                                 # ipv6 literal
        end = h.find("]")
        return h[: end + 1].lower() if end > 0 else None
    h = h.split(":", 1)[0]                                # port
    h = h.rstrip(".").lower()
    if not h or not _HOST_RE.match(h):
        return None
    return h


def host_matches(host: str, entry: str) -> bool:
    """Suffix-anchored on a label boundary. Never a substring test."""
    e = entry.strip().lower().rstrip(".")
    if e.startswith("*."):
        e = e[2:]
    if not e:
        return False
    return host == e or host.endswith("." + e)


# A program name becomes a filename. Agents derive it from URL slugs and
# filenames, so it is not always a hand-typed literal - and `../../etc/x`
# would load an arbitrary json as an authoritative scope policy. Anything but
# a plain name is refused outright. (¬‿¬)
# A leading underscore is allowed - `_template` / `_example-eero` are the
# documented names for the non-program files, and rejecting them made the
# shipped examples unloadable. Safety here comes from refusing separators and
# `..`, not from the first character.
_PROGRAM_RE = re.compile(r"^[a-z0-9_][a-z0-9_.\-]*$")


def load_policy(program: str) -> tuple[dict | None, str | None]:
    name = (program or "").strip().lower()
    if not _PROGRAM_RE.match(name) or ".." in name:
        return None, f"invalid program name {program!r} - letters, digits, dot, dash, underscore only"
    root = os.path.realpath(policy_dir())
    path = os.path.realpath(os.path.join(root, f"{name}.json"))
    if path != root and not path.startswith(root + os.sep):
        return None, f"policy path for {program!r} escapes the policy directory"
    if not os.path.isfile(path):
        return None, f"no policy for program '{program}' at {path}"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh), None
    except (OSError, ValueError) as e:
        return None, f"policy for '{program}' is unreadable/malformed: {e}"


def check(program: str, hosts: list[str]) -> Result:
    r = Result(check=CHECK)

    if not hosts:
        return Result.invalid(CHECK, "no hosts given", "cc scope <program> <host> [host...]")

    pol, err = load_policy(program)
    if err:
        # Never guess. A program we have no rules for is a hard stop.
        return Result.invalid(
            CHECK,
            err,
            f"write {os.path.join(policy_dir(), program.lower() + '.json')} with in_scope/out_of_scope before probing",
        )

    in_scope = pol.get("in_scope", []) or []
    out_scope = pol.get("out_of_scope", []) or []
    if not in_scope:
        return Result.invalid(CHECK, f"policy for '{program}' declares no in_scope entries")

    r.data.update({"program": program, "in_scope": in_scope, "out_of_scope": out_scope})
    if pol.get("fetched_at"):
        r.note(f"policy fetched_at {pol['fetched_at']} - re-read the program page if that is stale")

    verdicts = {}
    for raw in hosts:
        h = normalize_host(raw)
        if not h:
            r.add(
                Finding(
                    what="not a parseable host",
                    where=raw,
                    fix="pass a bare host or a URL, not a wildcard or a regex",
                    severity="invalid",
                )
            )
            verdicts[raw] = "INVALID"
            continue

        blocked = next((e for e in out_scope if host_matches(h, e)), None)
        if blocked:
            r.add(
                Finding(
                    what="host is explicitly OUT of scope",
                    where=h,
                    detail=f"matched out_of_scope entry '{blocked}'",
                    fix="do not probe it",
                )
            )
            verdicts[h] = "OUT"
            continue

        allowed = next((e for e in in_scope if host_matches(h, e)), None)
        if allowed:
            r.note(f"IN  {h}  (matches '{allowed}')")
            verdicts[h] = "IN"
            continue

        # The substring trap: report it as the boundary violation it is.
        near = next((e for e in in_scope if e.strip("*.").lower() in h), None)
        detail = "no in_scope entry matches on a label boundary"
        if near:
            detail = (
                f"contains '{near.strip('*.')}' as a SUBSTRING but is not a subdomain of it "
                f"- this is the notaneero.com / eero.com.attacker.net shape"
            )
        r.add(
            Finding(
                what="host is NOT in scope",
                where=h,
                detail=detail,
                fix="leave it alone, or get it added to the program scope first",
            )
        )
        verdicts[h] = "OUT"

    r.data["verdicts"] = verdicts
    return r
