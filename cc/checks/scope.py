"""scope - decide whether a host is inside a bounty program's declared scope.

Wrong ALLOW is the critical error, exactly as in scopeguard - except scopeguard
draws a filesystem boundary and this draws a DNS one. Probing an out-of-scope
host is the one bug-bounty mistake that is not merely wasted effort.

The bug this exists to make unreachable is substring matching. `notaneero.com`
contains `eero.com`. `eero.com.attacker.net` contains `eero.com`. Neither is in
scope for eero. Matching is suffix-anchored on a label boundary, always:

    host == domain   OR   host.endswith("." + domain)

Some programs scope by PATH, not just host: google-oss-vrp declares
`github.com/google`, meaning "repos under the google org", not "all of
github.com". A policy entry containing `/` therefore matches on host AND on
whole path segments: `github.com/google` covers `github.com/google/osv-scalibr`
and never `github.com/google-not` or `github.com/notgoogle`. The old matcher
threw the path away, so the one real shipped policy had ZERO usable entries -
every Google OSS URL normalised to `github.com` and reported OUT. XX

Judgment calls:
1. No policy for the program is INVALID. There is no code path that defaults a
   host to in-scope because the rules could not be found. >:[
2. Explicit out-of-scope entries beat in-scope wildcards. `*.example.com` in
   scope plus `internal.example.com` out means internal is OUT.
3. Hosts are lowercased and one trailing dot is stripped (`a.com.` == `a.com`).
   A leading `*.` in a policy entry means "subdomains and the apex".
4. A port, scheme or query on the input is stripped before matching. The path
   is KEPT (see above) but only consulted when the policy entry declares one -
   a host-only entry still matches any path on that host. An input that is not
   parseable is INVALID.
5. IDN/punycode is compared as given. We do not transcode, because a silent
   transcode is a way to match something the operator did not read.
6. Path segments compare case-insensitively (GitHub owner names are), and
   always as WHOLE segments - never substrings, same doctrine as hosts.
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


_IPV6_RE = re.compile(r"^\[[0-9a-f:.]+\]$")


def normalize_target(raw: str) -> tuple[str, list[str]] | None:
    """URL or bare host -> (comparable host, path segments). None = not a host.

    Control characters anywhere in the input are an outright rejection: this
    string ends up in output, and a newline-bearing "host" once emitted an
    unquoted extra line in the human report - operator input walking out of
    its own field.
    """
    if not raw or not raw.strip():
        return None
    s = raw.strip()
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in s):
        return None
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", s)   # scheme
    s = s.split("?", 1)[0].split("#", 1)[0]              # query / fragment
    h, _, path = s.partition("/")
    if "@" in h:                                          # userinfo
        h = h.rsplit("@", 1)[1]
    segs = [p for p in path.split("/") if p]
    if h.startswith("["):                                 # ipv6 literal
        end = h.find("]")
        if end <= 0:
            return None
        lit = h[: end + 1].lower()
        return (lit, segs) if _IPV6_RE.match(lit) else None
    h = h.split(":", 1)[0]                                # port
    h = h.rstrip(".").lower()
    if not h or not _HOST_RE.match(h):
        return None
    return h, segs


def normalize_host(raw: str) -> str | None:
    """URL or bare host -> comparable host. None when it is not a host."""
    t = normalize_target(raw)
    return t[0] if t else None


def host_matches(host: str, entry: str) -> bool:
    """Suffix-anchored on a label boundary. Never a substring test."""
    e = entry.strip().lower().rstrip(".")
    if e.startswith("*."):
        e = e[2:]
    if not e:
        return False
    return host == e or host.endswith("." + e)


def target_matches(host: str, segs: list[str], entry: str) -> bool:
    """Does (host, path) fall under a policy entry?

    Host-only entries keep the pure DNS suffix match. Entries with a path
    (`github.com/google`) additionally require the input path to start with
    the entry's path as WHOLE segments - `/google/osv-scalibr` is under
    `/google`; `/google-not` and `/notgoogle` are not. Substrings never match,
    in either half.
    """
    e = entry.strip().lower().strip("/")
    if "/" not in e:
        return host_matches(host, e)
    ehost, _, epath = e.partition("/")
    if not host_matches(host, ehost):
        return False
    esegs = [p for p in epath.split("/") if p]
    if not esegs:
        return False
    have = [p.lower() for p in segs]
    return have[: len(esegs)] == esegs


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
        t = normalize_target(raw)
        if not t:
            # Operator input that failed to parse is untrusted text - it does
            # not get to sit in `where` (a control character once walked a
            # fake verdict line into the human output that way).
            r.add(
                Finding(
                    what="not a parseable host",
                    fix="pass a bare host or a URL, not a wildcard or a regex",
                    severity="invalid",
                ).with_foreign("operator input", raw)
            )
            verdicts[raw] = "INVALID"
            continue
        h, segs = t
        disp = h + ("/" + "/".join(p.lower() for p in segs) if segs else "")

        blocked = next((e for e in out_scope if target_matches(h, segs, e)), None)
        if blocked:
            r.add(
                Finding(
                    what="host is explicitly OUT of scope",
                    where=disp,
                    detail=f"matched out_of_scope entry '{blocked}'",
                    fix="do not probe it",
                )
            )
            verdicts[disp] = "OUT"
            continue

        allowed = next((e for e in in_scope if target_matches(h, segs, e)), None)
        if allowed:
            r.note(f"IN  {disp}  (matches '{allowed}')")
            verdicts[disp] = "IN"
            continue

        # The substring trap: report it as the boundary violation it is.
        near = next((e for e in in_scope if "/" not in e.strip("/") and e.strip("*.").lower() in h), None)
        # A path entry whose HOST matched but whose path did not is the same
        # trap one directory deeper: github.com/google-not under a
        # github.com/google policy.
        near_path = next(
            (e for e in in_scope
             if "/" in e.strip("/") and host_matches(h, e.strip().lower().partition("/")[0])),
            None,
        )
        detail = "no in_scope entry matches on a label boundary"
        if near:
            detail = (
                f"contains '{near.strip('*.')}' as a SUBSTRING but is not a subdomain of it "
                f"- this is the notaneero.com / eero.com.attacker.net shape"
            )
        elif near_path:
            detail = (
                f"the host matches '{near_path}' but the path does not fall under its "
                f"path on a whole-segment boundary - scope here is by path, not host"
            )
        r.add(
            Finding(
                what="host is NOT in scope",
                where=disp,
                detail=detail,
                fix="leave it alone, or get it added to the program scope first",
            )
        )
        verdicts[disp] = "OUT"

    r.data["verdicts"] = verdicts
    return r
