"""Scope matching. Wrong ALLOW is the critical error, so the adversarial cases
are the point of this file, not an afterthought."""

import json
import os
import tempfile
import unittest

from cc.checks import scope
from cc.result import EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID


class TestHostMatches(unittest.TestCase):
    def test_apex_and_subdomain_match(self):
        self.assertTrue(scope.host_matches("eero.com", "eero.com"))
        self.assertTrue(scope.host_matches("api.eero.com", "eero.com"))
        self.assertTrue(scope.host_matches("a.b.eero.com", "*.eero.com"))

    def test_substring_never_matches(self):
        # The bug this module exists to make unreachable.
        self.assertFalse(scope.host_matches("notaneero.com", "eero.com"))
        self.assertFalse(scope.host_matches("myeero.com", "eero.com"))
        self.assertFalse(scope.host_matches("eero.com.attacker.net", "eero.com"))
        self.assertFalse(scope.host_matches("xeero.com", "eero.com"))

    def test_suffix_needs_a_label_boundary(self):
        self.assertFalse(scope.host_matches("evilexample.com", "example.com"))
        self.assertTrue(scope.host_matches("evil.example.com", "example.com"))

    def test_empty_entry_never_matches_anything(self):
        # An empty scope entry matching everything would be a total bypass.
        self.assertFalse(scope.host_matches("anything.com", ""))
        self.assertFalse(scope.host_matches("anything.com", "*."))


class TestNormalizeHost(unittest.TestCase):
    def test_strips_scheme_port_path_and_trailing_dot(self):
        self.assertEqual(scope.normalize_host("https://api.eero.com:8443/x?y=1"), "api.eero.com")
        self.assertEqual(scope.normalize_host("eero.com."), "eero.com")
        self.assertEqual(scope.normalize_host("EERO.com"), "eero.com")

    def test_strips_userinfo(self):
        # http://eero.com@evil.tld must resolve to evil.tld, never eero.com.
        self.assertEqual(scope.normalize_host("http://eero.com@evil.tld/"), "evil.tld")

    def test_rejects_garbage(self):
        for bad in ("", "   ", "http://", "*.eero.com", "a b.com"):
            self.assertIsNone(scope.normalize_host(bad), bad)


class TestScopeCheck(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.environ[scope.POLICY_DIR_ENV] = self.dir
        with open(os.path.join(self.dir, "acme.json"), "w") as fh:
            json.dump(
                {
                    "program": "acme",
                    "fetched_at": "2026-08-01",
                    "in_scope": ["acme.com", "*.acme.io"],
                    "out_of_scope": ["blog.acme.com"],
                },
                fh,
            )

    def tearDown(self):
        os.environ.pop(scope.POLICY_DIR_ENV, None)

    def test_in_scope_is_clean(self):
        r = scope.check("acme", ["acme.com", "x.acme.io"])
        self.assertEqual(r.code, EXIT_CLEAN)

    def test_out_of_scope_is_a_finding(self):
        r = scope.check("acme", ["notacme.com"])
        self.assertEqual(r.code, EXIT_FINDING)

    def test_explicit_out_beats_in_scope_wildcard(self):
        r = scope.check("acme", ["blog.acme.com"])
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertIn("explicitly OUT", r.findings[0].what)

    def test_missing_policy_is_invalid_never_allowed(self):
        # There must be no path that defaults a host to in-scope.
        r = scope.check("no-such-program", ["anything.com"])
        self.assertEqual(r.code, EXIT_INVALID)

    def test_policy_with_no_in_scope_is_invalid(self):
        with open(os.path.join(self.dir, "empty.json"), "w") as fh:
            json.dump({"in_scope": []}, fh)
        self.assertEqual(scope.check("empty", ["a.com"]).code, EXIT_INVALID)

    def test_malformed_policy_is_invalid(self):
        with open(os.path.join(self.dir, "broken.json"), "w") as fh:
            fh.write("{not json")
        self.assertEqual(scope.check("broken", ["a.com"]).code, EXIT_INVALID)

    def test_program_name_traversal_is_refused(self):
        # An agent may derive `program` from a URL slug or a filename, so it is
        # not always a hand-typed literal. A relative path must never load an
        # arbitrary json and have it treated as an authoritative scope policy.
        up = ".." + os.sep
        for bad in (up * 3 + "somewhere", "..", "a" + os.sep + "b", os.sep + "abs", "acme" + os.sep + ".." + os.sep + "acme"):
            self.assertEqual(scope.check(bad, ["a.com"]).code, EXIT_INVALID, bad)

    def test_underscore_prefixed_example_policies_still_load(self):
        # `_template` / `_example-eero` are the documented names for the
        # non-program files; rejecting a leading underscore made the shipped
        # examples unloadable and turned a FINDING into an INVALID.
        with open(os.path.join(self.dir, "_example-acme.json"), "w") as fh:
            json.dump({"in_scope": ["acme.com"]}, fh)
        r = scope.check("_example-acme", ["notacme.com"])
        self.assertEqual(r.code, EXIT_FINDING, [f.what for f in r.findings])

    def test_traversal_cannot_load_a_json_outside_the_policy_dir(self):
        # Prove it with a real file one level up from the policy dir.
        outside = os.path.join(os.path.dirname(self.dir), "sneaky.json")
        with open(outside, "w") as fh:
            json.dump({"in_scope": ["anything.com"]}, fh)
        r = scope.check(".." + os.sep + "sneaky", ["anything.com"])
        self.assertEqual(r.code, EXIT_INVALID)

    def test_no_hosts_is_invalid(self):
        self.assertEqual(scope.check("acme", []).code, EXIT_INVALID)


if __name__ == "__main__":
    unittest.main()
