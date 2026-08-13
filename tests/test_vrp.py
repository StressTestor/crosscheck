"""vrp: eligibility before PoC effort.

The distinction under test: MISSING policy is INVALID (a hard stop), STALE
policy is JUDGMENT (a nudge). A rule that hard-stops a pipeline on a cache age
gets routed around by week two, and a rule routed around once is gone.
"""

import datetime as dt
import json
import os
import tempfile
import unittest

from cc.checks import scope, vrp
from cc.result import EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID, EXIT_JUDGMENT


class TestVrp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.environ[scope.POLICY_DIR_ENV] = self.dir
        self.today = dt.date(2026, 8, 9)

    def tearDown(self):
        os.environ.pop(scope.POLICY_DIR_ENV, None)

    def _policy(self, name, **kw):
        base = {
            "program": name,
            "fetched_at": "2026-08-01",
            "in_scope": ["x.com"],
            "eligible_classes": ["ssrf"],
        }
        base.update(kw)
        with open(os.path.join(self.dir, f"{name}.json"), "w") as fh:
            json.dump(base, fh)

    def test_missing_policy_is_invalid(self):
        r = vrp.check("nope", "ssrf", today=self.today)
        self.assertEqual(r.code, EXIT_INVALID)

    def test_stale_policy_is_judgment_not_invalid(self):
        self._policy("p", fetched_at="2025-01-01")
        r = vrp.check("p", "ssrf", max_age_days=90, today=self.today)
        self.assertEqual(r.code, EXIT_JUDGMENT)

    def test_fresh_eligible_class_is_clean(self):
        self._policy("p")
        r = vrp.check("p", "ssrf", today=self.today)
        self.assertEqual(r.code, EXIT_CLEAN)

    def test_ineligible_class_is_a_finding(self):
        self._policy(
            "p",
            ineligible_classes=[{"class": "self-xss", "quote": "Self-XSS is not eligible."}],
        )
        r = vrp.check("p", "self-xss", today=self.today)
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertIn("Self-XSS is not eligible.", r.findings[0].detail)

    def test_below_bar_class_is_a_finding(self):
        self._policy("p", severity_bar="high+", below_bar_classes=["denial of service"])
        r = vrp.check("p", "denial of service", today=self.today)
        self.assertEqual(r.code, EXIT_FINDING)

    def test_narrow_ineligible_class_does_not_rule_on_the_broad_one(self):
        # marko's #1: a bare substring test made 'xss' collide with an
        # ineligible 'self-xss' entry, so the module whose job is deciding
        # whether to start a weekend of PoC work told you not to bother.
        self._policy("p", eligible_classes=["xss"],
                     ineligible_classes=[{"class": "self-xss", "quote": "Self-XSS is not eligible."}])
        self.assertEqual(vrp.check("p", "xss", today=self.today).code, EXIT_CLEAN)
        self.assertEqual(vrp.check("p", "self-xss", today=self.today).code, EXIT_FINDING)

    def test_broad_policy_class_still_covers_a_narrower_ask(self):
        # Discriminating: the fix must not make matching useless. A policy
        # ruling on 'ssrf' still rules on 'blind ssrf'.
        self._policy("p", ineligible_classes=[{"class": "ssrf", "quote": "SSRF out of scope."}])
        self.assertEqual(vrp.check("p", "blind SSRF", today=self.today).code, EXIT_FINDING)

    def test_unrelated_classes_do_not_collide(self):
        self._policy("p", eligible_classes=["ssrf"],
                     ineligible_classes=[{"class": "rate limiting", "quote": "no"}])
        self.assertEqual(vrp.check("p", "ssrf", today=self.today).code, EXIT_CLEAN)

    def test_unknown_class_is_judgment_not_clean(self):
        # Absence of a rule is not permission.
        self._policy("p")
        r = vrp.check("p", "prototype pollution", today=self.today)
        self.assertEqual(r.code, EXIT_JUDGMENT)

    def test_active_exclusion_window_fires(self):
        self._policy(
            "p",
            exclusion_windows=[
                {"from": "2026-08-01", "until": "2026-08-31", "classes": ["dns"], "quote": "No DNS reports in August."}
            ],
        )
        r = vrp.check("p", "dns hijack", today=self.today)
        self.assertEqual(r.code, EXIT_FINDING)

    def test_expired_exclusion_window_does_not_fire(self):
        # The travix case: "not accepting DNS reports until END OF JULY" is
        # expired on 2026-08-09 and must not block.
        self._policy(
            "p",
            eligible_classes=["dns hijack"],
            exclusion_windows=[
                {"from": "2026-07-01", "until": "2026-07-31", "classes": ["dns"], "quote": "until end of July"}
            ],
        )
        r = vrp.check("p", "dns hijack", today=self.today)
        self.assertEqual(r.code, EXIT_CLEAN)

    def _floor_policy(self, name="g", verified=True):
        self._policy(
            name,
            eligible_classes=["product vulnerability"],
            floor={
                "source_url": "https://example.invalid/rules",
                "verified": verified,
                "unrewarded": [
                    {"tier": "OT2", "classes": ["product vulnerability"], "quote": "no reward at OT2"},
                    {"tier": "OT3", "classes": ["product vulnerability"], "quote": "no reward at OT3"},
                ],
            },
        )
        return name

    def test_class_unrewarded_at_this_tier_is_a_finding(self):
        # The corpus's largest realized loss: three PoC-confirmed osv-scalibr
        # findings closed $0 because the class pays nothing at that tier.
        r = vrp.check(self._floor_policy(), "product vulnerability", tier="OT2", today=self.today)
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertTrue(any("pays NOTHING at tier OT2" in f.what for f in r.findings))
        self.assertTrue(any("no reward at OT2" in (f.detail or "") for f in r.findings))

    def test_unverified_floor_row_is_judgment_not_finding(self):
        # The transcript admits it was not read off the primary page. A hard
        # $0 FINDING off unverified provenance talks you out of real work; the
        # machine verdict has to carry the uncertainty, not just a comment.
        r = vrp.check(self._floor_policy(verified=False), "product vulnerability",
                      tier="OT2", today=self.today)
        self.assertEqual(r.code, EXIT_JUDGMENT, [f.what for f in r.findings])
        self.assertTrue(any("UNVERIFIED" in f.what for f in r.findings))
        # The quote still travels with the judgment so it can be checked.
        self.assertTrue(any("no reward at OT2" in (f.detail or "") for f in r.findings))

    def test_absent_verified_stamp_means_unverified(self):
        # Absence of the stamp is not verification - same doctrine as
        # "absence of a rule is not permission".
        self._policy(
            "nostamp",
            eligible_classes=["product vulnerability"],
            floor={"unrewarded": [{"tier": "OT2", "classes": ["product vulnerability"], "quote": "q"}]},
        )
        r = vrp.check("nostamp", "product vulnerability", tier="OT2", today=self.today)
        self.assertEqual(r.code, EXIT_JUDGMENT)

    def test_same_class_at_a_rewarded_tier_is_clean(self):
        # Discriminating: the floor must not blanket-block the class.
        r = vrp.check(self._floor_policy(), "product vulnerability", tier="OT0", today=self.today)
        self.assertEqual(r.code, EXIT_CLEAN, [f.what for f in r.findings])

    def test_no_tier_is_judgment_never_a_guess(self):
        r = vrp.check(self._floor_policy(), "product vulnerability", today=self.today)
        self.assertEqual(r.code, EXIT_JUDGMENT)
        self.assertTrue(any("none was given" in f.what for f in r.findings))

    def test_tier_without_a_floor_table_is_judgment(self):
        self._policy("nofloor", eligible_classes=["ssrf"])
        r = vrp.check("nofloor", "ssrf", tier="OT2", today=self.today)
        self.assertEqual(r.code, EXIT_JUDGMENT)
        self.assertTrue(any("no floor table" in f.what for f in r.findings))

    def test_floor_matching_runs_broad_to_narrow_only(self):
        # A BROAD policy class covers a NARROWER ask: if 'xss' pays nothing,
        # neither does 'self-xss'. Same rule that lets 'ssrf' cover 'blind ssrf'.
        self._policy(
            "g2",
            eligible_classes=["self-xss"],
            floor={"verified": True,
                   "unrewarded": [{"tier": "OT2", "classes": ["xss"], "quote": "q"}]},
        )
        self.assertEqual(vrp.check("g2", "self-xss", tier="OT2", today=self.today).code, EXIT_FINDING)

        # But a NARROW policy class must not rule on the BROADER ask - a floor
        # on 'self-xss' says nothing about xss generally.
        self._policy(
            "g3",
            eligible_classes=["xss"],
            floor={"unrewarded": [{"tier": "OT2", "classes": ["self-xss"], "quote": "q"}]},
        )
        r = vrp.check("g3", "xss", tier="OT2", today=self.today)
        self.assertEqual(r.code, EXIT_CLEAN, [f.what for f in r.findings])

    def test_missing_fetched_at_is_judgment(self):
        self._policy("p", fetched_at="")
        r = vrp.check("p", "ssrf", today=self.today)
        self.assertEqual(r.code, EXIT_JUDGMENT)


if __name__ == "__main__":
    unittest.main()
