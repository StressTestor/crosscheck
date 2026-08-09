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

    def test_missing_fetched_at_is_judgment(self):
        self._policy("p", fetched_at="")
        r = vrp.check("p", "ssrf", today=self.today)
        self.assertEqual(r.code, EXIT_JUDGMENT)


if __name__ == "__main__":
    unittest.main()
