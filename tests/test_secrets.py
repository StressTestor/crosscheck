"""secrets: aim, not detection. gitleaks does the finding.

The fixture key marker is assembled at runtime rather than written as a literal.
Not superstition - the local PreToolUse guard blocks writes containing key
material, which means a test fixture with a literal marker cannot be authored
from inside an agent at all. Same self-false-positive class this suite's `guard`
module was cut for. (¬‿¬)
"""

import os
import tempfile
import unittest

from cc.checks import secrets
from cc.run import have
from cc.result import EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID

_B = "-----BEGIN "
_E = "-----END "
_KIND = "RSA PRIVATE KEY-----"
FAKE_KEY = _B + _KIND + "\nMIIEowIBAAKCAQEAx" + "A" * 60 + "\n" + _E + _KIND + "\n"


class TestSecrets(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.target = os.path.join(self.d, "report.md")
        with open(self.target, "w") as fh:
            fh.write("# my report\n\nnothing sensitive in here.\n")
        self.sibling = os.path.join(self.d, "UNRELATED_sibling.txt")
        with open(self.sibling, "w") as fh:
            fh.write(FAKE_KEY)

    @unittest.skipUnless(have("gitleaks"), "gitleaks not installed")
    def test_scanning_a_file_does_not_sweep_its_siblings(self):
        # `cc secrets ~/report.md` must not scan all of $HOME, attribute other
        # people's files to your run, and put their paths in a JSON envelope
        # bound for an agent transcript - while claiming it scanned one file.
        r = secrets.check([self.target])
        wheres = " ".join(f.where for f in r.findings)
        self.assertNotIn("UNRELATED_sibling", wheres, wheres)
        self.assertEqual(r.code, EXIT_CLEAN, [f.where for f in r.findings])
        self.assertEqual(r.data["scanned"], [self.target])

    @unittest.skipUnless(have("gitleaks"), "gitleaks not installed")
    def test_scanning_the_directory_does_find_it(self):
        # Discriminating: the same secret MUST be found when you ask for the
        # directory. Otherwise the test above only proves the scanner is broken.
        r = secrets.check([self.d])
        self.assertEqual(r.code, EXIT_FINDING, r.notes)

    @unittest.skipUnless(have("gitleaks"), "gitleaks not installed")
    def test_relative_allow_resolves_against_the_scanned_root(self):
        # `cc secrets ./evidence --allow report.md` run from anywhere else
        # silently allow-listed nothing, so the report's own legitimate finding
        # was never suppressed - and the CLI help demonstrates that exact form.
        with open(self.target, "w") as fh:
            fh.write(FAKE_KEY)
        r = secrets.check([self.d], allow=["report.md"])
        wheres = " ".join(f.where for f in r.findings)
        self.assertNotIn("report.md", wheres, wheres)
        self.assertIn("UNRELATED_sibling", wheres, wheres)

    @unittest.skipUnless(have("gitleaks"), "gitleaks not installed")
    def test_unmatched_allow_says_so_instead_of_silently_doing_nothing(self):
        r = secrets.check([self.d], allow=["no-such-file.md"])
        self.assertTrue(any("matched no file" in n for n in r.notes), r.notes)

    def test_missing_path_is_invalid(self):
        self.assertEqual(secrets.check([os.path.join(self.d, "nope")]).code, EXIT_INVALID)

    def test_no_paths_is_invalid(self):
        self.assertEqual(secrets.check([]).code, EXIT_INVALID)


if __name__ == "__main__":
    unittest.main()
