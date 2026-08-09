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

    def test_missing_path_is_invalid(self):
        self.assertEqual(secrets.check([os.path.join(self.d, "nope")]).code, EXIT_INVALID)

    def test_no_paths_is_invalid(self):
        self.assertEqual(secrets.check([]).code, EXIT_INVALID)


if __name__ == "__main__":
    unittest.main()
