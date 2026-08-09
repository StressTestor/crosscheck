"""pr-body and ci.

pr-body's contract is that it executes the REPO'S checker, so the fixture here
is a real (tiny) github-script-shaped bot, not a mock of our own rules.
"""

import os
import shutil
import tempfile
import unittest

from cc.checks import prbody, ci
from cc.run import have
from cc.result import EXIT_CLEAN, EXIT_FINDING, EXIT_INVALID, EXIT_JUDGMENT

BOT = """
'use strict';
module.exports = async ({github, context, core}) => {
  const body = context.payload.pull_request.body || '';
  const problems = [];
  if (!/## Summary\\s*\\n[\\s\\S]{10,}/.test(body)) problems.push('**Summary** is missing.');
  if (!/#\\d+/.test(body)) problems.push('**Linked Issue** is missing.');
  if (problems.length) {
    await github.rest.issues.createComment({owner:'o', repo:'r', issue_number:1,
      body: ['<!-- marker -->', ...problems.map(p => `- ${p}`)].join('\\n')});
    core.setFailed(`${problems.length} issue(s)`);
  }
};
"""


class TestPrBody(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.repo, ".github", "scripts"))
        with open(os.path.join(self.repo, ".github", "scripts", "check-pr-description.js"), "w") as fh:
            fh.write(BOT)
        self.body = os.path.join(self.repo, "draft.md")

    def _draft(self, text):
        with open(self.body, "w") as fh:
            fh.write(text)
        return self.body

    @unittest.skipUnless(have("node"), "node not installed")
    def test_runs_the_repos_own_bot_and_reports_its_problems(self):
        r = prbody.check(self.repo, self._draft("nothing here"))
        self.assertEqual(r.code, EXIT_FINDING)
        whats = " ".join(f.what for f in r.findings)
        self.assertIn("Summary", whats)
        self.assertIn("Linked Issue", whats)

    @unittest.skipUnless(have("node"), "node not installed")
    def test_good_draft_passes_the_repos_bot(self):
        # Discriminating: a check that only ever fails proves nothing.
        r = prbody.check(self.repo, self._draft("## Summary\nthis is a real summary of the change\n\nFixes #12\n"))
        self.assertEqual(r.code, EXIT_CLEAN, [f.what for f in r.findings])

    def test_empty_draft_is_a_finding(self):
        r = prbody.check(self.repo, self._draft("   "))
        self.assertEqual(r.code, EXIT_FINDING)

    def test_missing_body_file_is_invalid(self):
        self.assertEqual(prbody.check(self.repo, "/nope/nope.md").code, EXIT_INVALID)

    def test_template_fallback_when_no_bot(self):
        repo = tempfile.mkdtemp()
        os.makedirs(os.path.join(repo, ".github"))
        with open(os.path.join(repo, ".github", "pull_request_template.md"), "w") as fh:
            fh.write("## Summary\n\n## Testing\n")
        body = os.path.join(repo, "d.md")
        with open(body, "w") as fh:
            fh.write("## Summary\nyes\n")
        r = prbody.check(repo, body)
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertIn("Testing", r.findings[0].where)

    def test_no_bot_and_no_template_is_clean(self):
        repo = tempfile.mkdtemp()
        body = os.path.join(repo, "d.md")
        with open(body, "w") as fh:
            fh.write("anything\n")
        self.assertEqual(prbody.check(repo, body).code, EXIT_CLEAN)

    def test_conventional_title_enforced_only_when_repo_asks(self):
        repo = tempfile.mkdtemp()
        os.makedirs(os.path.join(repo, ".github", "workflows"))
        with open(os.path.join(repo, ".github", "workflows", "t.yml"), "w") as fh:
            fh.write("name: x\n# Conventional Commits enforced here\n")
        body = os.path.join(repo, "d.md")
        with open(body, "w") as fh:
            fh.write("hello\n")
        self.assertTrue(prbody.enforces_conventional_title(repo))
        r = prbody.check(repo, body, title="not conventional")
        self.assertTrue(any("Conventional Commits" in f.what for f in r.findings))
        r2 = prbody.check(repo, body, title="fix(scope): real summary")
        self.assertFalse(any("Conventional Commits" in f.what for f in r2.findings))


UNPINNED = """
name: x
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""

PINNED = """
name: x
on: [push]
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
"""


class TestCi(unittest.TestCase):
    def _repo(self, content, name="w.yml"):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, ".github", "workflows"))
        with open(os.path.join(d, ".github", "workflows", name), "w") as fh:
            fh.write(content)
        return d

    def test_unpinned_action_is_a_finding(self):
        r = ci.check(self._repo(UNPINNED), audit=False)
        self.assertEqual(r.code, EXIT_FINDING)
        self.assertTrue(any("mutable tag" in f.what for f in r.findings))

    def test_missing_permissions_block_is_a_finding(self):
        r = ci.check(self._repo(UNPINNED), audit=False)
        self.assertTrue(any("no permissions block" in f.what for f in r.findings))

    def test_pinned_and_scoped_has_no_pin_or_permission_finding(self):
        r = ci.check(self._repo(PINNED), audit=False)
        pin_or_perm = [f for f in r.findings if "mutable tag" in f.what or "no permissions block" in f.what]
        self.assertEqual(pin_or_perm, [], [f.what for f in pin_or_perm])

    def test_no_workflows_is_clean(self):
        self.assertEqual(ci.check(tempfile.mkdtemp(), audit=False).code, EXIT_CLEAN)

    def test_touching_a_workflow_routes_to_gha_review(self):
        # The routing contract is the `route` payload plus a judgment-severity
        # finding. The aggregate code may legitimately be FINDING instead of
        # JUDGMENT when the installed SAST also has something to say - findings
        # outrank judgments - so assert the contract, not the aggregate.
        d = self._repo(PINNED)
        r = ci.check(d, changed=[".github/workflows/w.yml"], audit=False)
        self.assertEqual(r.data["route"]["gate"], "gha-security-review")
        self.assertEqual(r.data["route"]["workflowFiles"], [".github/workflows/w.yml"])
        self.assertTrue(any(f.severity == "judgment" for f in r.findings))
        self.assertIn(r.code, (EXIT_JUDGMENT, EXIT_FINDING))

    def test_no_changed_files_means_no_route(self):
        r = ci.check(self._repo(PINNED), audit=False)
        self.assertNotIn("route", r.data)

    def test_actionlint_self_diagnostics_are_not_findings(self):
        # "no project was found in any parent directories" is actionlint
        # talking about itself. Reporting it as a security finding is how a
        # tool earns a mute.
        d = self._repo(PINNED)
        r = ci.check(d, audit=False)
        self.assertFalse(
            any("no project was found" in (f.detail or "") for f in r.findings),
            [f.detail for f in r.findings],
        )

    def test_require_sast_without_tools_is_invalid(self):
        d = self._repo(PINNED)
        real = ci.have
        ci.have = lambda t: False  # simulate a machine with no SAST installed
        try:
            r = ci.check(d, require_sast=True, audit=False)
            self.assertEqual(r.code, EXIT_INVALID)
        finally:
            ci.have = real

    def test_composite_action_pins_are_scanned(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, ".github", "workflows"))
        with open(os.path.join(d, ".github", "workflows", "w.yml"), "w") as fh:
            fh.write(PINNED)
        os.makedirs(os.path.join(d, ".github", "actions", "thing"))
        with open(os.path.join(d, ".github", "actions", "thing", "action.yml"), "w") as fh:
            fh.write("runs:\n  steps:\n    - uses: some/action@v1\n")
        r = ci.check(d, audit=False)
        self.assertTrue(any("action.yml" in f.where for f in r.findings), [f.where for f in r.findings])


if __name__ == "__main__":
    unittest.main()
