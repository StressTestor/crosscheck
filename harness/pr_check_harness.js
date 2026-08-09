// Run a repo's OWN PR-description checker against a local draft body.
//
// These bots are written as `module.exports = async ({github, context, core})`
// for actions/github-script. Every rule lives in that file, so re-deriving the
// rules from the prose template is guesswork that drifts. Instead we stub the
// three injected objects and run the maintainer's real code. Whatever the bot
// would have commented on your PR, you get here, before you push. (｡◕‿↼)
//
// Stubs are deliberately offline: paginate returns [], every label call 404s.
// The checker's own fail-soft paths turn those into warnings, so the
// description verdict is never masked by a permissions or network detail.
//
// usage: node pr_check_harness.js <checker.js> <body-file> [--json]
// stdout: JSON {problems:[], failed:bool, message:str, warnings:[], error:str}

'use strict';

const path = require('path');
const fs = require('fs');

function fail(msg) {
  process.stdout.write(JSON.stringify({ problems: [], failed: false, error: msg }) + '\n');
  process.exit(0); // the python side decides the exit code, not us
}

const [, , checkerPath, bodyPath] = process.argv;
if (!checkerPath || !bodyPath) fail('usage: pr_check_harness.js <checker.js> <body-file>');

let body;
try {
  body = fs.readFileSync(bodyPath, 'utf8');
} catch (e) {
  fail(`cannot read body file: ${e.message}`);
}

let checker;
try {
  checker = require(path.resolve(checkerPath));
} catch (e) {
  fail(`cannot load checker: ${e.message}`);
}
if (typeof checker !== 'function') fail('checker does not export a function');

const warnings = [];
const captured = { comments: [], failedMessage: null };

const notFound = () => {
  const e = new Error('Not Found');
  e.status = 404;
  return e;
};

const github = {
  // No network. An empty comment list is the honest offline answer: it means
  // "no existing bot comment", which is exactly the first-run state.
  paginate: async () => [],
  rest: {
    issues: {
      listComments: async () => ({ data: [] }),
      createComment: async ({ body }) => { captured.comments.push(body); return { data: {} }; },
      updateComment: async ({ body }) => { captured.comments.push(body); return { data: {} }; },
      deleteComment: async () => ({ data: {} }),
      // Label management is the maintainer's surface, not a description rule.
      // 404 drives the checker's documented fail-soft path.
      getLabel: async () => { throw notFound(); },
      addLabels: async () => { throw notFound(); },
      removeLabel: async () => { throw notFound(); },
    },
  },
};

const context = {
  repo: { owner: 'local', repo: 'local' },
  eventName: 'pull_request',
  payload: {
    pull_request: {
      number: 0,
      body,
      title: process.env.CC_PR_TITLE || '',
      user: { type: 'User' },
      base: { ref: process.env.CC_BASE_REF || 'main' },
      head: { ref: process.env.CC_HEAD_REF || 'feature' },
      draft: false,
      mergeable_state: 'clean',
    },
  },
};

const core = {
  setFailed: (m) => { captured.failedMessage = String(m); },
  warning: (m) => warnings.push(String(m)),
  notice: (m) => warnings.push(String(m)),
  info: () => {},
  debug: () => {},
  error: (m) => warnings.push(String(m)),
  setOutput: () => {},
  summary: { addRaw: () => core.summary, write: async () => {} },
};

(async () => {
  let error = null;
  try {
    await checker({ github, context, core });
  } catch (e) {
    error = e && e.message ? e.message : String(e);
  }

  // The bot renders its findings as markdown bullets in the comment body.
  // Pull them back out so the caller gets a list, not a blob.
  const problems = [];
  for (const c of captured.comments) {
    for (const line of String(c).split('\n')) {
      const m = line.match(/^\s*-\s+(.*\S)\s*$/);
      if (m) problems.push(m[1]);
    }
  }

  process.stdout.write(
    JSON.stringify({
      problems,
      failed: captured.failedMessage !== null,
      message: captured.failedMessage,
      warnings,
      error,
    }) + '\n'
  );
})();
