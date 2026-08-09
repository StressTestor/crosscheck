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

// Load the checker WITHOUT node's module loader.
//
// Two reasons. First, `require()` walks every parent directory looking for
// package.json/node_modules, so a filesystem allowlist tight enough to be
// worth having also breaks the load. Second, and more to the point: this is
// JavaScript out of a cloned repo. A repo you pulled an hour ago to audit is
// attacker-controlled code running as you.
//
// So we read the single file ourselves and evaluate it in a vm context whose
// `require` is deny-by-default. Legitimate github-script checkers only touch
// the injected {github, context, core}; anything reaching for fs or
// child_process is not doing PR-description validation. >:[
const vm = require('vm');

const ALLOWED_MODULES = new Set(['path', 'util', 'url', 'querystring', 'string_decoder']);

function guardedRequire(name) {
  const clean = String(name).replace(/^node:/, '');
  if (ALLOWED_MODULES.has(clean)) return require(clean);
  const e = new Error(
    `crosscheck sandbox: this checker tried to require('${name}'). ` +
    `Only ${[...ALLOWED_MODULES].join(', ')} are permitted.`
  );
  e.code = 'CROSSCHECK_SANDBOX_DENIED';
  throw e;
}

let source;
try {
  source = fs.readFileSync(path.resolve(checkerPath), 'utf8');
} catch (e) {
  fail(`cannot read checker: ${e.message}`);
}

let checker;
try {
  const moduleObj = { exports: {} };
  const sandbox = {
    module: moduleObj,
    exports: moduleObj.exports,
    require: guardedRequire,
    console: { log() {}, error() {}, warn() {}, info() {}, debug() {} },
    process: { env: {}, platform: process.platform, version: process.version },
    Buffer,
    URL,
    URLSearchParams,
    TextEncoder,
    TextDecoder,
    setTimeout, clearTimeout, setInterval, clearInterval,
    __filename: path.resolve(checkerPath),
    __dirname: path.dirname(path.resolve(checkerPath)),
  };
  vm.createContext(sandbox);
  // A timeout here only bounds synchronous top-level work; the await below is
  // bounded by the caller's own subprocess timeout.
  new vm.Script(source, { filename: path.resolve(checkerPath) }).runInContext(sandbox, { timeout: 10000 });
  checker = moduleObj.exports;
  if (checker && typeof checker.default === 'function') checker = checker.default;
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
