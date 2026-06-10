/**
 * Git handler HTTP contract (#375).
 *
 * src/handlers/git.js previously had no automated coverage — the #371
 * (CORS) and #373 (multi-slash) fixes were verified by hand. These
 * tests pin the HTTP-level contract:
 *
 *   - OPTIONS preflight carries the canonical git CORS headers
 *   - info/refs advertise works through single/double/triple-slash
 *     URLs (#373 regression — git http-backend rejects "aliased"
 *     paths, so JSS collapses multi-slash before forwarding)
 *   - missing repo → 404 WITH CORS headers (#374 regression — without
 *     them a browser git client sees a CORS error, not the 404)
 *   - path traversal attempts are blocked (never 200, never 500)
 *     with CORS headers
 *   - unauthenticated push advertise → 401 + WWW-Authenticate + the
 *     git CORS headers (the preHandler's 401/403 path lacked them
 *     until #548; this 401 is emitted by the server.js WAC
 *     preHandler, not by handleGit)
 *   - a real end-to-end `git push` succeeds and the pushed file is
 *     served as a static resource (receive-pack POST through
 *     http-backend + updateInstead extraction)
 *
 * Boot pattern mirrors test/git-auto-init.test.js: temp data dir,
 * `git: true, public: true` so WAC is open and the handler logic is
 * exercised in isolation. The 401 case boots a second, non-public
 * server and snapshots/restores process.env.DATA_ROOT around it
 * (createServer({ root }) mutates it globally).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import { createServer as createNetServer } from 'net';
import { spawn, spawnSync } from 'child_process';
import fs from 'fs-extra';
import path from 'path';

const TEST_HOST = 'localhost';
const DATA_DIR = './test-data-git-handler';
const LOCAL_REPO = './test-data-git-handler-local';

function getAvailablePort() {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.on('error', reject);
    srv.listen(0, TEST_HOST, () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

// Synchronous git for purely-LOCAL operations (init/add/commit). Fine
// to block the event loop because no in-process server is involved.
function git(args, cwd) {
  const res = spawnSync('git', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  return {
    status: res.status,
    stdout: res.stdout?.toString() || '',
    stderr: res.stderr?.toString() || '',
  };
}

// Async git for operations that talk to the in-process test server
// (push). spawnSync would block the event loop, the server could never
// respond, and the test would deadlock until the runner times out.
//
// GIT_TERMINAL_PROMPT=0 makes git fail fast instead of waiting on a
// credential prompt if the remote unexpectedly challenges (stdin is
// 'ignore', so a prompt could otherwise wedge the test in CI). The
// `error` listener covers spawn-level failures (e.g. git missing from
// PATH), where `close` may never fire and the promise would hang.
function gitAsync(args, cwd) {
  return new Promise((resolve) => {
    const child = spawn('git', args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (err) => resolve({ status: -1, stdout, stderr: `spawn failed: ${err.message}` }));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function assertGitCors(res, label) {
  assert.strictEqual(res.headers.get('access-control-allow-origin'), '*',
    `${label}: Access-Control-Allow-Origin must be *`);
  assert.strictEqual(res.headers.get('access-control-allow-methods'), 'GET, POST, OPTIONS',
    `${label}: Access-Control-Allow-Methods mismatch`);
  assert.strictEqual(res.headers.get('access-control-allow-headers'), 'Content-Type, Authorization, Git-Protocol',
    `${label}: Access-Control-Allow-Headers must include Git-Protocol (#371)`);
}

describe('git handler HTTP contract (#375)', () => {
  let server;
  let baseUrl;
  // Repo created once in before() via a real receive-pack advertise
  // (auto-init), then reused by the advertise/slash tests below.
  const REPO = 'public/site';

  before(async () => {
    await fs.remove(DATA_DIR);
    await fs.ensureDir(DATA_DIR);

    const port = await getAvailablePort();
    baseUrl = `http://${TEST_HOST}:${port}`;

    server = createServer({
      logger: false,
      root: DATA_DIR,
      git: true,
      public: true,
    });
    await server.listen({ port, host: TEST_HOST });

    // Materialize a repo at REPO via the auto-init path so the
    // upload-pack advertise tests have something real to talk to.
    const res = await fetch(`${baseUrl}/${REPO}/info/refs?service=git-receive-pack`);
    assert.strictEqual(res.status, 200, 'prereq: auto-init advertise must succeed');
  });

  after(async () => {
    if (server) await server.close();
    await fs.remove(DATA_DIR);
    await fs.remove(LOCAL_REPO);
  });

  it('OPTIONS preflight returns 200 with the canonical git CORS headers', async () => {
    const res = await fetch(`${baseUrl}/${REPO}/info/refs?service=git-upload-pack`, {
      method: 'OPTIONS',
    });
    assert.strictEqual(res.status, 200, 'preflight must be 200');
    assertGitCors(res, 'OPTIONS preflight');
  });

  it('single-slash info/refs advertise returns 200 with the advertisement content type', async () => {
    const res = await fetch(`${baseUrl}/${REPO}/info/refs?service=git-upload-pack`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('content-type'),
      'application/x-git-upload-pack-advertisement');
  });

  it('double-slash //info/refs returns 200 (#373 regression)', async () => {
    // git http-backend rejects "aliased" multi-slash paths; JSS must
    // collapse them before forwarding or the request 500s.
    const res = await fetch(`${baseUrl}/${REPO}//info/refs?service=git-upload-pack`);
    assert.strictEqual(res.status, 200,
      `double slash must not break the advertise; got ${res.status}`);
  });

  it('triple-slash ///info/refs returns 200 (#373 regression)', async () => {
    const res = await fetch(`${baseUrl}/${REPO}///info/refs?service=git-upload-pack`);
    assert.strictEqual(res.status, 200,
      `triple slash must not break the advertise; got ${res.status}`);
  });

  it('missing repo returns 404 with CORS headers (#374 regression)', async () => {
    // upload-pack (fetch) on a non-existent path: no auto-init, plain 404.
    const res = await fetch(`${baseUrl}/public/no-such-repo/info/refs?service=git-upload-pack`);
    assert.strictEqual(res.status, 404);
    assertGitCors(res, 'missing-repo 404');
  });

  it('path traversal attempt is blocked, never 200/500, with CORS headers', async () => {
    // Percent-encoded so fetch() doesn't normalize the dots away
    // client-side. handleGit decodes, strips `..`, and containment-
    // checks the result — depending on what survives sanitization the
    // response is 403 (escape detected) or 404 (sanitized path has no
    // repo). Both are acceptable; 200 (leak) and 500 (crash) are not.
    const res = await fetch(
      `${baseUrl}/%2e%2e/%2e%2e/%2e%2e/etc/info/refs?service=git-upload-pack`);
    assert.ok(res.status === 403 || res.status === 404,
      `traversal must be blocked with 403/404, got ${res.status}`);
    assertGitCors(res, 'traversal block');
  });

  it('unauthenticated push advertise returns 401 with WWW-Authenticate and git CORS headers (non-public server, #548)', async () => {
    // Second server WITHOUT public:true so the WAC preHandler gates
    // the push. Snapshot/restore DATA_ROOT — createServer({ root })
    // mutates it process-wide and the main suite's server reads it
    // per-request.
    const DATA_DIR_AUTH = './test-data-git-handler-auth';
    await fs.remove(DATA_DIR_AUTH);
    await fs.ensureDir(DATA_DIR_AUTH);
    const port = await getAvailablePort();
    const originalDataRoot = process.env.DATA_ROOT;
    const authServer = createServer({ logger: false, root: DATA_DIR_AUTH, git: true });
    try {
      await authServer.listen({ port, host: TEST_HOST });
      const res = await fetch(
        `http://${TEST_HOST}:${port}/public/x/info/refs?service=git-receive-pack`);
      assert.strictEqual(res.status, 401,
        `unauthenticated push advertise must be 401, got ${res.status}`);
      assert.ok(res.headers.get('www-authenticate'),
        'WWW-Authenticate must be present so git CLI clients prompt for credentials');
      // #548: the WAC preHandler's 401/403 path must carry the git
      // CORS headers, or browser git clients see a generic CORS error
      // instead of the auth challenge.
      assertGitCors(res, 'unauthenticated push 401');
    } finally {
      await authServer.close();
      if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
      else process.env.DATA_ROOT = originalDataRoot;
      await fs.remove(DATA_DIR_AUTH);
    }
  });

  it('end-to-end push succeeds and the pushed file is served as a static resource', async () => {
    // Build a local repo with one file and push it. Auto-init pins the
    // server-side HEAD to refs/heads/main (#471), so pushing HEAD:main
    // triggers receive.denyCurrentBranch=updateInstead extraction and
    // the file becomes a static resource at the pod URL.
    await fs.remove(LOCAL_REPO);
    await fs.ensureDir(LOCAL_REPO);
    assert.strictEqual(git(['init', '--quiet'], LOCAL_REPO).status, 0, 'git init');
    await fs.writeFile(path.join(LOCAL_REPO, 'index.html'), '<p>pushed-via-test</p>\n');
    assert.strictEqual(git(['add', 'index.html'], LOCAL_REPO).status, 0, 'git add');
    const commit = git([
      '-c', 'user.email=test@example.invalid',
      '-c', 'user.name=jss-test',
      'commit', '--quiet', '-m', 'test commit',
    ], LOCAL_REPO);
    assert.strictEqual(commit.status, 0, `git commit failed: ${commit.stderr}`);

    const push = await gitAsync(['push', '--quiet', `${baseUrl}/public/pushed-site`, 'HEAD:main'], LOCAL_REPO);
    assert.strictEqual(push.status, 0, `git push failed: ${push.stderr.slice(0, 400)}`);

    // updateInstead extracted the working tree → file is now served.
    const res = await fetch(`${baseUrl}/public/pushed-site/index.html`);
    assert.strictEqual(res.status, 200, 'pushed file must be served over HTTP');
    const body = await res.text();
    assert.ok(body.includes('pushed-via-test'), 'served content must match the pushed file');
  });
});
