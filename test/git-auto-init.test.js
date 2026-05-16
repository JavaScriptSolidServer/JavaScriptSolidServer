/**
 * Git auto-init on first push.
 *
 * Verifies that `git-receive-pack` requests to a path with no existing
 * repo will (a) auto-init a bare repo when the path is empty or
 * non-existent, and (b) refuse with the existing 404 when the path
 * contains user content. ACL enforcement is exercised upstream by the
 * server's preHandler; these tests run with `public: true` so the
 * authorization gate is open and we can isolate the init logic.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import { createServer as createNetServer } from 'net';
import fs from 'fs-extra';
import path from 'path';
import { existsSync, statSync, writeFileSync, readFileSync } from 'fs';

const TEST_HOST = 'localhost';
const DATA_DIR = './test-data-git-auto-init';

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

describe('Git auto-init on first push', () => {
  let server;
  let baseUrl;

  before(async () => {
    await fs.remove(DATA_DIR);
    await fs.ensureDir(DATA_DIR);

    const port = await getAvailablePort();
    baseUrl = `http://${TEST_HOST}:${port}`;

    server = createServer({
      logger: false,
      root: DATA_DIR,
      git: true,
      public: true   // skip WAC so the auto-init logic runs in isolation
    });
    await server.listen({ port, host: TEST_HOST });
  });

  after(async () => {
    if (server) await server.close();
    await fs.remove(DATA_DIR);
  });

  it('auto-inits a regular repo on push-advertise to a non-existent path', async () => {
    const repoPath = 'public/apps/penny';
    const url = `${baseUrl}/${repoPath}/info/refs?service=git-receive-pack`;

    const res = await fetch(url);
    assert.strictEqual(res.status, 200, 'advertise must succeed (200) after auto-init');

    const repoAbs = path.resolve(DATA_DIR, repoPath);
    assert.ok(existsSync(repoAbs), 'directory must be created');
    assert.ok(statSync(repoAbs).isDirectory(), 'created path must be a directory');
    // Regular (non-bare) repo: .git/ subdirectory holds the internals.
    // Working tree lives at the path itself so pushed files become
    // static resources.
    const dotGit = path.join(repoAbs, '.git');
    assert.ok(existsSync(dotGit), '.git subdirectory must exist');
    assert.ok(statSync(dotGit).isDirectory(), '.git must be a directory');
    assert.ok(existsSync(path.join(dotGit, 'HEAD')), '.git/HEAD must exist');
    assert.ok(existsSync(path.join(dotGit, 'objects')), '.git/objects must exist');
    assert.ok(existsSync(path.join(dotGit, 'refs')), '.git/refs must exist');
  });

  it('pins the initial branch to `main` regardless of server config', async () => {
    // `updateInstead` only extracts the working tree when the push
    // targets the branch HEAD points at. If `git init` honoured the
    // server's `init.defaultBranch`, a server configured for e.g.
    // `gh-pages` would silently fail to extract files pushed to `main`.
    // Pin the auto-init'd HEAD so `git push pod HEAD:main` works
    // everywhere. See #471.
    const repoPath = 'public/apps/penny';
    const headPath = path.resolve(DATA_DIR, repoPath, '.git', 'HEAD');
    assert.ok(existsSync(headPath), 'prereq: repo from earlier test still exists');
    const head = readFileSync(headPath, 'utf8').trim();
    assert.strictEqual(head, 'ref: refs/heads/main',
      `HEAD must point at refs/heads/main, got: ${head}`);
  });

  it('auto-inits a regular repo when the target directory exists but is empty', async () => {
    const repoPath = 'public/empty-dir';
    await fs.ensureDir(path.resolve(DATA_DIR, repoPath));

    const url = `${baseUrl}/${repoPath}/info/refs?service=git-receive-pack`;
    const res = await fetch(url);
    assert.strictEqual(res.status, 200);

    const repoAbs = path.resolve(DATA_DIR, repoPath);
    assert.ok(existsSync(path.join(repoAbs, '.git', 'HEAD')), '.git/HEAD must exist');
  });

  it('refuses to auto-init when the target directory contains user content', async () => {
    const repoPath = 'public/has-files';
    const repoAbs = path.resolve(DATA_DIR, repoPath);
    await fs.ensureDir(repoAbs);
    writeFileSync(path.join(repoAbs, 'index.html'), '<p>hi</p>');

    const url = `${baseUrl}/${repoPath}/info/refs?service=git-receive-pack`;
    const res = await fetch(url);
    assert.strictEqual(res.status, 404, 'must return 404 when path has non-git content');

    // User's file must be intact and no .git should have been created.
    assert.ok(existsSync(path.join(repoAbs, 'index.html')), 'user file must survive');
    assert.ok(!existsSync(path.join(repoAbs, '.git')), 'no .git directory should appear');
  });

  it('does NOT auto-init on a fetch (`git-upload-pack`)', async () => {
    const repoPath = 'public/fetch-only';
    const url = `${baseUrl}/${repoPath}/info/refs?service=git-upload-pack`;

    const res = await fetch(url);
    assert.strictEqual(res.status, 404, 'fetch on missing repo must remain a 404');

    const repoAbs = path.resolve(DATA_DIR, repoPath);
    assert.ok(!existsSync(repoAbs), 'no directory should be created for a fetch');
  });

  it('refuses auto-init when ACL Write is not granted (unauthenticated)', async () => {
    // Spin up a *separate* server WITHOUT public:true so WAC actually
    // gates write operations. This is the contract-level guard: if a
    // future refactor of the preHandler ever lets an unauth request
    // reach handleGit, auto-init would silently materialize repos. This
    // test fails loudly in that scenario.
    const DATA_DIR_AUTH = './test-data-git-auto-init-authcheck';
    await fs.remove(DATA_DIR_AUTH);
    await fs.ensureDir(DATA_DIR_AUTH);
    const port = await getAvailablePort();
    const authBaseUrl = `http://${TEST_HOST}:${port}`;
    const authServer = createServer({
      logger: false,
      root: DATA_DIR_AUTH,
      git: true
      // NOTE: no `public: true` — WAC enforces real ACLs
    });
    try {
      await authServer.listen({ port, host: TEST_HOST });

      const repoPath = 'public/needs-auth';
      const url = `${authBaseUrl}/${repoPath}/info/refs?service=git-receive-pack`;
      const res = await fetch(url);  // no Authorization header

      assert.ok(res.status === 401 || res.status === 403,
        `expected 401/403 for unauthenticated push, got ${res.status}`);

      const repoAbs = path.resolve(DATA_DIR_AUTH, repoPath);
      assert.ok(!existsSync(repoAbs),
        'auto-init MUST NOT create a directory for an unauthenticated request');
    } finally {
      await authServer.close();
      await fs.remove(DATA_DIR_AUTH);
    }
  });

  it('subsequent pushes use the existing repo (no re-init)', async () => {
    const repoPath = 'public/apps/penny';
    const repoAbs = path.resolve(DATA_DIR, repoPath);
    // Repo was created by the first test in this suite; capture its
    // initial HEAD inode to verify we don't recreate the repo.
    const headPath = path.join(repoAbs, '.git', 'HEAD');
    assert.ok(existsSync(headPath), 'prereq: repo from earlier test still exists');
    const before = statSync(headPath);

    const url = `${baseUrl}/${repoPath}/info/refs?service=git-receive-pack`;
    const res = await fetch(url);
    assert.strictEqual(res.status, 200);

    const after = statSync(headPath);
    assert.strictEqual(after.ino, before.ino, 'HEAD inode must not change (no re-init)');
  });
});
