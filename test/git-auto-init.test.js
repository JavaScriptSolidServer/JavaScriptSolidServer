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
import { existsSync, statSync, writeFileSync } from 'fs';

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

  it('auto-inits a bare repo on push-advertise to a non-existent path', async () => {
    const repoPath = 'public/apps/penny';
    const url = `${baseUrl}/${repoPath}/info/refs?service=git-receive-pack`;

    const res = await fetch(url);
    assert.strictEqual(res.status, 200, 'advertise must succeed (200) after auto-init');

    const repoAbs = path.resolve(DATA_DIR, repoPath);
    assert.ok(existsSync(repoAbs), 'directory must be created');
    assert.ok(statSync(repoAbs).isDirectory(), 'created path must be a directory');
    // Bare repo: HEAD + objects/ + refs/ live at the path itself.
    assert.ok(existsSync(path.join(repoAbs, 'HEAD')), 'bare repo HEAD must exist');
    assert.ok(existsSync(path.join(repoAbs, 'objects')), 'bare repo objects/ must exist');
    assert.ok(existsSync(path.join(repoAbs, 'refs')), 'bare repo refs/ must exist');
  });

  it('auto-inits a bare repo when the target directory exists but is empty', async () => {
    const repoPath = 'public/empty-dir';
    await fs.ensureDir(path.resolve(DATA_DIR, repoPath));

    const url = `${baseUrl}/${repoPath}/info/refs?service=git-receive-pack`;
    const res = await fetch(url);
    assert.strictEqual(res.status, 200);

    const repoAbs = path.resolve(DATA_DIR, repoPath);
    assert.ok(existsSync(path.join(repoAbs, 'HEAD')), 'bare repo HEAD must exist');
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
    assert.ok(!existsSync(path.join(repoAbs, 'HEAD')), 'no bare-repo files should appear');
    assert.ok(!existsSync(path.join(repoAbs, 'objects')), 'no bare-repo objects/ should appear');
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
    // initial HEAD inode/mtime to verify we don't recreate the repo.
    const headPath = path.join(repoAbs, 'HEAD');
    assert.ok(existsSync(headPath), 'prereq: repo from earlier test still exists');
    const before = statSync(headPath);

    const url = `${baseUrl}/${repoPath}/info/refs?service=git-receive-pack`;
    const res = await fetch(url);
    assert.strictEqual(res.status, 200);

    const after = statSync(headPath);
    assert.strictEqual(after.ino, before.ino, 'HEAD inode must not change (no re-init)');
  });
});
