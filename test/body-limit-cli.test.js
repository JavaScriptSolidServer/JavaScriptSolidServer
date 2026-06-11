/**
 * CLI wiring for --body-limit / JSS_BODY_LIMIT (#561).
 *
 * test/body-limit.test.js covers createServer({ bodyLimit }) — the
 * programmatic path — but the CLI start command builds its createServer
 * options object by hand, and originally omitted `bodyLimit`. Result:
 * the #474 knob parsed fine and was then silently dropped, pinning every
 * CLI-started server to the 10 MiB default. git pushes of packs over the
 * default failed with 413 no matter what the operator passed (#561).
 *
 * These tests spawn `bin/jss.js start` as a real subprocess (same
 * pattern as cli-flag-like-values.test.js) and assert the limit
 * actually reaches Fastify:
 *
 *   - `--body-limit 1KB`  → a 2 KiB PUT is rejected with 413
 *   - `--body-limit 5MB`  → the same PUT is NOT rejected with 413
 *   - `JSS_BODY_LIMIT=1KB` (env, no flag) → 413, same as the flag
 *
 * The over-limit assertions are deliberately status-exact (413) while
 * the under-limit assertion is only "not 413": body parsing runs before
 * auth/WAC, so an under-limit request may still be refused later in the
 * pipeline — that's fine, the wiring under test is the parser cap.
 */

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { createServer as createNetServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'fs-extra';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(__dirname, '..', 'bin', 'jss.js');
const TEST_DATA_DIR = './test-data-body-limit-cli';

let child;

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

async function startCli({ args = [], env = {} }) {
  await fs.emptyDir(TEST_DATA_DIR);
  const port = await freePort();
  child = spawn(process.execPath, [
    BIN, 'start',
    '--port', String(port),
    '--host', '127.0.0.1',
    '--root', TEST_DATA_DIR,
    ...args,
  ], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const baseUrl = `http://127.0.0.1:${port}`;

  // Poll until the server answers (or the child dies / 15 s passes).
  const deadline = Date.now() + 15_000;
  let exited = false;
  child.once('exit', () => { exited = true; });
  while (Date.now() < deadline) {
    if (exited) throw new Error('jss CLI exited before becoming ready');
    try {
      await fetch(baseUrl, { signal: AbortSignal.timeout(1000) });
      return baseUrl;
    } catch {
      await new Promise(r => setTimeout(r, 250));
    }
  }
  throw new Error('jss CLI did not become ready within 15s');
}

async function stopCli() {
  if (!child) return;
  const c = child;
  child = null;
  if (c.exitCode === null && c.signalCode === null) {
    const gone = new Promise(r => c.once('exit', r));
    c.kill('SIGTERM');
    await Promise.race([gone, new Promise(r => setTimeout(r, 3000))]);
    if (c.exitCode === null && c.signalCode === null) c.kill('SIGKILL');
    await gone;
  }
}

async function putTwoKiB(baseUrl) {
  const res = await fetch(`${baseUrl}/body-limit-probe.bin`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: Buffer.alloc(2048, 0x61),
    signal: AbortSignal.timeout(5000),
  });
  return res.status;
}

describe('bin/jss.js — --body-limit reaches Fastify (#561)', () => {
  afterEach(async () => {
    await stopCli();
    await fs.remove(TEST_DATA_DIR);
  });

  it('--body-limit 1KB rejects a 2KiB PUT with 413', async () => {
    const baseUrl = await startCli({ args: ['--body-limit', '1KB'] });
    assert.strictEqual(await putTwoKiB(baseUrl), 413);
  });

  it('--body-limit 5MB does not 413 a 2KiB PUT', async () => {
    const baseUrl = await startCli({ args: ['--body-limit', '5MB'] });
    assert.notStrictEqual(await putTwoKiB(baseUrl), 413);
  });

  it('JSS_BODY_LIMIT=1KB (env, no flag) rejects a 2KiB PUT with 413', async () => {
    const baseUrl = await startCli({ env: { JSS_BODY_LIMIT: '1KB' } });
    assert.strictEqual(await putTwoKiB(baseUrl), 413);
  });
});
