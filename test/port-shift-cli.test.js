/**
 * CLI wiring for the busy-port shift (#557).
 *
 * test/port.test.js covers findFreePort/formatUrl directly; this spawns
 * `bin/jss.js start` on an occupied port and asserts the real user-facing
 * behaviour: instead of dying on EADDRINUSE, jss shifts to the next free
 * port (Vite-style), prints a notice to stderr (so it surfaces even under
 * --quiet), and actually serves there.
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
const TEST_DATA_DIR = './test-data-port-shift-cli';
const HOST = '127.0.0.1';

let child;
let blocker;

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.once('error', reject);
    srv.listen(0, HOST, () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function occupy(port) {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.once('error', reject);
    srv.listen(port, HOST, () => resolve(srv));
  });
}

async function stopCli() {
  if (!child) return;
  const c = child;
  child = null;
  if (c.exitCode !== null || c.signalCode !== null) return;
  const gone = new Promise((r) => c.once('exit', r));
  c.kill('SIGTERM');
  await Promise.race([gone, new Promise((r) => setTimeout(r, 3000))]);
  if (c.exitCode === null && c.signalCode === null) c.kill('SIGKILL');
  await Promise.race([gone, new Promise((r) => setTimeout(r, 2000))]);
}

describe('bin/jss.js — busy-port shift (#557)', () => {
  afterEach(async () => {
    await stopCli();
    if (blocker) {
      await new Promise((r) => blocker.close(r));
      blocker = null;
    }
    await fs.remove(TEST_DATA_DIR);
  });

  it('shifts to the next free port and serves there when the requested port is busy', async () => {
    await fs.emptyDir(TEST_DATA_DIR);
    const busy = await freePort();
    blocker = await occupy(busy); // hold `busy` so jss can't bind it

    let stderr = '';
    child = spawn(process.execPath, [
      BIN, 'start',
      '--port', String(busy),
      '--host', HOST,
      '--root', TEST_DATA_DIR,
      '--quiet', // banner suppressed; the shift notice still goes to stderr
    ], { env: { ...process.env }, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stderr.on('data', (d) => { stderr += d; });

    const deadline = Date.now() + 15_000;
    let exited = false;
    child.once('exit', () => { exited = true; });

    // 1. The shift notice (which carries the chosen port) must appear.
    let shifted = null;
    while (Date.now() < deadline) {
      const m = stderr.match(/using (\d+) instead/);
      if (m) { shifted = Number(m[1]); break; }
      if (exited) throw new Error(`jss exited before shifting. stderr: ${stderr}`);
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(shifted, `expected a port-shift notice on stderr; got: ${stderr || '(empty)'}`);
    assert.ok(stderr.includes(`Port ${busy} is in use`), 'notice should name the busy port');
    assert.notStrictEqual(shifted, busy);

    // 2. The server must actually serve on the shifted port.
    const url = `http://${HOST}:${shifted}`;
    let ready = false;
    while (Date.now() < deadline) {
      if (exited) throw new Error(`jss exited before serving. stderr: ${stderr}`);
      try {
        await fetch(url, { signal: AbortSignal.timeout(1000) });
        ready = true;
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    assert.ok(ready, `jss should serve on the shifted port ${shifted}`);
  });
});
