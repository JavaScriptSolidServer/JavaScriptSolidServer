/**
 * storage.withLock: a slow holder keeps its lock, a dead holder loses it (#600)
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import { withLock, lockPathFor } from '../src/storage/filesystem.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let ROOT, originalDataRoot;

describe('withLock', () => {
  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    ROOT = await fs.mkdtemp(path.join(os.tmpdir(), 'jss-lock-'));
    process.env.DATA_ROOT = ROOT;
    await fs.ensureDir(path.join(ROOT, 'pod'));
  });

  after(async () => {
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT; else process.env.DATA_ROOT = originalDataRoot;
    await fs.remove(ROOT);
  });

  it('a holder slower than the stale timeout keeps the lock: the second writer waits for it', async () => {
    const log = [];
    const opts = { staleMs: 100, waitMs: 5000 };
    const a = withLock('/pod/slow.json', async () => { await sleep(400); log.push('A done'); }, opts);
    await sleep(20);
    const b = withLock('/pod/slow.json', async () => { log.push('B start'); }, opts);
    await Promise.all([a, b]);
    assert.deepStrictEqual(log, ['A done', 'B start']);
  });

  it('a lock left by a dead holder is broken after the stale timeout', async () => {
    const lockPath = lockPathFor('/pod/dead.json');
    await fs.writeFile(lockPath, '');
    const old = new Date(Date.now() - 60_000);
    await fs.utimes(lockPath, old, old);
    const started = Date.now();
    let ran = false;
    await withLock('/pod/dead.json', async () => { ran = true; }, { staleMs: 100, waitMs: 5000 });
    assert.ok(ran, 'fn ran');
    assert.ok(Date.now() - started < 1000, 'acquired without waiting out the timeout');
    assert.ok(!await fs.pathExists(lockPath), 'lock removed afterwards');
  });

  it('a live lock that is never released ends in ELOCKED after waitMs', async () => {
    const lockPath = lockPathFor('/pod/held.json');
    await fs.writeFile(lockPath, '');
    const keep = setInterval(() => { const n = new Date(); fs.utimes(lockPath, n, n).catch(() => {}); }, 20);
    try {
      await assert.rejects(withLock('/pod/held.json', async () => {}, { staleMs: 100, waitMs: 300 }), (e) => e.code === 'ELOCKED');
    } finally {
      clearInterval(keep);
      await fs.remove(lockPath);
    }
  });
});
