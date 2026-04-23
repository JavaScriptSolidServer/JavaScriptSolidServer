/**
 * Regression tests for #309 — concurrent quota updates causing 500s.
 *
 * Without atomic writes, two concurrent updateQuotaUsage calls race on
 * .quota.json — the second load can read an empty/partial file and
 * JSON.parse throws "Unexpected end of JSON input".
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import {
  initializeQuota,
  updateQuotaUsage,
  loadQuota,
  saveQuota,
  checkQuota
} from '../src/storage/quota.js';

const POD = 'testpod';
let TEST_ROOT;
let originalDataRoot;

describe('quota — concurrent updates (#309)', () => {
  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    TEST_ROOT = await fs.mkdtemp(path.join(os.tmpdir(), 'jss-quota-'));
    process.env.DATA_ROOT = TEST_ROOT;
    await fs.ensureDir(path.join(TEST_ROOT, POD));
    await initializeQuota(POD, 50 * 1024 * 1024);
  });

  after(async () => {
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
    await fs.remove(TEST_ROOT);
  });

  it('many concurrent updates do not throw', async () => {
    const N = 50;
    const updates = Array.from({ length: N }, (_, i) =>
      updateQuotaUsage(POD, 10 + i)
    );
    await assert.doesNotReject(Promise.all(updates));
    const final = await loadQuota(POD);
    assert.strictEqual(typeof final.used, 'number');
    assert.ok(final.used > 0);
  });

  async function withResourceAndBrokenQuota(brokenContent) {
    const resourcePath = path.join(TEST_ROOT, POD, 'resource.txt');
    const quotaPath = path.join(TEST_ROOT, POD, '.quota.json');
    const size = 321;
    await fs.writeFile(resourcePath, 'x'.repeat(size));
    await fs.writeFile(quotaPath, brokenContent);
    return { size, cleanup: () => fs.remove(resourcePath) };
  }

  it('loadQuota reconciles usage from disk when quota file is empty', async () => {
    const { size, cleanup } = await withResourceAndBrokenQuota('');
    try {
      const q = await loadQuota(POD);
      assert.strictEqual(q.limit, 0);
      assert.strictEqual(q.used, size);
    } finally { await cleanup(); }
  });

  it('loadQuota reconciles usage from disk when quota file is corrupt', async () => {
    const { size, cleanup } = await withResourceAndBrokenQuota('{"limit":524');
    try {
      const q = await loadQuota(POD);
      assert.strictEqual(q.limit, 0);
      assert.strictEqual(q.used, size);
    } finally { await cleanup(); }
  });

  it('checkQuota preserves reconciled usage when re-initializing limit', async () => {
    const { size, cleanup } = await withResourceAndBrokenQuota('');
    try {
      const defaultQuota = 10 * 1024 * 1024;
      const { quota } = await checkQuota(POD, 0, defaultQuota);
      assert.strictEqual(quota.limit, defaultQuota);
      assert.strictEqual(quota.used, size, 'reconciled usage must not be reset to 0');
    } finally { await cleanup(); }
  });

  it('saveQuota is atomic — concurrent read during save never sees empty file', async () => {
    await saveQuota(POD, { limit: 1000, used: 100 });
    const quotaPath = path.join(TEST_ROOT, POD, '.quota.json');

    // Interleave 200 saves with 200 reads; with non-atomic writes, at least
    // one read would land on a truncated file — the empty-file assertion
    // below (or the JSON.parse) would then fail.
    const ops = [];
    for (let i = 0; i < 200; i++) {
      ops.push(saveQuota(POD, { limit: 1000, used: i }));
      ops.push(fs.readFile(quotaPath, 'utf-8').then((data) => {
        assert.notStrictEqual(
          data.length,
          0,
          'concurrent read saw an empty quota file'
        );
        JSON.parse(data);
      }));
    }
    await assert.doesNotReject(Promise.all(ops));
  });
});
