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
import path from 'path';
import {
  initializeQuota,
  updateQuotaUsage,
  loadQuota,
  saveQuota
} from '../src/storage/quota.js';

const TEST_ROOT = path.resolve('./data-quota-race-test');
const POD = 'testpod';
let originalDataRoot;

describe('quota — concurrent updates (#309)', () => {
  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    process.env.DATA_ROOT = TEST_ROOT;
    await fs.emptyDir(TEST_ROOT);
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

  it('loadQuota tolerates an empty quota file (repair path)', async () => {
    const quotaPath = path.join(TEST_ROOT, POD, '.quota.json');
    await fs.writeFile(quotaPath, '');
    const q = await loadQuota(POD);
    assert.deepStrictEqual(q, { limit: 0, used: 0 });
  });

  it('loadQuota tolerates a corrupt (partial JSON) quota file', async () => {
    const quotaPath = path.join(TEST_ROOT, POD, '.quota.json');
    await fs.writeFile(quotaPath, '{"limit":524');
    const q = await loadQuota(POD);
    assert.deepStrictEqual(q, { limit: 0, used: 0 });
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
