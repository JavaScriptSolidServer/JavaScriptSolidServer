/**
 * Regression tests for the quota check-and-commit race.
 *
 * saveQuota is atomic (temp + rename, #309), but check→write→record used to be
 * three separate async steps: two concurrent writers could both pass the check
 * and then overshoot the limit, and the read-modify-write in updateQuotaUsage
 * could lose updates. reserveQuota + a per-pod lock make check-and-commit
 * atomic — mirroring QuotaPolicy::reserve in the solid-pod-rs parity port.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import {
  initializeQuota,
  updateQuotaUsage,
  reserveQuota,
  loadQuota
} from '../src/storage/quota.js';

const POD = 'testpod';
let TEST_ROOT;
let originalDataRoot;

describe('quota — atomic reservation (check-and-commit race)', () => {
  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    TEST_ROOT = await fs.mkdtemp(path.join(os.tmpdir(), 'jss-quota-reserve-'));
    process.env.DATA_ROOT = TEST_ROOT;
    await fs.ensureDir(path.join(TEST_ROOT, POD));
  });

  after(async () => {
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
    await fs.remove(TEST_ROOT);
  });

  beforeEach(async () => {
    await initializeQuota(POD, 1000);
  });

  it('concurrent reservations never overshoot the limit', async () => {
    // 40 writers each try to reserve 100 bytes against a 1000-byte limit.
    // Only 10 can be admitted; a non-atomic check would let many more through.
    const N = 40;
    const results = await Promise.all(
      Array.from({ length: N }, () => reserveQuota(POD, 100, 0))
    );

    const admitted = results.filter((r) => r.allowed).length;
    assert.strictEqual(admitted, 10, 'exactly limit/size reservations may be admitted');

    const final = await loadQuota(POD);
    assert.ok(final.used <= final.limit, `used ${final.used} must not exceed limit ${final.limit}`);
    assert.strictEqual(final.used, 1000, 'committed usage must equal the admitted reservations');
  });

  it('concurrent updateQuotaUsage does not lose updates', async () => {
    await initializeQuota(POD, 10 * 1024 * 1024);
    const N = 50;
    const each = 100;
    await Promise.all(Array.from({ length: N }, () => updateQuotaUsage(POD, each)));

    const final = await loadQuota(POD);
    assert.strictEqual(final.used, N * each, 'every increment must be recorded (no lost update)');
  });

  it('a released reservation frees the space for a later writer', async () => {
    // Fill the quota, release one slot, then a new reservation must succeed.
    const filled = await Promise.all(
      Array.from({ length: 10 }, () => reserveQuota(POD, 100, 0))
    );
    assert.strictEqual(filled.filter((r) => r.allowed).length, 10);

    const overflow = await reserveQuota(POD, 100, 0);
    assert.strictEqual(overflow.allowed, false, 'quota is full');

    await updateQuotaUsage(POD, -100); // simulate a failed write releasing its reservation
    const retry = await reserveQuota(POD, 100, 0);
    assert.strictEqual(retry.allowed, true, 'freed space is reusable');
  });
});
