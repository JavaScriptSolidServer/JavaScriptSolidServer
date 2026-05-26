/**
 * Regression tests for #531 — listContainer misclassified symlinked
 * directories as plain resources.
 *
 * `fs.readdir(dir, { withFileTypes: true })` returns Dirents with lstat
 * semantics, so `Dirent.isDirectory()` is false for ANY symlink — even one
 * pointing at a directory. listContainer relied on that flag, so a symlinked
 * sub-directory was listed without a trailing slash and typed ldp:Resource
 * instead of ldp:BasicContainer, making it unbrowsable in container listings
 * (while a direct GET, which dereferences, worked fine).
 *
 * The fix reclassifies symlink entries from the dereferenced fs.stat() that
 * listContainer already performs for size/mtime.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import { listContainer } from '../src/storage/filesystem.js';

let TEST_ROOT;
let originalDataRoot;

describe('listContainer — symlink classification (#531)', () => {
  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    TEST_ROOT = await fs.mkdtemp(path.join(os.tmpdir(), 'jss-symlink-'));
    process.env.DATA_ROOT = TEST_ROOT;

    // The container being listed.
    const box = path.join(TEST_ROOT, 'box');
    await fs.ensureDir(box);

    // Real entries.
    await fs.ensureDir(path.join(box, 'realdir'));
    await fs.writeFile(path.join(box, 'realfile.txt'), 'hi');

    // Symlink targets live outside the container (and outside DATA_ROOT) to
    // mirror the real-world case of linking external content into a pod.
    const targetDir = path.join(TEST_ROOT, 'external-dir');
    const targetFile = path.join(TEST_ROOT, 'external-file.txt');
    await fs.ensureDir(targetDir);
    await fs.writeFile(targetFile, 'external');

    await fs.symlink(targetDir, path.join(box, 'linkdir'));
    await fs.symlink(targetFile, path.join(box, 'linkfile.txt'));
    // Dangling symlink — target does not exist.
    await fs.symlink(path.join(TEST_ROOT, 'nope'), path.join(box, 'broken'));
  });

  after(async () => {
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
    await fs.remove(TEST_ROOT);
  });

  it('classifies a symlink-to-directory as a directory', async () => {
    const entries = await listContainer('box');
    const byName = Object.fromEntries(entries.map((e) => [e.name, e]));

    assert.strictEqual(byName.linkdir.isDirectory, true,
      'symlinked directory should be listed as a container');
  });

  it('keeps a symlink-to-file as a non-directory', async () => {
    const entries = await listContainer('box');
    const byName = Object.fromEntries(entries.map((e) => [e.name, e]));

    assert.strictEqual(byName['linkfile.txt'].isDirectory, false,
      'symlinked file should remain a resource');
  });

  it('does not regress real directories and files', async () => {
    const entries = await listContainer('box');
    const byName = Object.fromEntries(entries.map((e) => [e.name, e]));

    assert.strictEqual(byName.realdir.isDirectory, true);
    assert.strictEqual(byName['realfile.txt'].isDirectory, false);
  });

  it('treats a dangling symlink as a non-directory (stat throws)', async () => {
    const entries = await listContainer('box');
    const byName = Object.fromEntries(entries.map((e) => [e.name, e]));

    assert.strictEqual(byName.broken.isDirectory, false,
      'a dangling symlink keeps the lstat-based isDirectory: false');
  });
});
