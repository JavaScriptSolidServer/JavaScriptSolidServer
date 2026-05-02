import { beforeEach, afterEach, describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';

import { createAdapter } from '../src/idp/adapter.js';

describe('FilesystemAdapter', () => {
  let tmpRoot;
  let originalDataRoot;

  beforeEach(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'jss-adapter-'));
    process.env.DATA_ROOT = tmpRoot;
  });

  afterEach(async () => {
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
    await fs.remove(tmpRoot);
  });

  it('findByUid returns a valid session whose storage id starts with underscore', async () => {
    const adapter = createAdapter('Session');
    const id = '_leadingUnderscoreSessionId';
    const uid = 'session-uid-123';

    await adapter.upsert(id, {
      uid,
      accountId: 'acct-1',
      kind: 'Session',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    }, 3600);

    const found = await adapter.findByUid(uid);

    assert.ok(found, 'expected findByUid to find underscore-prefixed session file');
    assert.strictEqual(found._id, id);
    assert.strictEqual(found.uid, uid);
  });

  it('findByUid still ignores index files', async () => {
    const adapter = createAdapter('Session');
    await fs.ensureDir(adapter.dir);
    await fs.writeJson(path.join(adapter.dir, '_session_index.json'), {
      uid: 'wrong-uid',
      _id: '_session_index',
    });

    const found = await adapter.findByUid('wrong-uid');

    assert.strictEqual(found, undefined);
  });
});