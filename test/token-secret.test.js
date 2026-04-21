/**
 * Unit tests for TOKEN_SECRET resolution (src/auth/token-secret.js).
 *
 * Covers #280: TOKEN_SECRET auto-persists on first run rather than hard-exiting.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  readOrWritePersistedSecret,
  resolveTokenSecret,
  DEFAULT_SECRET_PATH,
} from '../src/auth/token-secret.js';

describe('readOrWritePersistedSecret', () => {
  let tmpDir;
  let secretPath;

  before(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jss-token-secret-'));
    secretPath = path.join(tmpDir, '.jss', 'token.secret');
  });

  after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('generates + persists a secret when the file is missing', () => {
    const s = readOrWritePersistedSecret(secretPath);
    assert.strictEqual(typeof s, 'string');
    assert.strictEqual(s.length, 64); // 32 bytes, hex-encoded
    assert.strictEqual(fs.readFileSync(secretPath, 'utf8').trim(), s);
  });

  it('returns the same secret on subsequent calls', () => {
    const first  = readOrWritePersistedSecret(secretPath);
    const second = readOrWritePersistedSecret(secretPath);
    assert.strictEqual(first, second);
  });

  it('enforces tight permissions on POSIX (skipped on Windows)', { skip: process.platform === 'win32' }, () => {
    const stat = fs.statSync(secretPath);
    assert.strictEqual(stat.mode & 0o777, 0o600, 'secret file should be mode 0600');
    const dirStat = fs.statSync(path.dirname(secretPath));
    assert.strictEqual(dirStat.mode & 0o777, 0o700, 'secret dir should be mode 0700');
  });

  it('propagates errors other than ENOENT', () => {
    // Use a regular file as the would-be parent directory — mkdirSync then
    // fails with ENOTDIR synchronously. Portable across OSes.
    const blockerFile = path.join(tmpDir, 'blocker-file');
    fs.writeFileSync(blockerFile, 'not a dir');
    const unwritable = path.join(blockerFile, '.jss', 'token.secret');
    assert.throws(() => readOrWritePersistedSecret(unwritable));
  });
});

describe('resolveTokenSecret', () => {
  let tmpDir;

  before(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jss-resolve-secret-'));
  });

  after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const silentLog = { warn: () => {}, error: () => {} };

  it('prefers TOKEN_SECRET env var', () => {
    const s = resolveTokenSecret({
      env: { TOKEN_SECRET: 'from-env' },
      secretPath: path.join(tmpDir, 'unused', 'token.secret'),
      log: silentLog,
    });
    assert.strictEqual(s, 'from-env');
  });

  it('persists a generated secret when env is unset', () => {
    const p = path.join(tmpDir, 'persist', 'token.secret');
    const s = resolveTokenSecret({ env: {}, secretPath: p, log: silentLog });
    assert.strictEqual(s.length, 64);
    assert.strictEqual(fs.readFileSync(p, 'utf8').trim(), s);
  });

  it('returns the same persisted secret on the next call', () => {
    const p = path.join(tmpDir, 'persist-twice', 'token.secret');
    const first  = resolveTokenSecret({ env: {}, secretPath: p, log: silentLog });
    const second = resolveTokenSecret({ env: {}, secretPath: p, log: silentLog });
    assert.strictEqual(first, second);
  });

  // Build an unwritable path by planting a regular file where the helper
  // would try to mkdir a directory. mkdirSync then fails synchronously.
  function buildUnwritable(name) {
    const blocker = path.join(tmpDir, name, 'blocker-file');
    fs.mkdirSync(path.dirname(blocker), { recursive: true });
    fs.writeFileSync(blocker, 'not a dir');
    return path.join(blocker, '.jss', 'token.secret');
  }

  it('hard-exits in production when persistence fails', () => {
    let exitCode;
    resolveTokenSecret({
      env: { NODE_ENV: 'production' },
      secretPath: buildUnwritable('prod'),
      log: silentLog,
      exit: (code) => { exitCode = code; },
    });
    assert.strictEqual(exitCode, 1);
  });

  it('falls back to an ephemeral secret outside production when persistence fails', () => {
    const s = resolveTokenSecret({
      env: {},
      secretPath: buildUnwritable('dev'),
      log: silentLog,
      exit: () => { throw new Error('exit should not be called in dev') },
    });
    assert.strictEqual(typeof s, 'string');
    assert.strictEqual(s.length, 64);
  });
});

describe('DEFAULT_SECRET_PATH', () => {
  it('is absolute and platform-native', () => {
    assert.ok(path.isAbsolute(DEFAULT_SECRET_PATH));
    assert.ok(DEFAULT_SECRET_PATH.includes('.jss'));
    assert.ok(DEFAULT_SECRET_PATH.includes('token.secret'));
  });
});
