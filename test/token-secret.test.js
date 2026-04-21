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

  it('recovers when the secret file already exists but is empty', () => {
    // Simulates a concurrent or interrupted persistence case: the file
    // is present (so the fast path falls through the trim-empty check)
    // but carries no usable secret yet. tmp-file + renameSync repairs
    // it by overwriting atomically.
    const p = path.join(tmpDir, 'empty', '.jss', 'token.secret');
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, '');
    const s = readOrWritePersistedSecret(p);
    assert.strictEqual(s.length, 64);
    assert.strictEqual(fs.readFileSync(p, 'utf8').trim(), s);
  });

  it('tightens permissions when the file already exists with loose mode', { skip: process.platform === 'win32' }, () => {
    const p = path.join(tmpDir, 'loose', '.jss', 'token.secret');
    fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o755 });
    fs.writeFileSync(p, 'a'.repeat(64), { mode: 0o644 });
    readOrWritePersistedSecret(p);
    assert.strictEqual(fs.statSync(p).mode & 0o777, 0o600);
    assert.strictEqual(fs.statSync(path.dirname(p)).mode & 0o777, 0o700);
  });

  it('reads a pre-existing secret even when the parent dir is not writable', { skip: process.platform === 'win32' || process.getuid?.() === 0 }, () => {
    // Simulates a read-only deployment: secret provisioned ahead of time,
    // parent dir not writable for the current user. Must not block startup.
    const p = path.join(tmpDir, 'readonly-parent', '.jss', 'token.secret');
    fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
    const expected = 'b'.repeat(64);
    fs.writeFileSync(p, expected);
    fs.chmodSync(path.dirname(p), 0o500); // r-x, no write
    try {
      const s = readOrWritePersistedSecret(p);
      assert.strictEqual(s, expected);
    } finally {
      fs.chmodSync(path.dirname(p), 0o700);  // let after()'s rmSync clean up
    }
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
    assert.throws(() => {
      resolveTokenSecret({
        env: { NODE_ENV: 'production' },
        secretPath: buildUnwritable('prod'),
        log: silentLog,
        exit: (code) => { exitCode = code; },  // stubbed — doesn't actually terminate
      });
    });
    // exit(1) must still have been invoked even though we throw afterwards,
    // so a non-stubbed production process actually terminates.
    assert.strictEqual(exitCode, 1);
  });

  it('throws after exit so a stubbed exit() cannot leak undefined downstream', () => {
    // Regression: earlier versions returned undefined "for tests" after
    // calling exit(), which could let callers continue with an invalid
    // secret when exit is stubbed.
    assert.throws(
      () => resolveTokenSecret({
        env: { NODE_ENV: 'production' },
        secretPath: buildUnwritable('no-leak'),
        log: silentLog,
        exit: () => {},
      }),
      /TOKEN_SECRET/
    );
  });

  it('production error message references the actual secret directory', () => {
    const secretPath = buildUnwritable('custom-path');
    const errors = [];
    assert.throws(() => {
      resolveTokenSecret({
        env: { NODE_ENV: 'production' },
        secretPath,
        log: { warn: () => {}, error: (msg) => errors.push(msg) },
        exit: () => {},
      });
    });
    assert.ok(
      errors.some(m => m.includes(path.dirname(secretPath))),
      `expected an error to mention ${path.dirname(secretPath)}, got: ${errors.join(' | ')}`
    );
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
