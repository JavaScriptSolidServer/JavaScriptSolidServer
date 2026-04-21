/**
 * TOKEN_SECRET resolution.
 *
 * Extracted from token.js so it can be unit-tested without pulling in the
 * full auth graph (solid-oidc, nostr, webid-tls), which does module-level
 * work that keeps the node:test event loop busy.
 */

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

export const DEFAULT_SECRET_PATH = path.join(os.homedir(), '.jss', 'token.secret');

// Tighten permissions on POSIX. No-op on Windows, which uses ACLs and
// surfaces EPERM on chmod — swallow that specifically.
function chmodBestEffort(target, mode) {
  try {
    fs.chmodSync(target, mode);
  } catch (e) {
    if (e.code !== 'EPERM' && e.code !== 'ENOTSUP') throw e;
  }
}

/**
 * Read a persisted secret from `filePath`, or generate one and write it
 * (with dir mode 0700 and file mode 0600) if the file is missing. Safe
 * against multiple JSS processes starting in parallel: the write uses an
 * exclusive flag and we re-read on EEXIST, so every process converges on
 * the same secret rather than racing.
 *
 * Anything other than ENOENT on read (permission denied, read-only FS, …)
 * throws.
 */
export function readOrWritePersistedSecret(filePath = DEFAULT_SECRET_PATH) {
  // Always ensure the dir exists and is 0700 — enforce perms on every call,
  // not only when we're the one creating it. mkdirSync({mode}) is only
  // applied on creation, so an existing dir with looser mode needs chmod.
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodBestEffort(dir, 0o700);

  // Fast path: file already exists and is non-empty.
  try {
    const existing = fs.readFileSync(filePath, 'utf8').trim();
    if (existing) {
      chmodBestEffort(filePath, 0o600);
      return existing;
    }
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }

  const generated = crypto.randomBytes(32).toString('hex');
  try {
    // Exclusive create — concurrent processes can't overwrite each other's
    // freshly generated secrets. mode is honoured on POSIX; Windows ignores
    // it (uses ACLs).
    fs.writeFileSync(filePath, generated, { mode: 0o600, flag: 'wx' });
    chmodBestEffort(filePath, 0o600);
    return generated;
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
  }

  // Another process won the race — read what they wrote.
  const existing = fs.readFileSync(filePath, 'utf8').trim();
  if (existing) {
    chmodBestEffort(filePath, 0o600);
    return existing;
  }
  // Same fallback as before for a pre-existing empty file.
  fs.writeFileSync(filePath, generated, { mode: 0o600 });
  chmodBestEffort(filePath, 0o600);
  return generated;
}

/**
 * Resolve the token secret.
 *
 *   1. TOKEN_SECRET env → use it.
 *   2. Else read/create ~/.jss/token.secret.
 *   3. On file-write failure: hard-exit in production, ephemeral secret otherwise.
 *
 * Console I/O is injected so tests can assert log behaviour without spamming
 * the real console; defaults to the real console.
 */
export function resolveTokenSecret({
  env = process.env,
  secretPath = DEFAULT_SECRET_PATH,
  log = console,
  exit = (code) => process.exit(code),
} = {}) {
  if (env.TOKEN_SECRET) return env.TOKEN_SECRET;

  try {
    const s = readOrWritePersistedSecret(secretPath);
    log.warn(`Using persisted TOKEN_SECRET at ${secretPath} (set TOKEN_SECRET env var to override).`);
    return s;
  } catch (e) {
    if (env.NODE_ENV === 'production') {
      log.error(`SECURITY ERROR: TOKEN_SECRET not set and ${secretPath} is not writable (${e.message}).`);
      log.error(`Set TOKEN_SECRET explicitly, or grant write access to ${path.dirname(secretPath)}.`);
      exit(1);
      return undefined; // for tests that stub `exit`
    }
    const ephemeral = crypto.randomBytes(32).toString('hex');
    log.warn(`WARNING: Could not persist TOKEN_SECRET (${e.message}). Using ephemeral secret; tokens will not survive restarts.`);
    return ephemeral;
  }
}
