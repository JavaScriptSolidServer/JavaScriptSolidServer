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

/**
 * Read a persisted secret from `filePath`, or generate one and write it
 * (with dir mode 0700 and file mode 0600) if the file is missing.
 * Anything other than ENOENT (permission denied, read-only FS, …) throws.
 */
export function readOrWritePersistedSecret(filePath = DEFAULT_SECRET_PATH) {
  try {
    const existing = fs.readFileSync(filePath, 'utf8').trim();
    if (existing) return existing;
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
  const generated = crypto.randomBytes(32).toString('hex');
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  // mode is honoured on POSIX; silently ignored on Windows (uses ACLs).
  fs.writeFileSync(filePath, generated, { mode: 0o600 });
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
      log.error('Set TOKEN_SECRET explicitly, or grant write access to ~/.jss/.');
      exit(1);
      return undefined; // for tests that stub `exit`
    }
    const ephemeral = crypto.randomBytes(32).toString('hex');
    log.warn(`WARNING: Could not persist TOKEN_SECRET (${e.message}). Using ephemeral secret; tokens will not survive restarts.`);
    return ephemeral;
  }
}
