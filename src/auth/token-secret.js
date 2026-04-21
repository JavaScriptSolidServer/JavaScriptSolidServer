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

// Tighten permissions on POSIX, best-effort. No-op on Windows (ACLs) and
// on read-only filesystems — we never want perm-tightening to block using
// an otherwise-valid secret.
function chmodBestEffort(target, mode) {
  try {
    fs.chmodSync(target, mode);
  } catch {
    // Intentionally swallow — perms are defensive hardening, not required.
  }
}

/**
 * Read a persisted secret from `filePath`, or generate one and write it
 * (with dir mode 0700 and file mode 0600) if the file is missing.
 *
 * Read-first: if the file already exists and is non-empty we return it
 * without trying to mkdir or tighten the containing directory. Deployments
 * with a pre-provisioned secret on a read-only filesystem boot cleanly.
 *
 * Concurrent-startup safe: new secrets are written to a per-process temp
 * file in the same directory and `renameSync`'d into place, so another
 * process reading the target never sees a half-written file. If a peer
 * process won the rename we fall back to reading their value.
 *
 * Anything other than ENOENT on the initial read (permission denied,
 * corrupt FS, …) propagates.
 */
export function readOrWritePersistedSecret(filePath = DEFAULT_SECRET_PATH) {
  const dir = path.dirname(filePath);

  // Fast path: pre-existing non-empty file. We do not mkdir the parent
  // dir here, and perm-tightening is best-effort (chmodBestEffort swallows
  // all errors), so a pre-provisioned secret on a read-only filesystem
  // still boots cleanly.
  try {
    const existing = fs.readFileSync(filePath, 'utf8').trim();
    if (existing) {
      chmodBestEffort(dir, 0o700);
      chmodBestEffort(filePath, 0o600);
      return existing;
    }
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }

  // Slow path: create it. Only touch the FS with writes from here on.
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodBestEffort(dir, 0o700);

  const generated = crypto.randomBytes(32).toString('hex');
  // Atomic write: fully write a temp file, then rename into place. On
  // POSIX the rename is atomic, so concurrent readers see either the old
  // content or the new complete content — never a half-written file.
  const tmpPath = `${filePath}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmpPath, generated, { mode: 0o600 });
    fs.renameSync(tmpPath, filePath);
  } catch (e) {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
    throw e;
  }
  chmodBestEffort(filePath, 0o600);

  // Multiple processes racing each produce a different secret; only the
  // last renamer's value sticks on disk. Re-read so every process ends up
  // using the winning secret and token verification stays consistent.
  const persisted = fs.readFileSync(filePath, 'utf8').trim();
  return persisted || generated;
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
      const code = e?.code ? ` [${e.code}]` : '';
      log.error(`SECURITY ERROR: TOKEN_SECRET not set and ${secretPath} could not be read or created${code} (${e.message}).`);
      log.error(`Set TOKEN_SECRET explicitly, or grant the necessary access to ${path.dirname(secretPath)}.`);
      exit(1);
      // `exit` is injectable; if a caller stubs it out we must not silently
      // return undefined and let downstream code use an invalid secret.
      throw new Error(`Failed to resolve TOKEN_SECRET in production: ${e.message}`);
    }
    const ephemeral = crypto.randomBytes(32).toString('hex');
    log.warn(`WARNING: Could not persist TOKEN_SECRET (${e.message}). Using ephemeral secret; tokens will not survive restarts.`);
    return ephemeral;
  }
}
