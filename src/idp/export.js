/**
 * GET /idp/account/export — self-service pod data download (#353).
 *
 * The export side of the user-rights trio (#351 password change,
 * #352 account delete, this). Authenticated owner downloads a
 * streamed tar.gz of their pod tree + a manifest. End users walk
 * away with what they own without operator help and without
 * shell access.
 *
 * Per the Credible Exit framing (#448), the archive intentionally
 * INCLUDES `/private/privkey.jsonld` when the pod was provisioned
 * with `--provision-keys`. The user's secret IS theirs and must
 * leave with them — refusing would make L4+ identity migration
 * impossible. The endpoint is owner-authenticated; the secret
 * never leaves the WAC perimeter to anyone but the owner.
 *
 * Streaming pipeline: tar.pack → zlib.createGzip → reply. Memory
 * stays constant regardless of pod size; a multi-GB pod doesn't
 * OOM the server.
 *
 * Failure modes:
 *   401 — unauthenticated
 *   403 — multi-user: no account for the caller's WebID
 *   404 — pod directory unexpectedly missing (shouldn't happen for
 *         an account with a valid WebID, but caught defensively)
 *
 * Out of scope: re-import, cross-server pod migration, periodic
 * scheduled backups, partial / per-resource selection. See #353.
 */

import path from 'path';
import fs from 'fs';
import { promises as fsp } from 'fs';
import zlib from 'zlib';
import tar from 'tar-stream';
import { getWebIdFromRequestAsync } from '../auth/token.js';
import { findByWebId } from './accounts.js';

/**
 * @param {object} request - Fastify request
 * @param {object} reply - Fastify reply
 * @param {object} options
 * @param {boolean} [options.singleUser]
 * @param {string|null} [options.singleUserName] - null for root pod,
 *   string for /<name>/ pod
 * @param {string} [options.jssVersion] - written into the manifest
 *   for forensic / "what server made this" purposes
 */
export async function handleExportAccount(request, reply, options = {}) {
  // 1. Authenticate caller. Same path as DELETE /idp/account etc.;
  // works with bearer tokens, LWS-CID JWTs, etc. — anything
  // getWebIdFromRequestAsync resolves to a WebID.
  const { webId, error: authError } = await getWebIdFromRequestAsync(request);
  if (!webId) {
    return reply.code(401).send({
      error: 'invalid_token',
      error_description: authError || 'Authentication required',
    });
  }

  // 2. Resolve the pod tree on disk + the manifest data.
  const dataRoot = process.env.DATA_ROOT || './data';
  let podDir;
  let accountRecord = null;
  let manifest;

  if (options.singleUser) {
    // Single-user: pod is at `/` (root pod) or `/<name>/` based on
    // singleUserName. There's at most one IDP account; if it exists
    // include it, else emit a single-user manifest with no account.
    const isRootPod = !options.singleUserName;
    podDir = isRootPod
      ? dataRoot
      : path.join(dataRoot, options.singleUserName);

    accountRecord = await findByWebId(webId);   // may be null in --no-idp mode
    manifest = {
      webId,
      mode: 'single-user',
      podName: isRootPod ? null : options.singleUserName,
      exportedAt: new Date().toISOString(),
      jssVersion: options.jssVersion ?? 'unknown',
    };
  } else {
    // Multi-user: caller's WebID must resolve to an account record
    // on this server. Same 403 shape as DELETE /idp/account uses
    // when an authenticated WebID has no local account.
    accountRecord = await findByWebId(webId);
    if (!accountRecord) {
      return reply.code(403).send({
        error: 'forbidden',
        error_description: 'No account found for authenticated WebID',
      });
    }
    const podName = accountRecord.podName || accountRecord.username;
    podDir = path.join(dataRoot, podName);
    manifest = {
      webId: accountRecord.webId,
      username: accountRecord.username,
      email: accountRecord.email,
      podName,
      mode: 'multi-user',
      createdAt: accountRecord.createdAt,
      exportedAt: new Date().toISOString(),
      jssVersion: options.jssVersion ?? 'unknown',
    };
  }

  // Defensive: the pod dir should exist for any legitimate caller.
  // 404 lets the client distinguish "auth was fine, but there's
  // nothing on disk" from a true server error.
  try {
    const st = await fsp.stat(podDir);
    if (!st.isDirectory()) throw new Error('not a directory');
  } catch {
    return reply.code(404).send({
      error: 'not_found',
      error_description: `No pod directory at ${podDir}`,
    });
  }

  // 3. Set headers and start streaming.
  const slug = sanitizeSlug(webId);
  const isoDate = manifest.exportedAt.replace(/[:.]/g, '-');
  const filename = `jss-export-${slug}-${isoDate}.tar.gz`;

  reply
    .type('application/x-tar+gzip')
    .header('Content-Disposition', `attachment; filename="${filename}"`)
    .header('Cache-Control', 'no-store');

  const pack = tar.pack();
  const gzip = zlib.createGzip();
  pack.pipe(gzip);

  // Pump in the background; entries are added asynchronously below.
  const streamingPromise = packExport({
    pack,
    podDir,
    manifest,
    accountRecord,
  }).catch((err) => {
    // Once headers + body bytes are out, the only thing we can do is
    // destroy the stream and let Fastify surface the connection drop.
    request.log?.error({ err }, 'pod export failed mid-stream');
    pack.destroy(err);
  });

  // Don't await streamingPromise here — Fastify will close the
  // response when `gzip` ends. We do attach the catch above so an
  // error during traversal is logged instead of being swallowed.
  void streamingPromise;

  return reply.send(gzip);
}

async function packExport({ pack, podDir, manifest, accountRecord }) {
  // Manifest first so consumers can read the shape before deciding
  // whether to keep streaming the (potentially large) pod tree.
  await addEntry(pack, 'jss-export/manifest.json',
    Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));

  // Account record minus passwordHash. Single-user mode without an
  // IDP account skips this (no record to include).
  if (accountRecord) {
    const { passwordHash: _omit, ...safeAccount } = accountRecord;
    await addEntry(pack, 'jss-export/account.json',
      Buffer.from(JSON.stringify(safeAccount, null, 2), 'utf8'));
  }

  // Pod tree. Walk the directory, stream each file in turn. Symlinks
  // are followed (we want the file content, not the link metadata).
  await walkAndPack(pack, podDir, 'jss-export/pod');

  pack.finalize();
}

/**
 * Recursively pack `dir` into `pack` under the tar prefix `tarBase`.
 */
async function walkAndPack(pack, dir, tarBase) {
  const entries = await fsp.readdir(dir, { withFileTypes: true });
  for (const dirent of entries) {
    const fullPath = path.join(dir, dirent.name);
    const tarPath = `${tarBase}/${dirent.name}`;
    if (dirent.isDirectory()) {
      await walkAndPack(pack, fullPath, tarPath);
    } else if (dirent.isFile()) {
      const stat = await fsp.stat(fullPath);
      // Stream the file into the entry — keeps memory constant
      // even for large media files in a pod.
      await new Promise((resolve, reject) => {
        const entry = pack.entry(
          { name: tarPath, size: stat.size, mode: stat.mode & 0o777 },
          (err) => err ? reject(err) : resolve(),
        );
        fs.createReadStream(fullPath).pipe(entry);
      });
    }
    // Symlinks, sockets, etc. are intentionally skipped — they're
    // out of scope for "downloadable pod data" and would complicate
    // restore semantics without serving a real use case.
  }
}

/**
 * Add a single in-memory entry to the tar pack. Promisified wrapper
 * around `pack.entry({...}, callback)` so the caller can await.
 */
function addEntry(pack, name, content) {
  return new Promise((resolve, reject) => {
    pack.entry({ name, size: content.length }, content, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

/**
 * Squash a WebID into something safe for a download filename.
 * Just enough to be useful as a hint; doesn't need to round-trip.
 */
function sanitizeSlug(webId) {
  return webId
    .replace(/^https?:\/\//, '')
    .replace(/[#?].*$/, '')
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .slice(0, 80) || 'pod';
}
