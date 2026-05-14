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
 * Cross-account access is structurally impossible: the endpoint
 * takes no target parameter and always scopes to the caller's
 * authenticated WebID. There's no `403 cross-account` failure mode
 * because there's no path to attempt the access in the first place.
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
 * Entries at the data root that are server-internal, not pod data.
 * In single-user *root* pod mode, podDir IS dataRoot — packing it
 * naively would ship server-managed material to the caller. Skip:
 *
 *   .idp/      — IDP accounts (passwordHash for every user!) +
 *                 signing keys (mint tokens for any user) +
 *                 OIDC adapter state (sessions, refresh tokens)
 *   .private/  — pay/Bitcoin keypair + UTXO state (drainable)
 *
 * The pod's *own* /private/ folder (no leading dot) lives at
 * <dataRoot>/private/ in root-pod mode and IS pod data — operator
 * key, etc. — and is INCLUDED.
 *
 * Public namespaces under .well-known/ (webledgers, openid-config,
 * etc.) are reachable by any HTTP client by spec, so they're
 * "pod data" in the sense that they're part of the pod's public
 * surface — included.
 *
 * Named-pod single-user (podDir = <dataRoot>/<name>/) and multi-user
 * (podDir = <dataRoot>/<podName>/) don't hit this code path — the
 * pod tree is already isolated by the path layout.
 *
 * !!! SECURITY-CRITICAL — DO NOT ADD A NEW SERVER-INTERNAL TOP-LEVEL
 * DIRECTORY WITHOUT ALSO ADDING IT HERE AND ADDING A REGRESSION TEST.
 *
 * We use a denylist (not an allowlist of pod-data subdirs) because
 * pod content is open-ended — operators and apps create arbitrary
 * top-level containers, and an allowlist would break Credible Exit
 * by silently dropping legitimate user data. The trade-off: any new
 * server-managed dotfile dir landing at the data root must be added
 * here in the same PR that introduces it. The denylist test in
 * test/idp-export.test.js asserts on the property "no IdP secrets
 * appear in the archive" against on-disk seeded files, so it will
 * regress loudly if a future feature drops a secret-bearing dir at
 * the data root and forgets to update this set.
 */
const ROOT_POD_EXCLUDE = new Set(['.idp', '.private']);

/**
 * Allowlist of account record fields that are safe to include in
 * `account.json`. Defensive: a denylist that strips only
 * `passwordHash` would silently leak any future secret-bearing
 * field added to the account schema (passkey credential records,
 * OIDC client secrets, recovery tokens, etc.).
 *
 * Adding a new field here requires a security review. Passkey
 * credentials are intentionally NOT included — they're device-
 * bound and not portable to a fresh server.
 */
const ACCOUNT_EXPORT_FIELDS = [
  'id', 'webId', 'username', 'email', 'podName', 'createdAt', 'updatedAt',
  'passwordChangedAt', 'lastLoginAt',
];

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
  let isRootPod = false;

  if (options.singleUser) {
    // Single-user: pod is at `/` (root pod) or `/<name>/` based on
    // singleUserName. The seeded IDP account (per
    // seedSingleUserIdpAccount in src/server.js) is the sole owner —
    // an authenticated WebID without a matching local account is
    // some third-party identity (external Solid-OIDC, LWS-CID JWT,
    // etc.), NOT the pod owner, and must not get the operator's
    // /private/privkey.jsonld. The route is only mounted when
    // idpEnabled, so a missing account record means "caller is not
    // the seeded owner" — refuse with the same 403 shape as
    // multi-user.
    isRootPod = !options.singleUserName;
    podDir = isRootPod
      ? dataRoot
      : path.join(dataRoot, options.singleUserName);

    accountRecord = await findByWebId(webId);
    if (!accountRecord) {
      return reply.code(403).send({
        error: 'forbidden',
        error_description:
          'Authenticated WebID does not match the single-user account',
      });
    }
    // manifest.podName mirrors the IDP account's podName (the OIDC
    // short name) for parity with the multi-user branch — both
    // branches now read podName from accountRecord, so a downstream
    // importer keying on manifest.podName or account.json.podName
    // gets the same answer regardless of server mode. Filesystem
    // layout (root-pod vs /<name>/ pod) is conveyed by `mode` +
    // the seeded podName ('me' for root-pod, singleUserName otherwise).
    manifest = {
      webId: accountRecord.webId,
      username: accountRecord.username,
      email: accountRecord.email,
      podName: accountRecord.podName,
      mode: 'single-user',
      createdAt: accountRecord.createdAt,
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

  // sanitizeSlug() restricts the slug to [A-Za-z0-9._-] and isoDate
  // is ISO-8601 with `:`/`.` replaced — both are strict-ASCII safe
  // for the legacy `filename=` form. Also emit `filename*=UTF-8''…`
  // (RFC 5987) so any future non-ASCII slip-through degrades to
  // valid UTF-8 percent-encoding rather than a malformed header.
  const cdValue =
    `attachment; filename="${filename}"; ` +
    `filename*=UTF-8''${encodeURIComponent(filename)}`;
  reply
    .type('application/x-tar+gzip')
    .header('Content-Disposition', cdValue)
    .header('Cache-Control', 'no-store');

  const pack = tar.pack();
  const gzip = zlib.createGzip();
  pack.pipe(gzip);

  // Surface stream-level errors. Once response headers are out an
  // EACCES / mid-pack failure can otherwise present as a silently
  // truncated download — the client gets 200 + partial gzip + no
  // error signal. We log on the server side and destroy the
  // pipeline so the client at least sees an aborted transfer rather
  // than a corrupt but seemingly-complete archive.
  // Idempotent: invoked from pack.error, gzip.error, AND
  // streamingPromise.catch. Destroying a stream re-emits 'error',
  // which would re-enter this handler and produce duplicate log
  // lines for one underlying failure. The destroyed-flag short-
  // circuits all subsequent calls so a single failure logs once.
  const onStreamError = (err) => {
    if (gzip.destroyed || pack.destroyed) return;
    request.log.error({ err }, 'pod export stream error');
    pack.destroy(err);
    gzip.destroy(err);
  };
  pack.on('error', onStreamError);
  gzip.on('error', onStreamError);

  // Client disconnect handler. Without this, walkAndPack keeps
  // reading every file in the pod, opening file descriptors, and
  // pushing into a gzip whose downstream socket is gone. For a
  // multi-GB pod that's wasted IO + fds until the walk finishes.
  // Destroying both ends short-circuits the walk via stream error
  // propagation; the request.log captures the abort for diagnostics.
  reply.raw.on('close', () => {
    if (!reply.raw.writableEnded) {
      request.log.warn('pod export client disconnected mid-stream');
      pack.destroy(new Error('client disconnected'));
      gzip.destroy(new Error('client disconnected'));
    }
  });

  // Pump in the background; entries are added asynchronously below.
  // The root-pod denylist is wired in so single-user-root-pod mode
  // doesn't ship .idp/ (accounts + signing keys + OIDC state).
  const streamingPromise = packExport({
    pack,
    podDir,
    manifest,
    accountRecord,
    excludeAtRoot: (options.singleUser && isRootPod) ? ROOT_POD_EXCLUDE : null,
  }).catch(onStreamError);

  void streamingPromise;

  return reply.send(gzip);
}

async function packExport({ pack, podDir, manifest, accountRecord, excludeAtRoot }) {
  // Manifest first so consumers can read the shape before deciding
  // whether to keep streaming the (potentially large) pod tree.
  await addEntry(pack, 'jss-export/manifest.json',
    Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));

  // Account record — allowlisted fields only. Both branches in
  // handleExportAccount now refuse with 403 when accountRecord is
  // null, so by the time we get here the record is always defined
  // and account.json is always emitted.
  const safeAccount = {};
  for (const key of ACCOUNT_EXPORT_FIELDS) {
    if (accountRecord[key] !== undefined) safeAccount[key] = accountRecord[key];
  }
  await addEntry(pack, 'jss-export/account.json',
    Buffer.from(JSON.stringify(safeAccount, null, 2), 'utf8'));

  // Pod tree. The first-level filter (`excludeAtRoot`) is what
  // prevents single-user-root-pod mode from leaking .idp/.
  await walkAndPack(pack, podDir, 'jss-export/pod', excludeAtRoot);

  pack.finalize();
}

/**
 * Recursively pack `dir` into `pack` under the tar prefix `tarBase`.
 *
 * @param {Set<string>|null} excludeAtRoot - first-level names to skip
 *   (applied only at the top of the walk; deeper entries pass freely).
 *   Set to `ROOT_POD_EXCLUDE` in single-user-root-pod mode where
 *   podDir is the data root and server-internal dotfiles live next
 *   to pod data.
 */
async function walkAndPack(pack, dir, tarBase, excludeAtRoot = null) {
  const entries = await fsp.readdir(dir, { withFileTypes: true });
  for (const dirent of entries) {
    if (excludeAtRoot && excludeAtRoot.has(dirent.name)) {
      // Top-level server-internal dir — never appears in any export.
      continue;
    }
    const fullPath = path.join(dir, dirent.name);
    const tarPath = `${tarBase}/${dirent.name}`;
    if (dirent.isDirectory()) {
      // Emit an explicit directory entry so empty LDP containers
      // (a container the operator provisioned but hasn't populated)
      // survive a round-trip — preserves the pod's LDP shape on
      // restore. tar requires the trailing slash on directory names.
      await addDirEntry(pack, `${tarPath}/`);
      // No `excludeAtRoot` on recursion — the denylist is first-level only.
      await walkAndPack(pack, fullPath, tarPath, null);
    } else if (dirent.isFile()) {
      // Stream the file into the entry from an *open fd* — opens
      // and stats off the same fd, so a concurrent truncate/grow
      // can't desync `size` from the bytes actually piped. Without
      // this, a stat-then-open dance would TOCTOU on a live pod
      // and produce a corrupt tar that fails extraction.
      const fh = await fsp.open(fullPath, 'r');
      try {
        const st = await fh.stat();
        await new Promise((resolve, reject) => {
          const entry = pack.entry(
            { name: tarPath, size: st.size, mode: st.mode & 0o777 },
            (err) => err ? reject(err) : resolve(),
          );
          const rs = fh.createReadStream({ autoClose: false });
          rs.on('error', reject);
          entry.on('error', reject);
          rs.pipe(entry);
        });
      } finally {
        await fh.close();
      }
    }
    // Symlinks, sockets, FIFOs, etc. are intentionally skipped —
    // `dirent.isFile()` is false for those, even when the symlink
    // points at a regular file. Out of scope for "downloadable pod
    // data" and would complicate restore semantics.
  }
}

/**
 * Add a tar directory entry. `tar-stream` distinguishes by name
 * suffix (`/`) and explicit `type: 'directory'`.
 */
function addDirEntry(pack, name) {
  return new Promise((resolve, reject) => {
    pack.entry({ name, type: 'directory', size: 0 }, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
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
