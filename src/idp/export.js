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
 *   403 — caller's WebID has no matching local account record;
 *         applies to multi-user (no account for the WebID) and
 *         single-user (authenticated WebID is not the seeded owner —
 *         e.g. an external Solid-OIDC / LWS-CID identity)
 *   404 — pod directory unexpectedly missing (shouldn't happen for
 *         an account with a valid WebID, but caught defensively)
 *   500 — defense-in-depth: podDir resolved to a server-internal
 *         name (`.idp` / `.private` / etc.) in non-root-pod mode,
 *         meaning account-creation validation has regressed and
 *         allowed a reserved username through
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
import { promises as fsp, constants as fsConstants } from 'fs';
import crypto from 'crypto';
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
 *
 * !!! TOP-LEVEL ONLY. The allowlist gates only at the first level
 * of the account record. If a future field is itself an
 * object/array (e.g. `oidcClientConfig: { secret: ... }`,
 * `metadata: { recoveryAnswers: [...] }`, etc.), allowlisting the
 * top-level key alone exports the entire nested structure
 * including any secrets. Nested structures need their own scrubbing
 * before being added here, OR they should be projected into a flat
 * shape that excludes the secret-bearing fields.
 */
const ACCOUNT_EXPORT_FIELDS = [
  'id', 'webId', 'username', 'email', 'podName', 'createdAt', 'updatedAt',
  'passwordChangedAt', 'lastLoginAt',
];

/**
 * Error vocabulary note: 401 uses the OAuth-Bearer-defined
 * `invalid_token` (RFC 6750), while 403/404 use plain HTTP-semantic
 * tokens (`forbidden`, `not_found`). This mixed convention is
 * deliberate and consistent with the rest of `src/idp/` (see
 * credentials.js: 401→`invalid_token`/`invalid_grant`, 403→
 * `forbidden`, 400→`invalid_request`). Aligning to a single
 * vocabulary across the whole IdP surface is its own refactor.
 *
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
    //
    // Refuse empty-string / non-string singleUserName explicitly.
    // The previous `!singleUserName` falsy-check silently mapped
    // both '' and null to root-pod, but '' is almost certainly a
    // misconfiguration — an operator who meant root-pod omits the
    // option entirely, and an operator who meant a named pod
    // wouldn't use empty string. WORSE, with `!''`=true the old
    // code took the root-pod branch and applied ROOT_POD_EXCLUDE;
    // a strict null check WITHOUT this refusal would take the
    // named-pod branch with podDir = path.join(dataRoot, '') =
    // dataRoot AND excludeAtRoot = null, silently exporting
    // server-internal `.idp/` and `.private/`. So we explicitly
    // reject the empty-string / non-string case before deciding
    // isRootPod.
    if (
      options.singleUserName !== null &&
      options.singleUserName !== undefined &&
      (typeof options.singleUserName !== 'string' || options.singleUserName.length === 0)
    ) {
      request.log.error(
        { singleUserName: options.singleUserName },
        'pod export refused — singleUserName must be null/undefined or a non-empty string',
      );
      return reply.code(500).send({
        error: 'server_error',
        error_description: 'Invalid singleUserName configuration',
      });
    }
    isRootPod = options.singleUserName == null;
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
    // Defense-in-depth: in named-pod single-user mode, the seeded
    // accountRecord.podName MUST equal options.singleUserName (the
    // CLI option that derives podDir). If seedSingleUserIdpAccount
    // ever drifted, manifest.podName (read from accountRecord) would
    // advertise X while the pod tree is read from <dataRoot>/Y.
    // Refuse with 500 so a seeding regression fails loudly rather
    // than producing a silently mismatched archive.
    //
    // Skipped in root-pod mode where podDir is dataRoot regardless
    // of the seeded podName (which is intentionally 'me' for OIDC
    // identity, not a path component).
    if (!isRootPod && accountRecord.podName !== options.singleUserName) {
      request.log.error(
        {
          seededPodName: accountRecord.podName,
          cliSingleUserName: options.singleUserName,
        },
        'pod export refused — accountRecord.podName disagrees with ' +
        'singleUserName; seedSingleUserIdpAccount regression?',
      );
      return reply.code(500).send({
        error: 'server_error',
        error_description: 'Pod identity inconsistent with on-disk layout',
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

  // Defense-in-depth: in multi-user mode `excludeAtRoot` is null
  // because the pod is at <dataRoot>/<podName>/ (already isolated
  // from server-internal dotfiles by the path layout). But if
  // account-creation validation ever regressed and allowed a
  // username matching `.idp` / `.private`, podDir would resolve to
  // the server-internal directory and the export would happily
  // walk it. Refuse here — account creation rejecting these names
  // is the primary defense; this is the second line.
  if (
    !(options.singleUser && isRootPod) &&
    ROOT_POD_EXCLUDE.has(path.basename(podDir))
  ) {
    request.log.error(
      { podDir, basename: path.basename(podDir) },
      'export refused — podDir resolved to a server-internal name; ' +
      'account-creation validation regression?',
    );
    return reply.code(500).send({
      error: 'server_error',
      error_description: 'Pod resolution conflicts with server-internal layout',
    });
  }

  // Pre-flight the pod directory BEFORE flushing response headers.
  // We do both checks (stat for existence/type, readdir for
  // readability) up front so a first-byte EACCES on the top-level
  // readdir doesn't surface inside the streaming pipeline AFTER
  // reply.send(gzip) has already flushed headers — that would leave
  // the client with a 200 + truncated/empty body instead of a clean
  // 5xx JSON error.
  //
  // 404 vs 500 split:
  //   ENOENT/ENOTDIR → 404 (auth was fine, just no pod on disk)
  //   anything else (EACCES, EIO, etc.) → 500 (server-side problem)
  //
  // Generic error_descriptions on the wire — echoing the resolved
  // podDir back would leak the operator's filesystem layout. Path
  // stays in the server log via request.log.{warn,error} for
  // operator debugging.
  try {
    const st = await fsp.stat(podDir);
    if (!st.isDirectory()) {
      const err = new Error('not a directory');
      err.code = 'ENOTDIR';
      throw err;
    }
    // Pre-flight readability with `fsp.access(R_OK | X_OK)` rather
    // than a discarded readdir — same effect (catches EACCES on the
    // pod directory) without scanning the whole top-level entry
    // list twice. R_OK gates listing, X_OK gates traversal into
    // subdirectories, both required by the recursive walk.
    await fsp.access(podDir, fsConstants.R_OK | fsConstants.X_OK);
  } catch (err) {
    if (err && (err.code === 'ENOENT' || err.code === 'ENOTDIR')) {
      request.log.warn({ podDir }, 'pod export: podDir missing or not a directory');
      return reply.code(404).send({
        error: 'not_found',
        error_description: 'Pod data not found',
      });
    }
    request.log.error({ err, podDir }, 'pod export: pre-flight failed');
    return reply.code(500).send({
      error: 'server_error',
      error_description: 'Pod data is unreadable',
    });
  }

  // 3. Set headers and start streaming.
  const slug = sanitizeSlug(webId);
  const isoDate = manifest.exportedAt.replace(/[:.]/g, '-');
  // Short random suffix avoids collisions when a client batches
  // exports — ISO timestamps have only millisecond resolution and
  // two consecutive calls in the same ms would otherwise produce
  // identical filenames that overwrite each other on the client.
  const rand = crypto.randomBytes(3).toString('hex');  // 6 hex chars
  const filename = `jss-export-${slug}-${isoDate}-${rand}.tar.gz`;

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
  // Idempotent: invoked from pack.error, gzip.error, AND the
  // .catch(onStreamError) chained on packExport(...) below.
  // Destroying a stream re-emits 'error', which would re-enter this
  // handler and produce duplicate log lines for one underlying
  // failure. The destroyed-flag short-circuits all subsequent calls
  // so a single failure logs once.
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
  //
  // `responseFinished` closes a race window. We can't gate on
  // `packExport`'s resolution: that fires when `pack.finalize()`
  // returns, which is "we're done WRITING into the pipeline" — not
  // "the client has received the bytes". For a multi-GB gzipped
  // response over a slow link, the gap between those two events
  // can be substantial, and a real client disconnect during the
  // final flush would be silently swallowed (close handler
  // short-circuits on a flag set too early). Gate instead on
  // `reply.raw.on('finish')` — Node emits 'finish' when the last
  // byte has been flushed to the OS socket buffer, AFTER which a
  // 'close' event means "client disconnected after we were done"
  // and is correctly ignored. Before 'finish', a 'close' is a
  // genuine mid-stream disconnect and gets logged + cleans up.
  let responseFinished = false;
  reply.raw.on('finish', () => { responseFinished = true; });
  reply.raw.on('close', () => {
    if (responseFinished || reply.raw.writableEnded) return;
    request.log.warn('pod export client disconnected mid-stream');
    pack.destroy(new Error('client disconnected'));
    gzip.destroy(new Error('client disconnected'));
  });

  // Pump in the background; entries are added asynchronously below.
  // The root-pod denylist is wired in so single-user-root-pod mode
  // doesn't ship .idp/ (accounts + signing keys + OIDC state).
  // `.catch(onStreamError)` attaches a rejection handler so there's
  // no unhandled-rejection risk; the pipeline runs detached.
  packExport({
    pack,
    podDir,
    manifest,
    accountRecord,
    excludeAtRoot: (options.singleUser && isRootPod) ? ROOT_POD_EXCLUDE : null,
  }).catch(onStreamError);

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
