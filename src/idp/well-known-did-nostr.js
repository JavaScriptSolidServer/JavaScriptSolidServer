/**
 * did:nostr HTTP resolution endpoint.
 *
 * Implements the well-known path from the did:nostr spec:
 *
 *   GET /.well-known/did/nostr/<pubkey>.json
 *   GET /.well-known/did/nostr/<pubkey>.jsonld
 *   GET /.well-known/did/nostr/<pubkey>
 *
 * For any local account whose WebID profile declares this Nostr pubkey
 * as a CID `verificationMethod` referenced from `authentication`, JSS
 * generates a DID document on the fly with `alsoKnownAs: [<webId>]`.
 * Other resolvers (nostr.social, nostr.rocks, JSS's own
 * `src/auth/did-nostr.js`) can then fetch the DID doc from this pod
 * and follow the WebID linkage — making the pod its own
 * authoritative DID resolver for its accounts.
 *
 * Closes the "type your username" UX hack on the IdP login page
 * (#403 / #405): the existing did-nostr resolver finds local users
 * via this endpoint without any user-typed hint.
 */

import path from 'path';
import fs from 'fs-extra';
import { findById } from './accounts.js';
import { extractNostrPubkeysFromProfile } from '../auth/nostr-keys.js';

// In-memory pubkey → resolved-account-record index. Built lazily
// from disk; rebuilt when the TTL expires. Real production wants
// a write-path hook on LDP PUT/PATCH so updates are immediate;
// that's filed as a follow-up.
//
// Each entry stores `{ accountId, webId, mtimeMs }` so the hot
// path (NIP-98 auth via resolveDidNostrLocally + every DID-doc
// request) can answer without re-reading the account JSON from
// disk. accountId is kept for log diagnostics; webId is what
// the resolver actually needs.
let pubkeyIndex = null; // Map<pubkeyHex, { accountId, webId, mtimeMs }>
let indexBuiltAt = 0;
let rebuildInFlight = null; // Promise — in-flight rebuild dedup
const INDEX_TTL_MS = 5 * 60 * 1000;

// Rate-limit "profile unreadable" log spam. A single broken profile
// shouldn't flood logs every 5 minutes (every TTL rebuild) — but the
// first occurrence per rebuild cycle MUST be logged so operators can
// debug "why isn't my pubkey publishing?" without grepping silence.
const PROFILE_LOG_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
const profileLogTracker = new Map(); // accountId -> last logged ms
function logProfileFailure(accountId, profilePath, err) {
  const now = Date.now();
  const last = profileLogTracker.get(accountId) || 0;
  if (now - last < PROFILE_LOG_INTERVAL_MS) return;
  profileLogTracker.set(accountId, now);
  // Trim the tracker so it can't grow without bound.
  if (profileLogTracker.size > 10_000) {
    const oldest = profileLogTracker.keys().next().value;
    if (oldest !== undefined) profileLogTracker.delete(oldest);
  }
  console.error(
    `well-known-did-nostr: skipping account ${accountId} ` +
    `(profile=${profilePath}): ${err.code || err.name || 'error'} ${err.message}`,
  );
}
// Size cap on per-account profile reads. WebID profiles are tiny —
// 64 KB is generous and matches the bound the LDP layer would impose
// for any sane profile. A user shouldn't be able to make the indexer
// allocate megabytes by writing a giant profile, especially since
// rebuilds can be triggered by attacker-driven NIP-98 traffic once
// the TTL expires.
const MAX_PROFILE_BYTES = 64 * 1024;

/** @internal — exposed for tests */
export function _resetIndexForTests() {
  pubkeyIndex = null;
  indexBuiltAt = 0;
  rebuildInFlight = null;
  profileLogTracker.clear();
}

// Match the layout in src/idp/accounts.js — accounts live under
// <DATA_ROOT>/.idp/accounts. Computed lazily so DATA_ROOT changes
// (test setup, env override) are picked up.
function getAccountsDir() {
  const dataRoot = process.env.DATA_ROOT || './data';
  return path.join(dataRoot, '.idp', 'accounts');
}
function getWebIdIndexPath() {
  return path.join(getAccountsDir(), '_webid_index.json');
}

/**
 * Read a JSON file. Returns null in two cases (with different
 * semantics, kept the same return shape for caller simplicity):
 *
 *   - ENOENT — silently null. The index file legitimately doesn't
 *     exist on a fresh deployment with no accounts yet.
 *   - Any other error (parse error, permission denied, etc.) — null
 *     PLUS a loud console.error so operational issues surface in logs
 *     instead of silently disabling DID-doc publishing.
 */
async function readJsonOrEmpty(file) {
  try {
    return await fs.readJson(file);
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    console.error(`well-known-did-nostr: failed to read ${file}: ${err.message}`);
    return null;
  }
}

async function rebuildPubkeyIndex() {
  const idx = new Map();
  const dataRoot = process.env.DATA_ROOT || './data';
  const webIdIndex = await readJsonOrEmpty(getWebIdIndexPath());
  if (!webIdIndex) {
    pubkeyIndex = idx;
    indexBuiltAt = Date.now();
    return;
  }
  // Track pubkeys that appear under more than one account so we can
  // EXCLUDE them rather than silently picking one. An ambiguous binding
  // would make resolution depend on insertion order and be hard to
  // diagnose; better to refuse and log loudly.
  const seenAccounts = new Map(); // pubkey -> Set<accountId>
  for (const [, accountId] of Object.entries(webIdIndex)) {
    // Wrap each account read so one corrupt/unreadable account file
    // can't take down resolution for everyone — the index would just
    // skip that account and a single 500 wouldn't cascade across the
    // whole pod's NIP-98 traffic.
    let account;
    try {
      account = await findById(accountId);
    } catch (err) {
      console.error(
        `well-known-did-nostr: skipping account ${accountId} ` +
        `(read failed: ${err.message})`,
      );
      continue;
    }
    if (!account?.webId) continue;
    const profilePath = profilePathFromWebId(dataRoot, account.webId, accountId);
    if (!profilePath) continue;
    let profile;
    let mtimeMs = 0;
    try {
      const stat = await fs.stat(profilePath);
      mtimeMs = stat.mtimeMs;
      // Size cap to bound per-rebuild memory/CPU. A user can write
      // their own profile, and TTL-expired rebuilds can be triggered
      // by attacker-driven NIP-98 traffic — without this an
      // adversarially-large profile could pin the event loop on
      // JSON.parse during the rebuild loop.
      if (stat.size > MAX_PROFILE_BYTES) {
        console.error(
          `well-known-did-nostr: skipping account ${accountId} ` +
          `— profile size ${stat.size} > ${MAX_PROFILE_BYTES} bytes`,
        );
        continue;
      }
      const text = await fs.readFile(profilePath, 'utf8');
      profile = JSON.parse(text);
    } catch (err) {
      // Log so operators can debug "why isn't my pubkey publishing?".
      // Rate-limited per account so a single perpetually-broken
      // profile can't flood logs every TTL cycle.
      logProfileFailure(accountId, profilePath, err);
      continue; // unreadable / malformed — skip
    }
    // CID semantics — match the resource-side checks:
    // (1) profile's @id MUST match the account's webId (no fragment-
    //     swapping attack via a stored profile that claims to be
    //     someone else)
    // (2) VM's controller MUST be in the profile's expected controller
    //     set (declared `controller`, with @id fallback)
    // (3) VM MUST be referenced from `authentication` — a key in
    //     verificationMethod alone (no auth membership) shouldn't be
    //     published as authentic
    const profileSubject = absolutize(profile?.['@id'] || profile?.id, stripHashIfAny(account.webId));
    if (!profileSubject || profileSubject !== account.webId) continue;
    const expectedControllers = collectControllerIds(profile, profileSubject);
    if (expectedControllers.size === 0) continue;
    // Pass the already-validated absolute subject as the base. Without
    // this, profiles with a relative subject (e.g. `"@id": "#me"`)
    // would absolutize their `authentication` entries against an
    // unusable base, leaving the IDs relative — and then the
    // `authIds.has(vmId)` check below would never match even when the
    // VM is actually authenticated.
    const authIds = collectAuthenticationIds(profile, stripHashIfAny(profileSubject));

    for (const { pubkey, vm } of extractNostrPubkeysFromProfile(profile)) {
      const vmId = absolutize(vm.id || vm['@id'], stripHashIfAny(profileSubject));
      if (!vmId || !authIds.has(vmId)) continue;
      const vmCtrls = collectControllerIds({ controller: vm.controller }, profileSubject);
      let controllerOk = false;
      for (const c of vmCtrls) {
        if (expectedControllers.has(c)) { controllerOk = true; break; }
      }
      if (!controllerOk) continue;

      // Duplicate-pubkey detection: track every account that claims
      // it; resolve at the end of the scan.
      if (!seenAccounts.has(pubkey)) seenAccounts.set(pubkey, new Set());
      seenAccounts.get(pubkey).add(accountId);
      // Cache the resolved webId in the index so the lookup hot
      // path doesn't have to re-read the account JSON.
      if (!idx.has(pubkey)) idx.set(pubkey, { accountId, webId: account.webId, mtimeMs });
    }
  }
  // Drop ambiguous pubkeys and warn loudly.
  for (const [pubkey, accountIds] of seenAccounts) {
    if (accountIds.size > 1) {
      console.error(
        `well-known-did-nostr: pubkey ${pubkey} claimed by ` +
        `${accountIds.size} accounts (${[...accountIds].join(', ')}) — ` +
        `omitting from index to avoid ambiguous resolution`,
      );
      idx.delete(pubkey);
    }
  }
  pubkeyIndex = idx;
  indexBuiltAt = Date.now();
}

/**
 * Derive the on-disk profile path from a WebID (and validate
 * containment in DATA_ROOT). Returns the absolute filesystem path
 * or `null` if the WebID is unparseable / would escape dataRoot.
 *
 * Why a separate function: WHATWG URL parsing already strips most
 * `..` traversal at the URL layer, but the path-resolve containment
 * check is defense-in-depth for any future caller that bypasses
 * URL parsing (string manipulation, alternate parser, etc.). Lives
 * in its own function so the containment branch is unit-testable
 * with raw inputs that DON'T go through `new URL()`.
 *
 * @internal exported for tests
 */
export function profilePathFromWebId(dataRoot, webId, accountId = 'unknown') {
  if (typeof webId !== 'string') return null;
  let pathname;
  try {
    pathname = new URL(webId).pathname;
  } catch {
    return null;
  }
  // Strip leading `/` so it's treated as a relative segment, then
  // resolve and assert the result is at-or-under dataRootAbs. An
  // account record whose webId path resolves outside dataRoot is
  // never indexed.
  const relPath = pathname.replace(/^\/+/, '');
  const dataRootAbs = path.resolve(dataRoot);
  const resolved = path.resolve(dataRootAbs, relPath);
  if (resolved !== dataRootAbs && !resolved.startsWith(dataRootAbs + path.sep)) {
    console.error(
      `well-known-did-nostr: account ${accountId} webId ${webId} ` +
      `resolves outside dataRoot (${resolved}) — skipping`,
    );
    return null;
  }
  return resolved;
}

function collectControllerIds(source, baseUrl) {
  const out = new Set();
  const c = source?.controller;
  const list = Array.isArray(c) ? c : (c ? [c] : []);
  for (const ent of list) {
    let id;
    if (typeof ent === 'string') id = ent;
    else if (ent && typeof ent === 'object') id = ent['@id'] || ent.id;
    if (id) out.add(absolutize(id, baseUrl));
  }
  // Fallback to @id when no explicit controller (CID v1 self-control).
  if (out.size === 0 && source && (source['@id'] || source.id)) {
    out.add(absolutize(source['@id'] || source.id, baseUrl));
  }
  return out;
}

/**
 * Resolve a profile's `authentication` entries to a Set of absolute
 * IDs. Caller MUST pass an already-absolute base URL — re-deriving
 * the base from `profile['@id']` here would fail when the profile
 * subject is relative (e.g. `"@id": "#me"`), leaving the resulting
 * IDs relative and silently breaking the auth-membership check.
 */
function collectAuthenticationIds(profile, baseUrl) {
  const out = new Set();
  const auth = profile?.authentication;
  const list = Array.isArray(auth) ? auth : (auth ? [auth] : []);
  for (const ent of list) {
    let id;
    if (typeof ent === 'string') id = ent;
    else if (ent && typeof ent === 'object') id = ent['@id'] || ent.id;
    if (id) out.add(absolutize(id, baseUrl));
  }
  return out;
}

function absolutize(u, base) {
  if (!u) return u;
  try { return new URL(u, base).toString(); } catch { return u; }
}

function stripHashIfAny(u) {
  if (typeof u !== 'string') return u;
  try { const url = new URL(u); url.hash = ''; return url.toString(); }
  catch { return u; }
}

async function findAccountByNostrPubkey(pubkeyHex) {
  const lower = pubkeyHex.toLowerCase();
  if (!pubkeyIndex || (Date.now() - indexBuiltAt) > INDEX_TTL_MS) {
    // Dedup concurrent rebuilds: under a burst of requests that all
    // arrive after the TTL expires, only ONE rebuild runs and every
    // other caller awaits its promise. Without this, N concurrent
    // requests would each do a full disk scan + parse pass, with
    // N-1 of them throwing away their result.
    if (!rebuildInFlight) {
      rebuildInFlight = rebuildPubkeyIndex().finally(() => {
        rebuildInFlight = null;
      });
    }
    await rebuildInFlight;
  }
  const entry = pubkeyIndex.get(lower);
  if (!entry) return null;
  // The webId is now stored on the index entry — no per-request
  // findById disk read needed. NIP-98 auth (via
  // resolveDidNostrLocally) and DID-doc generation hit this on
  // every request, so dropping the I/O matters.
  return { account: { webId: entry.webId }, mtimeMs: entry.mtimeMs };
}

/**
 * In-process local DID resolution: given a Nostr pubkey, return the
 * matching account's WebID without any network fetch. Lets the
 * verifyNostrAuth resolver chain prefer local users via direct
 * function call instead of a same-host HTTP loop, removing both the
 * latency and the SSRF surface that came with feeding request-
 * controlled host headers into a `fetch()`.
 *
 * Returns null for non-local pubkeys (caller falls back to the
 * external HTTP resolver, with SSRF protection).
 */
export async function resolveDidNostrLocally(pubkeyHex) {
  if (typeof pubkeyHex !== 'string' || !/^[0-9a-f]{64}$/i.test(pubkeyHex)) return null;
  const found = await findAccountByNostrPubkey(pubkeyHex.toLowerCase());
  return found?.account?.webId || null;
}

/**
 * Build a CID-shaped DID document for a Nostr pubkey + account pair.
 *
 * Uses the spec example's vocabulary (Multikey + publicKeyMultibase)
 * for max interop with our own resolver and the W3C VC track. The
 * Multikey value is computed deterministically from the pubkey via
 * the f-form recipe (multibase `f` + multicodec `e701` + parity byte
 * `02` + 32-byte xonly hex) — the same shape the doctor's B.2 emits.
 */
function buildDidDocument({ pubkey, webId }) {
  const did = `did:nostr:${pubkey.toLowerCase()}`;
  const multikey = `f` + `e701` + `02` + pubkey.toLowerCase();
  const vmId = `${did}#key1`;
  return {
    '@context': ['https://w3id.org/did', 'https://w3id.org/nostr/context'],
    'id': did,
    'type': 'DIDNostr',
    'alsoKnownAs': [webId],
    'verificationMethod': [{
      'id': vmId,
      'type': 'Multikey',
      'controller': did,
      'publicKeyMultibase': multikey,
    }],
    'authentication': [vmId],
    'assertionMethod': [vmId],
  };
}

/**
 * Fastify handler for GET /.well-known/did/nostr/:pubkeyAndExt
 *
 * The :pubkeyAndExt parameter accepts `<pubkey>`, `<pubkey>.json`, or
 * `<pubkey>.jsonld`; the body is the same DID doc either way. The
 * spec specifies `.json` as the canonical path, so that's the
 * primary; the others are friendly aliases.
 *
 * The data root is read from `process.env.DATA_ROOT` (matching
 * `accounts.js`). We don't accept a parameter for it because the
 * account-index path is derived from the same env elsewhere — taking
 * a parameter would create two sources of truth and be misleading.
 */
export function buildWellKnownDidNostrHandler() {
  return async function handleWellKnownDidNostr(request, reply) {
    const raw = String(request.params.pubkeyAndExt || '');
    const ext = raw.endsWith('.jsonld') ? '.jsonld'
              : raw.endsWith('.json') ? '.json'
              : '';
    const pubkey = (ext ? raw.slice(0, -ext.length) : raw).toLowerCase();
    // Per-status header policy (so success and failure responses are
    // both predictable to clients/CDNs):
    //   200  Cache-Control: max-age=3600  — DID doc seldom changes
    //   404  Cache-Control: max-age=60    — short TTL so a newly added
    //                                       key surfaces quickly
    //   400  Cache-Control: no-store      — request was malformed; never cache
    // Nostr-Timestamp is set on EVERY response (including errors) per
    // the did:nostr spec recommendation that clients can correlate the
    // resolver's clock with the answer they got. Last-Modified only
    // makes sense for 200 (it tracks the underlying profile mtime);
    // for errors we omit it because there's no underlying resource.
    const nowEpoch = Math.floor(Date.now() / 1000);
    if (!/^[0-9a-f]{64}$/.test(pubkey)) {
      return reply.code(400)
        .header('Content-Type', 'application/json')
        .header('Cache-Control', 'no-store')
        .header('Nostr-Timestamp', String(nowEpoch))
        .send({ error: 'pubkey must be 64 hex chars' });
    }
    const found = await findAccountByNostrPubkey(pubkey);
    if (!found?.account) {
      return reply.code(404)
        .header('Cache-Control', 'max-age=60')
        .header('Content-Type', 'application/json')
        .header('Nostr-Timestamp', String(nowEpoch))
        .send({ error: 'no local account claims this pubkey' });
    }
    const { account, mtimeMs } = found;
    if (!account.webId) {
      // Defensive — every account has a webId, but if one slips through,
      // the DID doc would be useless without alsoKnownAs.
      return reply.code(404)
        .header('Cache-Control', 'max-age=60')
        .header('Content-Type', 'application/json')
        .header('Nostr-Timestamp', String(nowEpoch))
        .send({ error: 'account has no webId' });
    }

    const didDoc = buildDidDocument({ pubkey, webId: account.webId });
    const contentType = ext === '.jsonld'
      ? 'application/did+ld+json; charset=utf-8'
      : 'application/did+json; charset=utf-8';
    // Two distinct timestamp semantics, two distinct headers:
    //   - Nostr-Timestamp: the resolver's clock at answer time (uniform
    //     across 200/404/400 — clients use it to correlate the resolver
    //     clock with their own, regardless of cache hits).
    //   - Last-Modified: when the underlying mapping (the user's
    //     profile file) actually changed — only meaningful for 200,
    //     so clients/CDNs can do conditional GET against the source.
    const lastModifiedDate = mtimeMs > 0 ? new Date(mtimeMs) : new Date(indexBuiltAt);
    return reply
      .header('Content-Type', contentType)
      .header('Cache-Control', 'max-age=3600')
      .header('Nostr-Timestamp', String(nowEpoch))
      .header('Last-Modified', lastModifiedDate.toUTCString())
      .send(didDoc);
  };
}
