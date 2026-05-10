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

// In-memory pubkey → accountId index. Built lazily from disk; rebuilt
// when the TTL expires. Real production wants a write-path hook on
// LDP PUT/PATCH so updates are immediate; that's filed as a follow-up.
let pubkeyIndex = null; // Map<pubkeyHex, accountId>
let indexBuiltAt = 0;
const INDEX_TTL_MS = 5 * 60 * 1000;

/** @internal — exposed for tests */
export function _resetIndexForTests() {
  pubkeyIndex = null;
  indexBuiltAt = 0;
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
    if (!account?.podName || !account?.webId) continue;
    const profilePath = path.join(dataRoot, account.podName, 'profile', 'card.jsonld');
    let profile;
    let mtimeMs = 0;
    try {
      const stat = await fs.stat(profilePath);
      mtimeMs = stat.mtimeMs;
      const text = await fs.readFile(profilePath, 'utf8');
      profile = JSON.parse(text);
    } catch {
      continue; // unreadable / non-existent — skip
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
      if (!idx.has(pubkey)) idx.set(pubkey, { accountId, mtimeMs });
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
    await rebuildPubkeyIndex();
  }
  const entry = pubkeyIndex.get(lower);
  if (!entry) return null;
  const account = await findById(entry.accountId);
  if (!account) return null;
  return { account, mtimeMs: entry.mtimeMs };
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
    // Last-Modified reflects when the underlying mapping (the user's
    // profile file) actually changed — NOT the request time — so
    // clients/CDNs can do conditional GET correctly.
    const lastModifiedDate = mtimeMs > 0 ? new Date(mtimeMs) : new Date(indexBuiltAt);
    return reply
      .header('Content-Type', contentType)
      .header('Cache-Control', 'max-age=3600')
      .header('Nostr-Timestamp', String(Math.floor(lastModifiedDate.getTime() / 1000)))
      .header('Last-Modified', lastModifiedDate.toUTCString())
      .send(didDoc);
  };
}
