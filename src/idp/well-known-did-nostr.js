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
import { extractNostrPubkeysFromProfile } from '../auth/nostr.js';

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
 * Read a JSON file, returning null only when it doesn't exist.
 * Other failures (parse error, permission denied, etc.) propagate
 * via console.error so operational issues aren't silently swallowed
 * — they'd otherwise disable DID-doc publishing without any signal.
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

async function rebuildPubkeyIndex({ dataRoot }) {
  const idx = new Map();
  const webIdIndex = await readJsonOrEmpty(getWebIdIndexPath());
  if (!webIdIndex) {
    pubkeyIndex = idx;
    indexBuiltAt = Date.now();
    return;
  }
  for (const [, accountId] of Object.entries(webIdIndex)) {
    const account = await findById(accountId);
    if (!account?.podName) continue;
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
    // Only index VMs that the user has explicitly placed in
    // `authentication`. A pubkey present in verificationMethod but
    // intentionally not in authentication shouldn't be published —
    // the user excluded it from auth purposes (revocation pending,
    // assertion-only, etc.). Publishing it anyway would defeat the
    // user's intent.
    const authIds = collectAuthenticationIds(profile);
    for (const { pubkey, vm } of extractNostrPubkeysFromProfile(profile)) {
      const vmId = absolutize(vm.id || vm['@id'], stripHashIfAny(profile['@id']));
      if (!vmId || !authIds.has(vmId)) continue;
      // First-write wins; if two accounts somehow declare the same
      // pubkey, the first one resolved keeps the binding.
      if (!idx.has(pubkey)) idx.set(pubkey, { accountId, mtimeMs });
    }
  }
  pubkeyIndex = idx;
  indexBuiltAt = Date.now();
}

function collectAuthenticationIds(profile) {
  const out = new Set();
  const auth = profile?.authentication;
  const baseUrl = stripHashIfAny(profile?.['@id'] || profile?.id || '');
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

async function findAccountByNostrPubkey(pubkeyHex, opts) {
  const lower = pubkeyHex.toLowerCase();
  if (!pubkeyIndex || (Date.now() - indexBuiltAt) > INDEX_TTL_MS) {
    await rebuildPubkeyIndex(opts);
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
  const found = await findAccountByNostrPubkey(pubkeyHex.toLowerCase(), {
    dataRoot: process.env.DATA_ROOT || './data',
  });
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
 * Note on the dataRoot option: this handler reads profiles from
 * `<dataRoot>/<podName>/profile/card.jsonld`, but it also calls
 * `findById()` from accounts.js, which reads from
 * `<process.env.DATA_ROOT>/.idp/accounts/`. To keep the two layers
 * consistent we mirror DATA_ROOT into options.dataRoot at the
 * default, so passing `dataRoot` only differs when you've ALSO set
 * DATA_ROOT to the same value (typical) — in which case the
 * parameter is just an explicit form of the env. Custom values
 * outside DATA_ROOT are out of scope.
 */
export function buildWellKnownDidNostrHandler({ dataRoot } = {}) {
  const root = dataRoot || process.env.DATA_ROOT || './data';
  return async function handleWellKnownDidNostr(request, reply) {
    const raw = String(request.params.pubkeyAndExt || '');
    const ext = raw.endsWith('.jsonld') ? '.jsonld'
              : raw.endsWith('.json') ? '.json'
              : '';
    const pubkey = (ext ? raw.slice(0, -ext.length) : raw).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(pubkey)) {
      return reply.code(400)
        .header('Content-Type', 'application/json')
        .send({ error: 'pubkey must be 64 hex chars' });
    }
    const found = await findAccountByNostrPubkey(pubkey, { dataRoot: root });
    if (!found?.account) {
      return reply.code(404)
        .header('Cache-Control', 'max-age=60')
        .header('Content-Type', 'application/json')
        .send({ error: 'no local account claims this pubkey' });
    }
    const { account, mtimeMs } = found;
    if (!account.webId) {
      // Defensive — every account has a webId, but if one slips through,
      // the DID doc would be useless without alsoKnownAs.
      return reply.code(404)
        .header('Cache-Control', 'max-age=60')
        .header('Content-Type', 'application/json')
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
