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

async function readJsonOrEmpty(file) {
  try { return await fs.readJson(file); } catch { return null; }
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
    try {
      const text = await fs.readFile(profilePath, 'utf8');
      profile = JSON.parse(text);
    } catch {
      continue; // unreadable / non-existent — skip
    }
    for (const { pubkey } of extractNostrPubkeysFromProfile(profile)) {
      // First-write wins; if two accounts somehow declare the same
      // pubkey, the first one resolved keeps the binding.
      if (!idx.has(pubkey)) idx.set(pubkey, accountId);
    }
  }
  pubkeyIndex = idx;
  indexBuiltAt = Date.now();
}

async function findAccountByNostrPubkey(pubkeyHex, opts) {
  const lower = pubkeyHex.toLowerCase();
  if (!pubkeyIndex || (Date.now() - indexBuiltAt) > INDEX_TTL_MS) {
    await rebuildPubkeyIndex(opts);
  }
  const accountId = pubkeyIndex.get(lower);
  if (!accountId) return null;
  return findById(accountId);
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
 */
export function buildWellKnownDidNostrHandler({ dataRoot } = {}) {
  const root = dataRoot || process.env.DATA_ROOT || './data';
  return async function handleWellKnownDidNostr(request, reply) {
    const raw = String(request.params.pubkeyAndExt || '');
    const ext = raw.endsWith('.jsonld') ? '.jsonld'
              : raw.endsWith('.json') ? '.json'
              : '';
    const pubkey = ext ? raw.slice(0, -ext.length) : raw;
    if (!/^[0-9a-f]{64}$/i.test(pubkey)) {
      return reply.code(400)
        .header('Content-Type', 'application/json')
        .send({ error: 'pubkey must be 64 hex chars (lowercase)' });
    }
    const account = await findAccountByNostrPubkey(pubkey, { dataRoot: root });
    if (!account) {
      return reply.code(404)
        .header('Cache-Control', 'max-age=60')
        .header('Content-Type', 'application/json')
        .send({ error: 'no local account claims this pubkey' });
    }
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
    return reply
      .header('Content-Type', contentType)
      .header('Cache-Control', 'max-age=3600')
      .header('Nostr-Timestamp', String(Math.floor(Date.now() / 1000)))
      .header('Last-Modified', new Date().toUTCString())
      .send(didDoc);
  };
}
