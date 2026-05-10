/**
 * DID:nostr Resolution
 *
 * Resolves did:nostr:<pubkey> to a Solid WebID by:
 * 1. Fetching DID document from nostr.social
 * 2. Extracting alsoKnownAs WebID
 * 3. Verifying bidirectional link (WebID links back to did:nostr)
 */

import { validateExternalUrl } from '../utils/ssrf.js';
import { extractNostrPubkeysFromProfile } from './nostr-keys.js';

// Default DID resolver endpoint
const DEFAULT_DID_RESOLVER = 'https://nostr.social/.well-known/did/nostr';

// Cache for resolved DIDs (pubkey -> { webId, timestamp, failureTtl? }).
//
// Bounded LRU: pubkeys come from external NIP-98 events, so an
// attacker can flood the resolver with unique pubkeys and grow the
// cache without limit if it's an unbounded Map. The Map iteration
// order IS insertion order, so evicting `cache.keys().next().value`
// drops the oldest entry — same pattern as src/auth/cid-doc-fetch.js.
// On every set: re-insert (delete + set) bumps the entry to "newest"
// so the LRU semantics are preserved across cache hits.
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const FAILURE_CACHE_TTL = 60 * 1000; // 1 minute for failed lookups
const CACHE_MAX_ENTRIES = 10_000; // bound at ~few MB worst case

function setCacheEntry(key, entry) {
  // Re-insert to mark as MRU (Map preserves insertion order).
  if (cache.has(key)) cache.delete(key);
  cache.set(key, entry);
  while (cache.size > CACHE_MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest === undefined) break;
    cache.delete(oldest);
  }
}

// Rate-limit repeated error logs (key -> { count, lastLogged })
const errorLogTracker = new Map();
const ERROR_LOG_INTERVAL = 60_000;

function rateLimitedError(key, message) {
  const now = Date.now();
  const entry = errorLogTracker.get(key);
  if (entry && now - entry.lastLogged < ERROR_LOG_INTERVAL) {
    entry.count++;
    return;
  }
  // Clean up stale entries while we're here
  for (const [k, v] of errorLogTracker) {
    if (now - v.lastLogged > ERROR_LOG_INTERVAL) errorLogTracker.delete(k);
  }
  const suppressed = entry ? entry.count : 0;
  const suffix = suppressed > 0 ? ` (${suppressed} similar suppressed)` : '';
  console.error(`${message}${suffix}`);
  errorLogTracker.set(key, { count: 0, lastLogged: now });
}

// Redirect/SSRF/size limits, mirroring src/auth/cid-doc-fetch.js so
// both the DID-doc resolver and the WebID-backlink verifier apply
// the same hardening:
//   - manual redirect handling (5 hops max)
//   - SSRF re-validation on EVERY hop (an allowed origin could 30x
//     to a private IP / cloud metadata; default fetch redirect would
//     bypass the initial validateExternalUrl check)
//   - cross-origin redirects refused (open-redirect → arbitrary host)
//   - response size cap before reading the body
const MAX_REDIRECTS = 5;
const DEFAULT_FETCH_TIMEOUT_MS = 5000;
const DEFAULT_MAX_BYTES = 1 * 1024 * 1024; // 1 MB — DID docs / WebID profiles are tiny

/**
 * Fetch with a timeout, manual redirect following, SSRF re-validation
 * per hop, and a body-size cap. Returns `{ url, status, headers, body }`
 * — `body` is a string (caller decides whether to JSON-parse).
 *
 * Throws on validation, network, redirect, or size failures so the
 * resolver can swallow them uniformly into a null/false return.
 *
 * Exported for tests so the redirect + cross-origin + cap logic can
 * be unit-tested directly with a stubbed validator (the production
 * validator hard-blocks loopback, which is the only thing a unit
 * test can spin up — without injection the redirect tests can't
 * tell the SSRF guard from the redirect guard).
 *
 * @param {object} [opts]
 * @param {Function} [opts._validateUrl] - Test seam. Defaults to the
 *   real `validateExternalUrl`. Production callers MUST NOT override.
 */
export async function fetchWithRedirectGuard(initialUrl, {
  accept,
  timeout = DEFAULT_FETCH_TIMEOUT_MS,
  maxBytes = DEFAULT_MAX_BYTES,
  _validateUrl = validateExternalUrl,
} = {}) {
  const originalOrigin = new URL(initialUrl).origin;
  let currentUrl = initialUrl;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const isLastAllowedHop = hop === MAX_REDIRECTS;
    const validation = await _validateUrl(currentUrl, {
      requireHttps: process.env.NODE_ENV === 'production',
      blockPrivateIPs: true,
      resolveDNS: true,
    });
    if (!validation.valid) {
      throw new Error(`SSRF protection: ${validation.error}`);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    let res;
    try {
      res = await fetch(currentUrl, {
        headers: accept ? { Accept: accept } : {},
        redirect: 'manual',
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (res.status >= 300 && res.status < 400) {
      if (isLastAllowedHop) throw new Error(`too many redirects (>${MAX_REDIRECTS})`);
      const loc = res.headers.get('location');
      if (!loc) throw new Error(`redirect ${res.status} without Location`);
      const nextUrl = new URL(loc, currentUrl).toString();
      const nextOrigin = new URL(nextUrl).origin;
      if (nextOrigin !== originalOrigin) {
        throw new Error(`cross-origin redirect refused: ${originalOrigin} → ${nextOrigin}`);
      }
      currentUrl = nextUrl;
      continue;
    }
    // Cap the body before reading. Content-Length pre-check rejects
    // a server that advertises an oversized response; the streaming
    // cap rejects servers that lie about Content-Length.
    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new Error(`response too large (Content-Length=${declared} > ${maxBytes})`);
    }
    const reader = res.body?.getReader?.();
    let body = '';
    if (!reader) {
      body = await res.text();
      if (Buffer.byteLength(body, 'utf8') > maxBytes) {
        throw new Error(`response too large (>${maxBytes} bytes)`);
      }
    } else {
      const chunks = [];
      let total = 0;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
          try { await reader.cancel(); } catch { /* noop */ }
          throw new Error(`response too large (>${maxBytes} bytes)`);
        }
        chunks.push(value);
      }
      body = Buffer.concat(chunks).toString('utf8');
    }
    return { url: currentUrl, status: res.status, headers: res.headers, body };
  }
  throw new Error('fetch loop exited unexpectedly');
}

/**
 * Resolve did:nostr pubkey to WebID via DID document.
 *
 * Local users are resolved by `resolveDidNostrLocally` in the auth
 * caller (well-known-did-nostr.js exports an in-process function) —
 * this resolver is the cross-pod fallback that fetches an external
 * DID doc, so all fetches run through the SSRF guard.
 *
 * @param {string} pubkey - 64-char hex Nostr pubkey
 * @param {string} [resolverUrl] - DID resolver base URL (without the
 *   trailing `/<pubkey>.json`). Defaults to the configured
 *   DEFAULT_DID_RESOLVER (nostr.social).
 * @returns {Promise<string|null>} WebID URL or null
 */
export async function resolveDidNostrToWebId(pubkey, resolverUrl = DEFAULT_DID_RESOLVER) {
  if (!pubkey || pubkey.length !== 64) {
    return null;
  }

  // Check cache (lazy eviction of expired entries)
  const cacheKey = pubkey.toLowerCase();
  const cached = cache.get(cacheKey);
  if (cached) {
    const ttl = cached.failureTtl ? FAILURE_CACHE_TTL : CACHE_TTL;
    if (Date.now() - cached.timestamp < ttl) {
      // Re-insert to bump to MRU. Without this, a frequently-hit
      // entry could still be evicted as "oldest" once the cache is
      // at the cap, defeating the LRU intent.
      setCacheEntry(cacheKey, cached);
      return cached.webId;
    }
    cache.delete(cacheKey);
  }

  try {
    // SSRF guard runs inside fetchWithRedirectGuard on EVERY hop —
    // not just the initial URL — so an allowed resolver origin can't
    // 30x-redirect to a private IP / cloud metadata endpoint and
    // bypass the check. Same policy the LWS-CID verifier applies.
    const didUrl = `${resolverUrl}/${pubkey}.json`;
    // Two failure classes with different cache TTLs:
    //   - Transient: network error, SSRF/redirect refusal, non-2xx,
    //     unparseable JSON. These should re-try sooner, so cache
    //     with `failureTtl: true` (FAILURE_CACHE_TTL = 1 min).
    //   - "No linkage": successful fetch but the DID doc had no
    //     alsoKnownAs / profile.webid we could use. That's a valid
    //     answer, not a transient blip — cache with the regular
    //     CACHE_TTL (5 min) so we don't hammer the resolver.
    let didFetch;
    try {
      didFetch = await fetchWithRedirectGuard(didUrl, {
        accept: 'application/did+json, application/json',
      });
    } catch {
      setCacheEntry(cacheKey, { webId: null, timestamp: Date.now(), failureTtl: true });
      return null;
    }
    if (didFetch.status < 200 || didFetch.status >= 300) {
      setCacheEntry(cacheKey, { webId: null, timestamp: Date.now(), failureTtl: true });
      return null;
    }
    let didDoc;
    try {
      didDoc = JSON.parse(didFetch.body);
    } catch {
      setCacheEntry(cacheKey, { webId: null, timestamp: Date.now(), failureTtl: true });
      return null;
    }
    // Extract WebID from alsoKnownAs (array) or profile.webid or profile.sameAs
    let webId = null;

    if (Array.isArray(didDoc.alsoKnownAs) && didDoc.alsoKnownAs.length > 0) {
      // Find first HTTP(S) URL that looks like a WebID
      webId = didDoc.alsoKnownAs.find(aka =>
        typeof aka === 'string' && aka.startsWith('https://'));
    }

    // Fallback to profile fields
    if (!webId && didDoc.profile) {
      webId = didDoc.profile.webid || didDoc.profile.sameAs;
    }

    if (!webId) {
      setCacheEntry(cacheKey, { webId: null, timestamp: Date.now() });
      return null;
    }

    // Always verify the WebID actually claims this pubkey. The
    // earlier same-origin shortcut was unsafe on multi-tenant
    // pods: same-origin doesn't equal same-control. Mallory who
    // owns `<host>/.well-known/did/nostr/<MallorysPubkey>.json`
    // could publish a DID doc with `alsoKnownAs` pointing at
    // Alice's WebID on the same host, and "same origin" would
    // accept it. The verifier checks the Alice-side profile for
    // a verificationMethod that actually claims this pubkey, so
    // the binding can't be forged from outside Alice's profile.
    const verified = await verifyWebIdBacklink(webId, pubkey);

    if (verified) {
      setCacheEntry(cacheKey, { webId, timestamp: Date.now() });
      return webId;
    }

    setCacheEntry(cacheKey, { webId: null, timestamp: Date.now() });
    return null;

  } catch (err) {
    // Cache failures with short TTL to avoid hammering a down service
    setCacheEntry(cacheKey, { webId: null, timestamp: Date.now(), failureTtl: true });
    rateLimitedError(`did:${pubkey.substring(0, 8)}`, `DID resolution error for ${pubkey}: ${err.message}`);
    return null;
  }
}

/**
 * Verify WebID profile links back to did:nostr
 * @param {string} webId - WebID URL
 * @param {string} pubkey - Nostr pubkey
 * @returns {Promise<boolean>}
 */
async function verifyWebIdBacklink(webId, pubkey) {
  try {
    const expectedDid = `did:nostr:${pubkey.toLowerCase()}`;
    // The WebID came out of an externally-fetched DID doc, so it's
    // untrusted until verified. fetchWithRedirectGuard re-runs the
    // SSRF check on every redirect hop and refuses cross-origin
    // redirects, so a forged DID doc can't bounce us through an
    // open-redirect into a private IP.
    let backlinkRes;
    try {
      backlinkRes = await fetchWithRedirectGuard(webId, {
        accept: 'application/ld+json, application/json, text/html',
      });
    } catch {
      return false;
    }
    if (backlinkRes.status < 200 || backlinkRes.status >= 300) {
      return false;
    }
    const contentType = (backlinkRes.headers.get('content-type') || '');
    const text = backlinkRes.body;

    // Two acceptable linkage shapes (either is sufficient):
    //   1. CID v1: a verificationMethod containing this Nostr pubkey
    //      that is referenced from `authentication`. This is what
    //      JSS profiles ship and what the LWS10-CID resource-side
    //      verifier checks. Stronger than sameAs because the user
    //      is asserting the key, not merely an identity equivalence.
    //   2. owl:sameAs / schema:sameAs to did:nostr:<pubkey>. Older
    //      shape; still accepted for compatibility.
    const checkProfile = (jsonLd) =>
      checkCidVmBacklink(jsonLd, pubkey) ||
      checkSameAsLink(jsonLd, expectedDid);

    // Handle HTML with JSON-LD data island
    if (contentType.includes('text/html')) {
      const jsonLdMatch = text.match(/<script\s+type=["']application\/ld\+json["']\s*>([\s\S]*?)<\/script>/i);
      if (jsonLdMatch) {
        try {
          return checkProfile(JSON.parse(jsonLdMatch[1]));
        } catch {
          return false;
        }
      }
      return false;
    }

    // Handle JSON-LD directly
    if (contentType.includes('json')) {
      try {
        return checkProfile(JSON.parse(text));
      } catch {
        return false;
      }
    }

    return false;

  } catch (err) {
    rateLimitedError(`backlink:${webId}`, `WebID backlink verification error for ${webId}: ${err.message}`);
    return false;
  }
}

/**
 * Does the WebID profile contain a CID v1 `verificationMethod` for
 * the given Nostr pubkey, referenced from `authentication`?
 *
 * Mirrors the resource-side verifier's check: a key in
 * `verificationMethod` alone (no `authentication` membership) is
 * NOT a valid auth binding — the user has to explicitly designate
 * it for authentication. JWK entries also have to satisfy the
 * BIP-340 even-y check (handled inside extractNostrPubkeysFromProfile).
 */
function checkCidVmBacklink(jsonLd, pubkey) {
  const target = pubkey.toLowerCase();
  const vms = extractNostrPubkeysFromProfile(jsonLd);
  if (vms.length === 0) return false;

  // Build the absolute set of authentication-referenced IDs. The
  // base for absolutization is the profile's subject (its `@id`).
  // Profiles in the wild can have a relative subject ("@id":"#me"),
  // so we strip the hash and use it as the URL base for resolving
  // any relative entries.
  const subject = jsonLd?.['@id'] || jsonLd?.id || '';
  let base = '';
  try { const u = new URL(subject); u.hash = ''; base = u.toString(); }
  catch { base = ''; }
  const authIds = new Set();
  const auth = jsonLd?.authentication;
  const authList = Array.isArray(auth) ? auth : (auth ? [auth] : []);
  for (const ent of authList) {
    let id;
    if (typeof ent === 'string') id = ent;
    else if (ent && typeof ent === 'object') id = ent['@id'] || ent.id;
    if (!id) continue;
    try { authIds.add(new URL(id, base).toString()); }
    catch { authIds.add(id); }
  }

  for (const { pubkey: vmPubkey, vm } of vms) {
    if (vmPubkey !== target) continue;
    const vmIdRaw = vm.id || vm['@id'];
    if (typeof vmIdRaw !== 'string') continue;
    let vmId = vmIdRaw;
    try { vmId = new URL(vmIdRaw, base).toString(); } catch { /* fall through */ }
    if (authIds.has(vmId)) return true;
  }
  return false;
}

/**
 * Check if JSON-LD contains sameAs/owl:sameAs link to expected DID
 * @param {object} jsonLd - Parsed JSON-LD
 * @param {string} expectedDid - Expected did:nostr:pubkey
 * @returns {boolean}
 */
function checkSameAsLink(jsonLd, expectedDid) {
  // Check various sameAs fields
  const sameAsFields = [
    jsonLd['owl:sameAs'],
    jsonLd['sameAs'],
    jsonLd['schema:sameAs'],
    jsonLd['http://www.w3.org/2002/07/owl#sameAs']
  ];

  for (const field of sameAsFields) {
    if (!field) continue;

    // Handle string value
    if (typeof field === 'string' && field.toLowerCase() === expectedDid) {
      return true;
    }

    // Handle object with @id
    if (field && typeof field === 'object' && field['@id']?.toLowerCase() === expectedDid) {
      return true;
    }

    // Handle array
    if (Array.isArray(field)) {
      for (const item of field) {
        if (typeof item === 'string' && item.toLowerCase() === expectedDid) {
          return true;
        }
        if (item && typeof item === 'object' && item['@id']?.toLowerCase() === expectedDid) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Clear the resolution cache (for testing)
 */
export function clearCache() {
  cache.clear();
}

/** @internal — exposed for tests; current cache size after evictions. */
export function _cacheSizeForTests() {
  return cache.size;
}

/** @internal — exposed for tests; thin wrapper over checkCidVmBacklink. */
export function _checkCidVmBacklinkForTests(profile, pubkey) {
  return checkCidVmBacklink(profile, pubkey);
}

/** @internal — exposed for tests; LRU max for assertions. */
export const _CACHE_MAX_FOR_TESTS = CACHE_MAX_ENTRIES;
