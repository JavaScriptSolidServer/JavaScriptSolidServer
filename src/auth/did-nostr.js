/**
 * DID:nostr Resolution
 *
 * Resolves did:nostr:<pubkey> to a Solid WebID by:
 * 1. Fetching DID document from nostr.social
 * 2. Extracting alsoKnownAs WebID
 * 3. Verifying bidirectional link (WebID links back to did:nostr)
 */

// Default DID resolver endpoint
const DEFAULT_DID_RESOLVER = 'https://nostr.social/.well-known/did/nostr';

// Cache for resolved DIDs (pubkey -> webId or null)
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const FAILURE_CACHE_TTL = 60 * 1000; // 1 minute for failed lookups

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

/**
 * Fetch with timeout
 */
async function fetchWithTimeout(url, options = {}, timeout = 5000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

/**
 * Resolve did:nostr pubkey to WebID via DID document
 * @param {string} pubkey - 64-char hex Nostr pubkey
 * @param {string} resolverUrl - DID resolver base URL
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
      return cached.webId;
    }
    cache.delete(cacheKey);
  }

  try {
    // Fetch DID document
    const didUrl = `${resolverUrl}/${pubkey}.json`;
    const didRes = await fetchWithTimeout(didUrl, {
      headers: { 'Accept': 'application/did+json, application/json' }
    });

    if (!didRes.ok) {
      cache.set(cacheKey, { webId: null, timestamp: Date.now() });
      return null;
    }

    const didDoc = await didRes.json();

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
      cache.set(cacheKey, { webId: null, timestamp: Date.now() });
      return null;
    }

    // Verify bidirectional link - WebID must link back to did:nostr
    const verified = await verifyWebIdBacklink(webId, pubkey);

    if (verified) {
      cache.set(cacheKey, { webId, timestamp: Date.now() });
      return webId;
    }

    cache.set(cacheKey, { webId: null, timestamp: Date.now() });
    return null;

  } catch (err) {
    // Cache failures with short TTL to avoid hammering a down service
    cache.set(cacheKey, { webId: null, timestamp: Date.now(), failureTtl: true });
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

    // Fetch WebID profile
    const res = await fetchWithTimeout(webId, {
      headers: { 'Accept': 'application/ld+json, application/json, text/html' }
    });

    if (!res.ok) {
      return false;
    }

    const contentType = res.headers.get('content-type') || '';
    const text = await res.text();

    // Handle HTML with JSON-LD data island
    if (contentType.includes('text/html')) {
      const jsonLdMatch = text.match(/<script\s+type=["']application\/ld\+json["']\s*>([\s\S]*?)<\/script>/i);
      if (jsonLdMatch) {
        try {
          const jsonLd = JSON.parse(jsonLdMatch[1]);
          return checkSameAsLink(jsonLd, expectedDid);
        } catch {
          return false;
        }
      }
      return false;
    }

    // Handle JSON-LD directly
    if (contentType.includes('json')) {
      try {
        const jsonLd = JSON.parse(text);
        return checkSameAsLink(jsonLd, expectedDid);
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
