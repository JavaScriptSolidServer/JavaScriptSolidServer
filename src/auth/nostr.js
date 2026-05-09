/**
 * Nostr NIP-98 Authentication
 *
 * Implements HTTP authentication using Schnorr signatures as defined in:
 * - NIP-98: https://nips.nostr.com/98
 * - JIP-0001: https://github.com/JavaScriptSolidServer/jips/blob/main/jip-0001.md
 *
 * Authorization header format: "Nostr <base64-encoded-event>"
 *
 * The authenticated identity is returned as a did:nostr URI:
 *   did:nostr:<64-char-hex-pubkey>
 */

import { verifyEvent, getEventHash } from '../nostr/event.js';
import crypto from 'crypto';
import { resolveDidNostrToWebId } from './did-nostr.js';
import { validateExternalUrl } from '../utils/ssrf.js';

// NIP-98 event kind (references RFC 7235)
const HTTP_AUTH_KIND = 27235;

// Timestamp tolerance in seconds
const TIMESTAMP_TOLERANCE = 60;

// Multicodec varint for secp256k1-pub: 0xe7 0x01 → "e701" hex.
// Used to decode f-form Multikey verificationMethod values back into
// the 32-byte x-only Nostr pubkey.
const MULTICODEC_SECP256K1_PUB_HEX = 'e701';

// Profile-fetch limits — matches the LWS-CID verifier's defenses
// (cross-origin redirect refusal, hop cap, body-size cap).
const MAX_PROFILE_BYTES = 256 * 1024;
const MAX_PROFILE_REDIRECTS = 5;

/**
 * Check if request has Nostr authentication
 * Supports both "Nostr <token>" and "Basic <base64(nostr:token)>" formats
 * The Basic format allows git clients to authenticate via NIP-98
 * @param {object} request - Fastify request object
 * @returns {boolean}
 */
export function hasNostrAuth(request) {
  const authHeader = request.headers.authorization;
  if (!authHeader) return false;

  // Direct Nostr header
  if (authHeader.startsWith('Nostr ')) return true;

  // Basic auth with username=nostr (for git clients)
  if (authHeader.startsWith('Basic ')) {
    try {
      const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
      return decoded.startsWith('nostr:');
    } catch {
      return false;
    }
  }

  return false;
}

/**
 * Extract token from Nostr authorization header
 * Supports both "Nostr <token>" and "Basic <base64(nostr:token)>" formats
 * @param {string} authHeader - Authorization header value
 * @returns {string|null}
 */
export function extractNostrToken(authHeader) {
  if (!authHeader) return null;

  // Direct Nostr header
  if (authHeader.startsWith('Nostr ')) {
    return authHeader.slice(6).trim();
  }

  // Basic auth with username=nostr, password=token
  if (authHeader.startsWith('Basic ')) {
    try {
      const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
      if (decoded.startsWith('nostr:')) {
        return decoded.slice(6); // Remove "nostr:" prefix to get token
      }
    } catch {
      return null;
    }
  }

  return null;
}

// Maximum size for Nostr event (64KB should be plenty for auth events)
const MAX_NOSTR_EVENT_SIZE = 64 * 1024;

/**
 * Decode NIP-98 event from base64 token
 * @param {string} token - Base64 encoded event
 * @returns {object|null} Decoded event or null
 */
function decodeEvent(token) {
  try {
    // Security: limit token size before decoding
    if (token.length > MAX_NOSTR_EVENT_SIZE) {
      return null;
    }
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    // Security: limit decoded size before parsing
    if (decoded.length > MAX_NOSTR_EVENT_SIZE) {
      return null;
    }
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

/**
 * Get tag value from event
 * @param {object} event - Nostr event
 * @param {string} tagName - Tag name (e.g., 'u', 'method')
 * @returns {string|null} Tag value or null
 */
function getTagValue(event, tagName) {
  if (!event.tags || !Array.isArray(event.tags)) {
    return null;
  }
  const tag = event.tags.find(t => Array.isArray(t) && t[0] === tagName);
  return tag ? tag[1] : null;
}

/**
 * Convert Nostr pubkey to did:nostr URI
 * @param {string} pubkey - 64-char hex public key
 * @returns {string} did:nostr URI
 */
export function pubkeyToDidNostr(pubkey) {
  return `did:nostr:${pubkey.toLowerCase()}`;
}

/**
 * Verify NIP-98 authentication and return agent identity
 * @param {object} request - Fastify request object
 * @returns {Promise<{webId: string|null, error: string|null}>}
 */
export async function verifyNostrAuth(request) {
  const token = extractNostrToken(request.headers.authorization);

  if (!token) {
    return { webId: null, error: 'Missing Nostr token' };
  }

  // Decode the event
  const event = decodeEvent(token);
  if (!event) {
    return { webId: null, error: 'Invalid token format: could not decode base64 JSON' };
  }

  // Validate event kind (must be 27235)
  if (event.kind !== HTTP_AUTH_KIND) {
    return { webId: null, error: `Invalid event kind: expected ${HTTP_AUTH_KIND}, got ${event.kind}` };
  }

  // Validate timestamp (within ±60 seconds)
  const now = Math.floor(Date.now() / 1000);
  const eventTime = event.created_at;
  if (!eventTime || Math.abs(now - eventTime) > TIMESTAMP_TOLERANCE) {
    return { webId: null, error: 'Event timestamp outside acceptable window (±60s)' };
  }

  // Build full URL for validation
  const protocol = request.protocol || 'http';
  const host = request.headers.host || request.hostname;
  const fullUrl = `${protocol}://${host}${request.url}`;

  // Validate URL tag matches request URL
  const eventUrl = getTagValue(event, 'u');
  if (!eventUrl) {
    return { webId: null, error: 'Missing URL tag in event' };
  }

  // Compare URLs (normalize by removing trailing slashes)
  const normalizedEventUrl = eventUrl.replace(/\/$/, '');
  const normalizedRequestUrl = fullUrl.replace(/\/$/, '');
  const normalizedRequestUrlNoQuery = fullUrl.split('?')[0].replace(/\/$/, '');

  // Check for exact match first
  let urlMatches = normalizedEventUrl === normalizedRequestUrl ||
                   normalizedEventUrl === normalizedRequestUrlNoQuery;

  // For git clients: allow prefix matching (event URL is base of request URL)
  // This enables git credential helpers that sign for the repo base URL
  if (!urlMatches && normalizedRequestUrlNoQuery.startsWith(normalizedEventUrl + '/')) {
    urlMatches = true;
  }

  if (!urlMatches) {
    return { webId: null, error: `URL mismatch: event URL "${eventUrl}" does not match request URL "${fullUrl}"` };
  }

  // Validate method tag matches request method
  // For git clients: allow '*' as wildcard method
  // If method tag is missing, infer from HTTP request (lenient mode)
  const eventMethod = getTagValue(event, 'method');
  if (eventMethod && eventMethod !== '*' && eventMethod.toUpperCase() !== request.method.toUpperCase()) {
    return { webId: null, error: `Method mismatch: expected ${request.method}, got ${eventMethod}` };
  }

  // Validate payload hash if present and request has body
  const payloadTag = getTagValue(event, 'payload');
  if (payloadTag && request.body) {
    let bodyString;
    if (typeof request.body === 'string') {
      bodyString = request.body;
    } else if (Buffer.isBuffer(request.body)) {
      bodyString = request.body.toString();
    } else {
      bodyString = JSON.stringify(request.body);
    }

    const expectedHash = crypto.createHash('sha256').update(bodyString).digest('hex');
    if (payloadTag.toLowerCase() !== expectedHash.toLowerCase()) {
      return { webId: null, error: 'Payload hash mismatch' };
    }
  }

  // Validate pubkey exists
  if (!event.pubkey || typeof event.pubkey !== 'string' || event.pubkey.length !== 64) {
    return { webId: null, error: 'Invalid or missing pubkey' };
  }

  // Compute event id if missing (lenient mode for nosdav compatibility).
  // Uses the same canonical serialization as `verifyEvent` below so we
  // can't drift out of sync with how the verifier hashes events.
  if (!event.id) {
    event.id = getEventHash(event);
  }

  // Verify Schnorr signature
  const isValid = verifyEvent(event);
  if (!isValid) {
    return { webId: null, error: 'Invalid Schnorr signature' };
  }

  // First lookup: the resource's owner WebID profile. If the pod owner
  // declared this pubkey as a verificationMethod (CID v1 / LWS-CID
  // shape — produced by the doctor's B.2 path), authenticate as the
  // WebID. This is profile-only (no DID-doc fetch) and works for any
  // user who's added a Nostr VM to their profile — see #386 / #399.
  const vmWebId = await tryResolveViaCidVerificationMethod(request, event.pubkey);
  if (vmWebId) {
    return { webId: vmWebId, error: null };
  }

  // Second lookup: existing did:nostr DID-document resolver. Fetches
  // an external DID doc (e.g. nostr.social/.well-known/...) and checks
  // bidirectional alsoKnownAs ↔ WebID linking.
  const resolvedWebId = await resolveDidNostrToWebId(event.pubkey);
  if (resolvedWebId) {
    return { webId: resolvedWebId, error: null };
  }

  // Fall back to did:nostr as the agent identifier
  const didNostr = pubkeyToDidNostr(event.pubkey);

  return { webId: didNostr, error: null };
}

/**
 * Attempt to upgrade a verified Nostr pubkey to a WebID by looking it
 * up in the resource owner's CID document (= WebID profile).
 *
 * Returns the WebID if:
 *   - the pod-owner WebID can be derived from the request
 *   - the profile fetches cleanly (passes SSRF guard, JSON-LD)
 *   - one of its `verificationMethod` entries carries this pubkey
 *     (either as f-form Multikey or as a secp256k1 JsonWebKey)
 *   - that VM is referenced from `authentication`
 *
 * Returns null in any other case — the caller falls back to the
 * existing DID-doc / did:nostr-identity paths.
 */
async function tryResolveViaCidVerificationMethod(request, pubkeyHex) {
  const ownerWebId = getPodOwnerWebId(request);
  if (!ownerWebId) return null;
  const docUrl = stripHash(ownerWebId);

  // SSRF guard. The owner WebID is derived from server-side request
  // data, so it shouldn't be attacker-controllable, but route through
  // the same defense-in-depth as the LWS-CID verifier — including
  // manual redirect handling with same-origin enforcement, and a
  // body-size cap to deflect oversized-payload DoS.
  let profile;
  try {
    profile = await fetchProfileSafely(docUrl);
  } catch {
    return null;
  }
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) return null;

  const vm = findNostrVmInProfile(profile, pubkeyHex, docUrl);
  if (!vm) return null;
  if (!isInProofPurpose(profile, 'authentication', vm.id, docUrl)) return null;

  // Use the profile's declared subject as the authenticated identity
  // (with @id fallback). Absolutize so a relative @id resolves.
  const subject = profile['@id'] || profile.id;
  if (!subject) return null;
  return absolutize(subject, docUrl);
}

/**
 * Derive the pod-owner WebID URL from a Fastify request.
 *
 * JSS supports three pod-addressing modes (see src/idp/interactions.js
 * around the createPod path for the canonical list):
 *
 *   - **Subdomain mode** — `subdomainsEnabled` is true, request hits a
 *     subdomain like `alice.example.com`. WebID is at the subdomain
 *     root: `https://alice.example.com/profile/card.jsonld#me`.
 *   - **Path mode** — the JSS default (`subdomainsEnabled` off). Pod
 *     is at the first URL path segment:
 *     `https://example.com/alice/foo` → WebID
 *     `https://example.com/alice/profile/card.jsonld#me`.
 *   - **Path-mode-on-base** — subdomains are enabled but the request
 *     hits the base domain with a path. The internal canonical form
 *     rewrites this to the subdomain shape (per buildResourceUrl).
 *
 * Returns null when no pod name can be derived (single-user
 * deployments will hit this path; the caller falls back to the
 * existing did:nostr DID-doc resolver / did:nostr identity).
 */
function getPodOwnerWebId(request) {
  const headers = request.headers || {};
  const proto = firstHeaderValue(headers['x-forwarded-proto'])
              || request.protocol
              || 'https';
  const host  = firstHeaderValue(headers['x-forwarded-host'])
              || firstHeaderValue(headers.host)
              || request.hostname;
  if (!host) return null;

  // Subdomain mode (request already on a pod's subdomain).
  if (request.subdomainsEnabled && request.podName && request.baseDomain) {
    return `${proto}://${request.podName}.${request.baseDomain}/profile/card.jsonld#me`;
  }

  // Subdomain-enabled deployment, request landed on the base domain
  // with a path (e.g. https://example.com/alice/...). The canonical
  // form is the subdomain — match the rewriting buildResourceUrl does.
  if (request.subdomainsEnabled && request.baseDomain && host === request.baseDomain) {
    const m = (request.url || '').match(/^\/([^/?#]+)/);
    if (m && !m[1].startsWith('.') && !m[1].includes('.')) {
      return `${proto}://${m[1]}.${request.baseDomain}/profile/card.jsonld#me`;
    }
    return null;
  }

  // Path mode (JSS default): pod is the first URL segment.
  const m = (request.url || '').match(/^\/([^/?#]+)/);
  if (m && !m[1].startsWith('.') && !m[1].includes('.')) {
    return `${proto}://${host}/${m[1]}/profile/card.jsonld#me`;
  }
  return null;
}

/**
 * Fetch a CID document (= WebID profile) with the same defenses as the
 * LWS-CID verifier:
 *
 *   - SSRF validation on the URL (and on every redirect Location).
 *   - Manual redirect handling, capped at MAX_PROFILE_REDIRECTS.
 *   - Cross-origin redirects refused so an open redirect on the WebID's
 *     host can't substitute an attacker-controlled CID document.
 *   - Body cap (Content-Length up front, streaming-reader cap during
 *     read) so an untrusted host can't OOM us.
 *
 * Throws on any failure; the caller treats throw-as-null.
 */
async function fetchProfileSafely(docUrl) {
  const originalOrigin = new URL(docUrl).origin;
  let currentUrl = docUrl;

  for (let hop = 0; hop <= MAX_PROFILE_REDIRECTS; hop++) {
    const isLastAllowedHop = hop === MAX_PROFILE_REDIRECTS;
    const validation = await validateExternalUrl(currentUrl, {
      requireHttps: process.env.NODE_ENV === 'production',
      blockPrivateIPs: true,
      resolveDNS: true,
    });
    if (!validation.valid) {
      throw new Error(`SSRF protection: ${validation.error}`);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    let res;
    try {
      res = await fetch(currentUrl, {
        headers: { Accept: 'application/ld+json, application/json;q=0.9' },
        redirect: 'manual',
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (res.status >= 300 && res.status < 400) {
      if (isLastAllowedHop) {
        throw new Error(`too many redirects (>${MAX_PROFILE_REDIRECTS})`);
      }
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

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const ct = (res.headers.get('content-type') || '').toLowerCase();
    if (!ct.includes('json')) throw new Error(`unexpected content-type: ${ct || '(none)'}`);

    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > MAX_PROFILE_BYTES) {
      throw new Error(`CID document too large (Content-Length=${declared})`);
    }
    const text = await readBodyWithCap(res, MAX_PROFILE_BYTES);
    return JSON.parse(text);
  }
  throw new Error('profile fetch loop exited unexpectedly');
}

async function readBodyWithCap(res, maxBytes) {
  const reader = res.body?.getReader?.();
  if (!reader) {
    const text = await res.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      throw new Error(`CID document too large (>${maxBytes} bytes)`);
    }
    return text;
  }
  const chunks = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      try { await reader.cancel(); } catch { /* noop */ }
      throw new Error(`CID document too large (>${maxBytes} bytes)`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength))).toString('utf8');
}

function firstHeaderValue(v) {
  if (!v) return null;
  // Fastify/Node header values can be string or string[].
  const s = Array.isArray(v) ? v[0] : v;
  if (typeof s !== 'string') return null;
  const first = s.split(',')[0].trim();
  return first || null;
}

/**
 * Find a verificationMethod whose key material matches the Nostr
 * x-only pubkey hex. Two encodings supported:
 *   - f-form Multikey:  publicKeyMultibase = "f" + "e701" + parity + xonly
 *   - JsonWebKey:       publicKeyJwk.x = base64url(xonly)  (kty:EC, crv:secp256k1)
 *
 * Returns the entry (object form) on match, normalized so .id is the
 * absolute IRI. Returns null on no match.
 */
function findNostrVmInProfile(profile, pubkeyHex, baseUrl) {
  const target = pubkeyHex.toLowerCase();
  const targetB64u = hexToBase64url(target);
  const vms = asArray(profile.verificationMethod);
  for (const vm of vms) {
    if (!vm || typeof vm !== 'object') continue;
    const vmId = vm.id || vm['@id'];
    if (typeof vmId !== 'string') continue;

    if (typeof vm.publicKeyMultibase === 'string') {
      const xonly = decodeFFormSecp256k1(vm.publicKeyMultibase);
      if (xonly === target) return { ...vm, id: absolutize(vmId, baseUrl) };
    }
    if (vm.publicKeyJwk && typeof vm.publicKeyJwk === 'object') {
      const jwk = vm.publicKeyJwk;
      if (jwk.kty === 'EC' && (jwk.crv === 'secp256k1' || jwk.crv === 'P-256K')) {
        if (typeof jwk.x === 'string' && jwk.x === targetB64u) {
          return { ...vm, id: absolutize(vmId, baseUrl) };
        }
      }
    }
  }
  return null;
}

/**
 * Decode an f-form Multikey for secp256k1-pub back into the 32-byte
 * x-only pubkey hex. Returns null if the input isn't this shape.
 */
function decodeFFormSecp256k1(mb) {
  if (typeof mb !== 'string' || !mb.startsWith('f')) return null;
  const hex = mb.slice(1).toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) return null;
  if (!hex.startsWith(MULTICODEC_SECP256K1_PUB_HEX)) return null;
  const rest = hex.slice(MULTICODEC_SECP256K1_PUB_HEX.length);
  // Expect parity byte (02/03) + 32-byte xonly = 66 hex chars.
  if (rest.length !== 66) return null;
  const parity = rest.slice(0, 2);
  if (parity !== '02' && parity !== '03') return null;
  return rest.slice(2);
}

function hexToBase64url(hex) {
  return Buffer.from(hex, 'hex').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function isInProofPurpose(profile, predicate, vmId, baseUrl) {
  const entries = asArray(profile[predicate]);
  if (entries.length === 0) return false;
  for (const ent of entries) {
    if (typeof ent === 'string') {
      if (absolutize(ent, baseUrl) === vmId) return true;
    } else if (ent && typeof ent === 'object') {
      const id = ent['@id'] ?? ent.id;
      if (id && absolutize(id, baseUrl) === vmId) return true;
    }
  }
  return false;
}

function asArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

function absolutize(u, base) {
  if (!u) return u;
  try { return new URL(u, base).toString(); } catch { return u; }
}

function stripHash(u) {
  if (typeof u !== 'string') return u;
  try {
    const url = new URL(u);
    url.hash = '';
    return url.toString();
  } catch {
    return u.split('#')[0];
  }
}

/**
 * Get Nostr pubkey from request if authenticated via NIP-98
 * @param {object} request - Fastify request object
 * @returns {Promise<string|null>} Hex pubkey or null
 */
export async function getNostrPubkey(request) {
  if (!hasNostrAuth(request)) {
    return null;
  }

  const token = extractNostrToken(request.headers.authorization);
  if (!token) {
    return null;
  }

  try {
    const event = decodeEvent(token);
    return event?.pubkey || null;
  } catch {
    return null;
  }
}
