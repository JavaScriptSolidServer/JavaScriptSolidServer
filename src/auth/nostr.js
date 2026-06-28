/**
 * Nostr NIP-98 Authentication
 *
 * Implements HTTP authentication using Schnorr signatures as defined in:
 * - NIP-98: https://nips.nostr.com/98
 * - JIP-0001: https://github.com/JavaScriptSolidServer/jips/blob/main/jip-0001.md
 *
 * Authorization header format: "Nostr <base64-encoded-event>"
 *
 * Identity resolution chain (after a successful Schnorr verification):
 *
 *   1. Look up the Nostr pubkey in the resource owner's WebID profile
 *      as a CID v1 verificationMethod referenced from `authentication`.
 *      Match by f-form Multikey or by JsonWebKey x/y coordinates. If
 *      found, authenticate as the WebID. (#399 — pairs with the
 *      LWS10-CID verifier.)
 *   2. (IdP-only) Look up the pubkey in the local in-process index
 *      built from `<DATA_ROOT>/.idp/accounts/_webid_index.json`.
 *      No HTTP, no SSRF surface — direct function call. Catches
 *      same-pod users without a third-party round-trip. (#407)
 *   3. Resolve via the external did:nostr DID-document path
 *      (nostr.social `.well-known` + bidirectional alsoKnownAs).
 *      Used for cross-pod identities; SSRF + redirect hardened.
 *   4. Otherwise return `did:nostr:<64-char-hex-pubkey>` as the
 *      agent identity (the original behavior).
 */

import { verifyEvent, getEventHash } from '../nostr/event.js';
import crypto from 'crypto';
import { resolveDidNostrToWebId } from './did-nostr.js';
// resolveDidNostrLocally is loaded lazily (inside the idpEnabled
// branch) so non-IdP deployments don't pay the IdP/accounts module
// startup cost (bcryptjs, oidc-provider helpers, etc.) just by
// importing the NIP-98 verifier.
import { fetchCidDocument } from './cid-doc-fetch.js';
import { normalizeControllers } from './lws-cid.js'; // shared JSON-LD controller helper
import { decodeFFormSecp256k1, extractNostrPubkeysFromProfile, nostrJwkYParities } from './nostr-keys.js';
export { extractNostrPubkeysFromProfile }; // re-exported for back-compat

// NIP-98 event kind (references RFC 7235)
const HTTP_AUTH_KIND = 27235;

// Timestamp tolerance in seconds
const TIMESTAMP_TOLERANCE = 60;

// Profile-fetch body-size cap. Matches the LWS-CID verifier; both
// callers go through the shared fetchCidDocument helper.
const MAX_PROFILE_BYTES = 256 * 1024;

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

  // Build full URL for validation. Behind a reverse proxy the public-
  // facing URL is what the client signed, but request.headers.host /
  // request.protocol carry the internal upstream values. Honor the
  // forwarded headers (matching the conventions in src/ap/* and the
  // LWS-CID verifier) so a NIP-98 sig for the public URL still
  // matches in proxied deployments. Proto is lowercased + allowlisted
  // to avoid casing-mismatches from misconfigured proxies.
  const protoRaw = firstHeaderValue(request.headers['x-forwarded-proto'])
                || request.protocol
                || 'http';
  const protoLower = protoRaw.toLowerCase();
  const protocol = (protoLower === 'http' || protoLower === 'https') ? protoLower : 'http';
  const host = firstHeaderValue(request.headers['x-forwarded-host'])
            || firstHeaderValue(request.headers.host)
            || request.hostname;
  // Reject URL-meaningful characters in the host before interpolation
  // — same defense as in getPodOwnerWebId. Otherwise a Host like
  // `example.com@attacker.com` would produce a fullUrl that parses
  // with attacker.com as the hostname, which a sophisticated client
  // could try to align with a NIP-98 `u` tag for an external
  // resource.
  if (host && /[@/\s?#\\]/.test(host)) {
    return { webId: null, error: 'Host header contains invalid characters' };
  }
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
  // Validate whenever a payload tag is present AND a body was provided —
  // keyed on `!== undefined`, not truthiness, so a JSON body that parses
  // to a falsy value (`null`, `false`, `0`, `""`) is still hash-checked
  // rather than silently skipping the integrity guard (Copilot review on
  // #573). Fastify leaves request.body `undefined` when no body was sent.
  if (payloadTag && request.body !== undefined) {
    // Hash the EXACT bytes the client signed. NIP-98's `payload` tag is
    // sha256(request body) over the wire bytes. crypto.update() accepts a
    // string (encoded UTF-8) or a Buffer (raw bytes), so we pass each
    // through in its native form — never a lossy conversion.
    let bodyData;
    if (typeof request.rawBody === 'string') {
      // application/json raw wire string captured by the parser (#565),
      // because by this point request.body is already a parsed object and
      // the original bytes are gone. Re-serializing the object (the old
      // fallback) only matched when the client happened to send minified
      // JSON in Node's exact key order — pretty-printed or differently-
      // escaped bodies 401'd despite a valid signature. (JSON is UTF-8 by
      // spec, so the captured string round-trips losslessly.)
      bodyData = request.rawBody;
    } else if (typeof request.body === 'string') {
      bodyData = request.body;
    } else if (Buffer.isBuffer(request.body)) {
      // Hash the Buffer DIRECTLY. A .toString() round-trip UTF-8-mangles
      // binary / non-UTF-8 bodies (e.g. an image PUT) and would cause
      // false mismatches against the raw-byte hash the client signed.
      bodyData = request.body;
    } else {
      // No raw bytes captured (shouldn't happen for HTTP requests:
      // application/json sets rawBody, other types stay a Buffer). Keep a
      // deterministic fallback rather than throwing.
      bodyData = JSON.stringify(request.body);
    }

    const expectedHash = crypto.createHash('sha256').update(bodyData).digest('hex');
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

  // Second lookup: in-process local DID resolution (#407). Fast path
  // — direct function call into the local account index, no HTTP
  // fetch, no SSRF surface from request-controlled headers. Catches
  // any user who's published a Nostr Multikey VM into their profile
  // on this same pod.
  //
  // Gated on idpEnabled because the index reads from
  // <DATA_ROOT>/.idp/accounts which only exists when the IdP layer
  // is in use. On non-IdP deployments the local resolver has nothing
  // to find and would just spin disk on every request.
  if (request.idpEnabled) {
    // Dynamic import: only load the IdP-accounts stack when IdP is
    // actually enabled. Cached after first load (ESM module caching).
    const { resolveDidNostrLocally } = await import('../idp/well-known-did-nostr.js');
    const localWebId = await resolveDidNostrLocally(event.pubkey);
    if (localWebId) {
      return { webId: localWebId, error: null };
    }
  }

  // Third lookup: external did:nostr DID-document resolver. Fetches
  // a DID doc from the configured external resolver (nostr.social) and
  // checks bidirectional alsoKnownAs ↔ WebID linking. Used only for
  // cross-pod identities (the local case is handled above).
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

  // Subject-identity check (mirrors lws-cid.js). The CID document we
  // just fetched MUST identify itself as the WebID we computed from
  // the request — otherwise a profile hosted at the expected URL
  // could declare a different `@id` and trick us into authenticating
  // as that other identity using a sibling VM. We always return the
  // computed ownerWebId (never the profile's declared subject) so a
  // relative-IRI or mismatched `@id` can't substitute identity.
  const subject = absolutize(profile['@id'] || profile.id, docUrl);
  if (!subject || subject !== ownerWebId) return null;

  const vm = findNostrVmInProfile(profile, pubkeyHex, docUrl);
  if (!vm) return null;
  if (!isInProofPurpose(profile, 'authentication', vm.id, docUrl)) return null;

  // Controller consistency: the VM's `controller` MUST be in the
  // profile's expected controller set (declared `controller`, with
  // @id fallback). Without this, a profile with a Nostr-keyed VM
  // controlled by some unrelated identity could still upgrade us to
  // the WebID — a key-binding the actual subject never asserted.
  // Mirrors the lws-cid.js check using the same normalizer.
  const expectedCtrls = normalizeControllers(profile.controller ?? profile['@id'] ?? profile.id, docUrl);
  if (expectedCtrls.length === 0) return null;
  const vmCtrls = normalizeControllers(vm.controller, docUrl);
  if (!vmCtrls.some((c) => expectedCtrls.includes(c))) return null;

  return ownerWebId;
}

/**
 * Derive the pod-owner WebID URL from a Fastify request.
 *
 * JSS supports four pod-addressing modes (see src/idp/interactions.js
 * around the createPod path for the canonical list):
 *
 *   - **Single-user mode** — `request.singleUser` is true. The pod
 *     either lives at the host root (WebID
 *     `https://host/profile/card.jsonld#me`) or, when
 *     `request.singleUserName` is set, at `/<name>/profile/card.jsonld#me`.
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
 * Returns null when no pod name can be derived; the caller falls back
 * to the existing did:nostr DID-doc resolver / did:nostr identity.
 */
function getPodOwnerWebId(request) {
  const headers = request.headers || {};
  // Lowercase + allowlist the protocol. Some proxies send
  // `X-Forwarded-Proto: HTTPS` (or other casings); without
  // normalization the constructed ownerWebId would carry that
  // casing and the subject-identity check would reject the match
  // against a profile @id that uses lowercase `https://`.
  const protoRaw = firstHeaderValue(headers['x-forwarded-proto'])
                 || request.protocol
                 || 'https';
  const protoLower = protoRaw.toLowerCase();
  const proto = (protoLower === 'http' || protoLower === 'https') ? protoLower : 'https';
  // The Host header / x-forwarded-host can carry a port and may be an
  // IPv6 literal (`[::1]:3000`). For all WebID construction we use
  // `hostNoPort` — the URL parser's port-stripped hostname (still
  // bracketed for IPv6 here; we bail out on IPv6 below). This
  // matches what JSS itself stores: subdomain mode derives from
  // `baseDomain` (no port), and src/handlers/container.js builds
  // path-mode WebIDs from `request.hostname` (port-stripped). Using
  // a port-bearing host here would compute a WebID that doesn't
  // match the stored profile @id, so the subject-identity check
  // would reject otherwise-valid requests on non-default ports.
  const hostRaw = firstHeaderValue(headers['x-forwarded-host'])
                || firstHeaderValue(headers.host)
                || request.hostname;
  if (!hostRaw) return null;
  // Reject host strings that carry URL-special characters before we
  // hand them to the URL parser. Without this, a Host like
  // `example.com@attacker.com` would parse as userinfo + attacker.com
  // and steer the computed owner WebID at the attacker's domain.
  // A well-formed Host header carries hostname[:port][[]] only —
  // reject any other URL-meaningful character (`@`, `/`, `?`, `#`,
  // whitespace, query/fragment delimiters).
  if (/[@/\s?#\\]/.test(hostRaw)) return null;
  // `request.hostname` is port-stripped per Fastify but doesn't survive
  // x-forwarded-host parsing. Round-trip through URL semantics so
  // IPv6 brackets and ports are handled by the parser, not split(':').
  let hostNoPort;
  try { hostNoPort = new URL(`${proto}://${hostRaw}`).hostname; }
  catch { return null; }
  // Detect IPv6 literal hosts and bail early. URL.hostname keeps
  // brackets for IPv6 (verified Node v24.5.0:
  //   new URL('https://[2001:db8::1]:8443/x').hostname === '[2001:db8::1]'
  // per WHATWG URL §host serializing rule). Continuing into the
  // URL-construction branches with a bracket-less form would yield a
  // malformed string like `https://2001:db8::1/...` — invalid, would
  // throw at parse time and could pollute the shared CID-profile
  // cache with a failure entry under that bogus key.
  //
  // Solid deployments on raw IPv6 literals are effectively
  // non-existent; cleanly skipping the VM-lookup upgrade for them
  // (caller falls back to the existing did:nostr resolver) is the
  // right behavior. JSS itself has a parallel limitation in
  // src/handlers/container.js — fixing IPv6 needs to happen at that
  // pod-creation layer first.
  const isIpv6 = hostNoPort.startsWith('[') && hostNoPort.endsWith(']');
  if (isIpv6) return null;

  // Single-user deployment. The pod is either at the host root or
  // mounted under `/<singleUserName>/`; both shapes are supported.
  // Use the port-stripped form to match what JSS itself stores in
  // the profile @id at pod-creation time (src/handlers/container.js
  // builds with `request.hostname`, port-stripped). Otherwise a
  // request arriving on a non-default port would compute a WebID
  // the subject-identity check rejects.
  if (request.singleUser) {
    const name = request.singleUserName;
    return name
      ? `${proto}://${hostNoPort}/${name}/profile/card.jsonld#me`
      : `${proto}://${hostNoPort}/profile/card.jsonld#me`;
  }

  // Subdomain mode (request already on a pod's subdomain).
  if (request.subdomainsEnabled && request.podName && request.baseDomain) {
    return `${proto}://${request.podName}.${request.baseDomain}/profile/card.jsonld#me`;
  }

  // Subdomain-enabled deployment, request landed on the base domain
  // with a path (e.g. https://example.com/alice/...). The canonical
  // form is the subdomain — match the rewriting buildResourceUrl does.
  if (request.subdomainsEnabled && request.baseDomain && hostNoPort === request.baseDomain) {
    const m = (request.url || '').match(/^\/([^/?#]+)/);
    if (m && !m[1].startsWith('.') && !m[1].includes('.')) {
      return `${proto}://${m[1]}.${request.baseDomain}/profile/card.jsonld#me`;
    }
    return null;
  }

  // Path mode (JSS default): pod is the first URL segment. Match
  // src/handlers/container.js which builds path-mode WebIDs from
  // `request.hostname` (port-stripped), so the computed ownerWebId
  // equals the @id JSS itself wrote at pod-creation time.
  const m = (request.url || '').match(/^\/([^/?#]+)/);
  if (m && !m[1].startsWith('.') && !m[1].includes('.')) {
    return `${proto}://${hostNoPort}/${m[1]}/profile/card.jsonld#me`;
  }
  return null;
}

/**
 * Fetch a CID document (= WebID profile). Delegates to the shared
 * fetcher in src/auth/cid-doc-fetch.js so SSRF / redirect / body-cap
 * defenses don't drift between this and the LWS-CID verifier.
 *
 * Throws on any failure; the caller treats throw-as-null.
 *
 * KNOWN GAP (#381): the underlying validateExternalUrl currently
 * fail-opens when DNS returns no A/AAAA records. Fix belongs in the
 * shared util so every caller benefits at once.
 */
async function fetchProfileSafely(docUrl) {
  return fetchCidDocument(docUrl, { maxBytes: MAX_PROFILE_BYTES });
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
 * Confirm that a verified Nostr pubkey is declared as a CID
 * verificationMethod referenced from `authentication` in the given
 * WebID's profile. Used by the Schnorr-login IdP path (#403): once
 * the signature is verified and the user has typed their username,
 * the IdP layer can derive the candidate WebID and ask this whether
 * the verified pubkey actually belongs to that WebID.
 *
 * Mirrors the same controller-consistency / subject-identity /
 * authentication-membership checks as the resource-side path
 * (tryResolveViaCidVerificationMethod) so the two paths apply the
 * same key-binding semantics.
 *
 * Returns true on match, false on any failure (fetch, VM not in
 * authentication, subject mismatch, controller mismatch, bad input).
 *
 * @param {string} webId - canonical fragment-bearing WebID URI (e.g.
 *   `https://alice.example.com/profile/card.jsonld#me`). The profile's
 *   own `@id` must match this exactly after absolutization.
 * @param {string} pubkeyHex - 32-byte x-only Nostr pubkey hex
 * @returns {Promise<boolean>}
 */
export async function verifyNostrPubkeyAgainstWebId(webId, pubkeyHex) {
  if (typeof webId !== 'string' || !webId) return false;
  if (typeof pubkeyHex !== 'string' || !/^[0-9a-f]{64}$/i.test(pubkeyHex)) return false;
  const docUrl = stripHash(webId);
  let profile;
  try {
    profile = await fetchCidDocument(docUrl);
  } catch {
    return false;
  }
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) return false;

  // Confirm the profile actually identifies itself as the WebID we're
  // asking about — otherwise a profile hosted at the WebID's URL could
  // declare a different fragment as its subject and trick us. Both
  // sides absolutized so a relative @id (e.g. "#me") resolves against
  // docUrl and a webId without fragment (which the docstring no longer
  // permits, but be defensive) doesn't accidentally match a fragment
  // form.
  const subject = absolutize(profile['@id'] || profile.id, docUrl);
  const expectedSubject = absolutize(webId, docUrl);
  if (!subject || subject !== expectedSubject) return false;

  const vm = findNostrVmInProfile(profile, pubkeyHex.toLowerCase(), docUrl);
  if (!vm) return false;
  if (!isInProofPurpose(profile, 'authentication', vm.id, docUrl)) return false;

  // Controller consistency: the VM's `controller` MUST be in the
  // profile's expected controller set (declared `controller`, with
  // @id fallback). Without this, a profile with a Nostr-keyed VM
  // controlled by some unrelated identity would pass — a binding the
  // actual subject never asserted. Mirrors the resource-path check.
  const expectedCtrls = normalizeControllers(profile.controller ?? profile['@id'] ?? profile.id, docUrl);
  if (expectedCtrls.length === 0) return false;
  const vmCtrls = normalizeControllers(vm.controller, docUrl);
  if (!vmCtrls.some((c) => expectedCtrls.includes(c))) return false;

  return true;
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
        if (jwkMatchesNostrPubkey(jwk, target, targetB64u)) {
          return { ...vm, id: absolutize(vmId, baseUrl) };
        }
      }
    }
  }
  return null;
}

function hexToBase64url(hex) {
  return Buffer.from(hex, 'hex').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Does the JWK encode the given Nostr x-only pubkey?
 *
 * EC keys are (x, y) pairs — two distinct valid points share the same
 * x with opposite y parities. Matching on x alone would let an
 * attacker craft a JWK with the target x and a fabricated, off-curve
 * y, which we'd then accept as the user's Nostr key. So we also
 * require the JWK's y to be a genuine on-curve y for the target x —
 * accepting either parity, since the did:nostr spec allows both 0x02
 * (even) and 0x03 (odd) encodings of the same x-only identity (see
 * `nostrJwkYParities` / issue #571).
 *
 * Returns false if the JWK's coordinates aren't on-curve, can't be
 * decoded, or don't match an on-curve point for `targetHex`.
 */
function jwkMatchesNostrPubkey(jwk, targetHex, targetB64u) {
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') return false;
  if (jwk.x !== targetB64u) return false;
  // The two genuine on-curve y's (even + odd parity) for the target x.
  const validY = nostrJwkYParities(targetHex);
  if (!validY) return false;
  let jwkYHex;
  try {
    jwkYHex = Buffer.from(jwk.y.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
      .toString('hex').toLowerCase();
  } catch {
    return false;
  }
  return validY.includes(jwkYHex);
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
