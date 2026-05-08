/**
 * CORS proxy handler — fetches an arbitrary upstream URL on behalf of a
 * browser-side caller and returns the response with CORS headers, so
 * pod-hosted apps can talk to non-CORS-friendly origins (#378).
 *
 * URL shape: `/proxy?url=<absolute-url>` — query-param keeps the path a
 * plain Solid resource for WAC purposes (acl can sit at /proxy or /.acl
 * and inherit normally).
 *
 * Auth: WAC. The standard /proxy resource is checked by server.js's
 * authorize() pipeline before this handler runs; pod owner controls
 * access by writing an .acl on /proxy.
 *
 * SSRF: validateExternalUrl() runs on the user-supplied URL AND on every
 * redirect target. Manual redirect following is non-negotiable — letting
 * fetch() follow redirects automatically would let an attacker host a
 * 302 to 169.254.169.254 and bypass the initial guard.
 *
 * Body limits: streamed, with a configurable max-bytes ceiling enforced
 * during streaming. Timeout via AbortController.
 */

import { validateExternalUrl } from '../utils/ssrf.js';
import { Readable, Transform } from 'stream';

// CORS headers applied to every proxy response. Same shape/source-of-truth
// pattern as GIT_CORS_HEADERS in src/handlers/git.js (#374).
//
// Allow-Headers must list every request header the proxy actually
// forwards (see FORWARD_REQUEST_HEADERS) — otherwise browsers reject
// preflight before the request reaches us. Plus:
//   - Authorization, DPoP — for WAC + Solid-OIDC auth to *this* pod
//   - X-Upstream-Authorization — opt-in upstream credential (renamed to
//     Authorization on the way out, see pickRequestHeaders)
//
// Expose-Headers includes WAC-Allow so browser clients can render auth
// UX based on the pod's policy, plus the usual content/etag/location set.
//
// Allow-Credentials is set explicitly to 'false' to override the
// server-wide global CORS hook (which uses 'true' for the rest of the
// pod). Combining 'true' with `Allow-Origin: *` is a CORS spec
// violation that browsers reject — and an anonymous-readable proxy
// doesn't have a use case for credentialed cross-origin anyway (Cookie
// is stripped before forwarding).
export const PROXY_CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Credentials': 'false',
  'Access-Control-Allow-Methods': 'GET, POST, HEAD, OPTIONS',
  'Access-Control-Allow-Headers': [
    'Content-Type',
    'Authorization',
    'DPoP',
    'X-Upstream-Authorization',
    'Git-Protocol',
    'Accept',
    'Accept-Encoding',
    'Accept-Language',
    'If-Match',
    'If-None-Match',
    'If-Modified-Since',
    'Range',
    'User-Agent',
  ].join(', '),
  'Access-Control-Expose-Headers': 'Content-Type, ETag, Last-Modified, Link, Location, WWW-Authenticate, WAC-Allow',
};

export function setProxyCorsHeaders(reply) {
  for (const [k, v] of Object.entries(PROXY_CORS_HEADERS)) {
    reply.header(k, v);
  }
}

// Headers we forward from the caller to the upstream. Anything not on
// this list is dropped — origin/cookie/host/referer would either confuse
// upstream auth or leak the proxying pod's identity.
//
// Authorization is deliberately NOT forwarded by default: the browser
// uses it to authenticate to *this* pod (WAC, Solid-OIDC bearer/DPoP),
// and silently leaking that token to an arbitrary upstream is a security
// hole. Callers who genuinely need to send credentials to the upstream
// (e.g. a GitHub PAT for a private repo) opt in via the
// X-Upstream-Authorization header — pickRequestHeaders renames that to
// Authorization on the way out.
//
// DPoP is similarly not forwarded — it's bound to this pod's URL and
// would be rejected by any upstream anyway.
// Note: Content-Length is *not* forwarded. We may transform the body
// (Fastify-parsed JSON gets re-stringified before the upstream fetch),
// so the caller's declared length may not match what we send. Node's
// fetch sets Content-Length automatically based on the actual body.
// (Browsers send Content-Length on simple requests without needing it
// in Access-Control-Allow-Headers, since it's CORS-safelisted.)
const FORWARD_REQUEST_HEADERS = new Set([
  'accept',
  'accept-encoding',
  'accept-language',
  'content-type',
  'git-protocol',
  'if-match',
  'if-none-match',
  'if-modified-since',
  'range',
  'user-agent',
]);

const UPSTREAM_AUTH_HEADER = 'x-upstream-authorization';

// Headers we strip from the upstream response before returning to the
// caller. Encoding-related ones are removed because Node's fetch already
// transparently decodes; passing through Content-Encoding would
// double-decompress in the browser.
//
// Content-Length is stripped because (a) we strip Content-Encoding so
// the body length may differ from the upstream-declared length after
// decompression, and (b) we may truncate mid-stream when maxBytes is
// exceeded. Forwarding the upstream Content-Length in either case
// causes ERR_CONTENT_LENGTH_MISMATCH or hangs in the client. Node sends
// the actual length (or chunked) automatically.
const STRIP_RESPONSE_HEADERS = new Set([
  'content-encoding',
  'content-length',
  'transfer-encoding',
  'connection',
  'keep-alive',
  // Strip set-cookie — we never want to forward upstream cookies into
  // our origin's domain (would let upstream set cookies on the pod).
  'set-cookie',
]);

const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BYTES = 50 * 1024 * 1024; // 50 MB
const ALLOWED_METHODS = new Set(['GET', 'POST', 'HEAD', 'OPTIONS']);

function pickRequestHeaders(reqHeaders) {
  const out = {};
  for (const [k, v] of Object.entries(reqHeaders)) {
    if (v == null) continue;
    const lower = k.toLowerCase();
    if (FORWARD_REQUEST_HEADERS.has(lower)) {
      out[k] = v;
    } else if (lower === UPSTREAM_AUTH_HEADER) {
      // Opt-in upstream credential: client supplies the token under
      // X-Upstream-Authorization, we relay it as Authorization upstream.
      // Pod's own Authorization (used to auth to /proxy) never leaves
      // the pod — see FORWARD_REQUEST_HEADERS.
      out['Authorization'] = v;
    }
  }
  return out;
}

function copyResponseHeaders(reply, fetchResponse) {
  for (const [k, v] of fetchResponse.headers) {
    if (STRIP_RESPONSE_HEADERS.has(k.toLowerCase())) continue;
    reply.header(k, v);
  }
}

/**
 * Stream the upstream body to the caller, enforcing a byte cap mid-stream.
 * Uses Node 18+ Readable.fromWeb to bridge the fetch ReadableStream into
 * a Node Readable, then a Transform passthrough counts bytes and ends
 * the stream cleanly if maxBytes is exceeded.
 *
 * Note on the timeout: once status/headers are sent we can't change the
 * status code (Fastify throws ERR_HTTP_HEADERS_SENT), so the deadline
 * applies to the headers-received phase only. A slow-streaming upstream
 * past the deadline is *not* killed mid-stream in Phase 1 — see the
 * follow-up tracked in #378 / the open issue list. Mid-stream errors
 * (byte cap, fetch error) terminate the response with a truncated body
 * rather than a thrown error.
 */
function streamUpstream(reply, fetchResponse, maxBytes, abortController) {
  if (!fetchResponse.body) {
    return reply.send();
  }

  let bytesSeen = 0;
  const counter = new Transform({
    transform(chunk, _encoding, callback) {
      bytesSeen += chunk.length;
      if (bytesSeen > maxBytes) {
        abortController.abort();
        this.push(null);
        return callback();
      }
      callback(null, chunk);
    }
  });

  Readable.fromWeb(fetchResponse.body)
    .on('error', () => counter.end())
    .pipe(counter);

  return reply.send(counter);
}

/**
 * Handle a CORS proxy request.
 *
 * @param {FastifyRequest} request
 * @param {FastifyReply} reply
 * @param {object} options
 * @param {number} [options.maxBytes]
 * @param {number} [options.timeoutMs]
 * @param {number} [options.maxRedirects]
 */
export async function handleCorsProxy(request, reply, options = {}) {
  setProxyCorsHeaders(reply);

  // CORS preflight — short-circuit without fetching.
  if (request.method === 'OPTIONS') {
    return reply.code(204).send();
  }

  if (!ALLOWED_METHODS.has(request.method)) {
    return reply.code(405).send({ error: 'Method not allowed', method: request.method });
  }

  const targetUrl = request.query?.url;
  if (!targetUrl || typeof targetUrl !== 'string') {
    return reply.code(400).send({ error: 'Missing required query parameter: url' });
  }

  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;

  // Validate the initial URL, then follow redirects manually re-validating
  // each hop's Location header. Required because fetch's automatic redirect
  // following bypasses our SSRF guard at the second hop.
  let currentUrl = targetUrl;
  let currentMethod = request.method;
  let redirectsLeft = maxRedirects;

  // Body for non-GET/HEAD methods. Read once up front; we may need it on
  // the first hop and (for 307/308) on redirected hops.
  let body = null;
  if (currentMethod !== 'GET' && currentMethod !== 'HEAD') {
    body = request.rawBody ?? request.body;
    if (typeof body === 'object' && !(body instanceof Buffer) && body !== null) {
      body = JSON.stringify(body);
    }
  }

  // Forwarded headers are computed once (not per-hop) — Content-Length
  // gets dropped when we switch to GET on 301/302/303 to avoid sending
  // a stale length for an absent body.
  const forwardHeaders = pickRequestHeaders(request.headers);

  while (true) {
    const validation = await validateExternalUrl(currentUrl, {
      requireHttps: false, // allow http:// — pod operator can lock down via .acl scope
      blockPrivateIPs: true,
      resolveDNS: true,
    });
    if (!validation.valid) {
      return reply.code(400).send({ error: 'Invalid upstream URL', detail: validation.error });
    }

    const abortController = new AbortController();
    const timeoutId = setTimeout(() => abortController.abort(), timeoutMs);

    let upstream;
    try {
      upstream = await fetch(currentUrl, {
        method: currentMethod,
        headers: forwardHeaders,
        body: (currentMethod === 'GET' || currentMethod === 'HEAD') ? undefined : body,
        redirect: 'manual',
        signal: abortController.signal,
      });
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        return reply.code(504).send({ error: 'Upstream timeout' });
      }
      return reply.code(502).send({ error: 'Upstream fetch failed', detail: err.message });
    }
    // Headers received — clear the deadline. Streaming-phase timeouts
    // are a known Phase 1 limitation: once Fastify has sent headers we
    // can't change the status code, and the destroy-source-during-pipe
    // pattern doesn't reliably terminate the response. Tracked as a
    // follow-up.
    clearTimeout(timeoutId);

    // Manual redirect handling: 301/302/303 → GET (per HTTP semantics),
    // 307/308 → preserve method and body.
    if ([301, 302, 303, 307, 308].includes(upstream.status)) {
      const location = upstream.headers.get('location');
      if (!location) {
        return reply.code(502).send({ error: 'Upstream redirect with no Location header' });
      }
      if (--redirectsLeft < 0) {
        return reply.code(502).send({ error: `Exceeded ${maxRedirects} redirects` });
      }
      // Resolve relative redirects against the previous URL. Malformed
      // Location values throw — bubble that up as a 502 instead of 500.
      try {
        currentUrl = new URL(location, currentUrl).toString();
      } catch {
        return reply.code(502).send({ error: 'Upstream redirect with malformed Location', location });
      }
      if ([301, 302, 303].includes(upstream.status)) {
        // Method/body change is mandated by RFC 7231: redirected request
        // becomes GET with no body. Also drop content-length / content-type
        // so we don't send headers that no longer match the body.
        currentMethod = 'GET';
        body = null;
        delete forwardHeaders['content-length'];
        delete forwardHeaders['Content-Length'];
        delete forwardHeaders['content-type'];
        delete forwardHeaders['Content-Type'];
      }
      // Drain the redirect body to free the connection; we never return it.
      try { await upstream.body?.cancel(); } catch { /* ignore */ }
      continue;
    }

    // Final response — stream it back.
    reply.code(upstream.status);
    copyResponseHeaders(reply, upstream);
    setProxyCorsHeaders(reply); // reapply in case copyResponseHeaders set conflicting CORS values

    return streamUpstream(reply, upstream, maxBytes, abortController);
  }
}

/**
 * Match a request URL against the proxy route.
 * Used by server.js to decide whether the proxy preHandler should fire
 * and whether the standard WAC hook should skip.
 */
export function isCorsProxyRequest(urlPath) {
  return urlPath === '/proxy' || urlPath.startsWith('/proxy?');
}
