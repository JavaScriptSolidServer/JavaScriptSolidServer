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
const PROXY_CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, HEAD, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, Git-Protocol, Accept, Accept-Encoding, Accept-Language',
  'Access-Control-Expose-Headers': 'Content-Type, Content-Length, ETag, Last-Modified, Link, Location, WWW-Authenticate',
};

function setProxyCorsHeaders(reply) {
  for (const [k, v] of Object.entries(PROXY_CORS_HEADERS)) {
    reply.header(k, v);
  }
}

// Headers we forward from the caller to the upstream. Anything not on
// this list is dropped — origin/cookie/host/referer would either confuse
// upstream auth or leak the proxying pod's identity.
const FORWARD_REQUEST_HEADERS = new Set([
  'accept',
  'accept-encoding',
  'accept-language',
  'authorization',
  'content-type',
  'content-length',
  'git-protocol',
  'if-match',
  'if-none-match',
  'if-modified-since',
  'range',
  'user-agent',
]);

// Headers we strip from the upstream response before returning to the
// caller. Encoding-related ones are removed because Node's fetch already
// transparently decodes; passing through Content-Encoding would
// double-decompress in the browser.
const STRIP_RESPONSE_HEADERS = new Set([
  'content-encoding',
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
    if (FORWARD_REQUEST_HEADERS.has(k.toLowerCase())) {
      out[k] = v;
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
 * a Node Readable, then a Transform passthrough counts bytes and errors
 * the pipeline if maxBytes is exceeded.
 */
function streamWithCap(reply, fetchResponse, maxBytes, abortController) {
  if (!fetchResponse.body) {
    return reply.send();
  }

  let bytesSeen = 0;
  const counter = new Transform({
    transform(chunk, _encoding, callback) {
      bytesSeen += chunk.length;
      if (bytesSeen > maxBytes) {
        abortController.abort();
        return callback(new Error(`Upstream response exceeded ${maxBytes} bytes`));
      }
      callback(null, chunk);
    }
  });

  Readable.fromWeb(fetchResponse.body).on('error', (err) => counter.destroy(err)).pipe(counter);
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
  let redirectsLeft = maxRedirects;

  // Body for non-GET/HEAD methods. Read once up front; we may need it on
  // the first hop and (for 307/308) on redirected hops.
  let body = null;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    body = request.rawBody ?? request.body;
    if (typeof body === 'object' && !(body instanceof Buffer) && body !== null) {
      body = JSON.stringify(body);
    }
  }

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
        method: request.method,
        headers: pickRequestHeaders(request.headers),
        body,
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
    clearTimeout(timeoutId);

    // Manual redirect handling: 301/302/303 → GET, 307/308 → preserve method
    if ([301, 302, 303, 307, 308].includes(upstream.status)) {
      const location = upstream.headers.get('location');
      if (!location) {
        return reply.code(502).send({ error: 'Upstream redirect with no Location header' });
      }
      if (--redirectsLeft < 0) {
        return reply.code(502).send({ error: `Exceeded ${maxRedirects} redirects` });
      }
      // Resolve relative redirects against the previous URL.
      currentUrl = new URL(location, currentUrl).toString();
      // 301/302/303 force the next request to GET with no body.
      if ([301, 302, 303].includes(upstream.status)) {
        body = null;
      }
      // Drain the redirect body to free the connection; we never return it.
      try { await upstream.body?.cancel(); } catch { /* ignore */ }
      continue;
    }

    // Final response — stream it back.
    reply.code(upstream.status);
    copyResponseHeaders(reply, upstream);
    setProxyCorsHeaders(reply); // reapply in case copyResponseHeaders set conflicting CORS values

    return streamWithCap(reply, upstream, maxBytes, abortController);
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
