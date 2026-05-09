/**
 * Shared CID-document / WebID-profile fetcher.
 *
 * Used by both the LWS10-CID JWT verifier (`src/auth/lws-cid.js`) and
 * the NIP-98 → WebID VM-lookup path (`src/auth/nostr.js`). Centralized
 * so future SSRF / redirect / DoS hardening only needs to land in one
 * place.
 *
 * Defenses (mirrored from the original lws-cid implementation):
 *
 *   - URL validated through `validateExternalUrl` (loopback, private
 *     IPs, http-in-prod blocked) on the original URL AND every
 *     redirect Location.
 *   - Manual redirect handling — no automatic following — capped at
 *     MAX_REDIRECTS hops.
 *   - Cross-origin redirects refused (an open redirect on the WebID's
 *     host can't substitute an attacker-controlled CID document).
 *   - Body size cap enforced via Content-Length up front AND a
 *     streaming reader cap (cancel on overage), so untrusted hosts
 *     can't OOM us with a large payload.
 *   - 5-second timeout per request via AbortController.
 *
 * Throws on any failure; callers convert to whatever they want
 * (LWS-CID surfaces the error string, the NIP-98 path treats
 * throw-as-null and falls back to the existing did:nostr resolver).
 */

import { validateExternalUrl } from '../utils/ssrf.js';

// Default body cap (256 KB) — CID documents are tiny in practice.
const DEFAULT_MAX_BYTES = 256 * 1024;
const MAX_REDIRECTS = 5;
const FETCH_TIMEOUT_MS = 5000;

/**
 * Fetch and parse a JSON CID document with SSRF, redirect, and
 * body-size protections.
 *
 * @param {string} docUrl - URL to fetch (untrusted — comes from JWT
 *   claims or is derived from a request).
 * @param {object} [opts]
 * @param {number} [opts.maxBytes=DEFAULT_MAX_BYTES]
 * @returns {Promise<object>} parsed JSON
 * @throws on any validation, network, redirect, size, or parse failure
 */
export async function fetchCidDocument(docUrl, opts = {}) {
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const originalOrigin = new URL(docUrl).origin;
  let currentUrl = docUrl;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const isLastAllowedHop = hop === MAX_REDIRECTS;
    const validation = await validateExternalUrl(currentUrl, {
      requireHttps: process.env.NODE_ENV === 'production',
      blockPrivateIPs: true,
      resolveDNS: true,
    });
    if (!validation.valid) {
      throw new Error(`SSRF protection: ${validation.error}`);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
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
        throw new Error(`too many redirects (>${MAX_REDIRECTS})`);
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
    if (!ct.includes('json')) {
      throw new Error(`unexpected content-type: ${ct || '(none)'}`);
    }

    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new Error(`CID document too large (Content-Length=${declared})`);
    }
    const text = await readBodyWithCap(res, maxBytes);
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
