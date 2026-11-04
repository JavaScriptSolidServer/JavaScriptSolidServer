/**
 * #641 — the auth document fetch deadline must cover the body read.
 *
 * A profile host that sends headers promptly and then trickles the
 * body used to hold the authentication attempt (and the upstream
 * socket) open indefinitely: the abort timer was cleared as soon as
 * fetch() resolved, and the body was read with no clock on it.
 *
 * Three paths are covered:
 *   - did-nostr fetchWithRedirectGuard (real HTTP server, validator seam)
 *   - WebID-TLS verifyWebIdTls (real HTTP server; no SSRF guard there)
 *   - cid-doc-fetch fetchCidDocument (global.fetch stub with a trickling
 *     ReadableStream, because the SSRF guard blocks loopback)
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import { fetchWithRedirectGuard } from '../src/auth/did-nostr.js';
import { verifyWebIdTls, clearCache as clearTlsCache } from '../src/auth/webid-tls.js';
import { fetchCidDocument, _clearProfileCacheForTests } from '../src/auth/cid-doc-fetch.js';
import { readBodyWithCap } from '../src/utils/bounded-body.js';

const TIMEOUT_MS = 300;
const TRICKLE_MS = 50;
// Generous upper bound: the deadline plus scheduling slack, and far
// below how long the trickle would run if the timeout did not fire.
const MAX_ELAPSED_MS = 2500;

const allowAll = async () => ({ valid: true });

/** Start a server whose /trickle writes headers now and one byte every TRICKLE_MS forever. */
function startTrickleServer(contentType) {
  const closed = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/redirect-trickle')) {
      // 302 whose own body trickles forever: the hop must be abandoned
      // AND its socket released before the next hop is fetched.
      res.writeHead(302, { Location: '/ok', 'Content-Type': 'text/plain' });
      res.write('moved');
      const iv = setInterval(() => res.write(' '), TRICKLE_MS);
      const stop = () => { clearInterval(iv); closed.push(req.url); };
      req.on('close', stop);
      res.on('close', stop);
      return;
    }
    if (req.url.startsWith('/error-trickle')) {
      res.writeHead(500, { 'Content-Type': contentType });
      res.write('{');
      const iv = setInterval(() => res.write(' '), TRICKLE_MS);
      const stop = () => { clearInterval(iv); closed.push(req.url); };
      req.on('close', stop);
      res.on('close', stop);
      return;
    }
    if (req.url === '/ok') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"ok":true}');
      return;
    }
    if (req.url.startsWith('/trickle')) {
      res.writeHead(200, { 'Content-Type': contentType });
      res.write('{');
      const iv = setInterval(() => res.write(' '), TRICKLE_MS);
      const stop = () => { clearInterval(iv); closed.push(req.url); };
      req.on('close', stop);
      res.on('close', stop);
      return;
    }
    res.writeHead(404).end();
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => {
    resolve({ server, port: server.address().port, closed });
  }));
}

async function waitFor(pred, ms = 1500) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 20));
  }
  return pred();
}

describe('#641 auth document fetch: deadline covers the body read', () => {
  let srv;
  before(async () => { srv = await startTrickleServer('application/json'); });
  after(async () => {
    // Aborted upstream requests may linger as idle keep-alive sockets;
    // close() alone would wait for them.
    srv.server.closeAllConnections();
    await new Promise((resolve) => srv.server.close(resolve));
  });

  it('did-nostr fetchWithRedirectGuard rejects a trickling body within the deadline and drops the socket', async () => {
    const started = Date.now();
    await assert.rejects(
      () => fetchWithRedirectGuard(`http://127.0.0.1:${srv.port}/trickle/did`, {
        _validateUrl: allowAll,
        timeout: TIMEOUT_MS,
      }),
      /timed out|abort/i,
    );
    const elapsed = Date.now() - started;
    assert.ok(elapsed < MAX_ELAPSED_MS, `took ${elapsed}ms`);
    assert.ok(await waitFor(() => srv.closed.includes('/trickle/did')), 'upstream request was not closed');
  });

  it('WebID-TLS verifyWebIdTls gives up on a trickling profile within the deadline and drops the socket', async () => {
    clearTlsCache();
    const cert = { modulus: 'abc123def456', exponent: '10001' };
    const started = Date.now();
    const verified = await verifyWebIdTls(cert, `http://127.0.0.1:${srv.port}/trickle/tls`, { timeout: TIMEOUT_MS });
    const elapsed = Date.now() - started;
    assert.strictEqual(verified, false);
    assert.ok(elapsed < MAX_ELAPSED_MS, `took ${elapsed}ms`);
    assert.ok(await waitFor(() => srv.closed.includes('/trickle/tls')), 'upstream request was not closed');
  });

  it('did-nostr releases a trickling redirect body before following the hop', async () => {
    const started = Date.now();
    const r = await fetchWithRedirectGuard(`http://127.0.0.1:${srv.port}/redirect-trickle/did`, {
      _validateUrl: allowAll,
      timeout: TIMEOUT_MS,
    });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body, '{"ok":true}');
    assert.ok(Date.now() - started < MAX_ELAPSED_MS);
    assert.ok(await waitFor(() => srv.closed.includes('/redirect-trickle/did')), 'redirect hop socket was not released');
  });

  it('did-nostr returns an error status at once and releases its trickling body', async () => {
    const started = Date.now();
    const r = await fetchWithRedirectGuard(`http://127.0.0.1:${srv.port}/error-trickle/did`, {
      _validateUrl: allowAll,
      timeout: TIMEOUT_MS,
    });
    assert.strictEqual(r.status, 500);
    assert.strictEqual(r.body, '');
    assert.ok(Date.now() - started < 200, 'should return on the status, not wait for the deadline');
    assert.ok(await waitFor(() => srv.closed.includes('/error-trickle/did')), 'error response socket was not released');
  });

  it('WebID-TLS releases a trickling error-status body', async () => {
    clearTlsCache();
    const cert = { modulus: 'abc123def456', exponent: '10001' };
    const started = Date.now();
    const verified = await verifyWebIdTls(cert, `http://127.0.0.1:${srv.port}/error-trickle/tls`, { timeout: TIMEOUT_MS });
    assert.strictEqual(verified, false);
    assert.ok(Date.now() - started < 200, 'should fail on the status, not wait for the deadline');
    assert.ok(await waitFor(() => srv.closed.includes('/error-trickle/tls')), 'error response socket was not released');
  });

  describe('cid-doc-fetch fetchCidDocument (stubbed fetch, trickling stream)', () => {
    const realFetch = global.fetch;
    let cancelled = 0;

    before(() => {
      global.fetch = async (url, init = {}) => {
        const signal = init.signal;
        const status = String(url).includes('/err') ? 404 : 200;
        let stop;
        const stream = new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{'));
            const iv = setInterval(() => {
              try { controller.enqueue(new TextEncoder().encode(' ')); } catch { /* errored or closed */ }
            }, TRICKLE_MS);
            stop = () => { clearInterval(iv); cancelled++; };
            // Mirror what a real fetch body does on abort: error the stream.
            signal?.addEventListener('abort', () => {
              stop();
              try { controller.error(new DOMException('This operation was aborted', 'AbortError')); } catch { /* already closed */ }
            }, { once: true });
          },
          cancel() { stop?.(); },
        });
        return new Response(stream, { status, headers: { 'content-type': 'application/ld+json' } });
      };
    });
    after(() => { global.fetch = realFetch; });
    beforeEach(() => { _clearProfileCacheForTests(); cancelled = 0; });

    it('rejects within the deadline instead of waiting for the body', async () => {
      const started = Date.now();
      await assert.rejects(
        () => fetchCidDocument('https://example.com/profile/trickle.jsonld', { timeoutMs: TIMEOUT_MS }),
        /timed out|abort/i,
      );
      const elapsed = Date.now() - started;
      assert.ok(elapsed < MAX_ELAPSED_MS, `took ${elapsed}ms`);
      assert.ok(cancelled >= 1, 'body stream was not released');
    });

    it('releases a trickling body on an error status instead of leaving it to GC', async () => {
      const started = Date.now();
      await assert.rejects(
        () => fetchCidDocument('https://example.com/profile/err.jsonld', { timeoutMs: TIMEOUT_MS }),
        /HTTP 404/,
      );
      assert.ok(Date.now() - started < 200, 'should fail on the status, not wait for the deadline');
      assert.ok(await waitFor(() => cancelled >= 1), 'body stream was not released');
    });

    it('caches the timeout as a failure like any other fetch error', async () => {
      await assert.rejects(() => fetchCidDocument('https://example.com/profile/trickle2.jsonld', { timeoutMs: TIMEOUT_MS }));
      const started = Date.now();
      await assert.rejects(() => fetchCidDocument('https://example.com/profile/trickle2.jsonld', { timeoutMs: TIMEOUT_MS }), /timed out/);
      assert.ok(Date.now() - started < 100, 'second call should be served from the failure cache');
    });
  });

  describe('readBodyWithCap', () => {
    it('never returns a partial body when the signal fires mid-read', async () => {
      const ac = new AbortController();
      let pull = 0;
      const stream = new ReadableStream({
        pull(controller) {
          pull++;
          controller.enqueue(new TextEncoder().encode('x'));
          if (pull === 3) ac.abort();
        },
      });
      await assert.rejects(
        () => readBodyWithCap(new Response(stream), { maxBytes: 1024, signal: ac.signal, label: 'thing' }),
        /thing body read timed out/,
      );
    });

    it('still enforces the byte cap', async () => {
      await assert.rejects(
        () => readBodyWithCap(new Response('x'.repeat(2000)), { maxBytes: 1000, label: 'thing' }),
        /thing too large \(>1000 bytes\)/,
      );
    });

    it('reads a normal body to completion', async () => {
      const ac = new AbortController();
      const text = await readBodyWithCap(new Response('{"ok":true}'), { maxBytes: 1000, signal: ac.signal });
      assert.strictEqual(text, '{"ok":true}');
    });

    it('rejects immediately on an already-aborted signal', async () => {
      const ac = new AbortController();
      ac.abort();
      await assert.rejects(
        () => readBodyWithCap(new Response('x'), { maxBytes: 10, signal: ac.signal }),
        /response body read timed out/,
      );
    });
  });
});
