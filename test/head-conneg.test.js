/**
 * HEAD/GET content-type parity for files (#552).
 *
 * GET runs content negotiation on files (q-aware since #325), but HEAD's
 * file branch reported the STORED content type regardless of the Accept
 * header — an RFC 9110 §9.3.2 violation (HEAD should send the same
 * header fields as GET). Clients that probe with HEAD before fetching
 * saw a content type the subsequent GET never returned.
 *
 * The fix routes HEAD's file branch through the same decision tree GET
 * uses (negotiateHeadFileContentType). The core pin here is the parity
 * loop: for each Accept variant, HEAD's content-type must byte-equal
 * GET's on the same resource.
 *
 * Also pinned: when the negotiated form is a CONVERSION (GET would
 * re-serialize the body), HEAD must omit Content-Length rather than
 * report the on-disk size of a body GET never sends.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import { createServer as createNetServer } from 'net';
import fs from 'fs-extra';
import path from 'path';

const TEST_HOST = 'localhost';
const DATA_DIR = './test-data-head-conneg';

function getAvailablePort() {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.on('error', reject);
    srv.listen(0, TEST_HOST, () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

describe('HEAD/GET content-type parity (#552)', () => {
  let server;
  let baseUrl;
  let originalDataRoot;

  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    await fs.remove(DATA_DIR);
    await fs.ensureDir(DATA_DIR);

    const port = await getAvailablePort();
    baseUrl = `http://${TEST_HOST}:${port}`;

    server = createServer({
      logger: false,
      root: DATA_DIR,
      conneg: true,
      public: true,
      forceCloseConnections: true,
    });
    await server.listen({ port, host: TEST_HOST });

    // JSON-LD resource (the #552 reproduction target)
    const put = await fetch(`${baseUrl}/public/parity.jsonld`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/ld+json' },
      body: JSON.stringify({
        '@context': { name: 'http://xmlns.com/foaf/0.1/name' },
        '@id': '#it',
        name: 'head-parity-test',
      }),
    });
    assert.strictEqual(put.status, 201, 'prereq: PUT must succeed');

    // Extensionless HTML file — exercises GET's octet-stream HTML sniff.
    // Written directly to disk: PUT would route content-type by extension.
    await fs.writeFile(path.join(DATA_DIR, 'public', 'noext-html'),
      '<!DOCTYPE html><html><body>sniff me</body></html>');
  });

  after(async () => {
    if (server) await server.close();
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
    await fs.remove(DATA_DIR);
  });

  const ACCEPT_VARIANTS = [
    ['application/ld+json, text/turtle, application/json', 'ld+json first'],
    ['text/turtle, application/ld+json', 'turtle first'],
    ['application/ld+json;q=0.5, text/turtle', 'turtle preferred via q'],
    ['', 'no Accept header'],
  ];

  // Compare MEDIA TYPES (parameters stripped): Fastify appends
  // `; charset=utf-8` when it serializes a string BODY, which HEAD
  // never has — the charset parameter is a body-serialization
  // artifact, not part of what negotiation decides.
  const mediaType = (res) => (res.headers.get('content-type') || '').split(';')[0].trim();

  it('HEAD media type equals GET media type for every Accept variant (RFC 9110 §9.3.2)', async () => {
    for (const [accept, label] of ACCEPT_VARIANTS) {
      const headers = accept ? { Accept: accept } : {};
      const getRes = await fetch(`${baseUrl}/public/parity.jsonld`, { headers });
      const headRes = await fetch(`${baseUrl}/public/parity.jsonld`, { method: 'HEAD', headers });
      assert.strictEqual(getRes.status, 200, `${label}: GET must 200`);
      assert.strictEqual(headRes.status, 200, `${label}: HEAD must 200`);
      assert.strictEqual(mediaType(headRes), mediaType(getRes),
        `${label}: HEAD media type must equal GET's`);
    }
  });

  it('HEAD honors a Turtle-preferring Accept on a stored-JSON-LD file (the #552 bug)', async () => {
    const res = await fetch(`${baseUrl}/public/parity.jsonld`, {
      method: 'HEAD',
      headers: { Accept: 'text/turtle, application/ld+json' },
    });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/turtle/,
      'HEAD must report the negotiated Turtle, not the stored JSON-LD');
  });

  it('HEAD omits Content-Length when GET would convert the body', async () => {
    // GET re-serializes JSON-LD → Turtle; its body length is not the
    // on-disk size, so HEAD claiming stats.size would be a lie.
    const res = await fetch(`${baseUrl}/public/parity.jsonld`, {
      method: 'HEAD',
      headers: { Accept: 'text/turtle' },
    });
    assert.strictEqual(res.headers.get('content-length'), null,
      'no Content-Length on a conneg-converted HEAD');
  });

  it('HEAD keeps Content-Length for as-is responses', async () => {
    // Extensionless HTML: GET relabels (text/html) but serves the raw
    // bytes, so the on-disk size IS the body length.
    const res = await fetch(`${baseUrl}/public/noext-html`, { method: 'HEAD' });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/html/,
      'extensionless HTML sniff must apply to HEAD like GET');
    assert.ok(res.headers.get('content-length'),
      'as-is responses keep Content-Length');
  });

  it('HEAD negotiates large (>1 MiB) RDF files too — optimistic path, no full read', async () => {
    // Copilot review case on the first draft: the full-read cap must
    // not regress parity for large VALID RDF documents. Above the cap
    // HEAD skips the parse gate and trusts the extension.
    const big = {
      '@context': { name: 'http://xmlns.com/foaf/0.1/name' },
      '@id': '#it',
      name: 'x'.repeat(1024 * 1024 + 1024), // > HEAD_FULL_READ_MAX_BYTES
    };
    await fs.writeFile(path.join(DATA_DIR, 'public', 'big.jsonld'), JSON.stringify(big));
    const res = await fetch(`${baseUrl}/public/big.jsonld`, {
      method: 'HEAD',
      headers: { Accept: 'text/turtle, application/ld+json' },
    });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/turtle/,
      'large valid RDF must still negotiate on HEAD');
    assert.strictEqual(res.headers.get('content-length'), null,
      'converted large-file HEAD must omit Content-Length');
  });

  it('HEAD sniffs large (>1 MiB) extensionless HTML via bounded ranged read', async () => {
    const filler = '<!DOCTYPE html><html><body>' + 'y'.repeat(1024 * 1024 + 1024) + '</body></html>';
    await fs.writeFile(path.join(DATA_DIR, 'public', 'big-noext'), filler);
    const res = await fetch(`${baseUrl}/public/big-noext`, { method: 'HEAD' });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/html/,
      'the HTML sniff only needs the first bytes — size must not disable it');
    assert.ok(res.headers.get('content-length'),
      'as-is large file keeps Content-Length');
  });

  it('HEAD with If-None-Match still returns 304 (negotiation must not break revalidation)', async () => {
    const probe = await fetch(`${baseUrl}/public/parity.jsonld`, { method: 'HEAD' });
    const etag = probe.headers.get('etag');
    assert.ok(etag, 'prereq: ETag present');
    const res = await fetch(`${baseUrl}/public/parity.jsonld`, {
      method: 'HEAD',
      headers: { 'If-None-Match': etag },
    });
    assert.strictEqual(res.status, 304);
  });
});
