/**
 * NIP-98 payload-hash verifies the RAW request bytes, not a re-serialization
 * of the parsed body (#565).
 *
 * The bug: src/auth/nostr.js hashed `JSON.stringify(request.body)` — the
 * parsed-then-recompacted body — so a NIP-98 client that sent pretty-printed
 * (or otherwise non-minified) JSON 401'd with "Payload hash mismatch" even
 * though signature/URL/method/timestamp were all valid. NIP-98's `payload`
 * tag is sha256 over the exact body bytes on the wire.
 *
 * The fix has two halves, tested here:
 *   1. server.js captures the raw application/json bytes as request.rawBody
 *      (the default parser discards them once it produces an object), while
 *      otherwise mirroring Fastify's default parser — empty → 400,
 *      secure-json-parse (prototype-pollution safe), 400 on malformed.
 *   2. nostr.js hashes request.rawBody when present, never a re-serialization.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import { verifyNostrAuth } from '../src/auth/nostr.js';
import { generateSecretKey, getPublicKey, nip98Token } from '../src/nostr/event.js';
import fs from 'fs-extra';

const DATA_DIR = './test-data-nip98-payload';

describe('application/json parser: rawBody capture + preserved semantics (#565)', () => {
  let server;
  let originalDataRoot;

  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    await fs.remove(DATA_DIR);
    await fs.ensureDir(DATA_DIR);
    server = createServer({
      logger: false,
      root: DATA_DIR,
      public: true, // open writes so we exercise the parser without auth
      forceCloseConnections: true,
    });
    await server.ready();
  });

  after(async () => {
    if (server) await server.close();
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
    await fs.remove(DATA_DIR);
  });

  it('accepts a valid (pretty-printed) JSON body — parser stays functional', async () => {
    const res = await server.inject({
      method: 'PUT',
      url: '/public/pretty.json',
      headers: { 'content-type': 'application/json' },
      payload: JSON.stringify({ a: 1, b: 'two' }, null, 2),
    });
    assert.ok(res.statusCode === 200 || res.statusCode === 201 || res.statusCode === 204,
      `pretty JSON PUT should succeed, got ${res.statusCode}`);
  });

  it('rejects malformed JSON with 400 (mirrors Fastify default, not 500)', async () => {
    const res = await server.inject({
      method: 'PUT',
      url: '/public/bad.json',
      headers: { 'content-type': 'application/json' },
      payload: '{ not valid json',
    });
    assert.strictEqual(res.statusCode, 400);
  });

  it('blocks __proto__ prototype pollution (secure-json-parse preserved)', async () => {
    const res = await server.inject({
      method: 'PUT',
      url: '/public/proto.json',
      headers: { 'content-type': 'application/json' },
      payload: '{ "__proto__": { "polluted": true } }',
    });
    // secure-json-parse throws on __proto__ → our parser surfaces 400.
    assert.strictEqual(res.statusCode, 400, 'a __proto__ payload must be rejected');
    assert.strictEqual({}.polluted, undefined, 'Object.prototype must not be polluted');
  });
});

describe('NIP-98 payload hash uses the raw request bytes (#565)', () => {
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);

  // A pretty-printed body whose minified re-serialization differs byte-for-byte.
  const entry = { name: 'alice', nested: { x: 1, y: 2 }, tags: ['a', 'b'] };
  const prettyBody = JSON.stringify(entry, null, 2);
  const compactBody = JSON.stringify(entry);
  const parsed = JSON.parse(prettyBody);

  const url = 'http://localhost:9999/pool/entries/' + pk + '.json';

  // Build a mock Fastify request whose URL/host/method match what was signed,
  // so verification reaches the payload-hash check.
  function mockRequest(token, { rawBody, body }) {
    return {
      method: 'PUT',
      url: '/pool/entries/' + pk + '.json',
      protocol: 'http',
      hostname: 'localhost:9999',
      headers: { host: 'localhost:9999', authorization: `Nostr ${token}` },
      rawBody,
      body,
    };
  }

  it('a pretty-printed body with rawBody captured passes the payload check', async () => {
    // Client signed sha256(prettyBody) — exactly the bytes it sent.
    const token = nip98Token(url, 'PUT', sk, prettyBody);
    const result = await verifyNostrAuth(mockRequest(token, { rawBody: prettyBody, body: parsed }));
    assert.notStrictEqual(result.error, 'Payload hash mismatch',
      `pretty body should pass the payload check; got error: ${result.error}`);
    assert.ok(result.webId && result.webId.startsWith('did:nostr:'),
      `should resolve to the did:nostr identity; got ${JSON.stringify(result)}`);
  });

  it('control: the same body WITHOUT rawBody (object only) still mismatches — proves rawBody is the fix', async () => {
    const token = nip98Token(url, 'PUT', sk, prettyBody);
    // No rawBody → the old code path hashes JSON.stringify(parsed) = compact.
    const result = await verifyNostrAuth(mockRequest(token, { rawBody: undefined, body: parsed }));
    assert.strictEqual(result.error, 'Payload hash mismatch',
      'without the captured raw bytes, a pretty body must still fail (the bug)');
  });

  it('a compact body still verifies (no regression for already-working clients)', async () => {
    const token = nip98Token(url, 'PUT', sk, compactBody);
    const result = await verifyNostrAuth(mockRequest(token, { rawBody: compactBody, body: parsed }));
    assert.notStrictEqual(result.error, 'Payload hash mismatch',
      `compact body should still pass; got error: ${result.error}`);
  });

  it('a falsy JSON body (false) is still hash-checked, not skipped (Copilot review on #573)', async () => {
    // The body literally parses to `false`. A WRONG payload tag must still
    // be caught — under the old `&& request.body` truthiness guard this
    // validation was skipped entirely for falsy bodies.
    const falsyRaw = 'false';
    const wrongToken = nip98Token(url, 'PUT', sk, 'a-different-body');
    const mismatch = await verifyNostrAuth(mockRequest(wrongToken, { rawBody: falsyRaw, body: false }));
    assert.strictEqual(mismatch.error, 'Payload hash mismatch',
      'a falsy body with a wrong payload tag must be rejected, not skipped');

    // And the matching payload for the same falsy body passes.
    const goodToken = nip98Token(url, 'PUT', sk, falsyRaw);
    const ok = await verifyNostrAuth(mockRequest(goodToken, { rawBody: falsyRaw, body: false }));
    assert.notStrictEqual(ok.error, 'Payload hash mismatch',
      `a falsy body with the correct payload should pass; got ${ok.error}`);
  });

  it('a binary / non-UTF-8 Buffer body hashes the raw bytes (Copilot review on #573)', async () => {
    // Bytes that are NOT valid UTF-8 — a .toString() round-trip would
    // mangle them (replacement chars) and break the hash. The client
    // signs sha256 over the raw bytes; the server must do the same.
    const binary = Buffer.from([0xff, 0xfe, 0x00, 0x01, 0x80, 0xc3, 0x28]);
    // Sanity: this fixture genuinely changes bytes under a UTF-8 string
    // round-trip, so the old `.toString()` path WOULD have mismatched.
    assert.ok(!Buffer.from(binary.toString('utf8'), 'utf8').equals(binary),
      'fixture must be lossy under a UTF-8 round-trip');
    const token = nip98Token(url, 'PUT', sk, binary);
    // Non-JSON body → no rawBody; request.body is the raw Buffer (the `*`
    // content-type parser keeps it as a Buffer).
    const result = await verifyNostrAuth(mockRequest(token, { rawBody: undefined, body: binary }));
    assert.notStrictEqual(result.error, 'Payload hash mismatch',
      `binary body must hash raw bytes, not a UTF-8 round-trip; got error: ${result.error}`);
  });
});
