/**
 * NIP-98 verifier: a signed header authorizes one request, one method, one
 * URL (#643). Reported privately by Kraig Parkinson against v0.0.225.
 *
 * Before: the method tag was optional and `*` a wildcard, the `u` tag matched
 * by prefix, and nothing remembered an event id, so an Authorization header
 * captured from a GET of the pod root could be replayed within 60 s as a PUT
 * or DELETE on any sub-path. The git smart-HTTP routes keep the lenient rules
 * (credential helpers sign once for the repo base); everywhere else the
 * NIP-98 MUSTs apply and a reused event id is rejected.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createHash } from 'node:crypto';
import { verifyNostrAuth } from '../src/auth/nostr.js';
import { generateSecretKey, finalizeEvent, nip98Token } from '../src/nostr/event.js';

const HOST = 'pod.example';
const sk = generateSecretKey();

function tokenFromTags(tags) {
  const event = finalizeEvent({ kind: 27235, tags, content: '' }, sk);
  return Buffer.from(JSON.stringify(event)).toString('base64');
}

function req({ url, method = 'GET', token, body }) {
  const r = { url, method, protocol: 'http', hostname: HOST, headers: { host: HOST, authorization: `Nostr ${token}` } };
  if (body !== undefined) { r.body = body; r.rawBody = body; }
  return r;
}

// Every path here is unowned, so the resolver chain ends at did:nostr:<pubkey>.
const isAuthed = (r) => r.error === null && typeof r.webId === 'string' && r.webId.startsWith('did:nostr:');

describe('NIP-98 verifier: one header, one request (#643)', () => {
  it('a correctly signed GET verifies', async () => {
    const token = nip98Token(`http://${HOST}/alice/notes/`, 'GET', sk);
    assert.ok(isAuthed(await verifyNostrAuth(req({ url: '/alice/notes/', token }))));
  });

  it('the same event id a second time is rejected', async () => {
    const token = nip98Token(`http://${HOST}/alice/again/`, 'GET', sk);
    assert.ok(isAuthed(await verifyNostrAuth(req({ url: '/alice/again/', token }))));
    const again = await verifyNostrAuth(req({ url: '/alice/again/', token }));
    assert.strictEqual(again.webId, null);
    assert.match(again.error, /Replayed event id/);
  });

  it('a missing method tag is rejected outside git routes', async () => {
    const token = tokenFromTags([['u', `http://${HOST}/alice/`]]);
    const r = await verifyNostrAuth(req({ url: '/alice/', method: 'DELETE', token }));
    assert.strictEqual(r.webId, null);
    assert.match(r.error, /Missing method tag/);
  });

  it('a wildcard method is rejected outside git routes', async () => {
    const token = tokenFromTags([['u', `http://${HOST}/alice/`], ['method', '*']]);
    const r = await verifyNostrAuth(req({ url: '/alice/', method: 'DELETE', token }));
    assert.strictEqual(r.webId, null);
    assert.match(r.error, /Wildcard method/);
  });

  it('a signature for the base URL does not cover a sub-path outside git routes', async () => {
    const token = nip98Token(`http://${HOST}/alice/`, 'GET', sk);
    const r = await verifyNostrAuth(req({ url: '/alice/secret.json', token }));
    assert.strictEqual(r.webId, null);
    assert.match(r.error, /URL mismatch/);
  });

  it('a GET token replayed as a PUT with a body is rejected twice over', async () => {
    const token = nip98Token(`http://${HOST}/alice/notes/`, 'GET', sk);
    const r = await verifyNostrAuth(req({ url: '/alice/notes/', method: 'PUT', token, body: '{"owned":true}' }));
    assert.strictEqual(r.webId, null);
    assert.match(r.error, /Method mismatch/);
  });

  it('a PUT with a body needs the payload tag', async () => {
    const token = nip98Token(`http://${HOST}/alice/doc.json`, 'PUT', sk);
    const r = await verifyNostrAuth(req({ url: '/alice/doc.json', method: 'PUT', token, body: '{"a":1}' }));
    assert.strictEqual(r.webId, null);
    assert.match(r.error, /Missing payload tag/);
  });

  it('a PUT with a matching payload tag verifies', async () => {
    const body = '{"a":1}';
    const token = nip98Token(`http://${HOST}/alice/doc2.json`, 'PUT', sk, body);
    assert.ok(isAuthed(await verifyNostrAuth(req({ url: '/alice/doc2.json', method: 'PUT', token, body }))));
  });

  it('a PUT with a mismatching payload tag is still rejected', async () => {
    const token = nip98Token(`http://${HOST}/alice/doc3.json`, 'PUT', sk, '{"a":1}');
    const r = await verifyNostrAuth(req({ url: '/alice/doc3.json', method: 'PUT', token, body: '{"a":2}' }));
    assert.match(r.error, /Payload hash mismatch/);
  });

  it('git routes keep the lenient rules: wildcard method and base-URL prefix', async () => {
    const token = tokenFromTags([['u', `http://${HOST}/alice/repo`], ['method', '*']]);
    const r = await verifyNostrAuth(req({ url: '/alice/repo/info/refs?service=git-receive-pack', token }));
    assert.ok(isAuthed(r), r.error);
    const push = tokenFromTags([['u', `http://${HOST}/alice/repo`]]);
    const r2 = await verifyNostrAuth(req({ url: '/alice/repo/git-receive-pack', method: 'POST', token: push, body: Buffer.from('0000') }));
    assert.ok(isAuthed(r2), r2.error);
  });

  it('the replay cache forgets an id once it can no longer verify', async () => {
    const token = nip98Token(`http://${HOST}/alice/old/`, 'GET', sk);
    assert.ok(isAuthed(await verifyNostrAuth(req({ url: '/alice/old/', token }))));
    const event = JSON.parse(Buffer.from(token, 'base64').toString());
    const stale = { ...event, created_at: event.created_at - 200 }; // outside ±60 s, so rejected on time, never on replay
    const staleToken = Buffer.from(JSON.stringify(stale)).toString('base64');
    const r = await verifyNostrAuth(req({ url: '/alice/old/', token: staleToken }));
    assert.match(r.error, /timestamp/);
    assert.ok(!/Replayed/.test(r.error));
  });

  it('a payload hash is computed over the raw bytes (unchanged)', async () => {
    const body = Buffer.from([0xff, 0x00, 0x10]);
    const token = tokenFromTags([['u', `http://${HOST}/alice/bin`], ['method', 'PUT'], ['payload', createHash('sha256').update(body).digest('hex')]]);
    const r = { url: '/alice/bin', method: 'PUT', protocol: 'http', hostname: HOST, headers: { host: HOST, authorization: `Nostr ${token}` }, body };
    assert.ok(isAuthed(await verifyNostrAuth(r)));
  });
});
