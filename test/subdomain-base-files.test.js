/**
 * Regression tests for #307 — buildResourceUrl rewriting the base-domain
 * root file paths into non-existent pod subdomains.
 *
 * Unit tests against buildResourceUrl directly, since Node's fetch() overrides
 * the Host header with the TCP target, which makes end-to-end tests of
 * subdomain routing impossible without a real reverse proxy.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { buildResourceUrl } from '../src/auth/middleware.js';

function makeRequest({ urlPath, hostname, baseDomain, subdomainsEnabled = true, podName = null, protocol = 'https' }) {
  return {
    protocol,
    hostname,
    headers: { host: hostname },
    subdomainsEnabled,
    baseDomain,
    podName
  };
}

describe('buildResourceUrl — base-domain files (#307)', () => {
  const baseDomain = 'example.com';

  it('base-domain root (/) — no rewrite', () => {
    const req = makeRequest({ urlPath: '/', hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/'), 'https://example.com/');
  });

  it('base-domain /welcome.js — no rewrite (filename has extension)', () => {
    const req = makeRequest({ urlPath: '/welcome.js', hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/welcome.js'), 'https://example.com/welcome.js');
  });

  it('base-domain /mashlib.js — no rewrite', () => {
    const req = makeRequest({ urlPath: '/mashlib.js', hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/mashlib.js'), 'https://example.com/mashlib.js');
  });

  it('base-domain /terms.html — no rewrite', () => {
    const req = makeRequest({ urlPath: '/terms.html', hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/terms.html'), 'https://example.com/terms.html');
  });

  it('base-domain /.well-known/foo — no rewrite (leading dot)', () => {
    const req = makeRequest({ urlPath: '/.well-known/foo', hostname: baseDomain, baseDomain });
    assert.strictEqual(
      buildResourceUrl(req, '/.well-known/foo'),
      'https://example.com/.well-known/foo'
    );
  });
});

describe('buildResourceUrl — pod routing still works', () => {
  const baseDomain = 'example.com';

  it('base-domain /alice/ — rewrites to alice.example.com (no dot → pod name)', () => {
    const req = makeRequest({ urlPath: '/alice/', hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/alice/'), 'https://alice.example.com/');
  });

  it('base-domain /alice — rewrites (bare pod-root without trailing slash)', () => {
    const req = makeRequest({ urlPath: '/alice', hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/alice'), 'https://alice.example.com/');
  });

  it('base-domain /alice/profile/card.jsonld — rewrites to alice.example.com/profile/card.jsonld', () => {
    const req = makeRequest({ urlPath: '/alice/profile/card.jsonld', hostname: baseDomain, baseDomain });
    assert.strictEqual(
      buildResourceUrl(req, '/alice/profile/card.jsonld'),
      'https://alice.example.com/profile/card.jsonld'
    );
  });

  it('already-on-subdomain request — no rewrite (hostname !== baseDomain)', () => {
    const req = makeRequest({
      urlPath: '/profile/card.jsonld',
      hostname: 'alice.example.com',
      baseDomain,
      podName: 'alice'
    });
    assert.strictEqual(
      buildResourceUrl(req, '/profile/card.jsonld'),
      'https://alice.example.com/profile/card.jsonld'
    );
  });
});

describe('buildResourceUrl — subdomain mode disabled', () => {
  it('no rewrite when subdomainsEnabled is false', () => {
    const req = makeRequest({
      urlPath: '/alice/',
      hostname: 'example.com',
      baseDomain: 'example.com',
      subdomainsEnabled: false
    });
    assert.strictEqual(buildResourceUrl(req, '/alice/'), 'https://example.com/alice/');
  });

  it('no rewrite when baseDomain is not set', () => {
    const req = makeRequest({
      urlPath: '/alice/',
      hostname: 'example.com',
      baseDomain: null,
      subdomainsEnabled: true
    });
    assert.strictEqual(buildResourceUrl(req, '/alice/'), 'https://example.com/alice/');
  });
});
