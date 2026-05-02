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

function makeRequest({ hostname, baseDomain, subdomainsEnabled = true, podName = null, protocol = 'https' }) {
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
    const req = makeRequest({ hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/'), 'https://example.com/');
  });

  it('base-domain /welcome.js — no rewrite (filename has extension)', () => {
    const req = makeRequest({ hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/welcome.js'), 'https://example.com/welcome.js');
  });

  it('base-domain /mashlib.js — no rewrite', () => {
    const req = makeRequest({ hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/mashlib.js'), 'https://example.com/mashlib.js');
  });

  it('base-domain /terms.html — no rewrite', () => {
    const req = makeRequest({ hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/terms.html'), 'https://example.com/terms.html');
  });

  it('base-domain /.well-known/foo — no rewrite (leading dot)', () => {
    const req = makeRequest({ hostname: baseDomain, baseDomain });
    assert.strictEqual(
      buildResourceUrl(req, '/.well-known/foo'),
      'https://example.com/.well-known/foo'
    );
  });
});

describe('buildResourceUrl — pod routing still works', () => {
  const baseDomain = 'example.com';

  it('base-domain /alice/ — rewrites to alice.example.com (no dot → pod name)', () => {
    const req = makeRequest({ hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/alice/'), 'https://alice.example.com/');
  });

  it('base-domain /alice — rewrites (bare pod-root without trailing slash)', () => {
    const req = makeRequest({ hostname: baseDomain, baseDomain });
    assert.strictEqual(buildResourceUrl(req, '/alice'), 'https://alice.example.com/');
  });

  it('base-domain /alice/profile/card.jsonld — rewrites to alice.example.com/profile/card.jsonld', () => {
    const req = makeRequest({ hostname: baseDomain, baseDomain });
    assert.strictEqual(
      buildResourceUrl(req, '/alice/profile/card.jsonld'),
      'https://alice.example.com/profile/card.jsonld'
    );
  });

  it('already-on-subdomain request — no rewrite (hostname !== baseDomain)', () => {
    const req = makeRequest({
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
      hostname: 'example.com',
      baseDomain: 'example.com',
      subdomainsEnabled: false
    });
    assert.strictEqual(buildResourceUrl(req, '/alice/'), 'https://example.com/alice/');
  });

  it('no rewrite when baseDomain is not set', () => {
    const req = makeRequest({
      hostname: 'example.com',
      baseDomain: null,
      subdomainsEnabled: true
    });
    assert.strictEqual(buildResourceUrl(req, '/alice/'), 'https://example.com/alice/');
  });
});

// Regression: Fastify sets request.hostname to host:port when a non-default
// port is in use. Previously getBaseDomainHost was not called, so
// 'alice.pivot-test.local:4443' never matched '.pivot-test.local', making
// request.podName stay null and subdomain routing break entirely.
describe('buildResourceUrl — port-bearing hostname (subdomain mode)', () => {
  const baseDomain = 'pivot-test.local:4443';

  it('subdomain request with port — uses headers.host verbatim', () => {
    // Simulate Fastify: hostname includes port, headers.host also has port
    const req = makeRequest({
      hostname: 'alice.pivot-test.local:4443',
      baseDomain,
      podName: 'alice',
    });
    // Already on subdomain — buildResourceUrl uses headers.host directly
    assert.strictEqual(
      buildResourceUrl(req, '/'),
      'https://alice.pivot-test.local:4443/'
    );
  });

  it('base-domain with port — rewrites pod path to subdomain URL', () => {
    // hostname matches baseDomain host after stripping port
    const req = {
      protocol: 'https',
      hostname: 'pivot-test.local:4443',
      headers: { host: 'pivot-test.local:4443' },
      subdomainsEnabled: true,
      baseDomain,
      podName: null,
    };
    assert.strictEqual(
      buildResourceUrl(req, '/alice/'),
      'https://alice.pivot-test.local:4443/'
    );
  });

  it('base-domain with port — no rewrite for file with extension', () => {
    const req = {
      protocol: 'https',
      hostname: 'pivot-test.local:4443',
      headers: { host: 'pivot-test.local:4443' },
      subdomainsEnabled: true,
      baseDomain,
      podName: null,
    };
    assert.strictEqual(
      buildResourceUrl(req, '/mashlib.js'),
      'https://pivot-test.local:4443/mashlib.js'
    );
  });
});
