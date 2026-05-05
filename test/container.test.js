/**
 * Container listing generator — dotfile-allowlist regression (#350)
 *
 * Server-internal sidecars (.idp/, .quota.json, .server/, future .git/, etc.)
 * must NOT appear in ldp:contains, even though direct GETs are 403'd by the
 * routing-layer dotfile guard in server.js (which rejects non-allowlisted
 * dotpaths before WAC runs). Listing the names still leaks existence and
 * gives attackers free path-fingerprinting against root-pod (--single-user)
 * deployments.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateContainerJsonLd } from '../src/ldp/container.js';

describe('generateContainerJsonLd dotfile filtering (#350)', () => {
  it('emits regular entries unchanged', () => {
    const out = generateContainerJsonLd('https://example.com/pod/', [
      { name: 'public', isDirectory: true },
      { name: 'index.html', isDirectory: false },
    ]);
    const ids = out.contains.map(c => c['@id']);
    assert.deepStrictEqual(ids, [
      'https://example.com/pod/public/',
      'https://example.com/pod/index.html',
    ]);
  });

  it('keeps allowed Solid resources (.acl, .meta, .well-known)', () => {
    // .well-known stays — JSS serves legitimate public resources there
    // (e.g. webledger). At origin-root (including each pod's origin in
    // subdomain mode) the routing layer bypasses auth per RFC 8615; for
    // path-based pods at /pod/.well-known/ the bypass doesn't apply but
    // listing the name is still fine (regular subdirectory under WAC).
    const out = generateContainerJsonLd('https://example.com/pod/', [
      { name: '.acl', isDirectory: false },
      { name: '.meta', isDirectory: false },
      { name: '.well-known', isDirectory: true },
    ]);
    const ids = out.contains.map(c => c['@id']);
    assert.ok(ids.includes('https://example.com/pod/.acl'));
    assert.ok(ids.includes('https://example.com/pod/.meta'));
    assert.ok(ids.includes('https://example.com/pod/.well-known/'));
  });

  it('hides server-internal sidecars (.idp/, .quota.json, .server/)', () => {
    const out = generateContainerJsonLd('https://example.com/', [
      { name: '.idp', isDirectory: true },
      { name: '.quota.json', isDirectory: false },
      { name: '.server', isDirectory: true },
    ]);
    assert.deepStrictEqual(out.contains, []);
  });

  it('hides server control endpoints — listing allowlist is intentionally narrower than server.js routing allowlist', () => {
    // .pods, .notifications, .account are routed to handlers in server.js
    // (the broader 6-entry routing allowlist) but they're NOT public
    // linked-data resources that belong in ldp:contains. Pinning this
    // explicitly so that adding any of these to ALLOWED_DOTFILES would
    // fail the suite — see PR #357 review comment.
    const out = generateContainerJsonLd('https://example.com/', [
      { name: '.pods', isDirectory: true },
      { name: '.notifications', isDirectory: true },
      { name: '.account', isDirectory: false },
    ]);
    assert.deepStrictEqual(out.contains, []);
  });

  it('hides any unknown dotfile (default-deny on .git, .env, .DS_Store, etc.)', () => {
    const out = generateContainerJsonLd('https://example.com/pod/', [
      { name: '.git', isDirectory: true },
      { name: '.env', isDirectory: false },
      { name: '.DS_Store', isDirectory: false },
    ]);
    assert.deepStrictEqual(out.contains, []);
  });

  it('keeps regular entries when mixed with hidden ones', () => {
    const out = generateContainerJsonLd('https://example.com/', [
      { name: '.acl', isDirectory: false },
      { name: '.idp', isDirectory: true },
      { name: '.quota.json', isDirectory: false },
      { name: 'public', isDirectory: true },
      { name: 'profile', isDirectory: true },
    ]);
    const ids = out.contains.map(c => c['@id']);
    assert.deepStrictEqual(ids, [
      'https://example.com/.acl',
      'https://example.com/public/',
      'https://example.com/profile/',
    ]);
  });
});
