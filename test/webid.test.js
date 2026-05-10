/**
 * WebID Profile tests
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  assertStatus,
  assertHeader,
  assertHeaderContains,
} from './helpers.js';

describe('WebID Profile', () => {
  let baseUrl;
  let podInfo;

  before(async () => {
    const result = await startTestServer();
    baseUrl = result.baseUrl;
    podInfo = await createTestPod('webidtest');
  });

  after(async () => {
    await stopTestServer();
  });

  describe('Profile Document', () => {
    // Profile is now a plain JSON-LD doc at /pod/profile/card.jsonld.
    const profilePath = '/webidtest/profile/card.jsonld';

    it('should serve profile as JSON-LD', async () => {
      const res = await request(profilePath);

      assertStatus(res, 200);
      assertHeaderContains(res, 'Content-Type', 'application/ld+json');
    });

    it('should be valid JSON-LD with @context and @id', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.ok(jsonLd['@context'], 'Should have @context');
      assert.ok(jsonLd['@id'], 'Should have @id');
    });

    // LWS-CID document conformance, Phase A of #386. The profile must be
    // structurally a W3C Controlled Identifier document so a future
    // PATCH-in-keys app (or server migration) can drop verificationMethod
    // entries in without further plumbing. CID v1 vocabulary is declared
    // inline rather than via context URL so JSS's conneg layer can
    // expand every term without fetching external contexts — the IRIs
    // are the same either way.
    it('declares all six CID v1 terms in @context (#386 Phase A)', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();
      const ctx = jsonLd['@context'];
      assert.ok(ctx, '@context required');

      // All six CID terms must be declared and expand to the CID v1
      // namespace. Accept either prefixed (cid:term) or full-URI
      // (https://www.w3.org/ns/cid/v1#term) form.
      const cidTerms = ['controller', 'verificationMethod', 'authentication', 'assertionMethod', 'publicKeyJwk', 'publicKeyMultibase'];
      for (const term of cidTerms) {
        const mapping = ctx[term];
        assert.ok(mapping, `@context must define \`${term}\``);
        const id = typeof mapping === 'string' ? mapping : mapping['@id'];
        assert.match(id, new RegExp(`^(cid:${term}|https://www\\.w3\\.org/ns/cid/v1#${term})$`),
          `${term} must map to the CID v1 namespace`);
      }

      // Container/type flags Phase B relies on:
      // verificationMethod values are inline objects, NOT IRIs — must
      //   NOT have @type:@id (would force string-only) and SHOULD have
      //   @container:@set so a single entry is still an array.
      assert.notStrictEqual(ctx.verificationMethod['@type'], '@id',
        'verificationMethod values are objects, not IRIs');
      assert.strictEqual(ctx.verificationMethod['@container'], '@set');
      // authentication / assertionMethod reference verificationMethod
      // entries by IRI, so @type:@id is correct.
      assert.strictEqual(ctx.authentication['@type'], '@id');
      assert.strictEqual(ctx.assertionMethod['@type'], '@id');
      // JWK is a literal JSON value (rdf:JSON datatype) per JSON-LD 1.1.
      assert.strictEqual(ctx.publicKeyJwk['@type'], '@json');
    });

    it('declares CID v1 class names (Multikey, JsonWebKey) as flat aliases (#417)', async () => {
      // Without these mappings, an app PATCHing in a VM with the
      // spec-example shape `{type: "Multikey", ...}` produces a bare
      // relative-IRI `<Multikey>` in the Turtle conneg output, which
      // resolves to a fictional class on the pod's own host (e.g.
      // `<pod>/profile/Multikey` instead of `cid:Multikey`).
      //
      // The flat-alias shape (`"Multikey": "cid:Multikey"`) makes
      // bare-term emission work correctly through both JSON-LD
      // expansion AND our Turtle conneg layer — and matches the
      // "JSON-LD with flat context aliases" pattern consumers like
      // LOSOS / LION rely on.
      const res = await request(profilePath);
      const jsonLd = await res.json();
      const ctx = jsonLd['@context'];
      for (const cls of ['Multikey', 'JsonWebKey']) {
        const mapping = ctx[cls];
        assert.ok(mapping, `@context must define class alias \`${cls}\``);
        const id = typeof mapping === 'string' ? mapping : mapping['@id'];
        assert.match(id, new RegExp(`^(cid:${cls}|https://www\\.w3\\.org/ns/cid/v1#${cls})$`),
          `${cls} must map to the CID v1 namespace`);
      }
    });

    it('declares self-control via controller === @id (#386 Phase A)', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();
      assert.strictEqual(jsonLd.controller, jsonLd['@id'],
        'profile must declare itself as its own controller per CID v1');
    });

    it('should have correct WebID URI', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.ok(jsonLd['@id'].endsWith('/webidtest/profile/card.jsonld#me'),
        `WebID should end with /profile/card.jsonld#me, got ${jsonLd['@id']}`);
    });

    it('should have foaf:name', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.strictEqual(jsonLd['foaf:name'], 'webidtest');
    });

    it('should have solid:oidcIssuer', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.ok(jsonLd['oidcIssuer'], 'Should have oidcIssuer');
    });

    it('should have pim:storage pointing to pod', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.ok(jsonLd['storage'].endsWith('/webidtest/'), 'Storage should point to pod');
    });

    it('should have ldp:inbox', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      assert.ok(jsonLd['inbox'].endsWith('/webidtest/inbox/'), 'Should have inbox');
    });

    it('should have mainEntityOfPage pointing to the document', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      // Empty string is a relative URI reference to the document itself (JSON-LD)
      assert.strictEqual(jsonLd['mainEntityOfPage'], '', 'mainEntityOfPage should be "" (self)');
    });

    it('should have isPrimaryTopicOf pointing to the document', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();

      // Empty string is a relative URI reference to the document itself (JSON-LD)
      assert.strictEqual(jsonLd['isPrimaryTopicOf'], '', 'isPrimaryTopicOf should be "" (self)');
    });

    // LWS 1.0 Controlled Identifier alignment (#320).
    // These assertions live alongside the WebID predicate assertions — both
    // must continue to hold since the profile is dual-write.
    it('should emit a CID service[] with an lws:OpenIdProvider entry', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();
      assert.ok(Array.isArray(jsonLd.service), 'profile should have a service array');
      const oidc = jsonLd.service.find((s) => s['@type'] === 'lws:OpenIdProvider');
      assert.ok(oidc, 'service[] must include an lws:OpenIdProvider entry');
    });

    it('lws:OpenIdProvider service.serviceEndpoint mirrors oidcIssuer', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();
      assert.ok(Array.isArray(jsonLd.service), 'profile should have a service array');
      const oidc = jsonLd.service.find((s) => s['@type'] === 'lws:OpenIdProvider');
      assert.ok(oidc, 'service[] must include an lws:OpenIdProvider entry');
      assert.strictEqual(
        oidc.serviceEndpoint,
        jsonLd.oidcIssuer,
        'serviceEndpoint must equal the existing oidcIssuer value'
      );
    });

    it('lws:OpenIdProvider service.id is a fragment on the profile document', async () => {
      const res = await request(profilePath);
      const jsonLd = await res.json();
      assert.ok(Array.isArray(jsonLd.service), 'profile should have a service array');
      const oidc = jsonLd.service.find((s) => s['@type'] === 'lws:OpenIdProvider');
      assert.ok(oidc, 'service[] must include an lws:OpenIdProvider entry');
      const docUrl = jsonLd['@id'].split('#')[0];
      assert.strictEqual(oidc['@id'], `${docUrl}#oidc`,
        'service entry @id should be `<profile-doc>#oidc`');
    });
  });

  describe('WebID Resolution', () => {
    const profilePath = '/webidtest/profile/card.jsonld';

    it('should return LDP headers', async () => {
      const res = await request(profilePath);

      assertHeaderContains(res, 'Link', 'ldp#Resource');
      assertHeader(res, 'WAC-Allow');
    });

    it('should return CORS headers', async () => {
      const res = await request(profilePath, {
        headers: { 'Origin': 'https://example.com' }
      });

      assertHeader(res, 'Access-Control-Allow-Origin');
    });
  });
});

// With conneg enabled the profile is converted to Turtle on demand. The
// CID service[] must survive that conversion — LWS verifiers that ask for
// Turtle need to see the nested service node's type and serviceEndpoint,
// not just a bare URI reference to it.
describe('WebID Profile — Turtle conneg (#320)', () => {
  before(async () => {
    await startTestServer({ conneg: true });
    await createTestPod('webidturtletest');
  });

  after(async () => {
    await stopTestServer();
  });

  it('Turtle conneg: generated profile @context expands bare Multikey/JsonWebKey terms (#417)', async () => {
    // Combine the production profile generator's @context with a
    // synthetic VM (the spec-example shape `{type: "Multikey", ...}`)
    // and run it through the same conneg path the live profile
    // would. Asserts: the bare-term type expands to the CID v1
    // namespace, not to a relative IRI that resolves to a fake
    // class on the pod's host.
    const { generateProfile } = await import('../src/webid/profile.js');
    const { fromJsonLd } = await import('../src/rdf/conneg.js');
    const webId = 'https://example.test/profile/card.jsonld#me';
    const profile = generateProfile({
      webId,
      name: 'mk-test',
      podUri: 'https://example.test/',
      issuer: 'https://example.test/',
    });
    // Inject a Multikey VM authored with the spec-example bare-term
    // type — this is the shape the bug surfaces on.
    const vmId = webId.replace('#me', '#nostr-key-1');
    profile.verificationMethod = [{
      id: vmId,
      type: 'Multikey',
      controller: webId,
      publicKeyMultibase: 'fe70102de7ec0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab',
    }];
    profile.authentication = [vmId];

    const { content: ttl } = await fromJsonLd(profile, 'text/turtle', 'https://example.test/', true);

    // Pre-#417: would emit `a <Multikey>` (relative — resolves to
    // `https://example.test/profile/Multikey`).
    // After #417: the @context maps `Multikey -> cid:Multikey`, so
    // the converter expands the bare term to the CID v1 IRI.
    assert.ok(
      ttl.includes('cid:Multikey') || ttl.includes('cid/v1#Multikey'),
      `Turtle must emit a CID-namespaced Multikey class, got:\n${ttl}`,
    );
    assert.ok(
      !/\ba\s+<Multikey>\s*[;.]/.test(ttl),
      `Turtle must NOT emit bare <Multikey> (resolves to fictional class), got:\n${ttl}`,
    );
    // Don't regress #416: the VM block + publicKeyMultibase must
    // still survive the conversion.
    assert.ok(
      ttl.includes('publicKeyMultibase') || ttl.includes('cid/v1#publicKeyMultibase'),
      `Turtle must include cid:publicKeyMultibase, got:\n${ttl}`,
    );
    assert.ok(
      ttl.includes('fe70102de7ec'),
      `Turtle must include the publicKeyMultibase value, got:\n${ttl}`,
    );
  });

  it('Turtle variant includes cid:service with lws:OpenIdProvider and serviceEndpoint', async () => {
    const res = await request('/webidturtletest/profile/card.jsonld', {
      headers: { Accept: 'text/turtle' }
    });
    assertStatus(res, 200);
    assertHeaderContains(res, 'Content-Type', 'text/turtle');
    const ttl = await res.text();
    // Accept either prefixed (cid:service) or expanded full-URI form. The
    // critical property is that the nested service node's data survived the
    // JSON-LD → Turtle conversion — i.e. the type and endpoint are present
    // as their own triples, not dropped.
    assert.ok(
      ttl.includes('cid:service') || ttl.includes('cid/v1#service'),
      `Turtle should reference the CID service predicate, got:\n${ttl}`
    );
    assert.ok(
      ttl.includes('OpenIdProvider'),
      `Turtle should declare the lws:OpenIdProvider type, got:\n${ttl}`
    );
    assert.ok(
      ttl.includes('cid:serviceEndpoint') || ttl.includes('cid/v1#serviceEndpoint'),
      `Turtle should include the cid:serviceEndpoint predicate, got:\n${ttl}`
    );
    // The service entry URI appears as a subject (its own line), proving it
    // was emitted as a first-class node rather than a bare URI reference.
    assert.ok(
      /#oidc>\s+(?:a|<[^>]*#type>)/.test(ttl),
      `Turtle should emit the service entry as a subject, got:\n${ttl}`
    );
  });
});
