# LWS / Controlled Identifiers (CID v1)

JSS pod profiles are aligned with the W3C [Linked Web Storage 1.0 Authentication Suite](https://www.w3.org/news/2026/first-public-working-drafts-for-the-linked-web-storage-lws-1-0-authentication-suite/) (FPWDs published 2026-04-23) and its substrate, [W3C Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/).

The work is phased — see [#386](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/386) for the convergence tracker and [#319](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/319) for the FPWD-alignment audit.

## Three levels of compatibility

| | What it means | Status |
|---|---|---|
| **1. Profile shape** | A WebID profile that's structurally a W3C Controlled Identifier document — right `@context`, right vocabulary, parseable as a CID document by any LWS-aware tool | ✅ **Yes** (since v0.0.174, [#388](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/pull/388)) |
| **2. Profile carries keys** | The CID document actually declares `verificationMethod` entries an LWS verifier can look up by `kid` | ❌ Phase B — a separate "doctor / add-keys" app PATCHes them in after authentication. Out of JSS server scope. |
| **3. Server accepts LWS-CID JWTs** | An incoming request with an LWS-CID self-signed JWT (`sub`/`iss`/`client_id` triple-equality, `kid` lookup against the WebID's `verificationMethod`, signature check) | ❌ Phase 3 of [#386](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/386) — JSS still only knows OIDC/DPoP, NIP-98, passkey, simple bearer |

## What Phase A actually does

`src/webid/profile.js` declares the six CID v1 vocabulary terms — `controller`, `verificationMethod`, `authentication`, `assertionMethod`, `publicKeyJwk`, `publicKeyMultibase` — in the profile's `@context` (inline, so JSS's JSON-LD → Turtle conneg layer can expand them without fetching external contexts), and emits a `controller` triple pointing at the WebID itself per CID v1's self-control contract.

A freshly-created pod's `profile/card.jsonld` looks like this (excerpt — the existing Solid predicates `oidcIssuer`, `pim:storage`, `ldp:inbox`, `service` etc. are unchanged):

```jsonld
{
  "@context": {
    "foaf": "...", "solid": "...", "cid": "https://www.w3.org/ns/cid/v1#", "lws": "https://www.w3.org/ns/lws#",
    "controller":         { "@id": "cid:controller", "@type": "@id" },
    "verificationMethod": { "@id": "cid:verificationMethod", "@container": "@set" },
    "authentication":     { "@id": "cid:authentication", "@type": "@id", "@container": "@set" },
    "assertionMethod":    { "@id": "cid:assertionMethod", "@type": "@id", "@container": "@set" },
    "publicKeyJwk":       { "@id": "cid:publicKeyJwk", "@type": "@json" },
    "publicKeyMultibase": { "@id": "cid:publicKeyMultibase" }
  },
  "@id": "https://alice.example/profile/card.jsonld#me",
  "@type": ["foaf:Person"],
  "controller": "https://alice.example/profile/card.jsonld#me"
  // verificationMethod / authentication / assertionMethod arrays are
  // intentionally absent until Phase B's doctor app PATCHes them in.
}
```

## What Phase B will add

A standalone web app (separate repo, no JSS coupling) where the WebID owner authenticates via existing means (OIDC, NIP-98, passkey) and PATCHes their profile with one or more verification methods:

```jsonld
"verificationMethod": [
  { "id": "...#nostr-1", "type": "Multikey",   "controller": "...#me",
    "publicKeyMultibase": "fe70102..." },
  { "id": "...#did-key-1", "type": "Multikey", "controller": "...#me",
    "publicKeyMultibase": "z6MkpT..." },
  { "id": "...#passkey-1", "type": "JsonWebKey", "controller": "...#me",
    "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } }
],
"authentication": ["...#nostr-1", "...#did-key-1", "...#passkey-1"]
```

Because Phase A already declared the context terms, this is a pure data-layer PATCH — no `@context` rewrite needed.

## What Phase 3 will add (server-side verifier)

When an incoming request carries an LWS-CID JWT, JSS will:

1. Confirm `sub`/`iss`/`client_id` are the same URI (the caller's WebID)
2. Dereference the WebID, parse it as a CID document
3. Look up `kid` in the document's `verificationMethod` array
4. Confirm the method is in `authentication`
5. Verify the JWT signature with that public key

The verifier joins the existing auth methods (OIDC, NIP-98, etc.) — preference ordering tracked in [#306](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/306).

## Spec references

- [W3C CID v1.0 — Controlled Identifiers](https://www.w3.org/TR/cid-1.0/)
- [LWS 1.0 SSI via CID (FPWD 2026-04-23)](https://www.w3.org/TR/2026/WD-lws10-authn-ssi-cid-20260423/)
- [LWS 1.0 SSI via did:key (FPWD 2026-04-23)](https://www.w3.org/TR/2026/WD-lws10-authn-ssi-did-key-20260423/)
- [W3C announcement](https://www.w3.org/news/2026/first-public-working-drafts-for-the-linked-web-storage-lws-1-0-authentication-suite/)

## Related

- [`docs/authentication.md`](authentication.md) — current JSS auth surface (OIDC, NIP-98, passkey, etc.)
- [`docs/nostr.md`](nostr.md) — Nostr relay + did:nostr resolution
- [#386](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/386) — convergence tracker
- [#388](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/pull/388) — Phase A PR
- [#389](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/389) — `@context` array form support (turtle conneg)
- [#390](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/390) — `@type:'@json'` literal handling (turtle conneg)
