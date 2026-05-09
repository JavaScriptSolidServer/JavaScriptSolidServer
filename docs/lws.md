# LWS / Controlled Identifiers (CID v1)

JSS is aligned end-to-end with the W3C [Linked Web Storage 1.0 Authentication Suite](https://www.w3.org/news/2026/first-public-working-drafts-for-the-linked-web-storage-lws-1-0-authentication-suite/) (FPWDs published 2026-04-23) and its substrate, [W3C Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/) — pod profiles are CID-shaped, users add keys via the [doctor](https://jss.live/doctor/), and the server accepts strict LWS10-CID JWTs as an HTTP auth method alongside the existing Solid-OIDC and NIP-98 paths.

Convergence tracker: [#386](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/386). FPWD-alignment audit: [#319](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/319).

## Compatibility, by level

| | What it means | Status |
|---|---|---|
| **1. Profile shape** | A WebID profile that's structurally a W3C Controlled Identifier document — right `@context`, right vocabulary, parseable as a CID document by any LWS-aware tool | ✅ **Yes** (since v0.0.174, [#388](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/pull/388)) |
| **2. Profile carries keys** | The CID document actually declares `verificationMethod` entries an LWS verifier can look up by `kid` | ✅ Browser-side via the [doctor](https://jss.live/doctor/) — [B.2](https://github.com/JavaScriptSolidServer/doctor/pull/2) for Nostr/Multikey, [B.3](https://github.com/JavaScriptSolidServer/doctor/pull/4) for ES256K/JsonWebKey. The doctor authenticates as the WebID owner via Solid-OIDC and PATCHes the VM into the profile. |
| **3. Server accepts LWS-CID JWTs** | An incoming request with an LWS-CID self-signed JWT (`sub`/`iss`/`client_id` triple-equality, `kid` lookup against the WebID's `verificationMethod`, signature check) | ✅ Shipped in v0.0.177 ([#398](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/pull/398)). Strict FPWD §4 — ES256K is the focus algorithm; ES256, ES384, EdDSA, RS256 also accepted. |
| **Bonus: NIP-98 → WebID** | A Schnorr-signed NIP-98 request authenticates as the WebID (not `did:nostr:`) when the pubkey is declared as a CID `verificationMethod` referenced from `authentication` | ✅ Shipped in v0.0.178 ([#400](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/pull/400)). No client-side change — the doctor's B.2 output is enough to light it up. |

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

## Adding keys (Phase B — via the doctor)

The [doctor](https://jss.live/doctor/) is a separate browser-side tool that signs in to your pod via Solid-OIDC and writes verificationMethod entries to your profile. After the round-trip your profile has:

```jsonld
"verificationMethod": [
  { "id": "...#nostr-key-1", "type": "Multikey",   "controller": "...#me",
    "publicKeyMultibase": "fe70102…" },
  { "id": "...#lws-key-1",   "type": "JsonWebKey", "controller": "...#me",
    "publicKeyJwk": { "kty": "EC", "crv": "secp256k1", "alg": "ES256K", "x": "…", "y": "…" } }
],
"authentication": ["...#nostr-key-1", "...#lws-key-1"]
```

The Multikey entry handles did:nostr binding + NIP-98 lookup; the JsonWebKey entry handles strict LWS10-CID JWT auth. Both can be the same secp256k1 key — different signature schemes (Schnorr vs ECDSA), same private key.

Because Phase A already declared the context terms, this is a pure data-layer PATCH — no `@context` rewrite needed.

## Server-side verifier (Phase 3 — `src/auth/lws-cid.js`)

When an incoming request carries an LWS-CID JWT (detected by an `Authorization: Bearer <jwt>` whose JWT-header `kid` is an http(s) URL with a fragment), JSS:

1. Confirms `sub === iss === client_id` (canonicalized via URL parsing) — that URI is the WebID being claimed
2. Validates `aud` includes the server origin, `exp` not past, `iat` recent, lifetime ≤ 1 hour
3. Fetches the WebID profile through the shared SSRF guard — manual redirects with same-origin enforcement, 256 KB body cap, bounded LRU cache
4. Confirms the profile's `@id` equals the JWT's `sub` (closes a profile-substitution attack)
5. Looks up `kid` in `verificationMethod`; the entry must be referenced from `authentication` and its `controller` must match the profile's outer `controller`
6. Verifies the JWT signature per RFC7515 §5.2. ES256K via `@noble/curves` (already in tree from NIP-98); ES256, ES384, EdDSA, RS256 via `jose`

The verifier joins the existing auth methods (Solid-OIDC, NIP-98, Bearer-JWT-from-IDP, WebID-TLS) — preference order is OIDC → LWS-CID → NIP-98 → Bearer fallback (per [#306](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/306)).

## NIP-98 → WebID upgrade (`src/auth/nostr.js`)

Built on top of the LWS-CID infrastructure ([#400](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/pull/400)): when a NIP-98 request's signing pubkey is declared as a CID `verificationMethod` (and the VM is in `authentication`) on the resource owner's WebID profile, the request authenticates as the WebID instead of `did:nostr:<pubkey>`. Match is by f-form Multikey or by JsonWebKey full-point (x AND y, BIP-340 even-y). Profile fetch uses the same SSRF guard / cache as the LWS-CID verifier. No client-side change — Nostr clients sign as today.

So: anyone who's used the doctor's B.2 to add a Nostr Multikey VM gets WebID-based NIP-98 sign-in for free.

## Spec references

- [W3C CID v1.0 — Controlled Identifiers](https://www.w3.org/TR/cid-1.0/)
- [LWS 1.0 SSI via CID (FPWD 2026-04-23)](https://www.w3.org/TR/2026/WD-lws10-authn-ssi-cid-20260423/)
- [LWS 1.0 SSI via did:key (FPWD 2026-04-23)](https://www.w3.org/TR/2026/WD-lws10-authn-ssi-did-key-20260423/)
- [W3C announcement](https://www.w3.org/news/2026/first-public-working-drafts-for-the-linked-web-storage-lws-1-0-authentication-suite/)

## Related

- [`docs/authentication.md`](authentication.md) — full JSS auth surface (OIDC, NIP-98, LWS-CID, passkey, etc.)
- [`docs/nostr.md`](nostr.md) — Nostr relay + did:nostr resolution
- [doctor](https://github.com/JavaScriptSolidServer/doctor) — the browser-side diagnostic + add-keys app
- [#386](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/386) — convergence tracker
- [#388](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/pull/388) — Phase A (profile shape)
- [#398](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/pull/398) — Phase 3 (LWS-CID JWT verifier)
- [#400](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/pull/400) — NIP-98 → WebID via VM lookup
- [#389](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/389) — `@context` array form support (turtle conneg)
- [#390](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/390) — `@type:'@json'` literal handling (turtle conneg)
