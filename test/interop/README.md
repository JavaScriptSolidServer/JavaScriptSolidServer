# Interop Tests

Manual tests for debugging cross-server authentication issues. These tests depend on external services and are not run as part of `npm test`.

## Usage

```bash
cd test/interop
node <test-file>.js
```

## Tests

| File | Description |
|------|-------------|
| `css-interop.js` | Test OIDC config against CSS and NSS servers |
| `solidcommunity-interop.js` | Test DPoP auth against solidcommunity.net (CSS) |
| `nss-local.js` | Test DPoP auth against local NSS instance |
| `nss-local-fixed.js` | Test with Accept header fix applied |
| `nss-discovery.js` | Debug NSS OIDC discovery process |
| `webid-discovery.js` | Test WebID profile discovery and content negotiation |
| `rdflib-discovery.js` | Test rdflib parsing of WebID profiles |

## Known Issues

- **NSS WebID Discovery Bug**: NSS's `oidc-auth-manager` doesn't send Accept headers when fetching WebID profiles, causing discovery to fail when servers return HTML instead of Turtle. See: https://github.com/nodeSolidServer/oidc-auth-manager/issues/79

## Requirements

- `node-fetch`
- `jose`
- `rdflib` (for rdflib tests)
- Valid credentials for melvincarvalho.com IdP

## Note on WebID Formats

Two popular WebID locations exist:
- `https://example.com/#me` (root + fragment)
- `https://example.com/profile/card#me` (profile path)

JSS is currently configured for `/profile/card` but will support `/` in the future.

**Trade-offs**: When WebID is at root (`/#me`), the root container must be public for discovery. Care must be taken with child ACLs to ensure private resources remain protected.
