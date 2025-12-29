# AGENTS.md - AI Assistant Context for JSS

This document provides context for AI assistants working on JavaScript Solid Server (JSS).

## What is JSS?

A lightweight Solid server implementation focused on simplicity and modern JavaScript. Alternative to Node Solid Server (NSS) and Community Solid Server (CSS).

**Key differences from other Solid servers:**
- Single-file JSON-LD storage (no quad stores)
- Content negotiation converts JSON-LD ↔ Turtle on the fly
- Built on Fastify (not Express)
- Uses oidc-provider for identity
- Supports Nostr NIP-98 authentication (unique to JSS)

## Architecture

```
src/
├── server.js          # Fastify setup, route registration
├── handlers/          # LDP operations (GET, PUT, POST, PATCH, DELETE)
│   ├── resource.js    # File operations
│   └── container.js   # Directory operations, pod creation
├── auth/              # Authentication
│   ├── middleware.js  # WAC authorization hook
│   ├── solid-oidc.js  # DPoP token verification
│   ├── nostr.js       # NIP-98 Schnorr signatures
│   └── token.js       # Simple Bearer tokens
├── idp/               # Identity Provider (oidc-provider)
│   ├── provider.js    # OIDC configuration
│   ├── interactions.js # Login/consent UI handlers
│   └── accounts.js    # User account storage
├── wac/               # Web Access Control
│   ├── checker.js     # Permission checking
│   └── parser.js      # ACL file parsing/generation
├── rdf/               # RDF handling
│   ├── conneg.js      # Content negotiation
│   └── turtle.js      # Turtle ↔ JSON-LD conversion
├── notifications/     # WebSocket real-time updates
│   ├── websocket.js   # solid-0.1 protocol handler
│   └── events.js      # Event emitter for changes
├── ldp/               # Linked Data Platform
│   ├── headers.js     # LDP response headers
│   └── container.js   # Container JSON-LD generation
└── storage/           # File system operations
    └── filesystem.js  # Read/write/stat/list
```

## Key Design Decisions

### JSON-LD as canonical storage
All RDF is stored as JSON-LD. When clients request Turtle, we convert on the fly. This simplifies storage and allows non-RDF tools to read the data.

### HTML profiles with JSON-LD data islands
WebID profiles are HTML documents with embedded `<script type="application/ld+json">`. This allows:
- Human-readable profiles in browsers
- Machine-readable RDF via content negotiation
- Mashlib renders the profile using the embedded data

### Subdomain mode for XSS isolation
When `subdomains: true`, each pod gets its own subdomain (alice.example.com). This provides browser security isolation. Storage path includes pod name, but URLs use subdomains.

### Settings folder conventions
Mashlib expects `Settings/` (capital S) with:
- `Settings/Preferences.ttl`
- `Settings/publicTypeIndex.ttl`
- `Settings/privateTypeIndex.ttl`

Earlier versions used lowercase `settings/prefs` which broke mashlib.

## Common Gotchas

### Content negotiation
- Files stored as JSON-LD regardless of upload format
- `.ttl` extension triggers Turtle response regardless of Accept header
- Container listings need conneg too (fixed in v0.0.33)

### Authentication paths that skip auth
These paths bypass the auth middleware:
- `/.pods` - Pod creation
- `/.notifications` - WebSocket endpoint
- `/idp/*` - Identity provider routes
- `/.well-known/*` - Discovery endpoints
- OPTIONS requests

### WebSocket notifications
Uses legacy `solid-0.1` protocol (not Solid Notifications Protocol):
```
Server: protocol solid-0.1
Client: sub https://example.org/resource
Server: ack https://example.org/resource
Server: pub https://example.org/resource  (on change)
```
Discovered via `Updates-Via` header.

### DPoP token verification
Solid-OIDC uses DPoP-bound tokens. The DPoP proof must match:
- HTTP method (htm)
- Request URL (htu)
- Be recent (iat within 5 minutes)
- Key thumbprint matches token binding (cnf.jkt)

### ACL inheritance
WAC ACLs use `acl:default` for inheritance. When checking permissions:
1. Look for resource-specific ACL (resource.acl or .acl for containers)
2. Walk up to parent containers checking for `acl:default` rules
3. Stop at pod root

## Testing

```bash
npm test                    # Run all tests
npm run test:cth           # Conformance Test Harness (requires setup)
```

Tests use in-memory server instances. See `test/helpers.js` for test utilities.

## Deployment

### Production setup
```bash
npm install -g javascript-solid-server
jss --port 443 --ssl-key key.pem --ssl-cert cert.pem --idp --multiuser
```

### With HAProxy (recommended)
HAProxy handles SSL termination, JSS runs on localhost:8443. Wildcard cert needed for subdomain mode.

### PM2 process management
```bash
pm2 start "jss --config config.json" --name solid
pm2 logs solid
pm2 restart solid
```

## External Dependencies

- **oidc-provider**: OpenID Connect implementation (complex, many warnings are normal)
- **n3**: Turtle/N3 parsing and serialization
- **jose**: JWT/JWK handling for Solid-OIDC
- **@fastify/websocket**: WebSocket support

## Related Specs

- [Solid Protocol](https://solidproject.org/TR/protocol)
- [Solid-OIDC](https://solidproject.org/TR/oidc)
- [Web Access Control](https://solidproject.org/TR/wac)
- [Linked Data Platform](https://www.w3.org/TR/ldp/)

## Contact

Issues: https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues
