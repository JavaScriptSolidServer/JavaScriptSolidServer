## Pod Structure

```
/alice/
├── index.html          # WebID profile (HTML with JSON-LD)
├── .acl                 # Root ACL (owner + public read)
├── inbox/              # Notifications (public append)
│   └── .acl
├── public/             # Public files
├── private/            # Private files (owner only)
│   └── .acl
└── settings/           # User preferences (owner only)
    ├── .acl
    ├── prefs
    ├── publicTypeIndex
    └── privateTypeIndex
```

## Project Structure

```
src/
├── index.js              # Entry point
├── server.js             # Fastify setup
├── handlers/
│   ├── resource.js       # GET, PUT, DELETE, HEAD, PATCH
│   ├── container.js      # POST, pod creation
│   ├── git.js            # Git HTTP backend
│   └── pay.js            # HTTP 402 paid access
├── storage/
│   ├── filesystem.js     # File operations
│   └── quota.js          # Storage quota management
├── auth/
│   ├── middleware.js      # Auth hook
│   ├── token.js           # Simple token auth
│   ├── solid-oidc.js      # DPoP verification
│   ├── nostr.js           # NIP-98 Nostr authentication
│   ├── did-nostr.js       # did:nostr → WebID resolution
│   └── webid-tls.js       # WebID-TLS client certificate auth
├── wac/
│   ├── parser.js         # ACL parsing
│   └── checker.js        # Permission checking
├── ldp/
│   ├── headers.js        # LDP Link headers
│   └── container.js      # Container JSON-LD
├── webid/
│   └── profile.js        # WebID generation
├── patch/
│   ├── n3-patch.js       # N3 Patch support
│   └── sparql-update.js  # SPARQL Update support
├── notifications/
│   ├── index.js          # WebSocket plugin
│   ├── events.js         # Event emitter
│   └── websocket.js      # solid-0.1 protocol
├── idp/
│   ├── index.js           # Identity Provider plugin
│   ├── provider.js        # oidc-provider config
│   ├── adapter.js         # Filesystem adapter
│   ├── accounts.js        # User account management
│   ├── credentials.js     # Credentials endpoint
│   ├── keys.js            # JWKS key management
│   ├── interactions.js    # Login/consent handlers
│   ├── passkey.js         # WebAuthn/FIDO2 passkey support
│   ├── views.js           # HTML templates
│   └── invites.js         # Invite code management
├── ap/
│   ├── index.js          # ActivityPub plugin
│   ├── keys.js           # RSA keypair management
│   ├── store.js          # SQLite storage (followers, activities)
│   └── routes/
│       ├── actor.js      # Actor JSON-LD
│       ├── inbox.js      # Receive activities
│       ├── outbox.js     # User's activities
│       ├── collections.js # Followers/following
│       ├── mastodon.js  # Mastodon API (apps, instance, verify_credentials)
│       └── oauth.js     # OAuth 2.0 authorize/token flow
├── webledger.js          # Web Ledger balance tracking (webledgers.org)
├── mrc20.js              # State chain verification
├── remotestorage.js      # remoteStorage protocol (draft-dejong-remotestorage-22)
├── rdf/
│   ├── turtle.js         # Turtle <-> JSON-LD
│   └── conneg.js         # Content negotiation
├── mashlib/
│   └── index.js           # Mashlib data browser plugin
└── utils/
    ├── url.js             # URL utilities
    ├── conditional.js     # If-Match/If-None-Match
    └── ssrf.js            # SSRF protection
```

## Dependencies

14 direct dependencies for a fast, secure server:

- **fastify** - High-performance HTTP server
- **@fastify/middie** - Express/Connect middleware bridge (for IdP)
- **@fastify/rate-limit** - Rate limiting for API endpoints
- **@fastify/websocket** - WebSocket support for notifications
- **@simplewebauthn/server** - Passkey/WebAuthn authentication
- **bcryptjs** - Password hashing (pure JS, works on Termux/Android)
- **commander** - CLI command parsing
- **fs-extra** - Enhanced file operations
- **jose** - JWT/JWK handling for Solid-OIDC
- **microfed** - ActivityPub primitives (only when activitypub enabled)
- **n3** - Turtle parsing (only used when conneg enabled)
- **nostr-tools** - Nostr protocol and Schnorr signature verification
- **oidc-provider** - OpenID Connect Identity Provider (only when IdP enabled)
- **sql.js** - SQLite storage for federation data (WASM, cross-platform)

## Performance

This server is designed for speed. Benchmark results on a typical development machine:

| Operation | Requests/sec | Avg Latency | p99 Latency |
|-----------|-------------|-------------|-------------|
| GET resource | 5,400+ | 1.2ms | 3ms |
| GET container | 4,700+ | 1.6ms | 3ms |
| PUT (write) | 5,700+ | 1.1ms | 2ms |
| POST (create) | 5,200+ | 1.3ms | 3ms |
| OPTIONS | 10,000+ | 0.4ms | 1ms |

Run benchmarks yourself:
```bash
npm run benchmark
```

## Running Tests

```bash
npm test
```

Currently passing: **289 tests** (including 27 conformance tests)

### Conformance Test Harness (CTH)

This server passes the Solid Conformance Test Harness authentication tests:

```bash
# Start server with IdP and content negotiation
JSS_PORT=4000 JSS_CONNEG=true JSS_IDP=true jss start

# Create test users
curl -X POST http://localhost:4000/.pods \
  -H "Content-Type: application/json" \
  -d '{"name": "alice", "email": "alice@example.com", "password": "alicepassword123"}'

curl -X POST http://localhost:4000/.pods \
  -H "Content-Type: application/json" \
  -d '{"name": "bob", "email": "bob@example.com", "password": "bobpassword123"}'

# Run CTH authentication tests
docker run --rm --network=host \
  -e SOLID_IDENTITY_PROVIDER="http://localhost:4000/" \
  -e USERS_ALICE_WEBID="http://localhost:4000/alice/#me" \
  -e USERS_ALICE_PASSWORD="alicepassword123" \
  -e USERS_BOB_WEBID="http://localhost:4000/bob/#me" \
  -e USERS_BOB_PASSWORD="bobpassword123" \
  solidproject/conformance-test-harness:latest \
  --filter="authentication"
```

**CTH Status (v0.0.15):**
- Authentication tests: 6/6 passing

