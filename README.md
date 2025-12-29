# JavaScript Solid Server

A minimal, fast, JSON-LD native Solid server.

## Philosophy: JSON-LD First

This is a **JSON-LD native implementation**. Unlike traditional Solid servers that treat Turtle as the primary format and convert to/from it, this server:

- **Stores everything as JSON-LD** - No RDF parsing overhead for standard operations
- **Serves JSON-LD by default** - Modern web applications can consume responses directly
- **Content negotiation is optional** - Enable Turtle support with `{ conneg: true }` when needed
- **Fast by design** - Skip the RDF parsing tax when you don't need it

### Why JSON-LD First?

1. **Performance**: JSON parsing is native to JavaScript - no external RDF libraries needed for basic operations
2. **Simplicity**: JSON-LD is valid JSON - works with any JSON tooling
3. **Web-native**: Browsers and web apps understand JSON natively
4. **Semantic web ready**: JSON-LD is a W3C standard RDF serialization

### When to Enable Content Negotiation

Enable `conneg: true` when:
- Interoperating with Turtle-based Solid apps
- Serving data to legacy Solid clients
- Running conformance tests that require Turtle support

```javascript
import { createServer } from './src/server.js';

// Default: JSON-LD only (fast)
const server = createServer();

// With Turtle support (for interoperability)
const serverWithConneg = createServer({ conneg: true });
```

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

## Features

### Implemented (v0.0.23)

- **LDP CRUD Operations** - GET, PUT, POST, DELETE, HEAD
- **N3 Patch** - Solid's native patch format for RDF updates
- **SPARQL Update** - Standard SPARQL UPDATE protocol for PATCH
- **Conditional Requests** - If-Match/If-None-Match headers (304, 412)
- **CLI & Config** - `jss` command with config file/env var support
- **SSL/TLS** - HTTPS support with certificate configuration
- **WebSocket Notifications** - Real-time updates via solid-0.1 protocol (SolidOS compatible)
- **Container Management** - Create, list, and manage containers
- **Multi-user Pods** - Path-based (`/alice/`) or subdomain-based (`alice.example.com`)
- **Subdomain Mode** - XSS protection via origin isolation
- **Mashlib Data Browser** - Optional SolidOS UI (CDN or local hosting)
- **WebID Profiles** - JSON-LD structured data in HTML at pod root
- **Web Access Control (WAC)** - `.acl` file-based authorization
- **Solid-OIDC Identity Provider** - Built-in IdP with DPoP, dynamic registration
- **Solid-OIDC Resource Server** - Accept DPoP-bound access tokens from external IdPs
- **NSS-style Registration** - Username/password auth compatible with Solid apps
- **Nostr Authentication** - NIP-98 HTTP Auth with Schnorr signatures
- **Simple Auth Tokens** - Built-in token authentication for development
- **Content Negotiation** - Optional Turtle <-> JSON-LD conversion
- **CORS Support** - Full cross-origin resource sharing

### HTTP Methods

| Method | Support |
|--------|---------|
| GET | Full - Resources and containers |
| HEAD | Full |
| PUT | Full - Create/update resources |
| POST | Full - Create in containers |
| DELETE | Full |
| PATCH | N3 Patch format |
| OPTIONS | Full with CORS |

## Getting Started

### Prerequisites

- Node.js 18+

### Installation

```bash
npm install

# Or install globally
npm install -g javascript-solid-server
```

### Quick Start

```bash
# Initialize configuration (interactive)
jss init

# Start server
jss start

# Or with options
jss start --port 8443 --ssl-key ./key.pem --ssl-cert ./cert.pem
```

### CLI Commands

```bash
jss start [options]    # Start the server
jss init [options]     # Initialize configuration
jss --help             # Show help
```

### Start Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --port <n>` | Port to listen on | 3000 |
| `-h, --host <addr>` | Host to bind to | 0.0.0.0 |
| `-r, --root <path>` | Data directory | ./data |
| `-c, --config <file>` | Config file path | - |
| `--ssl-key <path>` | SSL private key (PEM) | - |
| `--ssl-cert <path>` | SSL certificate (PEM) | - |
| `--conneg` | Enable Turtle support | false |
| `--notifications` | Enable WebSocket | false |
| `--idp` | Enable built-in IdP | false |
| `--idp-issuer <url>` | IdP issuer URL | (auto) |
| `--subdomains` | Enable subdomain-based pods | false |
| `--base-domain <domain>` | Base domain for subdomains | - |
| `--mashlib` | Enable Mashlib (local mode) | false |
| `--mashlib-cdn` | Enable Mashlib (CDN mode) | false |
| `--mashlib-version <ver>` | Mashlib CDN version | 2.0.0 |
| `-q, --quiet` | Suppress logs | false |

### Environment Variables

All options can be set via environment variables with `JSS_` prefix:

```bash
export JSS_PORT=8443
export JSS_SSL_KEY=/path/to/key.pem
export JSS_SSL_CERT=/path/to/cert.pem
export JSS_CONNEG=true
export JSS_SUBDOMAINS=true
export JSS_BASE_DOMAIN=example.com
export JSS_MASHLIB=true
jss start
```

### Config File

Create `config.json`:

```json
{
  "port": 8443,
  "root": "./data",
  "sslKey": "./ssl/key.pem",
  "sslCert": "./ssl/cert.pem",
  "conneg": true,
  "notifications": true
}
```

Then: `jss start --config config.json`

### Creating a Pod

```bash
curl -X POST http://localhost:3000/.pods \
  -H "Content-Type: application/json" \
  -d '{"name": "alice"}'
```

Response:
```json
{
  "name": "alice",
  "webId": "http://localhost:3000/alice/#me",
  "podUri": "http://localhost:3000/alice/",
  "token": "eyJ..."
}
```

### Using the Pod

```bash
# Read public profile
curl http://localhost:3000/alice/

# Write to pod (with token)
curl -X PUT http://localhost:3000/alice/public/data.json \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/ld+json" \
  -d '{"@id": "#data", "http://example.org/value": 42}'

# Read back
curl http://localhost:3000/alice/public/data.json
```

### PATCH with N3

```bash
curl -X PATCH http://localhost:3000/alice/public/data.json \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: text/n3" \
  -d '@prefix solid: <http://www.w3.org/ns/solid/terms#>.
      _:patch a solid:InsertDeletePatch;
        solid:inserts { <#data> <http://example.org/name> "Updated" }.'
```

### PATCH with SPARQL Update

```bash
curl -X PATCH http://localhost:3000/alice/public/data.json \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/sparql-update" \
  -d 'PREFIX ex: <http://example.org/>
      DELETE DATA { <#data> ex:value 42 } ;
      INSERT DATA { <#data> ex:value 43 }'
```

### Conditional Requests

Use `If-Match` for safe updates (optimistic concurrency):

```bash
# Get current ETag
ETAG=$(curl -sI http://localhost:3000/alice/public/data.json | grep -i etag | awk '{print $2}')

# Update only if ETag matches
curl -X PUT http://localhost:3000/alice/public/data.json \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/ld+json" \
  -H "If-Match: $ETAG" \
  -d '{"@id": "#data", "http://example.org/value": 100}'
```

Use `If-None-Match: *` for create-only semantics:

```bash
# Create only if resource doesn't exist (returns 412 if it does)
curl -X PUT http://localhost:3000/alice/public/new-resource.json \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/ld+json" \
  -H "If-None-Match: *" \
  -d '{"@id": "#new"}'
```

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

## Authentication

### Simple Tokens (Development)

Use the token returned from pod creation:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3000/alice/private/
```

### Built-in Identity Provider (v0.0.12+)

Enable the built-in Solid-OIDC Identity Provider:

```bash
jss start --idp
```

With IdP enabled, pod creation requires email and password:

```bash
curl -X POST http://localhost:3000/.pods \
  -H "Content-Type: application/json" \
  -d '{"name": "alice", "email": "alice@example.com", "password": "secret123"}'
```

Response:
```json
{
  "name": "alice",
  "webId": "http://localhost:3000/alice/#me",
  "podUri": "http://localhost:3000/alice/",
  "idpIssuer": "http://localhost:3000",
  "loginUrl": "http://localhost:3000/idp/auth"
}
```

OIDC Discovery: `/.well-known/openid-configuration`

### Programmatic Login (CTH Compatible)

For automated testing and scripts, use the credentials endpoint:

```bash
curl -X POST http://localhost:3000/idp/credentials \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123"}'
```

Response:
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "webid": "http://localhost:3000/alice/#me"
}
```

For DPoP-bound tokens (Solid-OIDC compliant), include a DPoP proof header.

### Solid-OIDC (External IdP)

The server also accepts DPoP-bound access tokens from external Solid identity providers:

```bash
curl -H "Authorization: DPoP ACCESS_TOKEN" \
     -H "DPoP: DPOP_PROOF" \
     http://localhost:3000/alice/private/
```

## Subdomain Mode (XSS Protection)

By default, JSS uses **path-based pods** (`/alice/`, `/bob/`). This is simple but has a security limitation: all pods share the same origin, making cross-site scripting (XSS) attacks possible between pods.

**Subdomain mode** provides **origin isolation** - each pod gets its own subdomain (`alice.example.com`, `bob.example.com`), preventing XSS attacks between pods.

### Why Subdomain Mode?

| Mode | URL | Origin | XSS Risk |
|------|-----|--------|----------|
| Path-based | `example.com/alice/` | `example.com` | Shared origin - pods can XSS each other |
| Subdomain | `alice.example.com/` | `alice.example.com` | Isolated - browser's Same-Origin Policy protects |

### Enabling Subdomain Mode

```bash
jss start --subdomains --base-domain example.com
```

Or via environment variables:

```bash
export JSS_SUBDOMAINS=true
export JSS_BASE_DOMAIN=example.com
jss start
```

### DNS Configuration

You need a **wildcard DNS record** pointing to your server:

```
*.example.com  A  <your-server-ip>
```

### Pod URLs in Subdomain Mode

| Path Mode | Subdomain Mode |
|-----------|----------------|
| `example.com/alice/` | `alice.example.com/` |
| `example.com/alice/public/file.txt` | `alice.example.com/public/file.txt` |
| `example.com/alice/#me` | `alice.example.com/#me` |

Pod creation still uses the main domain:

```bash
curl -X POST https://example.com/.pods \
  -H "Content-Type: application/json" \
  -d '{"name": "alice"}'
```

## Configuration

```javascript
createServer({
  logger: true,        // Enable Fastify logging (default: true)
  conneg: false,       // Enable content negotiation (default: false)
  notifications: false, // Enable WebSocket notifications (default: false)
  subdomains: false,   // Enable subdomain-based pods (default: false)
  baseDomain: null,    // Base domain for subdomains (e.g., "example.com")
  mashlib: false,      // Enable Mashlib data browser - local mode (default: false)
  mashlibCdn: false,   // Enable Mashlib data browser - CDN mode (default: false)
  mashlibVersion: '2.0.0', // Mashlib version for CDN mode
});
```

### Mashlib Data Browser

Enable the [SolidOS Mashlib](https://github.com/SolidOS/mashlib) data browser for RDF resources. Two modes are available:

**CDN Mode** (recommended for getting started):
```bash
jss start --mashlib-cdn --conneg
```
Loads mashlib from unpkg.com CDN. Zero footprint - no local files needed.

**Local Mode** (for production/offline):
```bash
jss start --mashlib --conneg
```
Serves mashlib from `src/mashlib-local/dist/`. Requires building mashlib locally:
```bash
cd src/mashlib-local
npm install && npm run build
```

**How it works:**
1. Browser requests `/alice/public/data.ttl` with `Accept: text/html`
2. Server returns Mashlib HTML wrapper
3. Mashlib fetches the actual data via content negotiation
4. Mashlib renders an interactive, editable view

**Note:** Mashlib works best with `--conneg` enabled for Turtle support. Pod profiles (`/alice/`) continue to serve our JSON-LD-in-HTML format.

### WebSocket Notifications

Enable real-time notifications for resource changes:

```javascript
const server = createServer({ notifications: true });
```

Clients discover the WebSocket URL via the `Updates-Via` header:

```bash
curl -I http://localhost:3000/alice/public/
# Updates-Via: ws://localhost:3000/.notifications
```

Protocol (solid-0.1, compatible with SolidOS):
```
Server: protocol solid-0.1
Client: sub http://localhost:3000/alice/public/data.json
Server: ack http://localhost:3000/alice/public/data.json
Server: pub http://localhost:3000/alice/public/data.json  (on change)
```

## Running Tests

```bash
npm test
```

Currently passing: **182 tests** (including 27 conformance tests)

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

## Project Structure

```
src/
├── index.js              # Entry point
├── server.js             # Fastify setup
├── handlers/
│   ├── resource.js       # GET, PUT, DELETE, HEAD, PATCH
│   └── container.js      # POST, pod creation
├── storage/
│   └── filesystem.js     # File operations
├── auth/
│   ├── middleware.js     # Auth hook
│   ├── token.js          # Simple token auth
│   └── solid-oidc.js     # DPoP verification
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
│   ├── index.js          # Identity Provider plugin
│   ├── provider.js       # oidc-provider config
│   ├── adapter.js        # Filesystem adapter
│   ├── accounts.js       # User account management
│   ├── keys.js           # JWKS key management
│   ├── interactions.js   # Login/consent handlers
│   └── views.js          # HTML templates
├── rdf/
│   ├── turtle.js         # Turtle <-> JSON-LD
│   └── conneg.js         # Content negotiation
└── utils/
    ├── url.js            # URL utilities
    └── conditional.js    # If-Match/If-None-Match
```

## Dependencies

Minimal dependencies for a fast, secure server:

- **fastify** - High-performance HTTP server
- **@fastify/websocket** - WebSocket support for notifications
- **fs-extra** - Enhanced file operations
- **jose** - JWT/JWK handling for Solid-OIDC
- **n3** - Turtle parsing (only used when conneg enabled)
- **oidc-provider** - OpenID Connect Identity Provider (only when IdP enabled)
- **bcrypt** - Password hashing (only when IdP enabled)

## License

AGPL-3.0-only

This project is licensed under the GNU Affero General Public License v3.0. If you run a modified version as a network service, you must make the source code available to users of that service.
