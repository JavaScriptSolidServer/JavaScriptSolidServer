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

### Implemented (v0.0.13)

- **LDP CRUD Operations** - GET, PUT, POST, DELETE, HEAD
- **N3 Patch** - Solid's native patch format for RDF updates
- **SPARQL Update** - Standard SPARQL UPDATE protocol for PATCH
- **Conditional Requests** - If-Match/If-None-Match headers (304, 412)
- **CLI & Config** - `jss` command with config file/env var support
- **SSL/TLS** - HTTPS support with certificate configuration
- **WebSocket Notifications** - Real-time updates via solid-0.1 protocol (SolidOS compatible)
- **Container Management** - Create, list, and manage containers
- **Multi-user Pods** - Create pods at `/<username>/`
- **WebID Profiles** - JSON-LD structured data in HTML at pod root
- **Web Access Control (WAC)** - `.acl` file-based authorization
- **Solid-OIDC Identity Provider** - Built-in IdP with DPoP, dynamic registration
- **Solid-OIDC Resource Server** - Accept DPoP-bound access tokens from external IdPs
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
| `-q, --quiet` | Suppress logs | false |

### Environment Variables

All options can be set via environment variables with `JSS_` prefix:

```bash
export JSS_PORT=8443
export JSS_SSL_KEY=/path/to/key.pem
export JSS_SSL_CERT=/path/to/cert.pem
export JSS_CONNEG=true
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

## Configuration

```javascript
createServer({
  logger: true,        // Enable Fastify logging (default: true)
  conneg: false,       // Enable content negotiation (default: false)
  notifications: false // Enable WebSocket notifications (default: false)
});
```

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

MIT
