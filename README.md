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

## Features

### Implemented (v0.0.8)

- **LDP CRUD Operations** - GET, PUT, POST, DELETE, HEAD
- **N3 Patch** - Solid's native patch format for RDF updates
- **Container Management** - Create, list, and manage containers
- **Multi-user Pods** - Create pods at `/<username>/`
- **WebID Profiles** - JSON-LD structured data in HTML at pod root
- **Web Access Control (WAC)** - `.acl` file-based authorization
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
```

### Running

```bash
# Start server (default port 3000)
npm start

# Development mode with watch
npm dev
```

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

### Solid-OIDC (Production)

The server accepts DPoP-bound access tokens from external Solid identity providers:

```bash
curl -H "Authorization: DPoP ACCESS_TOKEN" \
     -H "DPoP: DPOP_PROOF" \
     http://localhost:3000/alice/private/
```

## Configuration

```javascript
createServer({
  logger: true,     // Enable Fastify logging (default: true)
  conneg: false     // Enable content negotiation (default: false)
});
```

## Running Tests

```bash
npm test
```

Currently passing: **105 tests**

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
│   └── n3-patch.js       # N3 Patch support
├── rdf/
│   ├── turtle.js         # Turtle <-> JSON-LD
│   └── conneg.js         # Content negotiation
└── utils/
    └── url.js            # URL utilities
```

## Dependencies

Minimal dependencies for a fast, secure server:

- **fastify** - High-performance HTTP server
- **fs-extra** - Enhanced file operations
- **jose** - JWT/JWK handling for Solid-OIDC
- **n3** - Turtle parsing (only used when conneg enabled)

## License

MIT
