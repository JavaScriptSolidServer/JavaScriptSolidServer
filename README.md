# JavaScript Solid Server

A minimal, fast, JSON-LD native Solid server.

**[Documentation](https://javascriptsolidserver.github.io/docs/)** | **[GitHub](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer)**

## Features

### Implemented (v0.0.77)

- **Passkey Authentication** - WebAuthn/FIDO2 passwordless login with Touch ID, Face ID, or security keys
- **HTTP Range Requests** - Partial content delivery for large files and media streaming
- **Single-User Mode** - Simplified setup for personal pod servers
- **ActivityPub Federation** - Fediverse integration with WebFinger, inbox/outbox, HTTP signatures
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
- **WebID Profiles** - HTML with JSON-LD data islands, rendered with mashlib-jss + solidos-lite
- **Web Access Control (WAC)** - `.acl` file-based authorization with relative URL support
- **Solid-OIDC Identity Provider** - Built-in IdP with DPoP, RS256/ES256, dynamic registration
- **Solid-OIDC Resource Server** - Accept DPoP-bound access tokens from external IdPs
- **NSS-style Registration** - Username/password auth compatible with Solid apps
- **Nostr Authentication** - NIP-98 HTTP Auth with Schnorr signatures, did:nostr → WebID resolution
- **WebID-TLS** - Client certificate authentication for backend services and CLI tools
- **Simple Auth Tokens** - Built-in token authentication for development
- **Content Negotiation** - Turtle <-> JSON-LD conversion, including HTML data islands
- **CORS Support** - Full cross-origin resource sharing
- **Git HTTP Backend** - Clone and push to containers via `git` protocol
- **Nostr Relay** - Integrated NIP-01 relay on the same port (`wss://your.pod/relay`)
- **Invite-Only Registration** - CLI-managed invite codes for controlled signups
- **Storage Quotas** - Per-user storage limits with CLI management
- **Security** - Blocks access to dotfiles (`.git/`, `.env`, etc.) except Solid-specific ones

### HTTP Methods

| Method | Support |
|--------|---------|
| GET | Full - Resources and containers |
| HEAD | Full |
| PUT | Full - Create/update resources |
| POST | Full - Create in containers |
| DELETE | Full |
| PATCH | N3 Patch + SPARQL Update |
| OPTIONS | Full with CORS |

## Getting Started

### Prerequisites

- Node.js 18+

### Android/Termux

JSS runs on Android via Termux with automatic `bcryptjs` fallback:

```bash
pkg install nodejs git
npm install -g javascript-solid-server
jss start --port 8080 --nostr --git
```

Use PM2 for persistence:
```bash
npm install -g pm2
pm2 start jss -- start --port 8080 --nostr --git
pm2 save
```

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
jss invite <cmd>       # Manage invite codes (create, list, revoke)
jss quota <cmd>        # Manage storage quotas (set, show, reconcile)
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
| `--solidos-ui` | Enable modern SolidOS UI (requires --mashlib) | false |
| `--git` | Enable Git HTTP backend | false |
| `--nostr` | Enable Nostr relay | false |
| `--nostr-path <path>` | Nostr relay WebSocket path | /relay |
| `--nostr-max-events <n>` | Max events in relay memory | 1000 |
| `--invite-only` | Require invite code for registration | false |
| `--webid-tls` | Enable WebID-TLS client certificate auth | false |
| `--default-quota <size>` | Default storage quota per pod (e.g., 50MB) | 50MB |
| `--activitypub` | Enable ActivityPub federation | false |
| `--ap-username <name>` | ActivityPub username | me |
| `--ap-display-name <name>` | ActivityPub display name | (username) |
| `--ap-summary <text>` | ActivityPub bio/summary | - |
| `--ap-nostr-pubkey <hex>` | Nostr pubkey for identity linking | - |
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
export JSS_NOSTR=true
export JSS_INVITE_ONLY=true
export JSS_WEBID_TLS=true
export JSS_DEFAULT_QUOTA=100MB
export JSS_ACTIVITYPUB=true
export JSS_AP_USERNAME=alice
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

**Note:** Mashlib works best with `--conneg` enabled for Turtle support.

**Modern UI (SolidOS UI):**
```bash
jss start --mashlib --solidos-ui --conneg
```
Serves a modern Nextcloud-style UI shell while reusing mashlib's data layer. The `--solidos-ui` flag swaps the classic databrowser interface for a cleaner, mobile-friendly design with:
- Modern file browser with breadcrumb navigation
- Profile, Contacts, Sharing, and Settings views
- Path-based URLs (browser URL reflects current resource)
- Responsive design for mobile devices

Requires solidos-ui dist files in `src/mashlib-local/dist/solidos-ui/`. See [solidos-ui](https://github.com/solidos/solidos/tree/main/workspaces/solidos-ui) for details.

### Profile Pages

Pod profiles (`/alice/`) use HTML with embedded JSON-LD data islands and are rendered using:
- [mashlib-jss](https://github.com/JavaScriptSolidServer/mashlib-jss) - A fork of mashlib with `getPod()` fix for path-based pods
- [solidos-lite](https://github.com/SolidOS/solidos-lite) - Parses JSON-LD data islands into the RDF store

This allows profiles to work without server-side content negotiation while still providing full SolidOS editing capabilities.

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

## Git Support

Enable Git HTTP backend to clone and push to pod containers:

```bash
jss start --git
```

### Initialize a Repository

```bash
# Create a git repo in a pod container
cd data/alice/myrepo
git init
echo "# My Project" > README.md
git add . && git commit -m "Initial commit"
```

### Clone and Push

```bash
# Clone (public read access)
git clone http://localhost:3000/alice/myrepo

# Push (requires write access via WAC)
cd myrepo
echo "New content" >> README.md
git add . && git commit -m "Update"
git push
```

Git operations respect WAC permissions - clone requires Read access, push requires Write access.

**Auto-checkout:** After a successful push to a non-bare repository, JSS automatically updates the working directory - no post-receive hooks needed.

### Git Push with Nostr Authentication

Git push supports NIP-98 authentication via Basic Auth. Install the credential helper:

```bash
npm install -g git-credential-nostr
git-credential-nostr generate
git config --global credential.helper nostr
git config --global nostr.privkey <key-from-generate>
```

Create an ACL for your repo (includes public read for clone + owner write for push):

```bash
cd myrepo
git-credential-nostr acl > .acl
git add .acl && git commit -m "Add ACL"
```

See [git-credential-nostr](https://github.com/JavaScriptSolidServer/git-credential-nostr) for more details.

## ActivityPub Federation

Enable ActivityPub to federate with Mastodon, Pleroma, Misskey, and other Fediverse servers:

```bash
jss start --activitypub --ap-username alice --ap-display-name "Alice" --ap-summary "Hello from JSS!"
```

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `/.well-known/webfinger` | Actor discovery (Mastodon searches here) |
| `/.well-known/nodeinfo` | NodeInfo discovery |
| `/profile/card` | Actor (returns JSON-LD when `Accept: application/activity+json`) |
| `/inbox` | Shared inbox for receiving activities |
| `/profile/card/inbox` | Personal inbox |
| `/profile/card/outbox` | User's activities |
| `/profile/card/followers` | Followers collection |
| `/profile/card/following` | Following collection |

### How It Works

1. **Discovery**: Mastodon looks up `@alice@your.server` via WebFinger
2. **Actor**: Returns ActivityPub Actor JSON-LD with public key
3. **Follow**: Remote servers POST Follow activities to inbox
4. **Accept**: JSS auto-accepts follows and sends Accept back
5. **Delivery**: Posts are signed with HTTP Signatures and delivered to follower inboxes

### Identity Linking

Your WebID (`/profile/card#me`) becomes your ActivityPub Actor. Link to Nostr identity:

```bash
jss start --activitypub --ap-nostr-pubkey <64-char-hex-pubkey>
```

This adds `alsoKnownAs: ["did:nostr:<pubkey>"]` to your Actor profile, creating a verifiable link between your Solid, ActivityPub, and Nostr identities (the SAND stack).

### Programmatic Usage

```javascript
import { createServer } from 'javascript-solid-server';

const server = createServer({
  activitypub: true,
  apUsername: 'alice',
  apDisplayName: 'Alice',
  apSummary: 'Building the decentralized web!',
  apNostrPubkey: 'abc123...'  // Optional: links to did:nostr
});
```

### Testing Federation

```bash
# Check WebFinger
curl "http://localhost:3000/.well-known/webfinger?resource=acct:alice@localhost:3000"

# Get Actor (AP format)
curl -H "Accept: application/activity+json" http://localhost:3000/profile/card

# Check NodeInfo
curl http://localhost:3000/.well-known/nodeinfo/2.1
```

### Linking Nostr to WebID (did:nostr)

Bridge your Nostr identity to a Solid WebID for seamless authentication:

**Step 1:** Add your WebID to your Nostr profile (kind 0 event):
```json
{
  "name": "alice",
  "alsoKnownAs": ["https://solid.social/alice/profile/card#me"]
}
```

**Step 2:** Add the did:nostr link to your WebID profile:
```json
{
  "@id": "#me",
  "owl:sameAs": "did:nostr:<your-64-char-hex-pubkey>"
}
```

**How it works:**
1. NIP-98 signature is verified (existing flow)
2. DID document is fetched from `nostr.social/.well-known/did/nostr/<pubkey>.json`
3. `alsoKnownAs` is checked for a WebID URL
4. WebID profile is fetched and `owl:sameAs` verified
5. If bidirectional link exists → authenticated as WebID

This enables Nostr users to access their Solid pods using existing NIP-07 browser extensions.

## Invite-Only Registration

Control who can create accounts by requiring invite codes:

```bash
jss start --idp --invite-only
```

### Managing Invite Codes

```bash
# Create a single-use invite
jss invite create
# Created invite code: ABCD1234

# Create multi-use invite with note
jss invite create -u 5 -n "For team members"

# List all active invites
jss invite list
#   CODE        USES     CREATED      NOTE
#   -------------------------------------------------------
#   ABCD1234    0/1      2026-01-03
#   EFGH5678    2/5      2026-01-03   For team members

# Revoke an invite
jss invite revoke ABCD1234
```

### How It Works

| Mode | Registration | Pod Creation |
|------|--------------|--------------|
| Open (default) | Anyone can register | Anyone can create pods |
| Invite-only | Requires valid invite code | Via registration only |

When `--invite-only` is enabled:
- The registration page shows an "Invite Code" field
- Invalid or expired codes are rejected with an error
- Each use decrements the invite's remaining uses
- Depleted invites are automatically removed

Invite codes are stored in `.server/invites.json` in your data directory.

## Storage Quotas

Limit storage per pod to prevent abuse and manage resources:

```bash
jss start --default-quota 50MB
```

### Managing Quotas

```bash
# Set quota for a user (overrides default)
jss quota set alice 100MB

# Show quota info
jss quota show alice
#   alice:
#     Used:  12.5 MB
#     Limit: 100 MB
#     Free:  87.5 MB
#     Usage: 12%

# Recalculate from actual disk usage
jss quota reconcile alice
```

### How It Works

- Quotas are tracked incrementally on PUT, POST, and DELETE operations
- When quota is exceeded, the server returns HTTP 507 Insufficient Storage
- Each pod stores its quota in `/{pod}/.quota.json`
- Use `reconcile` to fix quota drift from manual file changes

### Size Formats

Supported formats: `50MB`, `1GB`, `500KB`, `1TB`

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

### Passkey Authentication (v0.0.77+)

Enable passwordless login with WebAuthn/FIDO2:

```bash
jss start --idp
```

**How it works:**
1. User logs in with username/password
2. Prompted to add a passkey (Touch ID, Face ID, security key)
3. Future logins: tap "Sign in with Passkey" → biometric → done!

**Benefits:**
- Phishing-resistant (bound to domain)
- No passwords to remember or leak
- Works on mobile and desktop

Passkeys are stored per-account and work across devices via platform sync (iCloud Keychain, Google Password Manager, etc.).

### Solid-OIDC (External IdP)

The server also accepts DPoP-bound access tokens from external Solid identity providers:

```bash
curl -H "Authorization: DPoP ACCESS_TOKEN" \
     -H "DPoP: DPOP_PROOF" \
     http://localhost:3000/alice/private/
```

### WebID-TLS (Client Certificates)

For backend services, CLI tools, and automated agents that need non-interactive authentication:

```bash
jss start --ssl-key key.pem --ssl-cert cert.pem --webid-tls
```

**How it works:**
1. Client presents X.509 certificate during TLS handshake
2. Certificate's `SubjectAlternativeName` contains a WebID URI
3. Server fetches the WebID profile
4. Server verifies the certificate's public key matches one in the profile

**Testing with curl:**

```bash
# Generate self-signed cert with WebID in SAN
openssl req -x509 -newkey rsa:2048 -keyout client-key.pem -out client-cert.pem -days 365 \
  -subj "/CN=Test" -addext "subjectAltName=URI:https://example.com/alice/#me" -nodes

# Make authenticated request
curl --cert client-cert.pem --key client-key.pem https://localhost:8443/alice/private/
```

**Profile requirement:** Your WebID profile must contain the certificate's public key:

```turtle
@prefix cert: <http://www.w3.org/ns/auth/cert#> .

<#me> cert:key [
    a cert:RSAPublicKey;
    cert:modulus "abc123..."^^xsd:hexBinary;
    cert:exponent 65537
] .
```

**Use cases:**
- Enterprise backend services with existing PKI
- Server-to-server communication
- CLI tools and scripts
- IoT devices with embedded certificates

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

## Comparison

| Server | Size | Deps | Notes |
|--------|------|------|-------|
| [JSS](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer) | 432 KB | 10 | Minimal, JSON-LD native |
| [NSS](https://github.com/nodeSolidServer/node-solid-server) | 777 KB | 58 | Original Solid server |
| [CSS](https://github.com/CommunitySolidServer/CommunitySolidServer) | 5.8 MB | 70 | Modular, configurable |
| [Pivot](https://github.com/solid-contrib/pivot) | ~6 MB | 70+ | Built on CSS |

## Security

### Root ACL Required

JSS uses **restrictive mode** by default: if no ACL file exists for a resource, access is denied. This prevents unauthorized writes to unprotected containers.

**You must create a root `.acl` file** in your data directory. Example (JSON-LD format):

```json
{
  "@context": {
    "acl": "http://www.w3.org/ns/auth/acl#",
    "foaf": "http://xmlns.com/foaf/0.1/"
  },
  "@graph": [
    {
      "@id": "#owner",
      "@type": "acl:Authorization",
      "acl:agent": { "@id": "https://your-domain.com/profile/card#me" },
      "acl:accessTo": { "@id": "https://your-domain.com/" },
      "acl:default": { "@id": "https://your-domain.com/" },
      "acl:mode": [
        { "@id": "acl:Read" },
        { "@id": "acl:Write" },
        { "@id": "acl:Control" }
      ]
    },
    {
      "@id": "#public",
      "@type": "acl:Authorization",
      "acl:agentClass": { "@id": "foaf:Agent" },
      "acl:accessTo": { "@id": "https://your-domain.com/" },
      "acl:default": { "@id": "https://your-domain.com/" },
      "acl:mode": [
        { "@id": "acl:Read" }
      ]
    }
  ]
}
```

Save this as `data/.acl` (replacing `your-domain.com` with your actual domain).

See [Issue #32](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/32) for background.

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

Currently passing: **223 tests** (including 27 conformance tests)

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
│   ├── container.js      # POST, pod creation
│   └── git.js            # Git HTTP backend
├── storage/
│   ├── filesystem.js     # File operations
│   └── quota.js          # Storage quota management
├── auth/
│   ├── middleware.js     # Auth hook
│   ├── token.js          # Simple token auth
│   ├── solid-oidc.js     # DPoP verification
│   ├── nostr.js          # NIP-98 Nostr authentication
│   ├── did-nostr.js      # did:nostr → WebID resolution
│   └── webid-tls.js      # WebID-TLS client certificate auth
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
│   ├── views.js          # HTML templates
│   └── invites.js        # Invite code management
├── ap/
│   ├── index.js          # ActivityPub plugin
│   ├── keys.js           # RSA keypair management
│   ├── store.js          # SQLite storage (followers, activities)
│   └── routes/
│       ├── actor.js      # Actor JSON-LD
│       ├── inbox.js      # Receive activities
│       ├── outbox.js     # User's activities
│       └── collections.js # Followers/following
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
- **microfed** - ActivityPub primitives (only when activitypub enabled)
- **better-sqlite3** - SQLite storage for federation data

## License

AGPL-3.0-only

This project is licensed under the GNU Affero General Public License v3.0. If you run a modified version as a network service, you must make the source code available to users of that service.
