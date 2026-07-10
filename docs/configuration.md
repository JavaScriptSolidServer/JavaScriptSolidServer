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

**ES Module Mode** (for custom or next-gen mashlib builds):
```bash
jss start --mashlib-module https://example.com/mashlib.js
```
Loads an ES module-based data browser from any URL. Uses `<script type="module">` and `<div id="mashlib">` (self-initializing). CSS is auto-derived by replacing `.js` with `.css`. Content negotiation is auto-enabled.

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
curl -I http://localhost:4443/alice/public/
# Updates-Via: ws://localhost:4443/.notifications
```

Protocol (solid-0.1, compatible with SolidOS):
```
Server: protocol solid-0.1
Client: sub http://localhost:4443/alice/public/data.json
Server: ack http://localhost:4443/alice/public/data.json
Server: pub http://localhost:4443/alice/public/data.json  (on change)
```


## CLI Start Options

### Start Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --port <n>` | Port to listen on | 4443 |
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
| `--mashlib-module <url>` | Enable ES module data browser from a URL | - |
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
| `--public` | Allow unauthenticated access (skip WAC); never writes into the served directory (no landing-page seed) | false |
| `--read-only` | Disable PUT/DELETE/PATCH methods | false |
| `--live-reload` | Auto-refresh browser on file changes | false |
| `--pay` | Enable HTTP 402 paid access for /pay/* | false |
| `--pay-cost <n>` | Cost per request in satoshis | 1 |
| `--pay-mempool-url <url>` | Mempool API URL for deposit verification | (testnet4) |
| `--pay-address <addr>` | Address for receiving deposits | - |
| `--pay-token <ticker>` | Token to sell (enables primary market + withdrawal) | - |
| `--pay-rate <n>` | Sats per token for buy/withdraw | 1 |
| `--pay-chains <ids>` | Multi-chain deposits + AMM (e.g. "tbtc3,tbtc4") | - |
| `--mongo` | Enable MongoDB-backed /db/ route | false |
| `--mongo-url <url>` | MongoDB connection URL | mongodb://localhost:27017 |
| `--mongo-database <name>` | MongoDB database name | solid |
| `--webrtc` | Enable WebRTC signaling server | false |
| `--webrtc-path <path>` | WebRTC signaling WebSocket path | /.webrtc |
| `--tunnel` | Enable tunnel proxy (decentralized ngrok) | false |
| `--tunnel-path <path>` | Tunnel WebSocket path | /.tunnel |
| `--terminal` | Enable WebSocket shell at `/.terminal` | false |
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
export JSS_MASHLIB_MODULE=https://example.com/mashlib.js
export JSS_NOSTR=true
export JSS_INVITE_ONLY=true
export JSS_WEBID_TLS=true
export JSS_DEFAULT_QUOTA=100MB
export JSS_ACTIVITYPUB=true
export JSS_AP_USERNAME=alice
export JSS_PUBLIC=true
export JSS_READ_ONLY=true
export JSS_SINGLE_USER=true
export JSS_SINGLE_USER_NAME=me
export JSS_SINGLE_USER_PASSWORD=choose-a-good-one  # seeds IDP account on first start
export JSS_LIVE_RELOAD=true
export JSS_SOLIDOS_UI=true
export JSS_PAY=true
export JSS_PAY_COST=10
export JSS_PAY_ADDRESS=your-address
export JSS_PAY_TOKEN=PODS
export JSS_PAY_RATE=10
export JSS_MONGO=true
export JSS_MONGO_URL=mongodb://localhost:27017
export JSS_MONGO_DATABASE=solid
export JSS_WEBRTC=true
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
curl -X POST http://localhost:4443/.pods \
  -H "Content-Type: application/json" \
  -d '{"name": "alice"}'
```

Response:
```json
{
  "name": "alice",
  "webId": "http://localhost:4443/alice/#me",
  "podUri": "http://localhost:4443/alice/",
  "token": "eyJ..."
}
```

### Single-User Mode

For personal pod servers where only one user needs access:

```bash
# Default: pod served at server root (#348). WebID is
# /profile/card.jsonld#me; the IDP login username is "me". On first
# run JSS will prompt for an initial password (TTY only).
jss start --single-user --idp

# Provide the initial IDP password non-interactively (systemd, containers, CI):
jss start --single-user --idp --single-user-password 'choose-a-good-one'
JSS_SINGLE_USER_PASSWORD='choose-a-good-one' jss start --single-user --idp

# Mount the pod at a named path instead of the origin. WebID becomes
# /alice/profile/card.jsonld#me; login as "alice".
jss start --single-user --single-user-name alice --idp

# Legacy /me/ pod — same as the old default before #348.
jss start --single-user --single-user-name me --idp

# Via environment
JSS_SINGLE_USER=true jss start --idp
```

**Features:**
- Pod auto-created on first startup with full structure (inbox, public, private, profile)
- IDP account auto-seeded so the operator can log in immediately
- Registration endpoint disabled (returns 403)
- Login works for the single user via password (`POST /idp/credentials`) or any other configured method
- Proper ACLs generated automatically

**Upgrading from a pre-#348 install:** if your existing pod was created with the old default (data lives under `<root>/me/`), JSS no longer auto-detects it — restarting plain `jss start --single-user` will start seeding a fresh empty root pod alongside your legacy `/me/` data, and your existing IDP account will keep authenticating against `/me/`. Pick one path on the next restart:
- **Keep the legacy layout:** add `--single-user-name me` to your launch command. No data movement needed.
- **Migrate to root pod:** move the *entire* contents of `<root>/me/` (including dotfiles like `.acl`, `.meta`, `.quota.json` — a plain `mv <root>/me/* <root>/` skips them) to `<root>/`, delete the IDP account for `me` (so the new root pod's `me` account can be seeded), then restart without the name flag. Use one of:

  ```bash
  # Option A: rsync handles dotfiles correctly with the trailing slash.
  rsync -a <root>/me/ <root>/ && rm -rf <root>/me

  # Option B: bash with dotglob enabled so * matches dotfiles too.
  shopt -s dotglob && mv <root>/me/* <root>/ && rmdir <root>/me
  ```

**Initial password sources, in priority order:**
1. `--single-user-password <pw>` CLI flag
2. `JSS_SINGLE_USER_PASSWORD` env var
3. Interactive no-echo prompt (TTY only)
4. None — the server starts and warns; the pod is created but isn't loggable until you restart with `--single-user-password <pw>`, set `JSS_SINGLE_USER_PASSWORD`, or run on a TTY to be prompted. (`jss passwd <user>` does not work here — it returns "User not found" until an account exists.)

The password is only consulted on the first start — once an account exists, subsequent restarts skip the seed step and never overwrite it. The password is never written to the saved config file (`.jss/config`).


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

## Application Mount Points (appPaths)

Programmatic compositions can mount whole applications beside the pod
(the plugin-zero pattern from
[#206](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/206)):

```js
import { createServer } from 'javascript-solid-server/src/server.js';

const fastify = createServer({ appPaths: ['/myapp'] });
// Register both forms: fastify wildcards don't match the bare prefix.
fastify.all('/myapp', myAppHandler);
fastify.all('/myapp/*', myAppHandler); // the app owns auth below its prefix
await fastify.listen({ port: 4443 });
```

Requests at or below an app path skip the WAC authorization hook — the
application authenticates and authorizes its own traffic, exactly like the
built-in `/storage/` and `/db/` routes. Everything outside the declared
prefixes keeps full WAC enforcement. Entries must start with `/` and be
longer than `/`; anything else is ignored.

Because the WAC hook is also what populates `request.webId`, requests under
an app path never carry it — don't rely on `request.webId` in app handlers.
Resolve identity with the public accessor
([#584](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/584)):

```js
import { getAgent } from 'javascript-solid-server/auth.js';

const webId = await getAgent(request); // string | null, covers Bearer/DPoP/NIP-98/LWS-CID
```

See [#582](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/582)
for the design discussion and
[melvincarvalho/tideholm](https://github.com/melvincarvalho/tideholm/tree/gh-pages/jss-plugin)
for a complete example (a multiplayer game where pod WebIDs are the player
accounts).

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

**ES Module Mode** (for custom or next-gen mashlib builds):
```bash
jss start --mashlib-module https://example.com/mashlib.js
```
Loads an ES module-based data browser from any URL. Uses `<script type="module">` and `<div id="mashlib">` (self-initializing). CSS is auto-derived by replacing `.js` with `.css`. Content negotiation is auto-enabled.

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
curl -I http://localhost:4443/alice/public/
# Updates-Via: ws://localhost:4443/.notifications
```

Protocol (solid-0.1, compatible with SolidOS):
```
Server: protocol solid-0.1
Client: sub http://localhost:4443/alice/public/data.json
Server: ack http://localhost:4443/alice/public/data.json
Server: pub http://localhost:4443/alice/public/data.json  (on change)
```

