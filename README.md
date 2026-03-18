# JavaScript Solid Server

[![npm version](https://img.shields.io/npm/v/javascript-solid-server)](https://www.npmjs.com/package/javascript-solid-server)

A minimal, fast, JSON-LD native Solid server.

**[Documentation](https://javascriptsolidserver.github.io/docs/)** | **[GitHub](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer)**

## Features

- **LDP CRUD** — GET, PUT, POST, DELETE, HEAD, PATCH (N3 + SPARQL Update)
- **JSON-LD Native** — Stores and serves JSON-LD by default, Turtle via `--conneg`
- **Web Access Control** — `.acl` file-based authorization
- **Solid-OIDC** — Built-in Identity Provider with DPoP, passkeys, Schnorr SSO
- **WebSocket Notifications** — Real-time updates (solid-0.1 protocol)
- **Content Negotiation** — Turtle ↔ JSON-LD conversion (optional)
- **Multi-user Pods** — Path-based (`/alice/`) or subdomain-based (`alice.example.com`)
- **Single-User Mode** — Personal pod server with `--single-user`
- **Git HTTP Backend** — Clone and push to pod containers
- **Nostr Relay** — Integrated NIP-01 relay (`wss://your.pod/relay`)
- **Nostr Auth** — NIP-98 signatures, did:nostr → WebID resolution
- **ActivityPub** — Fediverse federation with Mastodon-compatible API
- **remoteStorage** — [draft-dejong-remotestorage-22](https://remotestorage.io/spec/) file sync
- **MongoDB Storage** — Optional `/db/` route for JSON-LD at scale
- **WebRTC Signaling** — Peer-to-peer connections via WebID-authenticated signaling
- **Tunnel Proxy** — Decentralized ngrok through your pod
- **HTTP 402 Payments** — Monetize endpoints with per-request sat payments
- **Mashlib / SolidOS UI** — Optional data browser (CDN, local, or ES module)
- **Storage Quotas** — Per-user limits with CLI management
- **Invite-Only Mode** — Controlled registration via invite codes
- **SSL/TLS, CORS, Range Requests, Conditional Requests**

## Quick Start

```bash
# Install
npm install -g javascript-solid-server

# Start
jss start

# With common options
jss start --port 8443 --idp --mashlib --conneg --git --nostr
```

### Creating a Pod

```bash
curl -X POST http://localhost:3000/.pods \
  -H "Content-Type: application/json" \
  -d '{"name": "alice"}'
```

### Using the Pod

```bash
# Read
curl http://localhost:3000/alice/public/

# Write
curl -X PUT http://localhost:3000/alice/public/data.json \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/ld+json" \
  -d '{"@id": "#data", "http://example.org/value": 42}'
```

### Android/Termux

```bash
pkg install nodejs git
npm install -g javascript-solid-server
jss start --port 8080 --nostr --git
```

## CLI Reference

```bash
jss start [options]    # Start the server
jss init [options]     # Initialize configuration
jss invite <cmd>       # Manage invite codes
jss quota <cmd>        # Manage storage quotas
```

Key options: `--port`, `--idp`, `--conneg`, `--mashlib`, `--git`, `--nostr`, `--activitypub`, `--webrtc`, `--tunnel`, `--mongo`, `--pay`, `--public`, `--single-user`

Full options: [docs/configuration.md](docs/configuration.md)

## Documentation

| Topic | Link |
|-------|------|
| Configuration & Options | [docs/configuration.md](docs/configuration.md) |
| Authentication | [docs/authentication.md](docs/authentication.md) |
| Mashlib / SolidOS UI | [docs/mashlib.md](docs/mashlib.md) |
| WebSocket Notifications | [docs/notifications.md](docs/notifications.md) |
| Git Support | [docs/git-support.md](docs/git-support.md) |
| Nostr Relay | [docs/nostr.md](docs/nostr.md) |
| ActivityPub & Mastodon API | [docs/activitypub.md](docs/activitypub.md) |
| remoteStorage | [docs/remotestorage.md](docs/remotestorage.md) |
| WebRTC & Tunnel | [docs/webrtc.md](docs/webrtc.md) |
| MongoDB `/db/` Route | [docs/mongodb.md](docs/mongodb.md) |
| HTTP 402 Payments | [docs/payments.md](docs/payments.md) |
| Storage Quotas | [docs/quotas.md](docs/quotas.md) |
| Invite-Only Registration | [docs/invites.md](docs/invites.md) |
| Security & Subdomain Mode | [docs/security.md](docs/security.md) |
| Architecture & Structure | [docs/architecture.md](docs/architecture.md) |

## Comparison

| Server | Size | Deps | Notes |
|--------|------|------|-------|
| [JSS](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer) | ~18K LoC | 15 | Minimal, JSON-LD native |
| [NSS](https://github.com/nodeSolidServer/node-solid-server) | ~25K LoC | 58 | Original Solid server |
| [CSS](https://github.com/CommunitySolidServer/CommunitySolidServer) | ~65K LoC | 70 | Modular, configurable |
| [Pivot](https://github.com/solid-contrib/pivot) | ~70K LoC | 70+ | Built on CSS |

## Performance

| Operation | Requests/sec | Avg Latency | p99 Latency |
|-----------|-------------|-------------|-------------|
| GET resource | 5,400+ | 1.2ms | 3ms |
| GET container | 4,700+ | 1.6ms | 3ms |
| PUT (write) | 5,700+ | 1.1ms | 2ms |
| POST (create) | 5,200+ | 1.3ms | 3ms |
| OPTIONS | 10,000+ | 0.4ms | 1ms |

## Running Tests

```bash
npm test
```

## License

AGPL-3.0-only
