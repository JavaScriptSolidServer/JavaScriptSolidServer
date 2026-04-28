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
curl "http://localhost:4443/.well-known/webfinger?resource=acct:alice@localhost:4443"

# Get Actor (AP format)
curl -H "Accept: application/activity+json" http://localhost:4443/profile/card

# Check NodeInfo
curl http://localhost:4443/.well-known/nodeinfo/2.1
```

## Mastodon-compatible API

JSS exposes Mastodon API endpoints so that Mastodon clients (Elk, Phanpy, Ice Cubes) can connect:

```bash
jss start --activitypub --idp
```

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/apps` | Dynamic client registration |
| `GET /api/v1/accounts/verify_credentials` | Current user profile |
| `GET /api/v1/instance` | Instance metadata |
| `GET /oauth/authorize` | OAuth authorize page |
| `POST /oauth/authorize` | Process login |
| `POST /oauth/token` | Exchange code for Bearer token |

### OAuth 2.0 Flow

The OAuth layer is shared between Mastodon clients, remoteStorage apps, and third-party Solid panes:

1. Client registers via `POST /api/v1/apps` (gets `client_id` + `client_secret`)
2. Client redirects user to `GET /oauth/authorize?client_id=...&redirect_uri=...&response_type=code`
3. User logs in, JSS redirects back with `?code=...`
4. Client exchanges code for Bearer token via `POST /oauth/token`
5. Bearer token works with all JSS endpoints (Solid, ActivityPub, remoteStorage)

Supports out-of-band (OOB) redirect for CLI/desktop clients.

### Testing

```bash
# Register a client
curl -X POST http://localhost:4443/api/v1/apps \
  -H "Content-Type: application/json" \
  -d '{"client_name": "Test App", "redirect_uris": "urn:ietf:wg:oauth:2.0:oob"}'

# Check instance info
curl http://localhost:4443/api/v1/instance
```

