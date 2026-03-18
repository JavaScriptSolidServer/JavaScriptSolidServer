# Nostr Relay

Integrated NIP-01/NIP-11/NIP-16 Nostr relay running on the same port as the Solid server.

```bash
jss start --nostr
```

## Endpoint

`wss://your.pod/relay` (configurable via `--nostr-path`)

## Supported NIPs

- **NIP-01** — Basic protocol flow (EVENT, REQ, CLOSE)
- **NIP-11** — Relay information document (`GET /relay` with `Accept: application/nostr+json`)
- **NIP-16** — Event treatment (regular, replaceable, ephemeral)

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--nostr` | Enable Nostr relay | false |
| `--nostr-path <path>` | WebSocket path | /relay |
| `--nostr-max-events <n>` | Max events in memory | 1000 |

## How It Works

- Events are stored in memory (up to `--nostr-max-events`)
- Replaceable events (kinds 0, 3, 10000-19999) replace previous events by the same pubkey
- Ephemeral events (kinds 20000-29999) are broadcast but not stored
- Parameterized replaceable events (kinds 30000-39999) use the `d` tag for deduplication
- Rate limiting: 60 events per socket per minute

## Client Usage

```javascript
import { Relay } from 'nostr-tools';

const relay = await Relay.connect('wss://your.pod/relay');

// Subscribe
const sub = relay.subscribe([{ kinds: [1], limit: 10 }], {
  onevent(event) { console.log(event); }
});

// Publish
await relay.publish(signedEvent);
```

## Nostr Authentication (NIP-98)

JSS also supports NIP-98 HTTP Auth for Solid operations. See [docs/authentication.md](authentication.md) for details on:
- NIP-98 Schnorr signature authentication
- `did:nostr` → WebID resolution
- Linking Nostr identity to your WebID profile
