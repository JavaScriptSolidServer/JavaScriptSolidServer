# WebSocket Notifications

Real-time notifications for resource changes using the solid-0.1 protocol (SolidOS compatible).

```bash
jss start --notifications
```

## Discovery

Clients discover the WebSocket URL via the `Updates-Via` header:

```bash
curl -I http://localhost:4443/alice/public/
# Updates-Via: ws://localhost:4443/.notifications
```

## Protocol

```
Server: protocol solid-0.1
Client: sub http://localhost:4443/alice/public/data.json
Server: ack http://localhost:4443/alice/public/data.json
Server: pub http://localhost:4443/alice/public/data.json  (on change)
```

## How It Works

1. Client connects to the WebSocket URL from `Updates-Via`
2. Server sends `protocol solid-0.1` greeting
3. Client subscribes: `sub <resource-url>`
4. Server acknowledges: `ack <resource-url>`
5. On any change (PUT, PATCH, DELETE), server broadcasts: `pub <resource-url>`
6. Container subscriptions also fire when child resources change

## ACL Enforcement

- Anonymous clients can subscribe to public resources
- Private resource subscriptions require authentication
- Cross-origin subscriptions are rejected

## Live Reload

For development, `--live-reload` injects a script that auto-refreshes the browser when files change on disk:

```bash
jss start --live-reload --notifications
```

File system changes (editing files directly) also trigger WebSocket notifications.
