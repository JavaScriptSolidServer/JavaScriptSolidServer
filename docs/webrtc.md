## WebRTC Signaling

Peer-to-peer communication via WebRTC, using JSS as the signaling server. Once peers are connected, all media and data flows directly between them.

```bash
jss start --webrtc
```

### How It Works

1. Both peers connect to `wss://your.pod/.webrtc` (WebID auth required)
2. Caller sends an SDP offer targeting the callee's WebID
3. JSS relays the offer/answer and ICE candidates between peers
4. Once a direct path is found, the peer-to-peer connection is established
5. JSS steps out — video, audio, files, and data flow directly between peers

### Protocol

Messages are JSON over WebSocket:

```js
// Send an offer to another user
{ "type": "offer", "to": "https://bob.example/profile/card#me", "sdp": "..." }

// Receive an offer from another user
{ "type": "offer", "from": "https://alice.example/profile/card#me", "sdp": "..." }

// ICE candidate exchange
{ "type": "candidate", "to": "https://bob.example/profile/card#me", "candidate": {...} }

// Hang up
{ "type": "hangup", "to": "https://bob.example/profile/card#me" }
```

On connect, peers receive a list of online users and get notified when others join or leave.

## Tunnel Proxy (Decentralized ngrok)

Expose a local dev server to the internet through your JSS pod. A tunnel client connects via WebSocket, registers a name, and receives proxied HTTP requests.

```bash
jss start --tunnel
```

### How It Works

1. Tunnel client connects to `wss://your.pod/.tunnel` (WebID auth required)
2. Client registers a name: `{ "type": "register", "name": "myapp" }`
3. Public URL becomes available at `https://your.pod/tunnel/myapp/`
4. HTTP requests to that URL are serialized and sent to the tunnel client over WebSocket
5. Tunnel client forwards to localhost, returns the response

### Tunnel Client Protocol

```js
// 1. Register a tunnel
→ { "type": "register", "name": "myapp" }
← { "type": "registered", "name": "myapp", "url": "/tunnel/myapp/" }

// 2. Receive proxied HTTP requests
← { "type": "request", "id": "uuid", "method": "GET", "path": "/api/hello", "headers": {...} }

// 3. Return the response
→ { "type": "response", "id": "uuid", "status": 200, "headers": {...}, "body": "..." }
```

