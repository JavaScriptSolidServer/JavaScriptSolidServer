## remoteStorage

JSS implements the [remoteStorage protocol](https://remotestorage.io/spec/draft-dejong-remotestorage-22). The storage routes are always available, but WebFinger discovery and OAuth require `--activitypub` (which provides the WebFinger and OAuth endpoints). Any remoteStorage-compatible app can store and sync data on your pod.

```bash
jss start --activitypub --idp
```

### Discovery

remoteStorage clients discover the storage endpoint via WebFinger:

```bash
curl "http://localhost:4443/.well-known/webfinger?resource=acct:me@localhost:4443"
```

The response includes a `remotestorage` link relation pointing to `/storage/me/`.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/storage/:user/*` | Read file or list folder (JSON-LD) |
| `HEAD` | `/storage/:user/*` | Get metadata (ETag, Content-Type, size) |
| `PUT` | `/storage/:user/*` | Write file (creates parent folders) |
| `DELETE` | `/storage/:user/*` | Delete file |

### How It Works

- **Auth**: Bearer token via OAuth 2.0 (same flow as Mastodon clients)
- **Public folder**: `/storage/me/public/*` is readable without auth
- **Conditional requests**: If-Match, If-None-Match (uses shared ETag utilities)
- **Dotfile protection**: `.acl`, `.meta`, and other dotfiles are blocked
- **Read-only mode**: Respects `--read-only` flag
- **Streaming**: Large files are streamed, not buffered

### Testing

```bash
# Write a file (needs Bearer token from OAuth flow)
curl -X PUT http://localhost:4443/storage/me/documents/hello.txt \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: text/plain" \
  -d "Hello, remoteStorage!"

# Read it back
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:4443/storage/me/documents/hello.txt

# List a folder
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:4443/storage/me/documents/

# Read from public folder (no auth needed)
curl http://localhost:4443/storage/me/public/readme.txt
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

