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

### Dotfiles

Paths whose segments start with a dot are refused with `403` unless the
segment is one of the Solid-specific names (`.well-known`, `.acl`, `.meta`,
`.pods`, `.notifications`, `.account`). This keeps `.git/`, `.env`,
`.htpasswd` and similar files out of reach over HTTP even when they sit
inside a pod. Git smart-HTTP, the pay routes and app plugins mounted at a
dot prefix are allowed through on their own terms.

The check runs on the percent-decoded path, segment by segment, and the
storage lookup applies the same rule, so `%2Egit` is `.git` on both sides
and neither can be talked past the other (#639). A dot has to be literal
in the request: a segment that only starts with a dot after decoding is
refused even for the allowed names. A path that cannot be decoded, or that
hides a path separator behind `%2F`, is refused with `400` instead of
being passed on.

### Conditional writes are atomic

`If-Match` and `If-None-Match` on PUT, DELETE and PATCH are checked and acted on as one
step. Writes to a resource are queued within the process and held under a lock file next
to the resource (`.<name>.lock`, never listed or served) across processes that share the
data directory. Two clients racing with the same, still valid, ETag get one `2xx` and one
`412`; the loser's write is never silently overwritten. A request that cannot take the lock
within 30 seconds gets `503` with `Retry-After: 1`.

### Identity document fetches are bounded

Authentication can make the server fetch a document it does not control: a CID document for LWS-CID tokens, a DID document and WebID back-link for did:nostr, or a WebID profile for WebID-TLS. Every such fetch runs under one deadline that covers the connection, the response headers **and** the body read, plus a byte cap. The CID and did:nostr fetchers follow redirects themselves and apply the 5-second deadline per hop; the WebID-TLS profile fetch lets `fetch` follow redirects and applies one 5-second deadline to the whole chain. In addition, the CID and did:nostr fetches also go through the SSRF guard (`validateExternalUrl`) on the original URL and on every redirect hop, with cross-origin redirects refused. A host that answers promptly and then trickles the body cannot hold an authentication attempt, or the outbound socket, open beyond the deadline: the fetch fails, the failure is cached (1 minute for CID and did:nostr lookups, 5 minutes for a WebID-TLS verification), and the request is answered as unauthenticated. Responses that are not read (redirect hops, error statuses, oversized bodies) are cancelled so the socket is released at once.

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

