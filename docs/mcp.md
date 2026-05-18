# MCP — pod as a tool surface for agents

JSS speaks the [Model Context Protocol](https://modelcontextprotocol.io). Once `--mcp` is enabled, any MCP-compatible client — Claude Desktop, Cursor, custom agents, or `solid-apps/charlie` — can register your pod as a tool surface and read/write resources under the same WAC rules as any HTTP client.

> **Thesis**: MCP needs a backend. Solid is the backend.

## Quick start

```bash
jss start --idp --mcp
```

The MCP endpoint is `POST /mcp` on your pod, speaking JSON-RPC 2.0 over MCP's Streamable HTTP transport (protocol version `2025-03-26`).

### Smoke test

```bash
# Handshake
curl -s http://localhost:4443/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' | jq

# List the tools the server offers
curl -s http://localhost:4443/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq '.result.tools[].name'

# Call a tool (anonymous read of /public/)
curl -s http://localhost:4443/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_resources","arguments":{"path":"/public/"}}}' | jq
```

## Auth

The MCP endpoint reuses JSS's existing auth chain. Any token format JSS accepts on regular HTTP endpoints works here:

- **Bearer** — simple HMAC tokens from `POST /idp/credentials`
- **Solid-OIDC + DPoP** — for federated WebID identities
- **LWS-CID JWTs** — kid resolution via WebID profile
- **NIP-98** — Schnorr-signed Nostr events with `did:nostr:<pubkey>` identity

The MCP server extracts the WebID from the inbound request to `/mcp` itself. Every tool call is then WAC-checked against that WebID, on the resource path the tool touches. **There is no separate MCP auth layer** — granting an agent access to `/private/notes/` is the same operation as granting a human: edit the ACL.

Anonymous requests get the same WAC treatment as any other anonymous request — public resources are reachable, private ones aren't.

## Tools

### Resource CRUD

| Tool | Effect | WAC check |
|---|---|---|
| `list_resources` | List a container's contents (`ldp:contains`) | Read on container |
| `read_resource` | Return resource body (UTF-8) | Read on resource |
| `write_resource` | PUT resource (overwrites) | Write on resource (parent fallback for new resources) |
| `create_resource` | POST to container (server mints name unless `slug` given) | Append on container |
| `delete_resource` | DELETE resource | Write on resource |
| `head_resource` | Return size/modified without body | Read on resource |

### Skill discovery

Skills live at conventional paths the MCP server walks:

- `<pod>/SKILL.md` — pod-wide (owner's instructions to any bot)
- `<pod>/public/apps/<name>/SKILL.md` — per-app
- `<pod>/private/bots/<name>/SKILL.md` — per-bot

| Tool | Returns |
|---|---|
| `list_skills` | `skill:SkillIndex` listing every discovered skill with `skill:format`, `skill:scope`, `skill:source` |
| `get_skill` | Body of a specific skill file |
| `get_pod_skill` | Pod-wide SKILL.md (convenience) |

Both `SKILL.md` (Anthropic markdown format) and `SKILL.jsonld` (typed JSON-LD descriptor) are first-class. The discovery channel stays stable; new formats plug in via the `skill:format` declaration.

### Docs

| Tool | Returns |
|---|---|
| `list_docs` | JSS's own built-in docs (the markdown files shipped with the server) |
| `read_docs` | Markdown body of a doc by filename |

Pod-resident docs (`/docs/`, `/public/apps/<name>/docs/`) are reachable via the regular CRUD tools — no separate surface.

### ACL editing (#496)

The most common owner operation is delegating an agent access to a resource. The MCP server exposes ACL editing as first-class tools so bots don't need to hand-roll JSON-LD.

| Tool | Effect | WAC check |
|---|---|---|
| `read_acl` | Return the ACL for a resource as a structured list (agents, agentClasses, modes, isDefault) | Control on resource |
| `write_acl` | Persist a structured ACL to the resource's `.acl` file | Control on resource |

```json
// write_acl arguments
{
  "path": "/private/notes/",
  "authorizations": [
    {
      "agents": ["did:nostr:abc...", "https://alice.example.com/profile#me"],
      "modes": ["Read", "Append"],
      "isDefault": true
    },
    {
      "agentClasses": ["acl:AuthenticatedAgent"],
      "modes": ["Read"]
    }
  ]
}
```

The structured form abstracts away JSON-LD shape (`acl:agent` vs `acl:agentClass`, mode URI prefixes, `acl:default` propagation). New WAC vocabulary additions extend the structure without breaking existing bots.

### Subscribe — live change notifications (#494)

`subscribe` is a streaming tool. The response switches to SSE (`text/event-stream`) and emits MCP notifications as resources change. WAC-filtered per event so subscribers only see resources they have Read access to.

| Tool | Effect |
|---|---|
| `subscribe` | Stream resource_changed events for a container subtree or specific path |

```bash
curl -N http://localhost:4443/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"subscribe","arguments":{"path":"/forum/channels/general/"}}}'
```

Events arrive as:
```
event: notification
data: {"jsonrpc":"2.0","method":"notifications/tool_event","params":{"tool":"subscribe","event":{"type":"resource_changed","path":"/forum/channels/general/abc.jsonld"}}}
```

For chat-style bots, replace polling with `subscribe` and react to events as they land.

### Federation — bot-to-bot (#495)

`call_remote_pod` lets a bot on this pod invoke MCP tools on another pod. WAC-gated on both ends; depth-capped at 3 hops.

| Tool | Effect | Gating |
|---|---|---|
| `call_remote_pod` | Forward an MCP `tools/call` to another pod | Caller needs acl:Write on `<their-pod>/private/federation/` on this pod |

```json
{
  "pod_url": "https://alice.example.com",
  "tool": "read_resource",
  "arguments": { "path": "/public/notes/shared.md" },
  "auth": { "type": "bearer", "token": "..." }
}
```

To delegate outbound federation to a specific agent, grant them `acl:Write` on your `/private/federation/` container. Owners control which agents can initiate calls; remote pods control what they expose.

Foreign WebIDs (identities hosted on other pods) cannot initiate federation from this pod — there's no local path for the gate to live at. Multi-pod federation chains compose by hopping between pods, each gated locally.

### Introspection

| Tool | Returns |
|---|---|
| `pod_info` | Origin, server, MCP protocol version, authenticated identity, capability flags |

## Wiring Claude Desktop

In your Claude Desktop MCP settings, add an HTTP MCP server pointing at:

```
http://localhost:4443/mcp
```

For authenticated access, configure the client to send `Authorization: Bearer <token>`. Tokens come from `POST /idp/credentials` (username/password) or from any compatible OIDC/DPoP flow.

## What's not included (yet)

The current cut ships CRUD, structured ACL editing, subscribe, federation, skills, docs, and introspection. Deferred:

- **`update_resource` (PATCH)** — SPARQL Update / N3 patches. Read-modify-write through the CRUD tools is the workaround.
- **Discovery layer** — no DNS SRV / Solid Type Index entry for "this pod offers MCP". Owners share URLs explicitly today.
- **Pod-resident federation credentials** — every `call_remote_pod` carries its own auth. A vault for storing remote-pod credentials is a separate security surface worth its own design pass.

These are tracked as follow-ups on issue #490.

## Why this exists

The agent ecosystem has no shared answer for sovereign, ACL-gated storage. Every agent today bolts on its own DB, vector store, or secrets vault. Solid's pitch — user-owned data, queryable, access-controlled — is exactly what agents need. MCP is the wire that connects them.

When JSS exposes `/mcp`:

- **Agent identity becomes a first-class WAC subject.** `acl:agent <did:nostr:...>` for a bot is the same operation as for a human.
- **The pod is the bot's world.** A bot reads its instructions from `SKILL.md` on the pod, discovers tools as URL-addressable resources, and (with the owner's permission) writes back. No backend, no API key store, no secrets vault — just the pod.
- **Bot-to-bot falls out of the protocol.** Two pods running JSS can have their bots call each other's MCP endpoints, gated by WAC on both ends. No new federation wire.

See [#490](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/490) for the design discussion and roadmap.
