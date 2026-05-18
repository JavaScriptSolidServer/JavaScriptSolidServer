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

The first cut ships CRUD, ACL-as-resource (you can read/write `.acl` files via the regular tools), skills, docs, and introspection. Deferred:

- **`update_resource` (PATCH)** — SPARQL Update / N3 patches. Read-modify-write through the CRUD tools is the workaround.
- **`subscribe`** — wrap JSS's WebSocket notifications as MCP events over SSE. Today, agents can `read_resource` + poll.
- **`call_remote_pod`** — federation primitive for bot-to-bot. Today, an agent can talk to two pods by registering both as MCP servers in its client.

These are tracked as follow-ups on issue #490.

## Why this exists

The agent ecosystem has no shared answer for sovereign, ACL-gated storage. Every agent today bolts on its own DB, vector store, or secrets vault. Solid's pitch — user-owned data, queryable, access-controlled — is exactly what agents need. MCP is the wire that connects them.

When JSS exposes `/mcp`:

- **Agent identity becomes a first-class WAC subject.** `acl:agent <did:nostr:...>` for a bot is the same operation as for a human.
- **The pod is the bot's world.** A bot reads its instructions from `SKILL.md` on the pod, discovers tools as URL-addressable resources, and (with the owner's permission) writes back. No backend, no API key store, no secrets vault — just the pod.
- **Bot-to-bot falls out of the protocol.** Two pods running JSS can have their bots call each other's MCP endpoints, gated by WAC on both ends. No new federation wire.

See [#490](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/490) for the design discussion and roadmap.
