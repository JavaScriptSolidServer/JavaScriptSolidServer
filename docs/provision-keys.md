# Owner-key provisioning (`--provision-keys`)

Phase 1 of [#437](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/437). Generates a Schnorr secp256k1 keypair on pod creation and writes it as a W3C [Controlled Identifiers v1.0 Multikey](https://www.w3.org/TR/cid-1.0/) document at `<pod>/private/privkey.jsonld`.

The same key is intended to serve, over time, as: a Solid signing identity, a Nostr identity (same curve), and a `did:nostr:` DID controller (Phase 2). One CLI flag → pod-resident self-sovereign identity ready for both Solid and Nostr / agentic use cases.

## Usage

### Single-user mode (CLI flag)

```bash
jss start --single-user --provision-keys
```

On first start the server creates the pod and writes the key file. Subsequent starts re-use the existing pod and don't touch the key (skip-if-exists semantics, like the rest of the seeded structure).

### Multi-user mode (HTTP body field)

```bash
curl -X POST http://localhost:4444/.pods \
  -H "Content-Type: application/json" \
  -d '{ "name": "alice", "provisionKeys": true }'
```

Response includes the public side of the key under `ownerKey`:

```json
{
  "name": "alice",
  "webId": "http://localhost:4444/alice/profile/card.jsonld#me",
  "podUri": "http://localhost:4444/alice/",
  "token": "…",
  "ownerKey": {
    "keyDocument": "http://localhost:4444/alice/private/privkey.jsonld",
    "publicKeyMultibase": "fe70102…"
  }
}
```

The secret is **never** echoed in the response — it lives only at the `keyDocument` path on disk, behind the pod's owner-only WAC.

### Environment variable

```bash
JSS_PROVISION_KEYS=true jss start --single-user
```

Same effect as the CLI flag; useful in containerised deployments.

## What gets written

`<pod>/private/privkey.jsonld`:

```json
{
  "@context": "https://www.w3.org/ns/cid/v1",
  "type": "Multikey",
  "controller": "https://your.example/profile/card.jsonld#me",
  "publicKeyMultibase": "fe7010287a1b…",
  "secretKeyMultibase": "f81260a1b2c…"
}
```

- **`@context` + `type`** — W3C CID v1.0 conformant Multikey document. CID-aware tools recognise the shape natively.
- **`controller`** — In Phase 1 this is the pod owner's WebID. Phase 2 will swap in a `did:nostr:` controller once the resolver lands; the document is self-consistent at every phase.
- **`publicKeyMultibase`** — f-form (multibase `f` + multicodec `e701` for secp256k1-pub + parity byte + 32-byte x-only pubkey, all base16-lower). Round-trips through jss's existing `decodeFFormSecp256k1` decoder.
- **`secretKeyMultibase`** — f-form (multibase `f` + multicodec `8126` for secp256k1-priv + 32-byte secret scalar). The secret IS this scalar; no parity byte.

The file mode is set to `0o600` on POSIX. WAC restricts HTTP access to the pod owner via `<pod>/private/.acl` (the standard private-folder ACL JSS writes anyway).

## Threat model and protection

The web user (pod owner) reads the key over HTTP, authenticated against their WebID. WAC checks the request and serves the file:

```bash
curl -H "Authorization: Bearer <owner-token>" \
  http://localhost:4444/alice/private/privkey.jsonld
```

That path is fully protected by ACL. **What WAC cannot protect against is filesystem access.** Anyone with read on the data directory bypasses WAC entirely:

- `root` on the host
- Container layer dumps and exfiltrated images
- Backup tapes / snapshots that copy file contents
- Other unix users on a shared box (mitigated by the `0o600` mode)

For any pod that matters, layer in **filesystem-level protection**:

| Mechanism | What it adds |
|---|---|
| Full-disk encryption (LUKS / FileVault / BitLocker) | Protects offline copies of the disk |
| Encrypted volume / per-directory encryption | Protects against host-level snapshots |
| OS keyring (gnome-keyring, macOS Keychain) | Out-of-process secret storage; bigger lift |
| Restrictive `umask` + container user namespacing | Stops other users on a shared host |
| Filesystem ACLs (`setfacl`) | Fine-grained per-user limits |

Phase 4 of [#437](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/437) will add encrypted-at-rest and hardware-wallet support. Until then, treat the file as a credential and protect it accordingly.

## Credible exit

Phase 1 ships the simplest workable model: plaintext key on disk, owner-only WAC, `0o600`. This is intentional — it lets you start now and migrate later without losing the underlying identity:

| Phase | What changes | What stays |
|---|---|---|
| 1 (now) | plaintext on disk, WAC + 0o600 | the keypair, the WebID |
| 3 | optional `--key-passphrase` wraps the secret with scrypt+aesgcm | the keypair |
| 4 | hardware wallet / KMS / encrypted at rest | the keypair |

Each upgrade is a wrapper around the same secret material. You're not picking a final answer when you turn `--provision-keys` on — you're picking a starting point that can move with your security posture. ActivityPub took the same path: instances managed keys themselves at first, then later layered hardware-backed signing on top once the ecosystem matured.

## Backup

This is not optional.

```bash
# Authenticate as owner via HTTP (preferred — works even on a remote host).
# For a single-user / root pod the key is at <pod>/private/privkey.jsonld;
# for a named pod (multi-user) it's at <pod>/<name>/private/privkey.jsonld.
curl -H "Authorization: Bearer <owner-token>" \
     http://your.example/private/privkey.jsonld \
     -o pod-key-backup.jsonld
# named-pod variant:
curl -H "Authorization: Bearer <owner-token>" \
     http://your.example/alice/private/privkey.jsonld \
     -o pod-key-backup.jsonld
chmod 600 pod-key-backup.jsonld

# Or copy from disk if you have local access (preserves perms).
# Root pod (single-user, default since #348):
cp -p <DATA_ROOT>/private/privkey.jsonld pod-key-backup.jsonld
# Named pod (multi-user, or single-user with --single-user-name=alice):
cp -p <DATA_ROOT>/alice/private/privkey.jsonld pod-key-backup.jsonld
```

Store the backup somewhere that survives the pod's host: another machine, encrypted cloud storage, a hardware token, a sealed envelope in a safe — whatever you'd use for an SSH key you actually care about. Losing this file means losing this identity permanently. There is no recovery flow in Phase 1.

## Why opt-in by default

Keys-on-disk is a real security tradeoff. Defaulting `--provision-keys` on would mean every `jss start --single-user` ships a plaintext secret to disk silently — a bad surprise for an operator who only meant to spin up a server. Opt-in keeps the choice visible. (See [#437 design resolution #6](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/437).)

## See also

- [#437](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/437) — the umbrella issue and design resolutions
- [W3C Controlled Identifiers v1.0 (REC)](https://www.w3.org/TR/cid-1.0/)
- [`src/auth/nostr-keys.js`](../src/auth/nostr-keys.js) — the existing f-form Multikey decoder this code aligns with
- [BIP-340 (Schnorr signatures over secp256k1)](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
