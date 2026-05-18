# Installing Apps

JSS ships a built-in `install` subcommand that pulls a Solid app from a git repo and pushes it into your running pod at `/public/apps/<name>/`. One command, no clone-and-push dance, no token plumbing — the hard parts (git auto-init, ACL-gated push, working-tree extraction via `updateInstead`) are handled by the same git HTTP backend JSS already uses.

## Quick start

```bash
jss start --provision-keys &       # pod running on http://localhost:4443
jss install chrome                  # installs solid-apps/chrome → /public/apps/chrome/
```

Open `http://localhost:4443/public/apps/chrome/` in a browser. That's it.

## App specs

The argument to `install` accepts five forms:

| Input | Resolves to | Pod path |
|---|---|---|
| `chrome` | `github.com/solid-apps/chrome` (default registry) | `/public/apps/chrome/` |
| `JavaScriptSolidServer/git` | `github.com/JavaScriptSolidServer/git` | `/public/apps/git/` |
| `https://github.com/foo/bar` | as-is | `/public/apps/bar/` |
| `chrome#v1` | `github.com/solid-apps/chrome` at ref `v1` | `/public/apps/chrome/` |
| `litecut/litecut.github.io=litecut` | `github.com/litecut/litecut.github.io`, renamed | `/public/apps/litecut/` |

Two optional suffixes apply to any form:

- **`#<branch-or-tag>`** — pin a ref. Uses `git clone --branch <ref>` under the hood.
- **`=<name>`** — override the pod-path name. Useful when the repo's last segment isn't what you want under `/public/apps/`.

Multiple specs in one command:

```bash
jss install chrome vellum pdf hub
```

Each is installed independently; per-app `✓` / `⊘` / `✗` status, exit non-zero if any failed.

## Authentication

The install needs write access on the target pod. Two paths:

### Bearer token (default)

```bash
jss install chrome --user me --password me
# or via env (keeps the secret out of shell history):
JSS_SINGLE_USER_PASSWORD=secret jss install chrome
```

`POST <pod>/idp/credentials` returns a token, which is sent as `Authorization: Bearer ...` on each push.

If the pod runs in `--public` mode (no IDP), no token is fetched; writes are unauthenticated.

### Nostr (NIP-98)

```bash
jss install chrome --nostr-privkey <64-hex>
# or via env:
NOSTR_PRIVKEY=<64-hex> jss install chrome
```

Each push is signed with a NIP-98 event (Schnorr signature on a `kind: 27235` Nostr event). JSS verifies the signature, derives a `did:nostr:<pubkey>` identity, and runs WAC against that.

Pairs naturally with `--provision-keys`: the privkey JSS auto-generates at `<pod>/private/privkey.jsonld` is the natural source.

```bash
jss start --provision-keys &
PRIVKEY=$(jq -r .secretKeyMultibase pod-data/private/privkey.jsonld | sed 's/^f8126//')
NOSTR_PRIVKEY=$PRIVKEY jss install chrome
```

The target ACL must grant the corresponding pubkey:

```turtle
<#owner> a acl:Authorization;
  acl:agent <did:nostr:59427bb1...>;
  acl:accessTo <./>;
  acl:default <./>;
  acl:mode acl:Read, acl:Write, acl:Control.
```

This is typically already true on a `--provision-keys` pod — JSS seeds the owner ACL to grant the provisioned key.

## Targeting a different pod

```bash
jss install chrome --pod http://192.168.1.10:5544
```

Default is `http://localhost:4443`. Auth flags apply against the chosen pod.

## Bundles

`--bundle <source>` installs a set of apps from a JSON-LD manifest. Same auth, same target, same per-app status.

```bash
jss install --bundle starter           # solid-apps/bundles/HEAD/starter.jsonld
jss install --bundle media chrome      # bundle + ad-hoc additions
jss install --bundle ./my-stack.jsonld # local file
jss install --bundle https://my.pod/bundles/dev.jsonld
```

### Source resolution

| Input | Resolves to |
|---|---|
| `--bundle starter` | `https://raw.githubusercontent.com/solid-apps/bundles/HEAD/starter.jsonld` |
| `--bundle <org>/<repo>` | `https://raw.githubusercontent.com/<org>/<repo>/HEAD/bundle.jsonld` |
| `--bundle https://...` | fetch as-is |
| `--bundle ./path.jsonld` | local filesystem (absolute paths supported) |

`/HEAD/` resolves to the repo's default branch — works for both `gh-pages`-default repos (solid-apps convention) and `main`-default repos.

### Bundle format

JSON-LD `schema:ItemList`:

```json
{
  "@context": { "schema": "https://schema.org/", "app": "urn:jss:app:" },
  "@id": "#bundle",
  "@type": "schema:ItemList",
  "schema:name": "Starter",
  "schema:description": "Minimal pleasant first-run set",
  "schema:itemListElement": [
    "chrome",
    "vellum",
    { "app:spec": "litecut/litecut.github.io=litecut", "app:label": "Litecut" }
  ]
}
```

Each item is either:

- A **bare string** — any spec `jss install` accepts
- An **object** — required `app:spec`, optional `app:label` / `app:description` for UI tooling

### Curated bundles

The [`solid-apps/bundles`](https://github.com/solid-apps/bundles) repo hosts ready-made bundles:

| Bundle | Apps |
|---|---|
| `starter` | chrome, vellum, pdf, alarm |
| `all` | chrome, vellum, win98, pdf, hub, alarm, playlist |
| `media` | playlist, pdf |
| `productivity` | vellum, hub, win98 |

```bash
jss install --bundle starter
```

### Sharing custom bundles

Bundles are JSON-LD documents — they live anywhere a JSON-LD doc can. Host yours on your pod, in a GitHub repo, or any static server:

```bash
jss install --bundle https://my.pod/bundles/dev-stack.jsonld
```

ACL-gated, version-controlled (if in git), pointable from a single URL.

## How it works

Under the hood, `jss install <name>` is:

1. **Resolve** the spec to a source URL (`github.com/solid-apps/chrome` for bare names).
2. **Authenticate.** Fetch a bearer token from `<pod>/idp/credentials`, OR build a NIP-98 signed event if `--nostr-privkey` is set. Skipped entirely if the pod is in `--public` mode.
3. **Clone** the repo to a temp directory. Full clone — no `--depth`, because shallow pushes are rejected by `git-receive-pack`.
4. **Dual push** to `<pod>/public/apps/<name>` on both `HEAD:main` and `HEAD:gh-pages`. JSS auto-inits the destination repo, and whichever ref matches the server-side HEAD triggers `receive.denyCurrentBranch updateInstead` to extract the working tree onto disk where JSS serves it as static resources. The other ref is a harmless stranded reference.
5. **Clean up** the temp directory.

Idempotent on re-run. Skip-on-existing-non-repo paths (e.g. jspod's bundled `pilot`) report a friendly `⊘ skipped` instead of an error.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `✗ <name>: invalid app name "..."` | Spec doesn't match the validation regex | Check the spec; review the [App specs](#app-specs) table |
| `✗ <name>: clone failed: Repository not found` | The repo doesn't exist at the resolved URL | Verify the source — `github.com/solid-apps/<name>` for bare names |
| `✗ <name>: push failed: shallow update not allowed` | A manual clone-and-push used `--depth=1` (the install itself never does this) | Remove `--depth` from the clone |
| `✗ <name>: push failed: HTTP 401` | Auth failed | Check `--user` / `--password`; for Nostr, check that the ACL grants the pubkey |
| `✗ <name>: push failed: HTTP 413` | Body exceeds JSS's `bodyLimit` (10 MB) | Tracked as [JSS#474](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/474). Workaround: install a smaller repo or push a no-history snapshot |
| Working tree empty (`/public/apps/<name>/index.html` returns 404) | Server-side HEAD doesn't match the pushed branch | JSS 0.0.197+ pins `-b main` on auto-init; upgrade if you see this |
| `⊘ <name>: skipped (path already in use)` | The target path has content but no `.git/` (e.g. jspod's bundled `pilot`) | Expected — JSS refuses to clobber non-repo content |

## See also

- [Git Support](./git-support.md) — the substrate that powers `install`
- [`jss install` source](../src/cli/install.js)
- [solid-apps/bundles](https://github.com/solid-apps/bundles) — curated bundle repo
- [Phased plan (JSS#464)](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/464) — design roadmap; Phases 3 (`--did`) and 5 (curated no-arg default) still ahead
