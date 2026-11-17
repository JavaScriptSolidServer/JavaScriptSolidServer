# Mashlib Data Browser

Enable the [SolidOS Mashlib](https://github.com/SolidOS/mashlib) data browser for RDF resources.

## Modes

**CDN Mode** (recommended for getting started):
```bash
jss start --mashlib-cdn --conneg
```
Loads mashlib from unpkg.com CDN. Zero footprint — no local files needed.

**Local Mode** (for production/offline):
```bash
jss start --mashlib --conneg
```
Serves mashlib from `src/mashlib-local/dist/`. Requires building mashlib locally:
```bash
cd src/mashlib-local
npm install && npm run build
```

**ES Module Mode** (for custom or next-gen mashlib builds):
```bash
jss start --mashlib-module https://example.com/mashlib.js
```
Loads an ES module-based data browser from any URL. Uses `<script type="module">` and `<div id="mashlib">` (self-initializing). CSS is auto-derived by replacing `.js` with `.css`. Content negotiation is auto-enabled.

## How It Works

1. Browser requests `/alice/public/data.ttl` with `Accept: text/html`
2. Server returns Mashlib HTML wrapper
3. Mashlib fetches the actual data via content negotiation
4. Mashlib renders an interactive, editable view

**Note:** Mashlib works best with `--conneg` enabled for Turtle support.

## Extra panes at start-up

```bash
jss start --mashlib-cdn --conneg --panes https://melvincarvalho.github.io/pane-loader/examples/meetings-pane.js
```

`--panes` (env `JSS_PANES`, config `panes`) takes a comma-separated list of pane module URLs. Each is an ES module whose default export is a SolidOS pane (`name`, `label`, `render`). The data browser page loads and registers them before it starts SolidOS, so they are in the registry at first render. Mashlib is not changed or rebuilt.

- A URL is an `http(s)` address or an absolute path on this server (`/public/panes/my-pane.js`); anything else is ignored.
- A pane that fails to load, or is not a pane, is skipped with a console warning, and the data browser still starts.
- Panes are fetched at the same time and registered in the order listed. The page waits at most 5 seconds for them. A pane slower than that is registered when it arrives and is offered from the next view drawn; the view already on show is not redrawn.
- It applies to `--mashlib-cdn` and to `--mashlib-module`. A module entry point starts SolidOS itself, so in that mode the panes are added once it has put the pane registry (`panes.register`) on the page, and the view on show is redrawn so that they are offered. An entry point that never provides the registry gets one console warning after 30 seconds.
- On the command line and in `JSS_PANES` the list is split on commas. A pane URL that contains a comma has to go in the config file, as an array.
- Entries that are not usable are listed at start-up, not silently ignored.
- A loaded pane is registered after the built-in ones, so it is offered alongside them and does not replace the default view.
- With no `--panes`, the page is exactly as before.

The loader is [pane-loader](https://github.com/melvincarvalho/pane-loader), shipped with JSS and served at `/.well-known/jss/pane-loader.js` when panes are configured. The shipped copy leaves out the upstream `?pane=URL` shortcut, so the only panes loaded are the ones in this list. Background: [SolidOS Panes, section 7](https://melvincarvalho.github.io/solidos-panes/#dynamic).

**Trust:** a pane runs in the page with the logged-in session and can do whatever the person can. This list is set by whoever runs the server; add only panes you would install for every user. Signing and consent are tracked in https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/651.

## Modern UI (SolidOS UI)

```bash
jss start --mashlib --solidos-ui --conneg
```

Serves a modern Nextcloud-style UI shell while reusing mashlib's data layer:
- Modern file browser with breadcrumb navigation
- Profile, Contacts, Sharing, and Settings views
- Path-based URLs (browser URL reflects current resource)
- Responsive design for mobile devices

Requires solidos-ui dist files in `src/mashlib-local/dist/solidos-ui/`. See [solidos-ui](https://github.com/solidos/solidos/tree/main/workspaces/solidos-ui) for details.

## Profile Pages

Pod profiles (`/alice/`) use HTML with embedded JSON-LD data islands and are rendered using:
- [mashlib-jss](https://github.com/JavaScriptSolidServer/mashlib-jss) — A fork of mashlib with `getPod()` fix for path-based pods
- [solidos-lite](https://github.com/SolidOS/solidos-lite) — Parses JSON-LD data islands into the RDF store

This allows profiles to work without server-side content negotiation while still providing full SolidOS editing capabilities.
