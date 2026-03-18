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
