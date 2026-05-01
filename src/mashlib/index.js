/**
 * Mashlib Data Browser Integration
 *
 * Generates HTML wrapper that loads SolidOS Mashlib from CDN.
 * When a browser requests an RDF resource with Accept: text/html,
 * we return this wrapper which then fetches and renders the data.
 *
 * Phase 1 of #7: when the originating resource is reasonably small
 * RDF, the JSON-LD bytes are embedded in the wrapper as a `<script
 * type="application/ld+json" id="dataisland" data-uri="…">` block.
 * Browsers ignore non-JS script bodies, so this is harmless to all
 * existing clients (mashlib still XHR-fetches today). It immediately
 * benefits anything that knows to look for `application/ld+json`
 * islands — search engine rich-results, archival crawlers, scrapers,
 * static-site exporters — and gives Phase 2 a zero-network fast path.
 */

/**
 * Cap on how much JSON-LD we'll inline. A 256 KB resource fits any
 * realistic profile, type index, or container listing. Above that we
 * drop the island and let the existing XHR path handle it so we don't
 * make every navigation re-download a multi-megabyte resource.
 */
export const DATA_ISLAND_MAX_BYTES = 256 * 1024;

/**
 * Escape a JSON-LD body for safe inclusion inside `<script
 * type="application/ld+json">…</script>`. Browsers don't execute the
 * script (wrong MIME), but a literal `</script>` substring inside the
 * body would prematurely close the tag and let arbitrary subsequent
 * bytes be parsed as inline HTML. Replacing `<` with `<` (only
 * inside the script body) defeats that without changing the JSON-LD
 * semantics — `<` is just a unicode escape for `<`.
 */
function escapeForScriptBlock(jsonLdString) {
  // Targeted: only sequences that could close or open a tag inside
  // the script body.
  return jsonLdString
    .replace(/<\/script>/gi, '<\\/script>')
    .replace(/<!--/g, '\\u003c!--');
}

/**
 * Build the data-island `<script>` block for the given JSON-LD payload.
 * Returns an empty string if the payload is missing or over the size
 * cap so callers can unconditionally interpolate `dataIsland(...)`.
 */
function dataIsland(resourceUrl, jsonLdString) {
  if (!jsonLdString) return '';
  if (Buffer.byteLength(jsonLdString, 'utf8') > DATA_ISLAND_MAX_BYTES) return '';
  const safeUri = String(resourceUrl)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  const safeBody = escapeForScriptBlock(jsonLdString);
  return `<script type="application/ld+json" id="dataisland" data-uri="${safeUri}">${safeBody}</script>`;
}

/**
 * Generate Mashlib databrowser HTML
 *
 * @param {string} resourceUrl - The URL of the resource being viewed
 * @param {string} cdnVersion - If provided, load mashlib from unpkg CDN (e.g., "2.0.0")
 * @param {object} [opts]
 * @param {string} [opts.embedJsonLd] - JSON-LD bytes to inline as a
 *   `<script type="application/ld+json">` data island. Honors a 256 KB
 *   size cap; oversize payloads are silently dropped. Phase 1 of #7.
 * @returns {string} HTML content
 */
export function generateDatabrowserHtml(resourceUrl, cdnVersion = null, opts = {}) {
  const island = dataIsland(resourceUrl, opts.embedJsonLd);
  if (cdnVersion) {
    // CDN mode - use script.onload to ensure mashlib is fully loaded before init
    // This avoids race conditions with defer + DOMContentLoaded
    const cdnBase = `https://unpkg.com/mashlib@${cdnVersion}/dist`;
    return `<!doctype html><html><head><meta charset="utf-8"/><title>SolidOS Web App</title>
<link href="${cdnBase}/mash.css" rel="stylesheet"></head>
<body id="PageBody">${island}<header id="PageHeader"></header>
<div class="TabulatorOutline" id="DummyUUID" role="main"><table id="outline"></table><div id="GlobalDashboard"></div></div>
<footer id="PageFooter"></footer>
<script>
(function() {
  var s = document.createElement('script');
  s.src = '${cdnBase}/mashlib.min.js';
  s.onload = function() { panes.runDataBrowser(); };
  s.onerror = function() { document.body.innerHTML = '<p>Failed to load Mashlib from CDN</p>'; };
  document.head.appendChild(s);
})();
</script></body></html>`;
  }

  // Local mode - use defer (reliable when served locally)
  return `<!doctype html><html><head><meta charset="utf-8"/><title>SolidOS Web App</title><script>document.addEventListener('DOMContentLoaded', function() {
        panes.runDataBrowser()
      })</script><script defer="defer" src="/mashlib.min.js"></script><link href="/mash.css" rel="stylesheet"></head><body id="PageBody">${island}<header id="PageHeader"></header><div class="TabulatorOutline" id="DummyUUID" role="main"><table id="outline"></table><div id="GlobalDashboard"></div></div><footer id="PageFooter"></footer></body></html>`;
}

/**
 * Generate ES module-based databrowser HTML
 *
 * @param {string} moduleUrl - URL to the ES module entry point
 * @returns {string} HTML content
 */
export function generateModuleDatabrowserHtml(moduleUrl) {
  const cssUrl = moduleUrl.replace(/\.js$/, '.css');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Solid Data Browser</title>
<link rel="stylesheet" href="${cssUrl}"></head>
<body><div id="mashlib"></div>
<script type="module" src="${moduleUrl}"></script>
</body></html>`;
}

/**
 * Check if request wants HTML and mashlib should handle it
 * @param {object} request - Fastify request
 * @param {boolean} mashlibEnabled - Whether mashlib is enabled
 * @param {string} contentType - Content type of the resource
 * @returns {boolean}
 */
export function shouldServeMashlib(request, mashlibEnabled, contentType) {
  const accept = request.headers.accept || '';
  const secFetchDest = request.headers['sec-fetch-dest'] || '';

  if (!mashlibEnabled) {
    return false;
  }

  // Only serve mashlib for top-level document navigation
  // sec-fetch-dest: 'document' = browser navigation (serve mashlib)
  // sec-fetch-dest: 'empty' = JavaScript fetch/XHR (serve RDF data)
  if (secFetchDest && secFetchDest !== 'document') {
    return false;
  }

  // Must explicitly accept HTML as a primary type (not via */*)
  // Browser navigation: "text/html,application/xhtml+xml,..."
  // Mashlib fetch: "application/rdf+xml;q=0.9, */*;q=0.1,..."
  if (!accept.includes('text/html')) {
    return false;
  }

  // Don't serve mashlib if RDF types appear BEFORE text/html in Accept header
  // This handles cases like "application/rdf+xml, text/html" where RDF is preferred
  const htmlPos = accept.indexOf('text/html');
  const acceptRdfTypes = ['application/rdf+xml', 'text/turtle', 'application/ld+json', 'text/n3', 'application/n-triples'];
  for (const rdfType of acceptRdfTypes) {
    const rdfPos = accept.indexOf(rdfType);
    if (rdfPos !== -1 && rdfPos < htmlPos) {
      return false; // RDF type is preferred over HTML
    }
  }

  // Only serve mashlib for RDF content types
  const rdfTypes = [
    'text/turtle',
    'application/ld+json',
    'application/json',
    'text/n3',
    'application/n-triples',
    'application/rdf+xml',
    'text/markdown',
    'audio/mpegurl',
    'application/vnd.apple.mpegurl',
    'audio/x-scpls'
  ];

  const baseType = contentType.split(';')[0].trim().toLowerCase();
  return rdfTypes.includes(baseType);
}

/**
 * Generate SolidOS UI HTML (modern Nextcloud-style interface)
 * Uses mashlib for data layer but solidos-ui for the UI shell
 *
 * @returns {string} HTML content
 */
export function generateSolidosUiHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SolidOS - Modern UI</title>
  <!-- SolidOS UI Styles -->
  <link rel="stylesheet" href="/solidos-ui/styles/variables.css">
  <link rel="stylesheet" href="/solidos-ui/styles/shell.css">
  <link rel="stylesheet" href="/solidos-ui/styles/components.css">
  <link rel="stylesheet" href="/solidos-ui/styles/responsive.css">
  <!-- View-specific styles -->
  <link rel="stylesheet" href="/solidos-ui/views/profile/profile.css">
  <link rel="stylesheet" href="/solidos-ui/views/contacts/contacts.css">
  <link rel="stylesheet" href="/solidos-ui/views/sharing/sharing.css">
  <link rel="stylesheet" href="/solidos-ui/views/settings/settings.css">
  <!-- Bundled styles (contains all component styles) -->
  <link rel="stylesheet" href="/solidos-ui/style.css">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { height: 100%; }
    #app { height: 100%; }
  </style>
</head>
<body>
  <div id="app"></div>

  <script>
    // Load mashlib first, then solidos-ui
    (function() {
      var mashScript = document.createElement('script');
      mashScript.src = '/mashlib.min.js';
      mashScript.onload = function() {
        // Now load solidos-ui
        import('/solidos-ui/solidos-ui.js').then(function(module) {
          var initSolidOSSkin = module.initSolidOSSkin;
          var SolidLogic = window.SolidLogic;
          var panes = window.panes;
          var store = SolidLogic.store;

          initSolidOSSkin('#app', {
            store: store,
            fetcher: store.fetcher,
            paneRegistry: panes,
            authn: SolidLogic.authn,
            logic: SolidLogic.solidLogicSingleton,
          }, {
            onNavigate: function(uri) {
              if (uri) {
                // Use path-based navigation - update URL to match resource
                try {
                  var url = new URL(uri);
                  // Always use the path from the URI, regardless of origin
                  // (URIs may use internal hostname like jss:4000 vs localhost:4000)
                  var newPath = url.pathname;
                  if (newPath !== window.location.pathname) {
                    window.history.pushState({ uri: uri }, '', newPath);
                  }
                } catch (e) {
                  console.warn('Invalid URI for navigation:', uri);
                }
              }
            },
            onLogout: function() {
              window.location.reload();
            },
          }).then(function(skin) {
            // Handle browser back/forward
            window.addEventListener('popstate', function(event) {
              // Use the current URL as the resource (not hash-based)
              var resourceUrl = window.location.origin + window.location.pathname;
              skin.goto(resourceUrl);
            });

            // Navigate to the current URL's resource
            // The URL path IS the resource in JSS (not hash-based routing)
            var currentPath = window.location.pathname;
            if (currentPath && currentPath !== '/') {
              var resourceUrl = window.location.origin + currentPath;
              skin.goto(resourceUrl);
            }

            // Expose for debugging
            window.solidosSkin = skin;
          });
        }).catch(function(err) {
          console.error('Failed to load solidos-ui:', err);
          document.body.innerHTML = '<p>Failed to load SolidOS UI</p>';
        });
      };
      mashScript.onerror = function() {
        document.body.innerHTML = '<p>Failed to load Mashlib</p>';
      };
      document.head.appendChild(mashScript);
    })();
  </script>
</body>
</html>`;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
