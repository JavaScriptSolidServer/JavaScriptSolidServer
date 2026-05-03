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
 * type="application/ld+json">…</script>`.
 *
 * Browsers don't execute the script (wrong MIME), but the HTML parser
 * still scans the body for an end-of-script tag. The relevant rule:
 * any `</` followed by `script` (case-insensitive) terminates the
 * element regardless of what follows — `</script>`, `</script >`,
 * `</script\n>`, `</SCRIPT>` and friends all close it. Escaping just
 * the literal `</script>` token is too narrow.
 *
 * The robust fix is to replace every literal `<` byte in the body with
 * the JSON string-escape for U+003C — the six characters
 * backslash-u-0-0-3-c (the same form the implementation emits below).
 * JSON-LD is JSON, and a JSON parser decodes that escape back to a
 * literal `<` natively, so document semantics are preserved. After
 * this transform the body literally cannot contain a `<` byte — so no
 * end-tag (or comment, CDATA, etc.) can possibly start.
 */
function escapeForScriptBlock(jsonLdString) {
  return String(jsonLdString).replace(/</g, '\\u003c');
}

/**
 * Build the data-island `<script>` block for the given JSON-LD payload.
 * Returns an empty string if the payload is missing or over the size
 * cap so callers can unconditionally interpolate `dataIsland(...)`.
 *
 * The cap applies to the *escaped* body — i.e. the bytes that will
 * actually appear in the HTTP response. `escapeForScriptBlock` can
 * expand input up to 6x (each literal `<` becomes the 6-byte JSON
 * escape sequence backslash-u-0-0-3-c), so checking the raw input
 * size alone could let an HTML response balloon past the cap.
 *
 * Two-stage check:
 *   1. Cheap raw-byte pre-check — escape can only grow the body,
 *      so a raw payload already over the cap is guaranteed to be
 *      over after escaping; drop without doing the work.
 *   2. Post-escape check — catches the rare case where input was
 *      under the cap but expanded above it (`<`-heavy bodies).
 */
function dataIsland(resourceUrl, jsonLdString) {
  if (!jsonLdString) return '';
  const raw = String(jsonLdString);
  if (Buffer.byteLength(raw, 'utf8') > DATA_ISLAND_MAX_BYTES) return '';
  const safeBody = escapeForScriptBlock(raw);
  if (Buffer.byteLength(safeBody, 'utf8') > DATA_ISLAND_MAX_BYTES) return '';
  const safeUri = escapeHtml(String(resourceUrl));
  return `<script type="application/ld+json" id="dataisland" data-uri="${safeUri}">${safeBody}</script>`;
}

/**
 * Inline round-trip optimization reader (#346).
 *
 * Exposes a generic `window.__dataIsland.get(uri)` accessor any client
 * can use, plus a compatibility patch for rdflib-based clients
 * (mashlib and friends) that intercepts `fetcher.load(uri)` and
 * resolves from the inline JSON-LD data island instead of issuing a
 * second HTTP request. Falls through cleanly to the original network
 * fetch on any miss, parse error, or absent rdflib.
 *
 * Three detection paths to cover the timing space:
 *   1. Synchronous check — if `$rdf` is already on the page when this
 *      script runs (e.g. reader injected after mashlib in some custom
 *      flow), patch immediately.
 *   2. Setter on `window.$rdf` — catches the assignment as soon as
 *      mashlib publishes its rdflib instance. Closes the race where
 *      mashlib's bundle initializes and calls `panes.runDataBrowser()`
 *      synchronously inside an `onload` handler before any setTimeout
 *      poll could fire.
 *   3. Polling fallback — bounded retry for environments where the
 *      property setter is rejected (e.g. `$rdf` already defined as a
 *      non-configurable own property).
 *
 * Net effect: when JSS serves an HTML wrapper with an embedded data
 * island, the page renders with one HTTP round-trip instead of two.
 */
export function roundTripOptimizationScript() {
  return `<script>
(function () {
  if (typeof window === 'undefined') return;

  // Initialize defensively: another script may have set a truthy
  // window.__dataIsland that lacks a .get function — or, worse,
  // assigned a primitive (string, number, etc.) where attaching
  // .get would silently fail in non-strict mode and throw in strict
  // mode. Normalize to a plain object first if the existing value
  // is not an object or function (this also handles a null value,
  // since typeof null === 'object'). Preserve well-formed existing
  // implementations so consumers can register custom .get hooks.
  var di = window.__dataIsland;
  if (di === null || di === undefined
      || (typeof di !== 'object' && typeof di !== 'function')) {
    di = window.__dataIsland = {};
  }
  if (typeof di.get !== 'function') {
    di.get = function (uri) {
      if (!uri) return null;
      try {
        // Fetch by id and compare data-uri as a string. Avoids
        // selector construction entirely so there is no CSS.escape
        // pitfall, no attribute-string-context injection surface,
        // and no false misses on URIs containing characters older
        // browsers' selector parsers handle inconsistently.
        var el = document.getElementById('dataisland');
        if (el && el.type === 'application/ld+json'
            && el.getAttribute('data-uri') === String(uri)) {
          return {
            contentType: 'application/ld+json',
            content: el.textContent
          };
        }
      } catch (e) { /* fall through to null */ }
      return null;
    };
  }

  function applyPatch(rdf) {
    if (!rdf || !rdf.fetcher || !rdf.fetcher.load) return;
    if (rdf.fetcher.__dataIslandPatched) return;
    rdf.fetcher.__dataIslandPatched = true;
    var f = rdf.fetcher;
    var orig = f.load.bind(f);
    f.load = function (uri, options) {
      var s = (uri && uri.uri) || (uri && uri.value) || String(uri);
      var d = window.__dataIsland.get(s);
      if (d) {
        return new Promise(function (resolve, reject) {
          rdf.parse(d.content, f.store, s, d.contentType, function (err) {
            if (err) {
              reject(err);
              return;
            }
            // Wrap the success path so unexpected throws (e.g.
            // f.requested missing/non-writable on some rdflib builds)
            // surface as Promise rejections rather than hanging the
            // resolution.
            try {
              if (f.requested && typeof f.requested === 'object') {
                f.requested[s] = 'done';
              }
              // Return a real Response when available so consumers
              // using "instanceof Response", ".text()", ".json()",
              // etc. work the same as on the network path. Fall
              // back to a Response-shaped plain object in environments
              // where the Response constructor isn't available.
              var resp;
              if (typeof Response === 'function') {
                resp = new Response(d.content, {
                  status: 200,
                  statusText: 'OK',
                  headers: { 'content-type': d.contentType }
                });
                // Response.url is read-only and empty when
                // constructed; consumers reading it expect the
                // resource URL. defineProperty is supported on
                // Response in all browsers we target.
                try {
                  Object.defineProperty(resp, 'url',
                    { value: s, configurable: true });
                } catch (urlErr) { /* leave url empty */ }
              } else {
                resp = {
                  ok: true,
                  status: 200,
                  statusText: 'OK',
                  url: s,
                  headers: {
                    // Match real Response.headers.get() behavior on
                    // the inline-data path: case-insensitive lookup,
                    // returns the data island's content-type for
                    // 'content-type', null for unknown headers.
                    get: function (name) {
                      if (typeof name !== 'string') return null;
                      if (name.toLowerCase() === 'content-type') {
                        return d.contentType;
                      }
                      return null;
                    }
                  }
                };
              }
              resolve(resp);
            } catch (callbackErr) {
              reject(callbackErr);
            }
          });
        }).catch(function () { return orig(uri, options); });
      }
      return orig(uri, options);
    };
  }

  // Path 1: synchronous check
  if (typeof $rdf !== 'undefined') applyPatch($rdf);

  // Path 2: setter for $rdf — catches synchronous mashlib initialization
  try {
    var captured = (typeof $rdf !== 'undefined') ? $rdf : undefined;
    Object.defineProperty(window, '$rdf', {
      configurable: true,
      get: function () { return captured; },
      set: function (v) { captured = v; applyPatch(v); }
    });
  } catch (e) {
    /* property non-configurable or otherwise un-redefinable;
       the polling fallback below covers this case */
  }

  // Path 3: polling fallback
  var n = 0;
  (function poll() {
    if (++n > 100) return;
    if (typeof $rdf !== 'undefined' && $rdf && $rdf.fetcher
        && $rdf.fetcher.__dataIslandPatched) return;
    if (typeof $rdf !== 'undefined') applyPatch($rdf);
    setTimeout(poll, 100);
  })();
})();
</script>`;
}

/**
 * Generate Mashlib databrowser HTML
 *
 * @param {string} resourceUrl - The URL of the resource being viewed
 * @param {string} cdnVersion - If provided, load mashlib from unpkg CDN (e.g., "2.0.0")
 * @param {object} [opts]
 * @param {string|Buffer} [opts.embedJsonLd] - JSON-LD body to inline
 *   as a `<script type="application/ld+json">` data island. Accepts a
 *   UTF-8 string or a Buffer (coerced via `String()`). Honors a 256 KB
 *   size cap; oversize payloads are silently dropped. Phase 1 of #7.
 * @param {boolean} [opts.roundTripOptimization=true] - Inline a small
 *   reader script that lets rdflib-based clients (mashlib and friends)
 *   resolve `fetcher.load(uri)` from the data island instead of issuing
 *   a second HTTP request. Falls through to network fetch on any miss
 *   or parse error. #346.
 * @returns {string} HTML content
 */
export function generateDatabrowserHtml(resourceUrl, cdnVersion = null, opts = {}) {
  const island = dataIsland(resourceUrl, opts.embedJsonLd);
  const reader = opts.roundTripOptimization === false ? '' : roundTripOptimizationScript();
  if (cdnVersion) {
    // CDN mode: load the matching mashlib databrowser shell template from CDN,
    // then load CSS/JS from the same version while staying on this origin.
    const cdnBase = `https://unpkg.com/mashlib@${cdnVersion}/dist`;
  return `<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>SolidOS Web App</title>${island}${reader}</head>
<body id="PageBody"><p>Loading Mashlib…</p>
<script>
(function() {
  var cdnBase = '${cdnBase}';

  (function cleanupRefreshParam() {
    try {
      var current = new URL(window.location.href);
      if (current.searchParams.has('_jssr')) {
        current.searchParams.delete('_jssr');
        var next = current.pathname + (current.search ? current.search : '') + (current.hash ? current.hash : '');
        window.history.replaceState(window.history.state, '', next);
      }
      sessionStorage.removeItem('jssAuthRefreshPending');
    } catch {}
  })();

  // bfcache: mobile Chrome restores frozen page state instead of re-running
  // scripts — panes.runDataBrowser() never fires. Force a reload on restore.
  window.addEventListener('pageshow', function(event) {
    if (event.persisted) { window.location.reload(); }
  });

  function showError(message) {
    document.body.innerHTML = '<p>' + message + '</p>';
  }

  function ensureStylesheet(href) {
    var existing = document.querySelector('link[rel="stylesheet"][href="' + href + '"]');
    if (existing) return;
    var link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = href;
    document.head.appendChild(link);
  }

  function loadScript(src, onload, onerror) {
    var script = document.createElement('script');
    script.src = src;
    script.onload = onload;
    script.onerror = onerror;
    document.head.appendChild(script);
  }

  function installAuthReloadFallback() {
    if (window.__jssAuthReloadInstalled) return;

    var installed = false;
    function hardRefresh() {
      try {
        if (sessionStorage.getItem('jssAuthRefreshPending') === '1') return;
        sessionStorage.setItem('jssAuthRefreshPending', '1');
      } catch {}
      var url = new URL(window.location.href);
      url.searchParams.set('_jssr', String(Date.now()));
      // Use navigation (not reload) to avoid serving a stale cached shell.
      window.location.replace(url.toString());
    }

    document.addEventListener('account-menu-select', function(e) {
      try {
        var detail = e && e.detail;
        if (detail && detail.action === 'logout') {
          setTimeout(hardRefresh, 30);
        }
      } catch {}
    }, true);

    var attach = function() {
      var authSession = window.SolidLogic && window.SolidLogic.authSession;
      if (!authSession || !authSession.events || installed) return;

      installed = true;
      window.__jssAuthReloadInstalled = true;

      var safeReload = function() {
        // Keep this as a server-side safety net until client lifecycle
        // handles logout rerender consistently.
        hardRefresh();
      };

      authSession.events.on('logout', safeReload);
    };

    var attempts = 0;
    var timer = setInterval(function() {
      attempts += 1;
      attach();
      if (window.__jssAuthReloadInstalled || attempts > 30) {
        clearInterval(timer);
      }
    }, 200);
  }

  function applyShellFromTemplate(htmlText) {
    var parsed = new DOMParser().parseFromString(htmlText, 'text/html');

    if (parsed.title) {
      document.title = parsed.title;
    }

    if (parsed.body) {
      var attrs = Array.from(parsed.body.attributes || []);
      document.body.innerHTML = parsed.body.innerHTML;
      for (var i = 0; i < attrs.length; i++) {
        document.body.setAttribute(attrs[i].name, attrs[i].value);
      }
    }
  }

  function fetchFirst(urls) {
    var i = 0;
    function next() {
      if (i >= urls.length) {
        return Promise.reject(new Error('No shell template found on CDN'));
      }
      var url = urls[i++];
      return fetch(url, { cache: 'no-store' }).then(function(res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.text();
      }).catch(function() {
        return next();
      });
    }
    return next();
  }

  var shellCandidates = [
    cdnBase + '/databrowser.html'
  ];

  fetchFirst(shellCandidates)
    .then(function(shellHtml) {
      applyShellFromTemplate(shellHtml);
      ensureStylesheet(cdnBase + '/mash.css');
      loadScript(
        cdnBase + '/mashlib.min.js',
        function() {
          installAuthReloadFallback();
          if (window.panes && typeof window.panes.runDataBrowser === 'function') {
            window.panes.runDataBrowser();
          } else {
            showError('Mashlib loaded but panes.runDataBrowser is unavailable');
          }
        },
        function() { showError('Failed to load Mashlib from CDN'); }
      );
    })
    .catch(function() {
      showError('Failed to load Mashlib shell from CDN');
    });
})();
</script></body></html>`;
  }

  // Local mode - use defer (reliable when served locally)
  return `<!doctype html><html><head><meta charset="utf-8"/><title>SolidOS Web App</title><script>
      (function() {
        (function cleanupRefreshParam() {
          try {
            var current = new URL(window.location.href);
            if (current.searchParams.has('_jssr')) {
              current.searchParams.delete('_jssr');
              var next = current.pathname + (current.search ? current.search : '') + (current.hash ? current.hash : '');
              window.history.replaceState(window.history.state, '', next);
            }
            sessionStorage.removeItem('jssAuthRefreshPending');
          } catch {}
        })();

        // bfcache: mobile Chrome restores frozen page state instead of re-running
        // scripts — panes.runDataBrowser() never fires. Force a reload on restore.
        window.addEventListener('pageshow', function(event) {
          if (event.persisted) { window.location.reload(); }
        });

        function installAuthReloadFallback() {
          if (window.__jssAuthReloadInstalled) return;

          var installed = false;
          function hardRefresh() {
            try {
              if (sessionStorage.getItem('jssAuthRefreshPending') === '1') return;
              sessionStorage.setItem('jssAuthRefreshPending', '1');
            } catch {}
            var url = new URL(window.location.href);
            url.searchParams.set('_jssr', String(Date.now()));
            // Use navigation (not reload) to avoid serving a stale cached shell.
            window.location.replace(url.toString());
          }

          document.addEventListener('account-menu-select', function(e) {
            try {
              var detail = e && e.detail;
              if (detail && detail.action === 'logout') {
                setTimeout(hardRefresh, 30);
              }
            } catch {}
          }, true);

          var attach = function() {
            var authSession = window.SolidLogic && window.SolidLogic.authSession;
            if (!authSession || !authSession.events || installed) return;

            installed = true;
            window.__jssAuthReloadInstalled = true;

            var safeReload = function() {
              // Keep this as a server-side safety net until client lifecycle
              // handles logout rerender consistently.
              hardRefresh();
            };

            authSession.events.on('logout', safeReload);
          };

          var attempts = 0;
          var timer = setInterval(function() {
            attempts += 1;
            attach();
            if (window.__jssAuthReloadInstalled || attempts > 30) {
              clearInterval(timer);
            }
          }, 200);
        }

        document.addEventListener('DOMContentLoaded', function() {
          panes.runDataBrowser();
          installAuthReloadFallback();
        });
      })();
      </script><script defer="defer" src="/mashlib.min.js"></script><link href="/mash.css" rel="stylesheet"></head><body id="PageBody">${island}${reader}<header id="PageHeader"></header><div class="TabulatorOutline" id="DummyUUID" role="main"><table id="outline"></table><div id="GlobalDashboard"></div></div><footer id="PageFooter"></footer></body></html>`;
}

/**
 * Generate ES module-based databrowser HTML
 *
 * @param {string} moduleUrl - URL to the ES module entry point
 * @param {string} resourceUrl - The URL of the resource being viewed
 * @param {object} [opts]
 * @param {string|Buffer} [opts.embedJsonLd] - JSON-LD body for the
 *   data island, same contract as `generateDatabrowserHtml`. Phase 1 of #7.
 * @param {boolean} [opts.roundTripOptimization=true] - Inline reader
 *   script (#346); see `generateDatabrowserHtml` for details.
 * @returns {string} HTML content
 */
export function generateModuleDatabrowserHtml(moduleUrl, resourceUrl = '', opts = {}) {
  const cssUrl = moduleUrl.replace(/\.js$/, '.css');
  const island = dataIsland(resourceUrl, opts.embedJsonLd);
  const reader = opts.roundTripOptimization === false ? '' : roundTripOptimizationScript();
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Solid Data Browser</title>
<link rel="stylesheet" href="${cssUrl}"></head>
<body>${island}${reader}<div id="mashlib"></div>
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
