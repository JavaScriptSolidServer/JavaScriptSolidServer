/**
 * Mashlib Data Browser Integration
 *
 * Generates HTML wrapper that loads SolidOS Mashlib from CDN.
 * When a browser requests an RDF resource with Accept: text/html,
 * we return this wrapper which then fetches and renders the data.
 */

/**
 * Generate Mashlib databrowser HTML
 *
 * @param {string} resourceUrl - The URL of the resource being viewed (unused, kept for API compatibility)
 * @param {string} cdnVersion - If provided, load mashlib from unpkg CDN (e.g., "2.0.0")
 * @returns {string} HTML content
 */
export function generateDatabrowserHtml(resourceUrl, cdnVersion = null) {
  if (cdnVersion) {
    // CDN mode - use script.onload to ensure mashlib is fully loaded before init
    // This avoids race conditions with defer + DOMContentLoaded
    const cdnBase = `https://unpkg.com/mashlib@${cdnVersion}/dist`;
    return `<!doctype html><html><head><meta charset="utf-8"/><title>SolidOS Web App</title>
<link href="${cdnBase}/mash.css" rel="stylesheet"></head>
<body id="PageBody"><header id="PageHeader"></header>
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
      })</script><script defer="defer" src="/mashlib.min.js"></script><link href="/mash.css" rel="stylesheet"></head><body id="PageBody"><header id="PageHeader"></header><div class="TabulatorOutline" id="DummyUUID" role="main"><table id="outline"></table><div id="GlobalDashboard"></div></div><footer id="PageFooter"></footer></body></html>`;
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
    'application/rdf+xml'
  ];

  const baseType = contentType.split(';')[0].trim().toLowerCase();
  return rdfTypes.includes(baseType);
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
