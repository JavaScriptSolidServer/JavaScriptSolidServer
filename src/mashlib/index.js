/**
 * Mashlib Data Browser Integration
 *
 * Generates HTML wrapper that loads SolidOS Mashlib from CDN.
 * When a browser requests an RDF resource with Accept: text/html,
 * we return this wrapper which then fetches and renders the data.
 */

const CDN_BASE = 'https://unpkg.com/mashlib';

/**
 * Generate Mashlib databrowser HTML
 * @param {string} resourceUrl - The URL of the resource being viewed
 * @param {string} version - Mashlib version (default: '2.0.0')
 * @returns {string} HTML content
 */
export function generateDatabrowserHtml(resourceUrl, version = '2.0.0') {
  const cdnUrl = `${CDN_BASE}@${version}/dist`;

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SolidOS - ${escapeHtml(resourceUrl)}</title>
  <script defer src="${cdnUrl}/mashlib.min.js"></script>
  <link href="${cdnUrl}/mash.css" rel="stylesheet">
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      // runDataBrowser uses window.location to determine what to fetch
      panes.runDataBrowser();
    });
  </script>
  <style>
    /* Loading indicator */
    body:not(.loaded) #PageBody::before {
      content: 'Loading SolidOS...';
      display: block;
      padding: 2em;
      text-align: center;
      color: #666;
    }
  </style>
</head>
<body id="PageBody">
  <header id="PageHeader"></header>
  <div class="TabulatorOutline" id="DummyUUID" role="main">
    <table id="outline"></table>
    <div id="GlobalDashboard"></div>
  </div>
  <footer id="PageFooter"></footer>
</body>
</html>`;
}

/**
 * Check if request wants HTML and mashlib should handle it
 * @param {object} request - Fastify request
 * @param {boolean} mashlibEnabled - Whether mashlib is enabled
 * @param {string} contentType - Content type of the resource
 * @returns {boolean}
 */
export function shouldServeMashlib(request, mashlibEnabled, contentType) {
  if (!mashlibEnabled) {
    return false;
  }

  const accept = request.headers.accept || '';

  // Must explicitly accept HTML
  if (!accept.includes('text/html')) {
    return false;
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
