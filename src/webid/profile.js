/**
 * WebID Profile generation
 * Creates profile documents following Solid conventions
 * Profile is HTML with embedded JSON-LD structured data
 */

const FOAF = 'http://xmlns.com/foaf/0.1/';
const SOLID = 'http://www.w3.org/ns/solid/terms#';
const SCHEMA = 'http://schema.org/';
const LDP = 'http://www.w3.org/ns/ldp#';
const PIM = 'http://www.w3.org/ns/pim/space#';

/**
 * Generate JSON-LD data for a WebID profile
 * @param {object} options
 * @param {string} options.webId - Full WebID URI (e.g., https://example.com/alice/profile/card#me)
 * @param {string} options.name - Display name
 * @param {string} options.podUri - Pod root URI (e.g., https://example.com/alice/)
 * @param {string} options.issuer - OIDC issuer URI
 * @returns {object} JSON-LD profile data
 */
export function generateProfileJsonLd({ webId, name, podUri, issuer }) {
  const pod = podUri.endsWith('/') ? podUri : podUri + '/';
  const profileDoc = webId.split('#')[0];

  return {
    '@context': {
      'foaf': FOAF,
      'solid': SOLID,
      'schema': SCHEMA,
      'pim': PIM,
      'ldp': LDP,
      'inbox': { '@id': 'ldp:inbox', '@type': '@id' },
      'storage': { '@id': 'pim:storage', '@type': '@id' },
      'oidcIssuer': { '@id': 'solid:oidcIssuer', '@type': '@id' },
      'preferencesFile': { '@id': 'pim:preferencesFile', '@type': '@id' },
      'publicTypeIndex': { '@id': 'solid:publicTypeIndex', '@type': '@id' },
      'privateTypeIndex': { '@id': 'solid:privateTypeIndex', '@type': '@id' },
      'mainEntityOfPage': { '@id': 'schema:mainEntityOfPage', '@type': '@id' }
    },
    '@id': webId,
    '@type': ['foaf:Person', 'schema:Person'],
    'foaf:name': name,
    'mainEntityOfPage': profileDoc,
    'inbox': `${pod}inbox/`,
    'storage': pod,
    'oidcIssuer': issuer,
    'preferencesFile': `${pod}Settings/Preferences.ttl`,
    'publicTypeIndex': `${pod}Settings/publicTypeIndex.ttl`,
    'privateTypeIndex': `${pod}Settings/privateTypeIndex.ttl`
  };
}

/**
 * Generate HTML profile with embedded JSON-LD data island
 * The page uses mashlib + solidos-lite to render the profile from the data island
 * @param {object} options
 * @param {string} options.webId - Full WebID URI
 * @param {string} options.name - Display name
 * @param {string} options.podUri - Pod root URI
 * @param {string} options.issuer - OIDC issuer URI
 * @returns {string} HTML document with JSON-LD data island
 */
export function generateProfile({ webId, name, podUri, issuer }) {
  const jsonLd = generateProfileJsonLd({ webId, name, podUri, issuer });

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(name)}'s Profile</title>
  <link rel="stylesheet" href="https://javascriptsolidserver.github.io/mashlib-jss/dist/mash.css">
  <script type="application/ld+json">
${JSON.stringify(jsonLd, null, 2)}
  </script>
  <style>
    body { margin: 0; font-family: system-ui, sans-serif; }
    .loading { padding: 2rem; text-align: center; color: #666; }
  </style>
</head>
<body>
  <div class="TabulatorOutline" id="DummyUUID" role="main">
    <table id="outline"></table>
    <div id="GlobalDashboard"></div>
  </div>
  <div class="loading" id="loading">Loading profile...</div>

  <script src="https://javascriptsolidserver.github.io/mashlib-jss/dist/mashlib.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/solidos-lite/solidos-lite.js"></script>
  <script>
  document.addEventListener('DOMContentLoaded', function() {
    const loadingEl = document.getElementById('loading');

    // Initialize solidos-lite to handle data islands
    const success = SolidOSLite.init({ verbose: false });
    if (!success) {
      loadingEl.textContent = 'Failed to initialize. Please try refreshing.';
      return;
    }

    // Parse data islands into the RDF store
    SolidOSLite.parseAllIslands();

    // Mark this document as already fetched
    const pageBase = window.location.href.split('?')[0].split('#')[0];
    const fetcher = SolidLogic.store.fetcher;
    fetcher.requested[pageBase] = 'done';
    fetcher.requested[pageBase.replace(/\\/$/, '')] = 'done';

    // Navigate to #me
    const subject = $rdf.sym(pageBase + '#me');
    const outliner = panes.getOutliner(document);
    outliner.GotoSubject(subject, true, undefined, true, undefined);

    loadingEl.style.display = 'none';
  });
  </script>
</body>
</html>`;
}

/**
 * Escape HTML entities
 */
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Generate preferences file as JSON-LD
 * Uses mashlib-compatible paths (Settings/Preferences.ttl)
 * @param {object} options
 * @param {string} options.webId - Full WebID URI
 * @param {string} options.podUri - Pod root URI
 * @returns {object} JSON-LD preferences document
 */
export function generatePreferences({ webId, podUri }) {
  const pod = podUri.endsWith('/') ? podUri : podUri + '/';

  return {
    '@context': {
      'solid': SOLID,
      'pim': PIM,
      'publicTypeIndex': { '@id': 'solid:publicTypeIndex', '@type': '@id' },
      'privateTypeIndex': { '@id': 'solid:privateTypeIndex', '@type': '@id' }
    },
    '@id': `${pod}Settings/Preferences.ttl`,
    'publicTypeIndex': `${pod}Settings/publicTypeIndex.ttl`,
    'privateTypeIndex': `${pod}Settings/privateTypeIndex.ttl`
  };
}

/**
 * Generate an empty type index
 * @param {string} uri - URI of the type index
 * @returns {object} JSON-LD type index document
 */
export function generateTypeIndex(uri) {
  return {
    '@context': {
      'solid': SOLID
    },
    '@id': uri,
    '@type': 'solid:TypeIndex'
  };
}

/**
 * Serialize JSON-LD to string
 * @param {object} jsonLd
 * @returns {string}
 */
export function serialize(jsonLd) {
  return JSON.stringify(jsonLd, null, 2);
}
