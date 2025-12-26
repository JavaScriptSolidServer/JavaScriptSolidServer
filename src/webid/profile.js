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
      'preferencesFile': { '@id': 'pim:preferencesFile', '@type': '@id' }
    },
    '@graph': [
      {
        '@id': profileDoc,
        '@type': 'foaf:PersonalProfileDocument',
        'foaf:maker': { '@id': webId },
        'foaf:primaryTopic': { '@id': webId }
      },
      {
        '@id': webId,
        '@type': ['foaf:Person', 'schema:Person'],
        'foaf:name': name,
        'inbox': `${pod}inbox/`,
        'storage': pod,
        'oidcIssuer': issuer,
        'preferencesFile': `${pod}settings/prefs`
      }
    ]
  };
}

/**
 * Generate HTML profile with embedded JSON-LD
 * @param {object} options
 * @param {string} options.webId - Full WebID URI
 * @param {string} options.name - Display name
 * @param {string} options.podUri - Pod root URI
 * @param {string} options.issuer - OIDC issuer URI
 * @returns {string} HTML document with JSON-LD
 */
export function generateProfile({ webId, name, podUri, issuer }) {
  const jsonLd = generateProfileJsonLd({ webId, name, podUri, issuer });
  const pod = podUri.endsWith('/') ? podUri : podUri + '/';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(name)}'s Profile</title>
  <script type="application/ld+json">
${JSON.stringify(jsonLd, null, 2)}
  </script>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 600px; margin: 2rem auto; padding: 0 1rem; }
    h1 { color: #333; }
    .card { background: #f5f5f5; padding: 1.5rem; border-radius: 8px; }
    dt { font-weight: bold; margin-top: 1rem; }
    dd { margin-left: 0; color: #666; }
    a { color: #7c4dff; }
  </style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(name)}</h1>
    <dl>
      <dt>WebID</dt>
      <dd><a href="${escapeHtml(webId)}">${escapeHtml(webId)}</a></dd>
      <dt>Storage</dt>
      <dd><a href="${escapeHtml(pod)}">${escapeHtml(pod)}</a></dd>
      <dt>Inbox</dt>
      <dd><a href="${escapeHtml(pod)}inbox/">${escapeHtml(pod)}inbox/</a></dd>
    </dl>
  </div>
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
    '@id': `${pod}settings/prefs`,
    'publicTypeIndex': `${pod}settings/publicTypeIndex`,
    'privateTypeIndex': `${pod}settings/privateTypeIndex`
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
