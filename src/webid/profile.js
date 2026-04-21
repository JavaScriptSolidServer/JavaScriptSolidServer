/**
 * WebID Profile generation
 *
 * Creates profile documents following Solid conventions. Default profile
 * shape is now plain JSON-LD at `profile/card.jsonld` — operators who
 * want a human-readable HTML shell can serve their own `index.html` with
 * an embedded `<script type="application/ld+json">` data island.
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
    'preferencesFile': `${pod}settings/prefs.jsonld`,
    'publicTypeIndex': `${pod}settings/publicTypeIndex.jsonld`,
    'privateTypeIndex': `${pod}settings/privateTypeIndex.jsonld`
  };
}

/**
 * Generate the profile document as a plain JSON-LD object.
 *
 * Previously returned an HTML shell with an embedded data island; that
 * shell still exists for hand-curated personal sites, but server-default
 * profiles are now plain JSON-LD for predictability and easier
 * post-processing by clients.
 *
 * @param {object} options
 * @param {string} options.webId - Full WebID URI
 * @param {string} options.name - Display name
 * @param {string} options.podUri - Pod root URI
 * @param {string} options.issuer - OIDC issuer URI
 * @returns {object} JSON-LD profile document
 */
export function generateProfile({ webId, name, podUri, issuer }) {
  return generateProfileJsonLd({ webId, name, podUri, issuer });
}

/**
 * Generate preferences file as JSON-LD.
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
    '@id': `${pod}settings/prefs.jsonld`,
    'publicTypeIndex': `${pod}settings/publicTypeIndex.jsonld`,
    'privateTypeIndex': `${pod}settings/privateTypeIndex.jsonld`
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
