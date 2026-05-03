/**
 * Generate container representation as JSON-LD
 */

const LDP = 'http://www.w3.org/ns/ldp#';

// Dotfiles allowed to appear in ldp:contains. Anything else starting with '.'
// is server-internal state (.idp, .quota.json, .server, future .git, etc.) and
// must not leak into container listings — even when its contents are otherwise
// ACL-gated, the *existence* gives attackers free path-fingerprinting (see #350).
// Mirrors the dotfile allowlist enforced at the routing layer in server.js.
const ALLOWED_DOTFILES = new Set(['.well-known', '.acl', '.meta', '.pods', '.notifications', '.account']);

function isHiddenEntry(name) {
  return name.startsWith('.') && !ALLOWED_DOTFILES.has(name);
}

/**
 * Generate JSON-LD representation of a container
 * @param {string} containerUrl - Full URL of the container
 * @param {Array<{name: string, isDirectory: boolean}>} entries - Container contents
 * @returns {object} - JSON-LD representation
 */
export function generateContainerJsonLd(containerUrl, entries) {
  // Ensure container URL ends with /
  const baseUrl = containerUrl.endsWith('/') ? containerUrl : containerUrl + '/';

  const contains = entries.filter(entry => !isHiddenEntry(entry.name)).map(entry => {
    const childUrl = baseUrl + entry.name + (entry.isDirectory ? '/' : '');
    const item = {
      '@id': childUrl,
      '@type': entry.isDirectory ? [`${LDP}Container`, `${LDP}BasicContainer`, `${LDP}Resource`] : [`${LDP}Resource`]
    };
    if (entry.size != null) item['stat:size'] = entry.size;
    if (entry.modified) item['dcterms:modified'] = entry.modified;
    return item;
  });

  return {
    '@context': {
      'ldp': LDP,
      'stat': 'http://www.w3.org/ns/posix/stat#',
      'dcterms': 'http://purl.org/dc/terms/',
      'contains': { '@id': 'ldp:contains', '@type': '@id' }
    },
    '@id': baseUrl,
    '@type': ['ldp:Container', 'ldp:BasicContainer', 'ldp:Resource'],
    'contains': contains
  };
}

/**
 * Convert JSON-LD to string
 * @param {object} jsonLd
 * @returns {string}
 */
export function serializeJsonLd(jsonLd) {
  return JSON.stringify(jsonLd, null, 2);
}
