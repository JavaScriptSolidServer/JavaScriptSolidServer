/**
 * Generate container representation as JSON-LD
 */

const LDP = 'http://www.w3.org/ns/ldp#';

// Dotfiles allowed to appear in ldp:contains. Anything else starting with '.'
// is server-internal state and must not leak into container listings — even
// when direct GETs are 403'd by the routing-layer dotfile guard in server.js
// (which rejects non-allowlisted dotpaths before WAC even runs), listing the
// *name* still leaks existence and gives attackers free path-fingerprinting
// (#350).
//
// `.well-known` is allowed because JSS exposes legitimate public resources
// there (e.g. the webledger registry at /.well-known/webledgers/...). At the
// origin root — including each pod's own origin in subdomain mode — server.js
// bypasses auth for `/.well-known/*` per RFC 8615. For path-based pods at
// `/pod/.well-known/`, the bypass does *not* apply (it matches root-relative
// paths only) — that case is a regular subdirectory governed by ordinary WAC,
// and listing the name is fine. We allow `.well-known` uniformly here so the
// subdomain-pod and root-pod cases work without conditional logic on the
// container path.
//
// Internal state that JSS currently persists under `.well-known/` (token
// store, pay state) shouldn't be in a public namespace at all; tracked at
// #358.
//
// `.acl` and `.meta` are canonical Solid per-resource sidecars.
const ALLOWED_DOTFILES = new Set(['.acl', '.meta', '.well-known']);

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
