/**
 * Generate container representation as JSON-LD
 */

const LDP = 'http://www.w3.org/ns/ldp#';

/**
 * Generate JSON-LD representation of a container
 * @param {string} containerUrl - Full URL of the container
 * @param {Array<{name: string, isDirectory: boolean}>} entries - Container contents
 * @returns {object} - JSON-LD representation
 */
export function generateContainerJsonLd(containerUrl, entries) {
  // Ensure container URL ends with /
  const baseUrl = containerUrl.endsWith('/') ? containerUrl : containerUrl + '/';

  const contains = entries.map(entry => {
    const childUrl = baseUrl + entry.name + (entry.isDirectory ? '/' : '');
    return {
      '@id': childUrl,
      '@type': entry.isDirectory ? [`${LDP}Container`, `${LDP}BasicContainer`, `${LDP}Resource`] : [`${LDP}Resource`]
    };
  });

  return {
    '@context': {
      'ldp': LDP,
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
