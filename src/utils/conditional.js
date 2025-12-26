/**
 * Conditional Request Utilities
 *
 * Implements HTTP conditional request headers:
 * - If-Match: Proceed only if ETag matches (for safe updates)
 * - If-None-Match: Proceed only if ETag doesn't match (for caching/create-only)
 */

/**
 * Normalize an ETag value (remove weak prefix and quotes)
 * @param {string} etag
 * @returns {string}
 */
function normalizeEtag(etag) {
  if (!etag) return '';
  // Remove weak prefix W/
  let normalized = etag.replace(/^W\//, '');
  // Remove surrounding quotes
  normalized = normalized.replace(/^"(.*)"$/, '$1');
  return normalized;
}

/**
 * Parse an If-Match or If-None-Match header value
 * @param {string} headerValue
 * @returns {string[]} Array of ETags, or ['*'] for wildcard
 */
function parseEtagHeader(headerValue) {
  if (!headerValue) return [];
  if (headerValue.trim() === '*') return ['*'];

  // Split by comma and normalize each ETag
  return headerValue.split(',').map(etag => normalizeEtag(etag.trim()));
}

/**
 * Check If-Match header
 * Returns true if the request should proceed, false if it should be rejected (412)
 *
 * @param {string} ifMatchHeader - The If-Match header value
 * @param {string|null} currentEtag - Current ETag of the resource (null if doesn't exist)
 * @returns {{ ok: boolean, status?: number, error?: string }}
 */
export function checkIfMatch(ifMatchHeader, currentEtag) {
  if (!ifMatchHeader) {
    return { ok: true }; // No If-Match header, proceed
  }

  const etags = parseEtagHeader(ifMatchHeader);

  // If resource doesn't exist, If-Match always fails
  if (currentEtag === null) {
    return {
      ok: false,
      status: 412,
      error: 'Precondition Failed: Resource does not exist'
    };
  }

  // Wildcard matches any existing resource
  if (etags.includes('*')) {
    return { ok: true };
  }

  // Check if any ETag matches
  const normalizedCurrent = normalizeEtag(currentEtag);
  const matches = etags.some(etag => etag === normalizedCurrent);

  if (!matches) {
    return {
      ok: false,
      status: 412,
      error: 'Precondition Failed: ETag mismatch'
    };
  }

  return { ok: true };
}

/**
 * Check If-None-Match header for GET/HEAD (caching)
 * Returns true if the request should proceed, false if 304 Not Modified
 *
 * @param {string} ifNoneMatchHeader - The If-None-Match header value
 * @param {string|null} currentEtag - Current ETag of the resource
 * @returns {{ ok: boolean, notModified?: boolean }}
 */
export function checkIfNoneMatchForGet(ifNoneMatchHeader, currentEtag) {
  if (!ifNoneMatchHeader || currentEtag === null) {
    return { ok: true }; // No header or no resource, proceed
  }

  const etags = parseEtagHeader(ifNoneMatchHeader);

  // Wildcard matches any existing resource
  if (etags.includes('*')) {
    return { ok: false, notModified: true };
  }

  // Check if any ETag matches
  const normalizedCurrent = normalizeEtag(currentEtag);
  const matches = etags.some(etag => etag === normalizedCurrent);

  if (matches) {
    return { ok: false, notModified: true };
  }

  return { ok: true };
}

/**
 * Check If-None-Match header for PUT/POST (create-only semantics)
 * Returns true if the request should proceed, false if 412 Precondition Failed
 *
 * @param {string} ifNoneMatchHeader - The If-None-Match header value
 * @param {string|null} currentEtag - Current ETag of the resource (null if doesn't exist)
 * @returns {{ ok: boolean, status?: number, error?: string }}
 */
export function checkIfNoneMatchForWrite(ifNoneMatchHeader, currentEtag) {
  if (!ifNoneMatchHeader) {
    return { ok: true }; // No header, proceed
  }

  const etags = parseEtagHeader(ifNoneMatchHeader);

  // If-None-Match: * means "only if resource doesn't exist"
  if (etags.includes('*')) {
    if (currentEtag !== null) {
      return {
        ok: false,
        status: 412,
        error: 'Precondition Failed: Resource already exists'
      };
    }
    return { ok: true };
  }

  // Check if any ETag matches (if so, fail)
  if (currentEtag !== null) {
    const normalizedCurrent = normalizeEtag(currentEtag);
    const matches = etags.some(etag => etag === normalizedCurrent);

    if (matches) {
      return {
        ok: false,
        status: 412,
        error: 'Precondition Failed: ETag matches'
      };
    }
  }

  return { ok: true };
}
