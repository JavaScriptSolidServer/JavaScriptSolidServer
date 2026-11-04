/**
 * Dotfile policy, shared by the request guard (src/server.js) and the
 * path lookup (src/utils/url.js) so the two can never disagree (#639).
 *
 * The guard used to inspect the raw request URL while the lookup
 * percent-decoded it, so `%2Egit` passed the guard and resolved to
 * `.git` on disk. Both sides now decode the same way, segment by
 * segment, and both fail closed on anything they cannot decode.
 */

// Solid-specific dotfiles that are part of the protocol surface.
export const ALLOWED_DOTFILES = ['.well-known', '.acl', '.meta', '.pods', '.notifications', '.account'];

export function isDotSegment(segment) {
  return segment.startsWith('.') && segment.length > 1;
}

/**
 * A leading dot has to be literal in the request. Decoding may never
 * introduce one: `%2Egit` is refused, and so is `%2Eacl`, because the
 * allow-list is for the literal Solid paths clients actually use.
 */
export function introducesDot(raw, decoded) {
  return isDotSegment(decoded) && !raw.startsWith('.');
}

export function isForbiddenDotSegment(raw, decoded) {
  return isDotSegment(decoded) && (!raw.startsWith('.') || !ALLOWED_DOTFILES.includes(decoded));
}

function badRequest(message) {
  const err = new Error(message);
  err.statusCode = 400;
  return err;
}

/**
 * Split a URL path (no query string) into segments and percent-decode
 * each one. Throws a 400 error on malformed percent-encoding and on an
 * encoded path separator (`%2F`), since a segment that decodes into two
 * segments cannot be checked as one.
 * @param {string} urlPath
 * @returns {Array<{ raw: string, decoded: string }>}
 */
export function decodeSegments(urlPath) {
  return urlPath.split('/').map((raw) => {
    let decoded;
    try {
      decoded = decodeURIComponent(raw);
    } catch {
      throw badRequest('Malformed percent-encoding in path');
    }
    if (decoded !== raw && (decoded.includes('/') || decoded.includes('\\'))) {
      throw badRequest('Encoded path separator in path');
    }
    return { raw, decoded };
  });
}

/**
 * The first decoded segment of the path that is a forbidden dotfile, or
 * null when the path is clean. Throws a 400 error when the path cannot
 * be decoded, so the caller fails closed.
 * @param {string} urlPath
 * @returns {string|null}
 */
export function findForbiddenDotfile(urlPath) {
  const hit = decodeSegments(urlPath).find(({ raw, decoded }) => isForbiddenDotSegment(raw, decoded));
  return hit ? hit.decoded : null;
}
