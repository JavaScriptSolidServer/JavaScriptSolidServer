/**
 * Port + URL helpers for `jss start` (#557).
 *
 * Ported from jspod's lib/start.js, where both have been proven in
 * production. Kept in a standalone module (not inline in bin/jss.js) so
 * they're unit-testable without executing the CLI.
 */

import { createServer } from 'net';

/**
 * Format a host + port into an URL a human can actually open, for the
 * startup banner. Wildcard bind addresses (0.0.0.0, ::, *) aren't
 * connectable, so show `localhost`; a bare IPv6 literal gets bracketed.
 *
 * @param {string} host - the bind host
 * @param {number} port - the bound port
 * @param {string} [protocol] - 'http' (default) or 'https'
 * @returns {string}
 */
export function formatUrl(host, port, protocol = 'http') {
  if (host === '0.0.0.0' || host === '::' || host === '*') {
    return `${protocol}://localhost:${port}`;
  }
  if (host.includes(':')) {
    // IPv6 literal — must be bracketed in a URL authority.
    return `${protocol}://[${host}]:${port}`;
  }
  return `${protocol}://${host}:${port}`;
}

/**
 * Find a free port at or above `startPort` on `host`. Mirrors Vite's
 * behaviour: probe one port at a time, up to `maxTries`, returning the
 * first bindable one — or `null` if every port in the range is taken.
 *
 * Uses a throwaway net server to test bindability without committing the
 * real server. (There is an inherent TOCTOU window between this probe
 * and the real listen; the caller falls back to its normal listen-error
 * path if the chosen port is grabbed in between.)
 *
 * @param {number} startPort
 * @param {string} host
 * @param {number} [maxTries]
 * @returns {Promise<number|null>}
 */
export async function findFreePort(startPort, host, maxTries = 10) {
  for (let p = startPort; p < startPort + maxTries; p++) {
    const free = await new Promise((resolve) => {
      const srv = createServer();
      srv.once('error', () => resolve(false));
      srv.once('listening', () => srv.close(() => resolve(true)));
      srv.listen(p, host);
    });
    if (free) return p;
  }
  return null;
}
