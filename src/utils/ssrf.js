/**
 * SSRF Protection Utilities
 * Validates URLs before making external requests to prevent Server-Side Request Forgery
 */

import { isIP } from 'net';
import dns from 'dns/promises';

/**
 * Check if an IP address is private/internal
 * Blocks: localhost, private ranges, link-local, loopback, etc.
 * @param {string} ip - IP address to check
 * @returns {boolean} - true if private/internal
 */
export function isPrivateIP(ip) {
  // IPv4 private/reserved ranges
  const privateRanges = [
    /^127\./, // Loopback (127.0.0.0/8)
    /^10\./, // Private Class A (10.0.0.0/8)
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private Class B (172.16.0.0/12)
    /^192\.168\./, // Private Class C (192.168.0.0/16)
    /^169\.254\./, // Link-local (169.254.0.0/16) - AWS/cloud metadata!
    /^0\./, // Current network (0.0.0.0/8)
    /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./, // Shared address space (100.64.0.0/10)
    /^192\.0\.0\./, // IETF Protocol Assignments (192.0.0.0/24)
    /^192\.0\.2\./, // TEST-NET-1 (192.0.2.0/24)
    /^198\.51\.100\./, // TEST-NET-2 (198.51.100.0/24)
    /^203\.0\.113\./, // TEST-NET-3 (203.0.113.0/24)
    /^224\./, // Multicast (224.0.0.0/4)
    /^240\./, // Reserved (240.0.0.0/4)
    /^255\.255\.255\.255$/, // Broadcast
  ];

  // IPv6 private/reserved
  const ipv6Private = [
    /^::1$/, // Loopback
    /^fe80:/i, // Link-local
    /^fc00:/i, // Unique local (fc00::/7)
    /^fd00:/i, // Unique local
    /^ff00:/i, // Multicast
    /^::ffff:(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)/i, // IPv4-mapped
  ];

  // Check IPv4
  for (const range of privateRanges) {
    if (range.test(ip)) {
      return true;
    }
  }

  // Check IPv6
  for (const range of ipv6Private) {
    if (range.test(ip)) {
      return true;
    }
  }

  return false;
}

/**
 * Validate a URL for safe external fetching
 * @param {string} urlString - URL to validate
 * @param {object} options - Validation options
 * @param {boolean} options.requireHttps - Require HTTPS (default true)
 * @param {boolean} options.blockPrivateIPs - Block private IPs (default true)
 * @param {boolean} options.resolveDNS - Resolve hostname to check IP (default true)
 * @returns {Promise<{valid: boolean, error: string|null, url: URL|null}>}
 */
export async function validateExternalUrl(urlString, options = {}) {
  const {
    requireHttps = true,
    blockPrivateIPs = true,
    resolveDNS = true,
  } = options;

  let url;
  try {
    url = new URL(urlString);
  } catch {
    return { valid: false, error: 'Invalid URL format', url: null };
  }

  // Check protocol
  if (requireHttps && url.protocol !== 'https:') {
    return { valid: false, error: 'URL must use HTTPS', url: null };
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { valid: false, error: 'URL must use HTTP or HTTPS', url: null };
  }

  const hostname = url.hostname;

  // Block localhost variants
  const localhostPatterns = ['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0'];
  if (localhostPatterns.includes(hostname.toLowerCase())) {
    return { valid: false, error: 'localhost URLs are not allowed', url: null };
  }

  // If hostname is an IP, check directly
  if (isIP(hostname)) {
    if (blockPrivateIPs && isPrivateIP(hostname)) {
      return { valid: false, error: 'Private/internal IP addresses are not allowed', url: null };
    }
    return { valid: true, error: null, url };
  }

  // Resolve DNS to check for private IPs (DNS rebinding protection)
  if (resolveDNS && blockPrivateIPs) {
    try {
      const addresses = await dns.resolve4(hostname).catch(() => []);
      const addresses6 = await dns.resolve6(hostname).catch(() => []);
      const allAddresses = [...addresses, ...addresses6];

      for (const ip of allAddresses) {
        if (isPrivateIP(ip)) {
          return {
            valid: false,
            error: `Hostname ${hostname} resolves to private IP ${ip}`,
            url: null
          };
        }
      }
    } catch (err) {
      // DNS resolution failed - this could be an attacker attempting to bypass SSRF
      // protection via DNS manipulation or timing attacks.
      // Security: block the request rather than allowing it through
      console.warn(`SSRF protection: DNS resolution failed for ${hostname}: ${err.message}`);
      return {
        valid: false,
        error: `DNS resolution failed for hostname: ${hostname}`,
        url: null
      };
    }
  }

  return { valid: true, error: null, url };
}

/**
 * Wrapper for fetch that validates URL first
 * @param {string} urlString - URL to fetch
 * @param {object} fetchOptions - Options for fetch()
 * @param {object} validationOptions - Options for URL validation
 * @returns {Promise<Response>}
 * @throws {Error} If URL validation fails
 */
export async function safeFetch(urlString, fetchOptions = {}, validationOptions = {}) {
  const validation = await validateExternalUrl(urlString, validationOptions);

  if (!validation.valid) {
    throw new Error(`SSRF protection: ${validation.error}`);
  }

  return fetch(urlString, fetchOptions);
}
