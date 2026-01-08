/**
 * Test helpers for JavaScript Solid Server
 */

import { createServer } from '../src/server.js';
import fs from 'fs-extra';
import path from 'path';

const TEST_DATA_DIR = './data';

let server = null;
let baseUrl = null;

// Store tokens for pods by name
const podTokens = new Map();

/**
 * Start a test server on a random available port
 * @param {object} options - Server options
 * @param {boolean} options.conneg - Enable content negotiation (default false)
 * @returns {Promise<{server: object, baseUrl: string}>}
 */
export async function startTestServer(options = {}) {
  // Clean up any existing test data
  await fs.emptyDir(TEST_DATA_DIR);

  server = createServer({ logger: false, ...options });
  // Use port 0 to let OS assign available port
  await server.listen({ port: 0, host: '127.0.0.1' });

  const address = server.server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;

  return { server, baseUrl };
}

/**
 * Stop the test server
 */
export async function stopTestServer() {
  if (server) {
    // Force close all connections to avoid hanging
    await server.close();
    server = null;
  }
  baseUrl = null;
  // Clean up test data
  await fs.emptyDir(TEST_DATA_DIR);
  // Clear tokens
  podTokens.clear();
}

/**
 * Get the base URL
 */
export function getBaseUrl() {
  return baseUrl;
}

/**
 * Create a pod for testing
 * @param {string} name - Pod name
 * @returns {Promise<{webId: string, podUri: string, token: string}>}
 */
export async function createTestPod(name) {
  const res = await fetch(`${baseUrl}/.pods`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name })
  });

  if (!res.ok) {
    throw new Error(`Failed to create pod: ${res.status}`);
  }

  const result = await res.json();

  // Store the token for this pod
  if (result.token) {
    podTokens.set(name, result.token);
  }

  return result;
}

/**
 * Get token for a pod
 * @param {string} name - Pod name
 * @returns {string|null}
 */
export function getPodToken(name) {
  return podTokens.get(name) || null;
}

/**
 * Make a request to the test server
 * @param {string} path - URL path
 * @param {object} options - fetch options (can include `auth: 'podname'` for authenticated requests)
 * @returns {Promise<Response>}
 */
export async function request(urlPath, options = {}) {
  const url = urlPath.startsWith('http') ? urlPath : `${baseUrl}${urlPath}`;

  // Handle authentication
  const { auth, ...fetchOptions } = options;
  if (auth) {
    const token = podTokens.get(auth);
    if (token) {
      fetchOptions.headers = {
        ...fetchOptions.headers,
        'Authorization': `Bearer ${token}`
      };
    }
  }

  return fetch(url, fetchOptions);
}

/**
 * Assert response status
 */
export function assertStatus(res, expected, message = '') {
  if (res.status !== expected) {
    throw new Error(`Expected status ${expected}, got ${res.status}. ${message}`);
  }
}

/**
 * Assert response header exists
 */
export function assertHeader(res, header, expected = undefined) {
  const value = res.headers.get(header);
  if (value === null) {
    throw new Error(`Expected header ${header} to exist`);
  }
  if (expected !== undefined && value !== expected) {
    throw new Error(`Expected header ${header} to be "${expected}", got "${value}"`);
  }
  return value;
}

/**
 * Assert response header contains value
 */
export function assertHeaderContains(res, header, substring) {
  const value = res.headers.get(header);
  if (value === null || !value.includes(substring)) {
    throw new Error(`Expected header ${header} to contain "${substring}", got "${value}"`);
  }
  return value;
}

/**
 * Parse JSON-LD from HTML (extracts from script tag)
 */
export function extractJsonLdFromHtml(html) {
  const match = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
  if (!match) {
    throw new Error('No JSON-LD found in HTML');
  }
  return JSON.parse(match[1]);
}
