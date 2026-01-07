/**
 * WAC (Web Access Control) Parser
 * Parses ACL files (JSON-LD or Turtle) into authorization rules
 */

import { turtleToJsonLd } from '../rdf/turtle.js';
import { safeJsonParse } from '../utils/url.js';

const ACL = 'http://www.w3.org/ns/auth/acl#';
const FOAF = 'http://xmlns.com/foaf/0.1/';

// Access modes
export const AccessMode = {
  READ: `${ACL}Read`,
  WRITE: `${ACL}Write`,
  APPEND: `${ACL}Append`,
  CONTROL: `${ACL}Control`
};

// Agent classes
export const AgentClass = {
  AGENT: `${FOAF}Agent`,           // Everyone (public)
  AUTHENTICATED: `${ACL}AuthenticatedAgent`  // Any authenticated user
};

/**
 * Parse an ACL document (JSON-LD or Turtle)
 * @param {string|object} content - ACL content (JSON-LD string/object or Turtle string)
 * @param {string} aclUrl - URL of the ACL document
 * @returns {Promise<Array<Authorization>>} List of authorization rules
 */
export async function parseAcl(content, aclUrl) {
  let doc;

  // If already an object, use it directly
  if (typeof content === 'object' && content !== null) {
    doc = content;
  } else if (typeof content === 'string') {
    // Try JSON-LD first (with size limit for DoS protection)
    try {
      doc = safeJsonParse(content);
    } catch {
      // Not JSON, try Turtle
      try {
        doc = await turtleToJsonLd(content, aclUrl);
      } catch (turtleError) {
        // Neither JSON-LD nor valid Turtle
        return [];
      }
    }
  } else {
    return [];
  }

  const authorizations = [];

  // Handle @graph array or single object
  const nodes = Array.isArray(doc) ? doc : (doc['@graph'] || [doc]);

  for (const node of nodes) {
    if (isAuthorization(node)) {
      const auth = parseAuthorization(node, aclUrl);
      if (auth) {
        authorizations.push(auth);
      }
    }
  }

  return authorizations;
}

/**
 * Check if node is an Authorization
 */
function isAuthorization(node) {
  const type = node['@type'];
  if (!type) return false;

  const types = Array.isArray(type) ? type : [type];
  return types.some(t =>
    t === 'acl:Authorization' ||
    t === `${ACL}Authorization` ||
    t === 'Authorization'
  );
}

/**
 * Get base URL from ACL URL (the container the ACL applies to)
 * e.g., https://example.com/foo/.acl -> https://example.com/foo/
 *       https://example.com/foo/bar.acl -> https://example.com/foo/
 */
function getBaseUrl(aclUrl) {
  if (!aclUrl) return null;
  // Remove .acl suffix and get the directory
  const withoutAcl = aclUrl.replace(/\.acl$/, '');
  // If it was a container ACL (ended with /.acl), withoutAcl ends with /
  // If it was a resource ACL (foo.acl), we need the parent directory
  if (withoutAcl.endsWith('/')) {
    return withoutAcl;
  }
  // Get parent directory
  const lastSlash = withoutAcl.lastIndexOf('/');
  return lastSlash > 0 ? withoutAcl.substring(0, lastSlash + 1) : withoutAcl;
}

/**
 * Resolve a URI against a base URL
 */
function resolveUri(uri, baseUrl) {
  if (!uri || !baseUrl) return uri;
  // Already absolute
  if (uri.startsWith('http://') || uri.startsWith('https://')) return uri;
  // Fragment-only (like #owner) - not a resource URL
  if (uri.startsWith('#')) return uri;
  // Resolve relative URL
  try {
    return new URL(uri, baseUrl).href;
  } catch {
    return uri;
  }
}

/**
 * Parse a single Authorization node
 */
function parseAuthorization(node, aclUrl) {
  const baseUrl = getBaseUrl(aclUrl);

  const auth = {
    id: node['@id'],
    accessTo: [],      // Resources this applies to
    default: [],       // Default for contained resources
    agents: [],        // Specific WebIDs
    agentClasses: [],  // Agent classes (public, authenticated)
    agentGroups: [],   // Groups
    modes: []          // Access modes
  };

  // Parse accessTo - resolve relative URLs
  auth.accessTo = parseUriArray(node['acl:accessTo'] || node['accessTo'])
    .map(uri => resolveUri(uri, baseUrl));

  // Parse default (for containers) - resolve relative URLs
  auth.default = parseUriArray(node['acl:default'] || node['default'])
    .map(uri => resolveUri(uri, baseUrl));

  // Parse agents (WebIDs can be relative too)
  auth.agents = parseUriArray(node['acl:agent'] || node['agent']);

  // Parse agentClass
  auth.agentClasses = parseUriArray(node['acl:agentClass'] || node['agentClass']);

  // Parse agentGroup
  auth.agentGroups = parseUriArray(node['acl:agentGroup'] || node['agentGroup']);

  // Parse modes
  auth.modes = parseUriArray(node['acl:mode'] || node['mode']).map(normalizeMode);

  return auth;
}

/**
 * Parse a value that could be a URI, @id object, or array of either
 */
function parseUriArray(value) {
  if (!value) return [];

  const values = Array.isArray(value) ? value : [value];

  return values.map(v => {
    if (typeof v === 'string') return v;
    if (v && typeof v === 'object' && v['@id']) return v['@id'];
    return null;
  }).filter(Boolean);
}

/**
 * Normalize mode URIs to full form
 */
function normalizeMode(mode) {
  const modeMap = {
    'Read': AccessMode.READ,
    'Write': AccessMode.WRITE,
    'Append': AccessMode.APPEND,
    'Control': AccessMode.CONTROL,
    'acl:Read': AccessMode.READ,
    'acl:Write': AccessMode.WRITE,
    'acl:Append': AccessMode.APPEND,
    'acl:Control': AccessMode.CONTROL
  };
  return modeMap[mode] || mode;
}

/**
 * Generate a default public read ACL
 * @param {string} resourceUrl - URL of the resource
 * @returns {object} JSON-LD ACL document
 */
export function generatePublicReadAcl(resourceUrl) {
  return {
    '@context': {
      'acl': ACL,
      'foaf': FOAF
    },
    '@graph': [
      {
        '@id': '#public',
        '@type': 'acl:Authorization',
        'acl:agentClass': { '@id': 'foaf:Agent' },
        'acl:accessTo': { '@id': resourceUrl },
        'acl:mode': [
          { '@id': 'acl:Read' }
        ]
      }
    ]
  };
}

/**
 * Generate a full owner ACL (owner has full control, public read)
 * @param {string} resourceUrl - URL of the resource
 * @param {string} ownerWebId - WebID of the owner
 * @param {boolean} isContainer - Whether this is a container
 * @returns {object} JSON-LD ACL document
 */
export function generateOwnerAcl(resourceUrl, ownerWebId, isContainer = false) {
  const graph = [
    {
      '@id': '#owner',
      '@type': 'acl:Authorization',
      'acl:agent': { '@id': ownerWebId },
      'acl:accessTo': { '@id': resourceUrl },
      'acl:mode': [
        { '@id': 'acl:Read' },
        { '@id': 'acl:Write' },
        { '@id': 'acl:Control' }
      ]
    },
    {
      '@id': '#public',
      '@type': 'acl:Authorization',
      'acl:agentClass': { '@id': 'foaf:Agent' },
      'acl:accessTo': { '@id': resourceUrl },
      'acl:mode': [
        { '@id': 'acl:Read' }
      ]
    }
  ];

  // Add default rules for containers
  // Only owner gets default - children don't inherit public read
  if (isContainer) {
    graph[0]['acl:default'] = { '@id': resourceUrl };
    // Note: intentionally not adding default to #public
    // so child resources require authentication by default
  }

  return {
    '@context': {
      'acl': ACL,
      'foaf': FOAF
    },
    '@graph': graph
  };
}

/**
 * Generate a private ACL (owner only, no public access)
 * @param {string} resourceUrl - URL of the resource
 * @param {string} ownerWebId - WebID of the owner
 * @param {boolean} isContainer - Whether this is a container
 * @returns {object} JSON-LD ACL document
 */
export function generatePrivateAcl(resourceUrl, ownerWebId, isContainer = true) {
  const auth = {
    '@id': '#owner',
    '@type': 'acl:Authorization',
    'acl:agent': { '@id': ownerWebId },
    'acl:accessTo': { '@id': resourceUrl },
    'acl:mode': [
      { '@id': 'acl:Read' },
      { '@id': 'acl:Write' },
      { '@id': 'acl:Control' }
    ]
  };

  if (isContainer) {
    auth['acl:default'] = { '@id': resourceUrl };
  }

  return {
    '@context': {
      'acl': ACL,
      'foaf': FOAF
    },
    '@graph': [auth]
  };
}

/**
 * Generate an inbox ACL (owner full control, public append)
 * @param {string} resourceUrl - URL of the inbox
 * @param {string} ownerWebId - WebID of the owner
 * @returns {object} JSON-LD ACL document
 */
export function generateInboxAcl(resourceUrl, ownerWebId) {
  return {
    '@context': {
      'acl': ACL,
      'foaf': FOAF
    },
    '@graph': [
      {
        '@id': '#owner',
        '@type': 'acl:Authorization',
        'acl:agent': { '@id': ownerWebId },
        'acl:accessTo': { '@id': resourceUrl },
        'acl:default': { '@id': resourceUrl },
        'acl:mode': [
          { '@id': 'acl:Read' },
          { '@id': 'acl:Write' },
          { '@id': 'acl:Control' }
        ]
      },
      {
        '@id': '#public',
        '@type': 'acl:Authorization',
        'acl:agentClass': { '@id': 'foaf:Agent' },
        'acl:accessTo': { '@id': resourceUrl },
        'acl:default': { '@id': resourceUrl },
        'acl:mode': [
          { '@id': 'acl:Append' }
        ]
      }
    ]
  };
}

/**
 * Generate a public folder ACL (owner full control, public read with inheritance)
 * Used for /public/ folders where content should be publicly readable
 * @param {string} resourceUrl - URL of the folder
 * @param {string} ownerWebId - WebID of the owner
 * @returns {object} JSON-LD ACL document
 */
export function generatePublicFolderAcl(resourceUrl, ownerWebId) {
  return {
    '@context': {
      'acl': ACL,
      'foaf': FOAF
    },
    '@graph': [
      {
        '@id': '#owner',
        '@type': 'acl:Authorization',
        'acl:agent': { '@id': ownerWebId },
        'acl:accessTo': { '@id': resourceUrl },
        'acl:default': { '@id': resourceUrl },
        'acl:mode': [
          { '@id': 'acl:Read' },
          { '@id': 'acl:Write' },
          { '@id': 'acl:Control' }
        ]
      },
      {
        '@id': '#public',
        '@type': 'acl:Authorization',
        'acl:agentClass': { '@id': 'foaf:Agent' },
        'acl:accessTo': { '@id': resourceUrl },
        'acl:default': { '@id': resourceUrl },
        'acl:mode': [
          { '@id': 'acl:Read' }
        ]
      }
    ]
  };
}

/**
 * Serialize ACL to JSON string
 */
export function serializeAcl(acl) {
  return JSON.stringify(acl, null, 2);
}
