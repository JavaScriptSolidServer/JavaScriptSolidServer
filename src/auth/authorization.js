import * as jose from 'jose';

// Simplified WAC implementation for MVP
// In production, this would parse .acl files and implement the full WAC spec
const aclRules = new Map();

// Verify JWT token
async function verifyToken (token) {
  try {
    const { payload } = await jose.jwtVerify(
      token,
      new TextEncoder().encode('secret-key-would-be-env-var')
    );
    return payload;
  } catch (error) {
    console.error('Token verification failed:', error.message);
    return null;
  }
}

// Extract token from request
function extractToken (request) {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.substring(7);
}

// Check if user has access to resource
async function checkAccess (webId, resourcePath, mode) {
  // For MVP, we'll use a simple rule:
  // 1. Users have full access to their own pods
  // 2. Public resources are readable by anyone

  // Check if resource is in user's pod
  const podPath = resourcePath.split('/')[1]; // e.g., /username/...
  const username = webId.split('/profile/')[1].split('#')[0];

  if (podPath === username) {
    return true; // User has full access to their own pod
  }

  // Check for public read access - for MVP, we'll assume all public reads are allowed
  if (mode === 'read') {
    return true;
  }

  return false;
}

export async function handleAuthorization (request, reply) {
  // Skip auth for public endpoints
  const publicPaths = ['/.well-known/openid-configuration', '/register', '/login'];
  if (publicPaths.includes(request.url)) {
    return true;
  }

  // Get token from headers
  const token = extractToken(request);
  if (!token) {
    reply.code(401).send({ error: 'Authentication required' });
    return false;
  }

  // Verify token
  const payload = await verifyToken(token);
  if (!payload) {
    reply.code(401).send({ error: 'Invalid token' });
    return false;
  }

  // Get WebID from token
  const webId = payload.sub;
  if (!webId) {
    reply.code(401).send({ error: 'Invalid token: missing WebID' });
    return false;
  }

  // Determine requested mode
  let mode;
  switch (request.method) {
    case 'GET':
    case 'HEAD':
      mode = 'read';
      break;
    case 'PUT':
    case 'POST':
    case 'PATCH':
    case 'DELETE':
      mode = 'write';
      break;
    default:
      mode = 'read';
  }

  // Check access
  const hasAccess = await checkAccess(webId, request.url, mode);
  if (!hasAccess) {
    reply.code(403).send({ error: 'Access denied' });
    return false;
  }

  // Set WebID in request for later use
  request.webId = webId;
  return true;
}
