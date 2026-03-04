/**
 * MongoDB Database Route Plugin for JSS
 *
 * Adds /db/* routes backed by MongoDB.
 * Documents are stored as JSON-LD and keyed by URI.
 */

import { connect, disconnect, findOne, upsertOne, deleteOne, listByPrefix } from './store.js';
import { getAllHeaders, getNotFoundHeaders } from '../ldp/headers.js';
import { generateContainerJsonLd, serializeJsonLd } from '../ldp/container.js';
import { checkIfMatch, checkIfNoneMatchForGet, checkIfNoneMatchForWrite } from '../utils/conditional.js';
import { emitChange } from '../notifications/events.js';
import { getWebIdFromRequestAsync } from '../auth/token.js';

/**
 * Database route Fastify plugin
 * @param {FastifyInstance} fastify
 * @param {object} options
 */
export async function dbPlugin(fastify, options) {
  await connect({
    url: options.mongoUrl,
    database: options.mongoDatabase || 'solid'
  });

  fastify.addHook('onClose', async () => {
    await disconnect();
  });

  // Auth hook for /db/* routes
  // WAC doesn't apply here — uses WebID-based ownership
  fastify.addHook('preHandler', async (request, reply) => {
    if (request.method === 'OPTIONS') return;

    // Public mode — skip auth
    if (request.config?.public) {
      request.webId = null;
      return;
    }

    const { webId } = await getWebIdFromRequestAsync(request);
    request.webId = webId;

    // Read is public
    if (request.method === 'GET' || request.method === 'HEAD') return;

    // Write requires authentication
    if (!webId) {
      return reply.code(401).send({ error: 'Unauthorized', message: 'Authentication required' });
    }

    // Single-user mode: any authenticated user is the owner
    if (options.singleUser) return;

    // Ownership check: only pod owner can write to /db/{podName}/...
    const urlPath = request.url.split('?')[0];
    const relative = urlPath.replace(/^\/db\//, '');
    const podName = relative.split('/')[0];
    if (podName) {
      // Build expected WebID for both path and subdomain modes
      const expectedWebId = request.subdomainsEnabled && request.baseDomain
        ? `${request.protocol}://${podName}.${request.baseDomain}/profile/card#me`
        : `${request.protocol}://${request.hostname}/${podName}/profile/card#me`;
      if (webId !== expectedWebId) {
        return reply.code(403).send({ error: 'Forbidden', message: 'You can only write to your own /db/ space' });
      }
    }
  });

  // Routes
  fastify.get('/db', handleDbGet);
  fastify.get('/db/*', handleDbGet);
  fastify.head('/db', handleDbHead);
  fastify.head('/db/*', handleDbHead);
  fastify.put('/db/*', handleDbPut);
  fastify.delete('/db/*', handleDbDelete);
  fastify.options('/db', handleDbOptions);
  fastify.options('/db/*', handleDbOptions);
}

/**
 * Build the full resource URL for a /db/ request
 */
function getResourceUrl(request) {
  const urlPath = request.url.split('?')[0];
  return `${request.protocol}://${request.hostname}${urlPath}`;
}

/**
 * GET /db/* — read resource or container listing
 */
async function handleDbGet(request, reply) {
  const urlPath = request.url.split('?')[0];
  const resourceUrl = getResourceUrl(request);
  const origin = request.headers.origin;
  const connegEnabled = request.connegEnabled || false;

  // Container request (treat /db as root container)
  if (urlPath === '/db' || urlPath.endsWith('/')) {
    const entries = await listByPrefix(resourceUrl);
    const jsonLd = generateContainerJsonLd(resourceUrl, entries);
    const content = serializeJsonLd(jsonLd);

    const etag = `"container-${entries.length}"`;

    const ifNoneMatch = request.headers['if-none-match'];
    if (ifNoneMatch) {
      const check = checkIfNoneMatchForGet(ifNoneMatch, etag);
      if (!check.ok && check.notModified) {
        return reply.code(304).send();
      }
    }

    const headers = getAllHeaders({
      isContainer: true, etag,
      contentType: 'application/ld+json',
      origin, resourceUrl, connegEnabled
    });
    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.send(content);
  }

  // Resource request
  const doc = await findOne(resourceUrl);
  if (!doc) {
    const headers = getNotFoundHeaders({ resourceUrl, origin, connegEnabled });
    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.code(404).send({ error: 'Not Found' });
  }

  const ifNoneMatch = request.headers['if-none-match'];
  if (ifNoneMatch) {
    const check = checkIfNoneMatchForGet(ifNoneMatch, doc.etag);
    if (!check.ok && check.notModified) {
      return reply.code(304).send();
    }
  }

  const headers = getAllHeaders({
    isContainer: false, etag: doc.etag,
    contentType: doc.contentType,
    origin, resourceUrl, connegEnabled
  });
  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.send(JSON.stringify(doc.data, null, 2));
}

/**
 * HEAD /db/* — same as GET but no body
 */
async function handleDbHead(request, reply) {
  const urlPath = request.url.split('?')[0];
  const resourceUrl = getResourceUrl(request);
  const origin = request.headers.origin;
  const connegEnabled = request.connegEnabled || false;

  if (urlPath === '/db' || urlPath.endsWith('/')) {
    const entries = await listByPrefix(resourceUrl);
    const etag = `"container-${entries.length}"`;
    const headers = getAllHeaders({
      isContainer: true, etag,
      contentType: 'application/ld+json',
      origin, resourceUrl, connegEnabled
    });
    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.code(200).send();
  }

  const doc = await findOne(resourceUrl);
  if (!doc) {
    const headers = getNotFoundHeaders({ resourceUrl, origin, connegEnabled });
    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.code(404).send();
  }

  const headers = getAllHeaders({
    isContainer: false, etag: doc.etag,
    contentType: doc.contentType,
    origin, resourceUrl, connegEnabled
  });
  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.code(200).send();
}

/**
 * PUT /db/* — create or update resource
 */
async function handleDbPut(request, reply) {
  if (request.config?.readOnly) {
    return reply.code(405).send({ error: 'Method Not Allowed', message: 'Server is in read-only mode' });
  }

  const urlPath = request.url.split('?')[0];
  const resourceUrl = getResourceUrl(request);

  if (urlPath.endsWith('/')) {
    return reply.code(409).send({ error: 'Conflict', message: 'Cannot PUT to a container' });
  }

  // Only accept JSON content types — stored as JSON-LD
  const incomingType = (request.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (incomingType && incomingType !== 'application/ld+json' && incomingType !== 'application/json') {
    return reply.code(415).send({ error: 'Unsupported Media Type', message: 'Only application/ld+json and application/json are accepted' });
  }

  // Parse body
  let data;
  let body = request.body;
  if (Buffer.isBuffer(body)) body = body.toString();
  if (typeof body === 'string') {
    try { data = JSON.parse(body); }
    catch { return reply.code(400).send({ error: 'Bad Request', message: 'Invalid JSON' }); }
  } else if (typeof body === 'object' && body !== null) {
    data = body;
  } else {
    return reply.code(400).send({ error: 'Bad Request', message: 'Request body required' });
  }

  // Conditional headers
  const existing = await findOne(resourceUrl);
  const currentEtag = existing?.etag || null;

  const ifMatch = request.headers['if-match'];
  if (ifMatch) {
    const check = checkIfMatch(ifMatch, currentEtag);
    if (!check.ok) return reply.code(check.status).send({ error: check.error });
  }

  const ifNoneMatch = request.headers['if-none-match'];
  if (ifNoneMatch) {
    const check = checkIfNoneMatchForWrite(ifNoneMatch, currentEtag);
    if (!check.ok) return reply.code(check.status).send({ error: check.error });
  }

  const { created, etag } = await upsertOne(resourceUrl, data, 'application/ld+json');

  const origin = request.headers.origin;
  const headers = getAllHeaders({
    isContainer: false, etag,
    origin, resourceUrl,
    connegEnabled: request.connegEnabled || false
  });
  headers['Location'] = resourceUrl;
  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

  if (request.notificationsEnabled) {
    emitChange(resourceUrl);
  }

  return reply.code(created ? 201 : 204).send();
}

/**
 * DELETE /db/* — delete resource
 */
async function handleDbDelete(request, reply) {
  if (request.config?.readOnly) {
    return reply.code(405).send({ error: 'Method Not Allowed', message: 'Server is in read-only mode' });
  }

  const resourceUrl = getResourceUrl(request);
  const origin = request.headers.origin;

  const existing = await findOne(resourceUrl);
  if (!existing) {
    const headers = getNotFoundHeaders({ resourceUrl, origin, connegEnabled: request.connegEnabled || false });
    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.code(404).send({ error: 'Not Found' });
  }

  const ifMatch = request.headers['if-match'];
  if (ifMatch) {
    const check = checkIfMatch(ifMatch, existing.etag);
    if (!check.ok) return reply.code(check.status).send({ error: check.error });
  }

  await deleteOne(resourceUrl);

  const headers = getAllHeaders({
    isContainer: false, origin, resourceUrl
  });
  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

  if (request.notificationsEnabled) {
    emitChange(resourceUrl);
  }

  return reply.code(204).send();
}

/**
 * OPTIONS /db/* — return allowed methods
 */
async function handleDbOptions(request, reply) {
  const resourceUrl = getResourceUrl(request);
  const origin = request.headers.origin;
  const headers = getAllHeaders({
    isContainer: request.url.split('?')[0] === '/db' || request.url.split('?')[0].endsWith('/'),
    origin, resourceUrl,
    connegEnabled: request.connegEnabled || false
  });
  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.code(204).send();
}

export default dbPlugin;
