import * as storage from '../storage/filesystem.js';
import { getAllHeaders } from '../ldp/headers.js';
import { generateContainerJsonLd, serializeJsonLd } from '../ldp/container.js';
import { isContainer, getContentType, isRdfContentType } from '../utils/url.js';

/**
 * Handle GET request
 */
export async function handleGet(request, reply) {
  const urlPath = request.url.split('?')[0]; // Remove query string
  const stats = await storage.stat(urlPath);

  if (!stats) {
    return reply.code(404).send({ error: 'Not Found' });
  }

  const origin = request.headers.origin;
  const resourceUrl = `${request.protocol}://${request.hostname}${urlPath}`;

  // Handle container
  if (stats.isDirectory) {
    // Check for index.html (serves as both profile and container representation)
    const indexPath = urlPath.endsWith('/') ? `${urlPath}index.html` : `${urlPath}/index.html`;
    const indexExists = await storage.exists(indexPath);

    if (indexExists) {
      // Serve index.html (contains JSON-LD structured data)
      const content = await storage.read(indexPath);
      const indexStats = await storage.stat(indexPath);

      const headers = getAllHeaders({
        isContainer: true,
        etag: indexStats?.etag || stats.etag,
        contentType: 'text/html',
        origin,
        resourceUrl
      });

      Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
      return reply.send(content);
    }

    // No index.html, return JSON-LD container listing
    const entries = await storage.listContainer(urlPath);
    const jsonLd = generateContainerJsonLd(resourceUrl, entries || []);

    const headers = getAllHeaders({
      isContainer: true,
      etag: stats.etag,
      contentType: 'application/ld+json',
      origin,
      resourceUrl
    });

    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.send(serializeJsonLd(jsonLd));
  }

  // Handle resource
  const content = await storage.read(urlPath);
  if (content === null) {
    return reply.code(500).send({ error: 'Read error' });
  }

  const contentType = getContentType(urlPath);
  const headers = getAllHeaders({
    isContainer: false,
    etag: stats.etag,
    contentType,
    origin,
    resourceUrl
  });

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.send(content);
}

/**
 * Handle HEAD request
 */
export async function handleHead(request, reply) {
  const urlPath = request.url.split('?')[0];
  const stats = await storage.stat(urlPath);

  if (!stats) {
    return reply.code(404).send();
  }

  const origin = request.headers.origin;
  const resourceUrl = `${request.protocol}://${request.hostname}${urlPath}`;
  const contentType = stats.isDirectory ? 'application/ld+json' : getContentType(urlPath);

  const headers = getAllHeaders({
    isContainer: stats.isDirectory,
    etag: stats.etag,
    contentType,
    origin,
    resourceUrl
  });

  if (!stats.isDirectory) {
    headers['Content-Length'] = stats.size;
  }

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.code(200).send();
}

/**
 * Handle PUT request
 */
export async function handlePut(request, reply) {
  const urlPath = request.url.split('?')[0];

  // Don't allow PUT to containers
  if (isContainer(urlPath)) {
    return reply.code(409).send({ error: 'Cannot PUT to container. Use POST instead.' });
  }

  // Check if resource already exists
  const existed = await storage.exists(urlPath);

  // Get content from request body
  let content = request.body;

  // Handle raw body for non-JSON content types
  if (Buffer.isBuffer(content)) {
    // Already a buffer, use as-is
  } else if (typeof content === 'string') {
    content = Buffer.from(content);
  } else if (content && typeof content === 'object') {
    content = Buffer.from(JSON.stringify(content));
  } else {
    content = Buffer.from('');
  }

  const success = await storage.write(urlPath, content);
  if (!success) {
    return reply.code(500).send({ error: 'Write failed' });
  }

  const origin = request.headers.origin;
  const resourceUrl = `${request.protocol}://${request.hostname}${urlPath}`;
  const headers = getAllHeaders({ isContainer: false, origin, resourceUrl });
  headers['Location'] = resourceUrl;

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.code(existed ? 204 : 201).send();
}

/**
 * Handle DELETE request
 */
export async function handleDelete(request, reply) {
  const urlPath = request.url.split('?')[0];

  const existed = await storage.exists(urlPath);
  if (!existed) {
    return reply.code(404).send({ error: 'Not Found' });
  }

  const success = await storage.remove(urlPath);
  if (!success) {
    return reply.code(500).send({ error: 'Delete failed' });
  }

  const origin = request.headers.origin;
  const resourceUrl = `${request.protocol}://${request.hostname}${urlPath}`;
  const headers = getAllHeaders({ isContainer: false, origin, resourceUrl });
  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

  return reply.code(204).send();
}

/**
 * Handle OPTIONS request
 */
export async function handleOptions(request, reply) {
  const urlPath = request.url.split('?')[0];
  const stats = await storage.stat(urlPath);

  const origin = request.headers.origin;
  const resourceUrl = `${request.protocol}://${request.hostname}${urlPath}`;
  const headers = getAllHeaders({
    isContainer: stats?.isDirectory || isContainer(urlPath),
    origin,
    resourceUrl
  });

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.code(204).send();
}
