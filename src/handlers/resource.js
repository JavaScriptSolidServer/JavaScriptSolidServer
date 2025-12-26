import * as storage from '../storage/filesystem.js';
import { getAllHeaders } from '../ldp/headers.js';
import { generateContainerJsonLd, serializeJsonLd } from '../ldp/container.js';
import { isContainer, getContentType, isRdfContentType } from '../utils/url.js';
import { parseN3Patch, applyN3Patch, validatePatch } from '../patch/n3-patch.js';

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

/**
 * Handle PATCH request
 * Supports N3 Patch format (text/n3) for updating RDF resources
 */
export async function handlePatch(request, reply) {
  const urlPath = request.url.split('?')[0];

  // Don't allow PATCH to containers
  if (isContainer(urlPath)) {
    return reply.code(409).send({ error: 'Cannot PATCH containers' });
  }

  // Check content type
  const contentType = request.headers['content-type'] || '';
  const isN3Patch = contentType.includes('text/n3') ||
                    contentType.includes('application/n3') ||
                    contentType.includes('application/sparql-update');

  if (!isN3Patch) {
    return reply.code(415).send({
      error: 'Unsupported Media Type',
      message: 'PATCH requires Content-Type: text/n3 for N3 Patch format'
    });
  }

  // Check if resource exists
  const stats = await storage.stat(urlPath);
  if (!stats) {
    return reply.code(404).send({ error: 'Not Found' });
  }

  // Read existing content
  const existingContent = await storage.read(urlPath);
  if (existingContent === null) {
    return reply.code(500).send({ error: 'Read error' });
  }

  // Parse existing document as JSON-LD
  let document;
  try {
    document = JSON.parse(existingContent.toString());
  } catch (e) {
    return reply.code(409).send({
      error: 'Conflict',
      message: 'Resource is not valid JSON-LD and cannot be patched'
    });
  }

  // Parse the patch
  const patchContent = Buffer.isBuffer(request.body)
    ? request.body.toString()
    : request.body;

  const resourceUrl = `${request.protocol}://${request.hostname}${urlPath}`;
  let patch;
  try {
    patch = parseN3Patch(patchContent, resourceUrl);
  } catch (e) {
    return reply.code(400).send({
      error: 'Bad Request',
      message: 'Invalid N3 Patch format: ' + e.message
    });
  }

  // Validate that deletes exist (optional strict mode)
  // const validation = validatePatch(document, patch, resourceUrl);
  // if (!validation.valid) {
  //   return reply.code(409).send({ error: 'Conflict', message: validation.error });
  // }

  // Apply the patch
  let updatedDocument;
  try {
    updatedDocument = applyN3Patch(document, patch, resourceUrl);
  } catch (e) {
    return reply.code(409).send({
      error: 'Conflict',
      message: 'Failed to apply patch: ' + e.message
    });
  }

  // Write updated document
  const updatedContent = JSON.stringify(updatedDocument, null, 2);
  const success = await storage.write(urlPath, Buffer.from(updatedContent));

  if (!success) {
    return reply.code(500).send({ error: 'Write failed' });
  }

  const origin = request.headers.origin;
  const headers = getAllHeaders({ isContainer: false, origin, resourceUrl });
  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

  return reply.code(204).send();
}
