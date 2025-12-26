import * as storage from '../storage/filesystem.js';
import { getAllHeaders } from '../ldp/headers.js';
import { isContainer } from '../utils/url.js';

/**
 * Handle POST request to container (create new resource)
 */
export async function handlePost(request, reply) {
  const urlPath = request.url.split('?')[0];

  // Ensure target is a container
  if (!isContainer(urlPath)) {
    return reply.code(405).send({ error: 'POST only allowed on containers' });
  }

  // Check container exists
  const stats = await storage.stat(urlPath);
  if (!stats || !stats.isDirectory) {
    // Create container if it doesn't exist
    await storage.createContainer(urlPath);
  }

  // Get slug from header or generate UUID
  const slug = request.headers.slug;
  const linkHeader = request.headers.link || '';

  // Check if creating a container (Link header contains ldp:Container or ldp:BasicContainer)
  const isCreatingContainer = linkHeader.includes('Container') || linkHeader.includes('BasicContainer');

  // Generate unique filename
  const filename = await storage.generateUniqueFilename(urlPath, slug, isCreatingContainer);
  const newPath = urlPath + filename + (isCreatingContainer ? '/' : '');

  let success;
  if (isCreatingContainer) {
    success = await storage.createContainer(newPath);
  } else {
    // Get content from request body
    let content = request.body;
    if (Buffer.isBuffer(content)) {
      // Already a buffer
    } else if (typeof content === 'string') {
      content = Buffer.from(content);
    } else if (content && typeof content === 'object') {
      content = Buffer.from(JSON.stringify(content));
    } else {
      content = Buffer.from('');
    }
    success = await storage.write(newPath, content);
  }

  if (!success) {
    return reply.code(500).send({ error: 'Create failed' });
  }

  const location = `${request.protocol}://${request.hostname}${newPath}`;
  const origin = request.headers.origin;

  const headers = getAllHeaders({
    isContainer: isCreatingContainer,
    origin
  });
  headers['Location'] = location;

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.code(201).send();
}

/**
 * Create a pod (container) for a user
 * POST /.pods with { "name": "alice" }
 */
export async function handleCreatePod(request, reply) {
  const { name } = request.body || {};

  if (!name || typeof name !== 'string') {
    return reply.code(400).send({ error: 'Pod name required' });
  }

  // Validate pod name (alphanumeric, dash, underscore)
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    return reply.code(400).send({ error: 'Invalid pod name. Use alphanumeric, dash, or underscore only.' });
  }

  const podPath = `/${name}/`;

  // Check if pod already exists
  if (await storage.exists(podPath)) {
    return reply.code(409).send({ error: 'Pod already exists' });
  }

  // Create pod container
  const success = await storage.createContainer(podPath);
  if (!success) {
    return reply.code(500).send({ error: 'Failed to create pod' });
  }

  const location = `${request.protocol}://${request.hostname}${podPath}`;
  const origin = request.headers.origin;

  const headers = getAllHeaders({ isContainer: true, origin });
  headers['Location'] = location;

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

  return reply.code(201).send({
    name,
    url: location
  });
}
