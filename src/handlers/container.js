import * as storage from '../storage/filesystem.js';
import { getAllHeaders } from '../ldp/headers.js';
import { isContainer } from '../utils/url.js';
import { generateProfile, generatePreferences, generateTypeIndex, serialize } from '../webid/profile.js';
import { generateOwnerAcl, generatePrivateAcl, generateInboxAcl, serializeAcl } from '../wac/parser.js';
import { createToken } from '../auth/token.js';

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
 *
 * Creates the following structure:
 *   /{name}/
 *   /{name}/profile/card     - WebID profile
 *   /{name}/inbox/           - Notifications
 *   /{name}/public/          - Public files
 *   /{name}/private/         - Private files
 *   /{name}/settings/prefs   - Preferences
 *   /{name}/settings/publicTypeIndex
 *   /{name}/settings/privateTypeIndex
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

  // Build URIs
  // WebID is at pod root: /alice/#me
  const baseUri = `${request.protocol}://${request.hostname}`;
  const podUri = `${baseUri}${podPath}`;
  const webId = `${podUri}#me`;
  const issuer = baseUri;

  try {
    // Create pod directory structure
    await storage.createContainer(podPath);
    await storage.createContainer(`${podPath}inbox/`);
    await storage.createContainer(`${podPath}public/`);
    await storage.createContainer(`${podPath}private/`);
    await storage.createContainer(`${podPath}settings/`);

    // Generate and write WebID profile as index.html at pod root
    const profileHtml = generateProfile({ webId, name, podUri, issuer });
    await storage.write(`${podPath}index.html`, profileHtml);

    // Generate and write preferences
    const prefs = generatePreferences({ webId, podUri });
    await storage.write(`${podPath}settings/prefs`, serialize(prefs));

    // Generate and write type indexes
    const publicTypeIndex = generateTypeIndex(`${podUri}settings/publicTypeIndex`);
    await storage.write(`${podPath}settings/publicTypeIndex`, serialize(publicTypeIndex));

    const privateTypeIndex = generateTypeIndex(`${podUri}settings/privateTypeIndex`);
    await storage.write(`${podPath}settings/privateTypeIndex`, serialize(privateTypeIndex));

    // Create default ACL files
    // Pod root: owner full control, public read
    const rootAcl = generateOwnerAcl(podUri, webId, true);
    await storage.write(`${podPath}.acl`, serializeAcl(rootAcl));

    // Private folder: owner only (no public)
    const privateAcl = generatePrivateAcl(`${podUri}private/`, webId);
    await storage.write(`${podPath}private/.acl`, serializeAcl(privateAcl));

    // Settings folder: owner only
    const settingsAcl = generatePrivateAcl(`${podUri}settings/`, webId);
    await storage.write(`${podPath}settings/.acl`, serializeAcl(settingsAcl));

    // Inbox: owner full, public append
    const inboxAcl = generateInboxAcl(`${podUri}inbox/`, webId);
    await storage.write(`${podPath}inbox/.acl`, serializeAcl(inboxAcl));

  } catch (err) {
    console.error('Pod creation error:', err);
    // Cleanup on failure
    await storage.remove(podPath);
    return reply.code(500).send({ error: 'Failed to create pod' });
  }

  const origin = request.headers.origin;
  const headers = getAllHeaders({ isContainer: true, origin });
  headers['Location'] = podUri;

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

  // Generate token for the pod owner
  const token = createToken(webId);

  return reply.code(201).send({
    name,
    webId,
    podUri,
    token
  });
}
