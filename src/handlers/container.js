import * as storage from '../storage/filesystem.js';
import { initializeQuota, checkQuota, updateQuotaUsage } from '../storage/quota.js';
import { getAllHeaders } from '../ldp/headers.js';
import { isContainer, getEffectiveUrlPath, getPodName } from '../utils/url.js';
import { generateProfile, generatePreferences, generateTypeIndex, serialize } from '../webid/profile.js';
import { generateOwnerAcl, generatePrivateAcl, generateInboxAcl, generatePublicFolderAcl, serializeAcl } from '../wac/parser.js';
import { createToken } from '../auth/token.js';
import { canAcceptInput, toJsonLd, RDF_TYPES } from '../rdf/conneg.js';
import { emitChange } from '../notifications/events.js';

/**
 * Get the storage path and resource URL for a request
 * In subdomain mode, storage path includes pod name, URL uses subdomain
 */
function getRequestPaths(request) {
  const urlPath = request.url.split('?')[0];
  // Storage path - includes pod name in subdomain mode
  const storagePath = getEffectiveUrlPath(request);
  // Resource URL - uses the actual request hostname (subdomain in subdomain mode)
  const resourceUrl = `${request.protocol}://${request.hostname}${urlPath}`;
  return { urlPath, storagePath, resourceUrl };
}

/**
 * Handle POST request to container (create new resource)
 */
export async function handlePost(request, reply) {
  // Read-only mode - block all writes
  if (request.config?.readOnly) {
    return reply.code(405).send({ error: 'Method Not Allowed', message: 'Server is in read-only mode' });
  }

  const { urlPath, storagePath } = getRequestPaths(request);

  // Ensure target is a container
  if (!isContainer(urlPath)) {
    return reply.code(405).send({ error: 'POST only allowed on containers' });
  }

  const connegEnabled = request.connegEnabled || false;
  const contentType = request.headers['content-type'] || '';

  // Check if we can accept this input type
  if (!canAcceptInput(contentType, connegEnabled)) {
    const acceptValue = connegEnabled
      ? 'application/ld+json, application/json, text/turtle, text/n3'
      : 'application/ld+json, application/json';
    reply.header('Accept', acceptValue);
    reply.header('Accept-Post', acceptValue);
    return reply.code(415).send({
      error: 'Unsupported Media Type',
      message: connegEnabled
        ? 'Supported types: application/ld+json, application/json, text/turtle, text/n3'
        : 'Supported types: application/ld+json, application/json (enable conneg for Turtle/N3 support)'
    });
  }

  // Check container exists
  const stats = await storage.stat(storagePath);
  if (!stats || !stats.isDirectory) {
    // Create container if it doesn't exist
    await storage.createContainer(storagePath);
  }

  // Get slug from header or generate UUID
  const slug = request.headers.slug;
  const linkHeader = request.headers.link || '';

  // Security: validate Slug header
  if (slug) {
    // Maximum length check
    if (slug.length > 255) {
      return reply.code(400).send({ error: 'Slug header too long (max 255 characters)' });
    }
    // Character validation - allow alphanumeric, dots, dashes, underscores
    if (!/^[a-zA-Z0-9._-]+$/.test(slug)) {
      return reply.code(400).send({ error: 'Invalid Slug format. Use only alphanumeric characters, dots, dashes, and underscores.' });
    }
  }

  // Check if creating a container (Link header contains ldp:Container or ldp:BasicContainer)
  const isCreatingContainer = linkHeader.includes('Container') || linkHeader.includes('BasicContainer');

  // Generate unique filename
  const filename = await storage.generateUniqueFilename(storagePath, slug, isCreatingContainer);
  const newUrlPath = urlPath + filename + (isCreatingContainer ? '/' : '');
  const newStoragePath = storagePath + filename + (isCreatingContainer ? '/' : '');
  const resourceUrl = `${request.protocol}://${request.hostname}${newUrlPath}`;

  let success;
  if (isCreatingContainer) {
    success = await storage.createContainer(newStoragePath);
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

    // Convert Turtle/N3 to JSON-LD if conneg enabled
    const inputType = contentType.split(';')[0].trim().toLowerCase();
    if (connegEnabled && (inputType === RDF_TYPES.TURTLE || inputType === RDF_TYPES.N3)) {
      try {
        const jsonLd = await toJsonLd(content, contentType, resourceUrl, connegEnabled);
        content = Buffer.from(JSON.stringify(jsonLd, null, 2));
      } catch (e) {
        return reply.code(400).send({
          error: 'Bad Request',
          message: 'Invalid Turtle/N3 format: ' + e.message
        });
      }
    }

    // Check storage quota before writing (skip in public mode - no pod structure)
    const podName = request.config?.public ? null : getPodName(request);
    if (podName) {
      const { allowed, error } = await checkQuota(podName, content.length, request.defaultQuota || 0);
      if (!allowed) {
        return reply.code(507).send({ error: 'Insufficient Storage', message: error });
      }
    }

    success = await storage.write(newStoragePath, content);

    // Update quota usage after successful write
    if (success && podName) {
      await updateQuotaUsage(podName, content.length);
    }
  }

  if (!success) {
    return reply.code(500).send({ error: 'Create failed' });
  }

  const origin = request.headers.origin;

  const headers = getAllHeaders({
    isContainer: isCreatingContainer,
    origin,
    connegEnabled,
    mashlibEnabled: request.mashlibEnabled
  });
  headers['Location'] = resourceUrl;

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

  // Emit change notification for WebSocket subscribers
  if (request.notificationsEnabled) {
    emitChange(resourceUrl);
  }

  return reply.code(201).send();
}

/**
 * Create pod directory structure (reusable for registration)
 * @param {string} name - Pod name (username)
 * @param {string} webId - User's WebID URI
 * @param {string} podUri - Pod root URI (e.g., https://alice.example.com/ or https://example.com/alice/)
 * @param {string} issuer - OIDC issuer URI
 * @param {number} defaultQuota - Default storage quota in bytes (optional)
 */
export async function createPodStructure(name, webId, podUri, issuer, defaultQuota = 0) {
  const podPath = `/${name}/`;

  // Create pod directory structure
  // Pod settings directory
  await storage.createContainer(podPath);
  await storage.createContainer(`${podPath}inbox/`);
  await storage.createContainer(`${podPath}public/`);
  await storage.createContainer(`${podPath}private/`);
  await storage.createContainer(`${podPath}settings/`);
  await storage.createContainer(`${podPath}profile/`);

  // Generate and write WebID profile at /profile/card.jsonld
  const profile = generateProfile({ webId, name, podUri, issuer });
  await storage.write(`${podPath}profile/card.jsonld`, serialize(profile));

  // Generate and write preferences
  const prefs = generatePreferences({ webId, podUri });
  await storage.write(`${podPath}settings/prefs.jsonld`, serialize(prefs));

  // Generate and write type indexes
  const publicTypeIndex = generateTypeIndex(`${podUri}settings/publicTypeIndex.jsonld`, { listed: true });
  await storage.write(`${podPath}settings/publicTypeIndex.jsonld`, serialize(publicTypeIndex));

  const privateTypeIndex = generateTypeIndex(`${podUri}settings/privateTypeIndex.jsonld`, { listed: false });
  await storage.write(`${podPath}settings/privateTypeIndex.jsonld`, serialize(privateTypeIndex));

  // Create default ACL files
  // Pod root: owner full control, public read
  const rootAcl = generateOwnerAcl(podUri, webId, true);
  await storage.write(`${podPath}.acl`, serializeAcl(rootAcl));

  // Private folder: owner only (no public)
  const privateAcl = generatePrivateAcl(`${podUri}private/`, webId);
  await storage.write(`${podPath}private/.acl`, serializeAcl(privateAcl));

  // settings folder: owner only (contains private preferences)
  const settingsAcl = generatePrivateAcl(`${podUri}settings/`, webId);
  await storage.write(`${podPath}settings/.acl`, serializeAcl(settingsAcl));

  // publicTypeIndex: public read, overrides the private default inherited from /settings/
  const publicTypeIndexAcl = generateOwnerAcl(`${podUri}settings/publicTypeIndex.jsonld`, webId, false);
  await storage.write(`${podPath}settings/publicTypeIndex.jsonld.acl`, serializeAcl(publicTypeIndexAcl));

  // Inbox: owner full, public append
  const inboxAcl = generateInboxAcl(`${podUri}inbox/`, webId);
  await storage.write(`${podPath}inbox/.acl`, serializeAcl(inboxAcl));

  // Public folder: owner full, public read (with inheritance)
  const publicAcl = generatePublicFolderAcl(`${podUri}public/`, webId);
  await storage.write(`${podPath}public/.acl`, serializeAcl(publicAcl));

  // Profile folder: owner full, public read (with inheritance)
  // Profile documents must be publicly readable for WebID verification
  const profileAcl = generatePublicFolderAcl(`${podUri}profile/`, webId);
  await storage.write(`${podPath}profile/.acl`, serializeAcl(profileAcl));

  // Initialize storage quota if configured
  if (defaultQuota > 0) {
    await initializeQuota(name, defaultQuota);
  }

  return { podPath, podUri };
}

/**
 * Create a pod (container) for a user
 * POST /.pods with { "name": "alice" }
 * With IdP enabled: { "name": "alice", "email": "alice@example.com", "password": "secret" }
 *
 * Creates the following structure:
 *   /{name}/
 *   /{name}/profile/card.jsonld          - WebID profile
 *   /{name}/inbox/                       - Notifications
 *   /{name}/public/                      - Public files
 *   /{name}/private/                     - Private files
 *   /{name}/settings/prefs.jsonld        - Preferences
 *   /{name}/settings/publicTypeIndex.jsonld
 *   /{name}/settings/privateTypeIndex.jsonld
 */
export async function handleCreatePod(request, reply) {
  // Read-only mode - block pod creation
  if (request.config?.readOnly) {
    return reply.code(405).send({ error: 'Method Not Allowed', message: 'Server is in read-only mode' });
  }

  const { name, email, password } = request.body || {};
  const idpEnabled = request.idpEnabled;

  if (!name || typeof name !== 'string') {
    return reply.code(400).send({ error: 'Pod name required' });
  }

  // If IdP is enabled, require email and password
  if (idpEnabled) {
    if (!email || typeof email !== 'string') {
      return reply.code(400).send({ error: 'Email required for account creation' });
    }
    if (!password) {
      return reply.code(400).send({ error: 'Password required' });
    }
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

  // Build URIs. WebID is the JSON-LD profile with an #me fragment.
  const subdomainsEnabled = request.subdomainsEnabled;
  const baseDomain = request.baseDomain;

  let baseUri, podUri, webId;
  if (subdomainsEnabled && baseDomain) {
    // Subdomain mode: alice.example.com/profile/card.jsonld#me
    const podHost = `${name}.${baseDomain}`;
    baseUri = `${request.protocol}://${baseDomain}`;
    podUri = `${request.protocol}://${podHost}/`;
    webId = `${podUri}profile/card.jsonld#me`;
  } else {
    // Path mode: example.com/alice/profile/card.jsonld#me
    baseUri = `${request.protocol}://${request.hostname}`;
    podUri = `${baseUri}${podPath}`;
    webId = `${podUri}profile/card.jsonld#me`;
  }

  // Issuer needs trailing slash for CTH compatibility
  const issuer = baseUri + '/';

  try {
    // Use shared pod creation function
    await createPodStructure(name, webId, podUri, issuer);
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

  // If IdP is enabled, create account and return token + login URL
  if (idpEnabled) {
    try {
      const { createAccount } = await import('../idp/accounts.js');
      await createAccount({ username: name, email, password, webId, podName: name });

      const token = createToken(webId);
      return reply.code(201).send({
        name,
        webId,
        podUri,
        token,
        idpIssuer: issuer,
        loginUrl: `${baseUri}/idp/auth`,
      });
    } catch (err) {
      console.error('Account creation error:', err);
      // Rollback pod creation on account failure
      await storage.remove(podPath);
      return reply.code(409).send({ error: err.message });
    }
  }

  // Generate token for the pod owner (simple auth mode)
  const token = createToken(webId);

  return reply.code(201).send({
    name,
    webId,
    podUri,
    token
  });
}
