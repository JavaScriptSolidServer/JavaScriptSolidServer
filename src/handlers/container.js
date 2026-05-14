import * as storage from '../storage/filesystem.js';
import { initializeQuota, checkQuota, updateQuotaUsage } from '../storage/quota.js';
import { getAllHeaders } from '../ldp/headers.js';
import { isContainer, getEffectiveUrlPath, getPodName } from '../utils/url.js';
import { generateProfile, generatePreferences, generateTypeIndex, serialize } from '../webid/profile.js';
import { generateOwnerAcl, generatePrivateAcl, generateInboxAcl, generatePublicFolderAcl, serializeAcl, relativizeOwnerWebId } from '../wac/parser.js';
import { provisionOwnerKey, assertProvisionKeysCompatible } from '../keys/provision.js';
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
 * @param {object} [options]
 * @param {boolean} [options.provisionKeys=false] - When true, generate a
 *   Schnorr secp256k1 keypair and write it to `<pod>/private/privkey.jsonld`
 *   in W3C CID v1.0 Multikey format. Phase 1 of #437. The secret lands on
 *   disk in plaintext under owner-only WAC + file mode 0600 — operators
 *   should add filesystem-level protection (FDE / OS keyring) for any pod
 *   that matters.
 * @returns {Promise<{ podPath, podUri, ownerKey?: { document, publicHex, secretHex, publicMultibase } }>}
 *   When `provisionKeys` is true, the return value includes the freshly
 *   minted key material so the caller can surface the public side in CLI
 *   output (the secret should NOT be displayed or logged).
 */
export async function createPodStructure(name, webId, podUri, issuer, defaultQuota = 0, options = {}) {
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

  // Create default ACL files. Each .acl is written inside the container it
  // protects, so `acl:accessTo` is always './' (resolved against the .acl's
  // own URL by the parser — see #428).
  //
  // The owner WebID is also written relatively (#430), derived from the
  // absolute `webId` and the .acl's location within the pod by
  // `relativizeOwnerWebId`. This works for any profile layout (modern
  // `profile/card.jsonld#me`, legacy `profile/card#me`, custom shapes) and
  // falls back to the absolute WebID for foreign owners. Together this
  // keeps the on-disk pod portable across hostnames.
  const owner = aclBase => relativizeOwnerWebId(webId, podUri, aclBase);

  const rootAcl = generateOwnerAcl('./', owner(''), true);
  await storage.write(`${podPath}.acl`, serializeAcl(rootAcl));

  const privateAcl = generatePrivateAcl('./', owner('private/'));
  await storage.write(`${podPath}private/.acl`, serializeAcl(privateAcl));

  const settingsAcl = generatePrivateAcl('./', owner('settings/'));
  await storage.write(`${podPath}settings/.acl`, serializeAcl(settingsAcl));

  // publicTypeIndex: public read, overrides the private default inherited
  // from /settings/. This is a resource ACL (lives at .../publicTypeIndex.jsonld.acl),
  // whose base URL is /settings/ — same depth as `settings/.acl` for the
  // owner reference.
  const publicTypeIndexAcl = generateOwnerAcl('./publicTypeIndex.jsonld', owner('settings/'), false);
  await storage.write(`${podPath}settings/publicTypeIndex.jsonld.acl`, serializeAcl(publicTypeIndexAcl));

  const inboxAcl = generateInboxAcl('./', owner('inbox/'));
  await storage.write(`${podPath}inbox/.acl`, serializeAcl(inboxAcl));

  const publicAcl = generatePublicFolderAcl('./', owner('public/'));
  await storage.write(`${podPath}public/.acl`, serializeAcl(publicAcl));

  // Profile documents must be publicly readable for WebID verification
  const profileAcl = generatePublicFolderAcl('./', owner('profile/'));
  await storage.write(`${podPath}profile/.acl`, serializeAcl(profileAcl));

  // Initialize storage quota if configured
  if (defaultQuota > 0) {
    await initializeQuota(name, defaultQuota);
  }

  // Optional: provision a Schnorr secp256k1 owner key in /private/.
  // Phase 1 of #437. See src/keys/provision.js for the design notes.
  // Throw on write failure so the caller's cleanup path runs and the
  // pod isn't left with a phantom `ownerKey` in the response that
  // doesn't correspond to any on-disk file.
  //
  // Strict `=== true` (not just truthy) so a misconfigured caller
  // passing `'true'` / `1` / etc. doesn't silently activate. Matches
  // handleCreatePod's HTTP-side check on the body field.
  let ownerKey;
  if (options.provisionKeys === true) {
    ownerKey = provisionOwnerKey({ controllerWebId: webId });
    const ok = await storage.write(
      `${podPath}private/privkey.jsonld`,
      JSON.stringify(ownerKey.document, null, 2),
      { mode: 0o600 }
    );
    if (!ok) {
      throw new Error(
        `Failed to write owner key file at ${podPath}private/privkey.jsonld`
      );
    }
  }

  return { podPath, podUri, ownerKey };
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

  const { name, email, password, provisionKeys } = request.body || {};
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

  // Refuse provisionKeys + --public: WAC would be bypassed, exposing the
  // freshly written secret to anyone. Use the same assertion helper as
  // createServer's startup-time check so the error message stays in
  // one place — converted to a 400 here because we're in an HTTP
  // request context, not the constructor.
  if (provisionKeys === true) {
    try {
      assertProvisionKeysCompatible({
        provisionKeys: true,
        isPublic: !!request.config?.public
      });
    } catch (err) {
      return reply.code(400).send({
        error: 'provisionKeys cannot be used in --public mode',
        message: err.message
      });
    }
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

  let podCreation;
  try {
    // Use shared pod creation function. Coerce provisionKeys to a
    // strict boolean so a JSON `null` / missing value defaults to off.
    podCreation = await createPodStructure(
      name, webId, podUri, issuer, 0,
      { provisionKeys: provisionKeys === true }
    );
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

  // Surface a summary of any provisioned key so callers can display
  // the public side. The secret is NEVER echoed in the response —
  // it lives only on disk under the pod's owner-only ACL.
  const keyInfo = podCreation?.ownerKey
    ? {
        keyDocument: `${podUri}private/privkey.jsonld`,
        publicKeyMultibase: podCreation.ownerKey.publicMultibase
      }
    : null;

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
        ...(keyInfo && { ownerKey: keyInfo })
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
    token,
    ...(keyInfo && { ownerKey: keyInfo })
  });
}
