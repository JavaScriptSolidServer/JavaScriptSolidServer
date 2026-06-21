/**
 * MCP tool definitions and dispatch.
 *
 * Each tool is a function: (args, ctx) -> Promise<MCPToolResult>
 * ctx.webId — authenticated identity (null = anonymous)
 * ctx.origin — request origin for building absolute URLs
 *
 * All WAC checks delegate to src/wac/checker.js so MCP tools have
 * the same access semantics as the HTTP endpoints.
 */

import * as storage from '../storage/filesystem.js';
import { checkAccess } from '../wac/checker.js';
import { AccessMode, parseAcl, serializeAcl } from '../wac/parser.js';
import { resourceEvents, emitChange } from '../notifications/events.js';
import { toolText, toolError, toolJson } from './protocol.js';
import { discoverSkills, readSkill, readPodSkill } from './skills.js';
import { readFile, readdir, stat as fsStat } from 'fs/promises';
import { join, dirname, resolve as pathResolve } from 'path';
import { fileURLToPath } from 'url';

const ACL_NS = 'http://www.w3.org/ns/auth/acl#';
const FOAF_AGENT = 'http://xmlns.com/foaf/0.1/Agent';
const ACL_AUTH_AGENT = 'http://www.w3.org/ns/auth/acl#AuthenticatedAgent';
const SHORT_MODE = {
  [`${ACL_NS}Read`]: 'Read',
  [`${ACL_NS}Write`]: 'Write',
  [`${ACL_NS}Append`]: 'Append',
  [`${ACL_NS}Control`]: 'Control'
};
const SHORT_AGENT_CLASS = {
  [FOAF_AGENT]: 'foaf:Agent',
  [ACL_AUTH_AGENT]: 'acl:AuthenticatedAgent'
};
const FULL_MODE = {
  Read: `${ACL_NS}Read`,
  Write: `${ACL_NS}Write`,
  Append: `${ACL_NS}Append`,
  Control: `${ACL_NS}Control`
};
const FULL_AGENT_CLASS = {
  'foaf:Agent': FOAF_AGENT,
  'acl:AuthenticatedAgent': ACL_AUTH_AGENT
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const JSS_DOCS_DIR = pathResolve(__dirname, '..', '..', 'docs');

function buildUrl(ctx, path) {
  if (!path.startsWith('/')) path = '/' + path;
  return `${ctx.origin}${path}`;
}

function parentPath(p) {
  if (p === '/' || p === '') return '/';
  const trimmed = p.endsWith('/') ? p.slice(0, -1) : p;
  const idx = trimmed.lastIndexOf('/');
  return idx <= 0 ? '/' : trimmed.slice(0, idx + 1);
}

async function wac(ctx, path, mode) {
  // For writes against a non-existent resource, fall back to checking
  // the parent container — same pattern as src/auth/middleware.js so MCP
  // tools have identical WAC semantics to the HTTP endpoints.
  const isWrite = mode === AccessMode.WRITE || mode === AccessMode.APPEND;
  let checkPath = path;
  let checkIsContainer = path.endsWith('/');
  if (isWrite && !path.endsWith('/') && !(await storage.exists(path))) {
    checkPath = parentPath(path);
    checkIsContainer = true;
  }
  const { allowed } = await checkAccess({
    resourceUrl: buildUrl(ctx, checkPath),
    resourcePath: checkPath,
    isContainer: checkIsContainer,
    agentWebId: ctx.webId,
    requiredMode: mode
  });
  return allowed;
}

// --- CRUD tools ---

async function list_resources({ path }, ctx) {
  if (!path || !path.endsWith('/')) {
    return toolError('path must be a container (ending in /)');
  }
  if (!(await wac(ctx, path, AccessMode.READ))) {
    return toolError(`access denied: read ${path}`);
  }
  if (!(await storage.exists(path))) {
    return toolError(`not found: ${path}`);
  }
  const entries = await storage.listContainer(path);
  return toolJson({
    container: path,
    items: (entries || []).map(e => ({
      name: e.name,
      path: `${path}${e.name}${e.isDirectory ? '/' : ''}`,
      isContainer: e.isDirectory,
      size: e.size ?? null,
      modified: e.modified ?? null
    }))
  });
}

async function read_resource({ path }, ctx) {
  if (!path) return toolError('path required');
  if (!(await wac(ctx, path, AccessMode.READ))) {
    return toolError(`access denied: read ${path}`);
  }
  if (!(await storage.exists(path))) {
    return toolError(`not found: ${path}`);
  }
  if (path.endsWith('/')) {
    return toolError('use list_resources for containers');
  }
  const content = await storage.read(path);
  let body = content.toString('utf8');
  // Truncate very large reads
  const MAX = 200_000;
  let truncated = false;
  if (body.length > MAX) {
    body = body.slice(0, MAX);
    truncated = true;
  }
  const result = { path, body };
  if (truncated) result.truncated = true;
  return toolJson(result);
}

async function write_resource({ path, content, contentType }, ctx) {
  if (!path) return toolError('path required');
  if (path.endsWith('/')) return toolError('cannot PUT a container; use create_resource');
  if (content == null) return toolError('content required');
  if (!(await wac(ctx, path, AccessMode.WRITE))) {
    return toolError(`access denied: write ${path}`);
  }
  await storage.write(path, Buffer.from(content, 'utf8'), {
    contentType: contentType || 'text/plain'
  });
  emitChange(buildUrl(ctx, path));
  return toolText(`wrote ${path} (${Buffer.byteLength(content, 'utf8')} bytes)`);
}

async function create_resource({ container, slug, content, contentType, isContainer }, ctx) {
  if (!container || !container.endsWith('/')) {
    return toolError('container path required (must end in /)');
  }
  if (!(await wac(ctx, container, AccessMode.APPEND))) {
    return toolError(`access denied: append ${container}`);
  }
  if (!(await storage.exists(container))) {
    return toolError(`container not found: ${container}`);
  }
  const name = await storage.generateUniqueFilename(container, slug || null, !!isContainer);
  const childPath = `${container}${name}${isContainer ? '/' : ''}`;
  if (isContainer) {
    await storage.createContainer(childPath);
    emitChange(buildUrl(ctx, childPath));
    return toolText(`created container ${childPath}`);
  }
  await storage.write(childPath, Buffer.from(content || '', 'utf8'), {
    contentType: contentType || 'text/plain'
  });
  emitChange(buildUrl(ctx, childPath));
  return toolText(`created ${childPath}`);
}

async function delete_resource({ path }, ctx) {
  if (!path) return toolError('path required');
  if (!(await wac(ctx, path, AccessMode.WRITE))) {
    return toolError(`access denied: delete ${path}`);
  }
  if (!(await storage.exists(path))) {
    return toolError(`not found: ${path}`);
  }
  await storage.remove(path);
  emitChange(buildUrl(ctx, path));
  return toolText(`deleted ${path}`);
}

async function head_resource({ path }, ctx) {
  if (!path) return toolError('path required');
  if (!(await wac(ctx, path, AccessMode.READ))) {
    return toolError(`access denied: read ${path}`);
  }
  if (!(await storage.exists(path))) {
    return toolError(`not found: ${path}`);
  }
  const s = await storage.stat(path);
  return toolJson({
    path,
    isContainer: path.endsWith('/'),
    size: s?.size ?? null,
    modified: s?.mtime ?? null
  });
}

// --- skill tools ---

async function list_skills(_args, _ctx) {
  const idx = await discoverSkills();
  return toolJson(idx);
}

async function get_skill({ path }, _ctx) {
  if (!path) return toolError('path required');
  try {
    const skill = await readSkill(path);
    return toolJson(skill);
  } catch (e) {
    return toolError(e.message);
  }
}

async function get_pod_skill(_args, _ctx) {
  const skill = await readPodSkill();
  if (!skill) return toolText('no pod-wide SKILL.md or SKILL.jsonld');
  return toolJson(skill);
}

// --- docs tools ---

async function list_docs(_args, _ctx) {
  try {
    const entries = await readdir(JSS_DOCS_DIR);
    const md = entries.filter(n => n.endsWith('.md'));
    const docs = await Promise.all(md.map(async name => {
      const fullPath = join(JSS_DOCS_DIR, name);
      const s = await fsStat(fullPath).catch(() => null);
      return { name, size: s?.size ?? null };
    }));
    return toolJson({ source: 'jss-builtin', docs });
  } catch {
    return toolJson({ source: 'jss-builtin', docs: [] });
  }
}

async function read_docs({ name }, _ctx) {
  if (!name) return toolError('name required (e.g. "git-support.md")');
  if (name.includes('..') || name.includes('/')) return toolError('name must be a bare filename');
  if (!name.endsWith('.md')) name = name + '.md';
  try {
    const body = await readFile(join(JSS_DOCS_DIR, name), 'utf8');
    return toolJson({ name, body });
  } catch (e) {
    return toolError(`doc not found: ${name}`);
  }
}

// --- ACL tools (#496) ---

function aclUrlFor(path) {
  // For containers, ACL is <container>.acl
  // For resources, ACL is <resource>.acl
  if (path.endsWith('/')) return path + '.acl';
  return path + '.acl';
}

function shortMode(mode) {
  return SHORT_MODE[mode] || mode;
}

function shortAgentClass(uri) {
  return SHORT_AGENT_CLASS[uri] || uri;
}

function fullMode(mode) {
  return FULL_MODE[mode] || mode;
}

function fullAgentClass(value) {
  return FULL_AGENT_CLASS[value] || value;
}

async function read_acl({ path }, ctx) {
  if (!path) return toolError('path required');
  // Reading the ACL document itself requires Control on the resource.
  if (!(await wac(ctx, path, AccessMode.CONTROL))) {
    return toolError(`access denied: control ${path}`);
  }
  const aclPath = aclUrlFor(path);
  if (!(await storage.exists(aclPath))) {
    return toolJson({ path, aclPath, exists: false, authorizations: [] });
  }
  const content = await storage.read(aclPath);
  const aclUrl = buildUrl(ctx, aclPath);
  const auths = await parseAcl(content.toString('utf8'), aclUrl);
  return toolJson({
    path,
    aclPath,
    exists: true,
    authorizations: auths.map(a => ({
      agents: a.agents || [],
      agentClasses: (a.agentClasses || []).map(shortAgentClass),
      modes: (a.modes || []).map(shortMode),
      isDefault: !!a.default
    }))
  });
}

function buildAclDoc(structured, targetRef, isContainer) {
  const graph = structured.authorizations.map((auth, i) => {
    const node = {
      '@id': `#auth${i}`,
      '@type': 'acl:Authorization',
      // accessTo is a *relative* IRI resolved against the .acl document's
      // own URL, so stored ACLs stay host-portable across origins (#428).
      // The bare './' the old code always used only lands on the right
      // target for a *container* ACL (<container>/.acl -> the container).
      // For a *resource* ACL (<resource>.acl) './' resolves to the parent
      // container, so checkAuthorizations() — which requires an exact
      // accessTo match — finds nothing and leaves the resource with zero
      // authorizations, locking out even the owner who just granted
      // themselves Control (#575). targetRef is therefore './' for a
      // container and './<basename>' for a resource.
      'acl:accessTo': { '@id': targetRef },
      'acl:mode': (auth.modes || []).map(m => ({ '@id': `acl:${m}` }))
    };
    if (auth.agents && auth.agents.length) {
      node['acl:agent'] = auth.agents.map(a => ({ '@id': a }));
    }
    if (auth.agentClasses && auth.agentClasses.length) {
      node['acl:agentClass'] = auth.agentClasses.map(c => ({
        '@id': fullAgentClass(c)
      }));
    }
    // acl:default only has meaning on a container ACL (it supplies the
    // defaults inherited by contained resources), where targetRef is './'.
    if (auth.isDefault && isContainer) {
      node['acl:default'] = { '@id': targetRef };
    }
    return node;
  });
  return {
    '@context': {
      acl: ACL_NS,
      foaf: 'http://xmlns.com/foaf/0.1/'
    },
    '@graph': graph
  };
}

async function write_acl({ path, authorizations }, ctx) {
  if (!path) return toolError('path required');
  if (!Array.isArray(authorizations)) {
    return toolError('authorizations must be an array');
  }
  // Writing the ACL document requires Control on the resource.
  if (!(await wac(ctx, path, AccessMode.CONTROL))) {
    return toolError(`access denied: control ${path}`);
  }
  const aclPath = aclUrlFor(path);
  const isContainer = path.endsWith('/');
  // Relative target IRI for the stored ACL (host-portable, #428): './' for
  // a container, './<basename>' for a resource. Resolved against the .acl
  // URL by the parser at check time.
  const targetRef = isContainer
    ? './'
    : './' + path.replace(/\/+$/, '').split('/').pop();
  const targetUrl = buildUrl(ctx, path); // absolute, for the lockout check below
  const doc = buildAclDoc({ authorizations }, targetRef, isContainer);
  const serialized = serializeAcl(doc);

  // Safety: refuse to write an ACL that would lock the caller out of
  // future Control. Two footguns are covered:
  //   1. relative WebID paths in `agents` resolving against the .acl URL
  //      to a different absolute URI than the caller's actual WebID;
  //   2. an authorization whose `accessTo` does not actually cover this
  //      resource (e.g. #575), which the checker would skip entirely.
  // Parse the proposed ACL with its real URL so relative refs resolve
  // correctly, then require an authorization that both grants Control to
  // the caller *and* applies to this target.
  const aclAbsUrl = buildUrl(ctx, aclPath);
  const proposed = await parseAcl(serialized, aclAbsUrl);
  const normUrl = u => String(u).replace(/\/$/, '');
  const appliesToTarget = auth => {
    const t = normUrl(targetUrl);
    return (auth.accessTo || []).some(a => normUrl(a) === t) ||
      (auth.default || []).some(d => {
        const p = normUrl(d);
        return t === p || t.startsWith(p + '/');
      });
  };
  const callerHasControl = proposed.some(auth => {
    if (!(auth.modes || []).includes(AccessMode.CONTROL)) return false;
    if (!appliesToTarget(auth)) return false;
    if (ctx.webId && (auth.agents || []).includes(ctx.webId)) return true;
    if ((auth.agentClasses || []).includes(FOAF_AGENT)) return true;
    if (ctx.webId && (auth.agentClasses || []).includes(ACL_AUTH_AGENT)) return true;
    return false;
  });
  if (!callerHasControl) {
    return toolError(
      `write_acl refused: the proposed ACL would not grant Control to the caller (${ctx.webId || 'anonymous'}). ` +
      'This is typically caused by relative WebID paths in agents resolving against the .acl URL — use absolute WebIDs. ' +
      'If you really want to remove your own access (e.g. transferring ownership), do it in two steps: ' +
      'first grant Control to the new owner, then have the new owner write_acl without you.'
    );
  }

  await storage.write(aclPath, Buffer.from(serialized, 'utf8'), {
    contentType: 'application/ld+json'
  });
  emitChange(buildUrl(ctx, aclPath));
  return toolText(`wrote ${aclPath} (${authorizations.length} authorization${authorizations.length === 1 ? '' : 's'})`);
}

// --- subscribe (#494) ---
//
// `subscribe` is a streaming tool. The handler signals its streaming
// shape by returning { stream: true, init, run }. The MCP plugin
// switches the HTTP response to SSE when it sees this shape and calls
// `init` first (for the initial event) then `run(send, signal)` to push
// notifications until the client disconnects.

function pathMatchesScope(eventUrl, scopePath, origin) {
  if (!eventUrl.startsWith(origin)) return false;
  const eventPath = eventUrl.slice(origin.length);
  if (scopePath === '/') return true;
  if (scopePath.endsWith('/')) return eventPath.startsWith(scopePath);
  return eventPath === scopePath;
}

function subscribe({ path }, ctx) {
  const scope = path || '/';
  return {
    stream: true,
    async init() {
      return {
        type: 'subscribed',
        scope,
        origin: ctx.origin,
        identity: ctx.webId || null
      };
    },
    async run(send, signal) {
      const onChange = async (eventUrl) => {
        if (signal.aborted) return;
        if (!pathMatchesScope(eventUrl, scope, ctx.origin)) return;

        // Per-event WAC filter — don't leak resources the subscriber
        // can't see. The check is best-effort: if the resource was just
        // deleted we may not have storage to read its ACL from, so we
        // err on the side of not emitting.
        const eventPath = eventUrl.slice(ctx.origin.length);
        try {
          const allowed = await wac(ctx, eventPath, AccessMode.READ);
          if (!allowed) return;
        } catch {
          return;
        }
        send({
          type: 'resource_changed',
          path: eventPath,
          url: eventUrl
        });
      };
      resourceEvents.on('change', onChange);
      const cleanup = () => resourceEvents.off('change', onChange);
      signal.addEventListener('abort', cleanup, { once: true });
      // Resolve when aborted — keeps the stream open until client disconnect
      await new Promise(resolve => signal.addEventListener('abort', resolve, { once: true }));
      cleanup();
    }
  };
}

// --- federation (#495) ---

// Conservative defaults locked in for v1. Future PRs may add more flexibility.
//
//   1. Federation gate is `<agent-pod>/private/federation/` — caller must
//      have acl:Write there to initiate outbound federation. The agent's
//      pod is derived from their WebID. Foreign WebIDs are denied (no
//      local path to gate against).
//   2. No pod-resident credential storage — every call carries its own
//      credentials in the `auth` argument (or none for anonymous reads).
//   3. Depth cap via MCP-Federation-Depth header, max 3.
const MAX_FEDERATION_DEPTH = 3;

function federationGatePathFor(webId, origin) {
  if (!webId || !origin) return null;
  if (!webId.startsWith(origin)) return null;  // foreign WebID — deny
  const localPath = webId.slice(origin.length);
  // Extract pod root: everything up to and including the segment before /profile/
  const profileIdx = localPath.indexOf('/profile/');
  const podPath = profileIdx > 0 ? localPath.slice(0, profileIdx + 1) : '/';
  return podPath + 'private/federation/';
}

async function call_remote_pod({ pod_url, tool, arguments: remoteArgs, auth }, ctx) {
  if (!pod_url || typeof pod_url !== 'string') {
    return toolError('pod_url required');
  }
  if (!tool || typeof tool !== 'string') {
    return toolError('tool required');
  }
  try {
    new URL(pod_url);
  } catch {
    return toolError(`pod_url is not a valid URL: ${pod_url}`);
  }

  // Local WAC gate — derived from the agent's WebID. Foreign or
  // anonymous identities can't federate.
  const gatePath = federationGatePathFor(ctx.webId, ctx.origin);
  if (!gatePath) {
    return toolError(
      'access denied: federation requires a local WebID identity (anonymous and foreign identities cannot initiate outbound federation)'
    );
  }
  if (!(await wac(ctx, gatePath, AccessMode.WRITE))) {
    return toolError(
      `access denied: write ${gatePath} (federation gate). Owner must grant acl:Write at this path to delegate outbound federation.`
    );
  }

  // Depth cap
  const depth = (ctx.federationDepth ?? 0) + 1;
  if (depth > MAX_FEDERATION_DEPTH) {
    return toolError(`federation depth exceeded (max ${MAX_FEDERATION_DEPTH})`);
  }

  // Build remote MCP request
  const remoteEndpoint = pod_url.replace(/\/+$/, '') + '/mcp';
  const body = {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: tool, arguments: remoteArgs || {} }
  };

  const headers = {
    'Content-Type': 'application/json',
    'MCP-Federation-Depth': String(depth)
  };
  if (auth && typeof auth === 'object') {
    if (auth.type === 'bearer' && auth.token) {
      headers.Authorization = `Bearer ${auth.token}`;
    } else if (auth.type === 'header' && auth.name && auth.value) {
      headers[auth.name] = auth.value;
    }
  }

  let response, payload;
  try {
    response = await fetch(remoteEndpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000)
    });
  } catch (e) {
    return toolError(`remote pod unreachable: ${e.message}`);
  }
  try {
    payload = await response.json();
  } catch (e) {
    return toolError(`remote response not JSON (${response.status}): ${e.message}`);
  }
  if (payload.error) {
    return toolError(`remote MCP error ${payload.error.code}: ${payload.error.message}`);
  }
  return toolJson({
    pod_url,
    tool,
    depth,
    remote_result: payload.result || null
  });
}

// --- pod info ---

async function pod_info(_args, ctx) {
  const skill = await readPodSkill().catch(() => null);
  return toolJson({
    pod: ctx.origin,
    server: 'jss',
    protocolVersion: '2025-03-26',
    identity: ctx.webId || null,
    capabilities: {
      crud: true,
      acl: true,
      skills: true,
      docs: true
    },
    skill: skill ? { path: skill.path, format: skill.format } : null
  });
}

// --- registry ---

export const TOOLS = {
  list_resources: {
    description: 'List contents of an LDP container. Returns child resources and sub-containers.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Container path, must end in /' }
      },
      required: ['path']
    },
    handler: list_resources
  },
  read_resource: {
    description: 'Read the body of a non-container resource (any content type). Returns UTF-8.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path']
    },
    handler: read_resource
  },
  write_resource: {
    description: 'Write (PUT) a resource at the given path. Overwrites if exists.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        content: { type: 'string' },
        contentType: { type: 'string', description: 'MIME type (default text/plain)' }
      },
      required: ['path', 'content']
    },
    handler: write_resource
  },
  create_resource: {
    description: 'Create a child resource in a container (LDP POST). Server mints the name unless slug is provided.',
    inputSchema: {
      type: 'object',
      properties: {
        container: { type: 'string', description: 'Parent container path, must end in /' },
        slug: { type: 'string', description: 'Optional filename hint' },
        content: { type: 'string' },
        contentType: { type: 'string' },
        isContainer: { type: 'boolean', description: 'Create a child container instead of a resource' }
      },
      required: ['container']
    },
    handler: create_resource
  },
  delete_resource: {
    description: 'Delete a resource or empty container.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path']
    },
    handler: delete_resource
  },
  head_resource: {
    description: 'Return metadata (size, modified) for a resource without reading the body.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path']
    },
    handler: head_resource
  },
  list_skills: {
    description: 'List SKILL.md / SKILL.jsonld files at conventional paths (pod-wide, per-app, per-bot).',
    inputSchema: { type: 'object', properties: {} },
    handler: list_skills
  },
  get_skill: {
    description: 'Read a specific skill file by pod path.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path']
    },
    handler: get_skill
  },
  get_pod_skill: {
    description: 'Read the pod-wide SKILL.md (the owner\'s instructions to bots).',
    inputSchema: { type: 'object', properties: {} },
    handler: get_pod_skill
  },
  list_docs: {
    description: 'List JSS\'s built-in docs (markdown files shipped with the server).',
    inputSchema: { type: 'object', properties: {} },
    handler: list_docs
  },
  read_docs: {
    description: 'Read a JSS doc by filename (e.g. "git-support.md", "app-install.md").',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string' } },
      required: ['name']
    },
    handler: read_docs
  },
  pod_info: {
    description: 'Basic pod identity and MCP capabilities.',
    inputSchema: { type: 'object', properties: {} },
    handler: pod_info
  },
  read_acl: {
    description: 'Read the WAC ACL for a resource as a structured list of authorizations. Requires acl:Control.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path']
    },
    handler: read_acl
  },
  write_acl: {
    description: 'Write a structured ACL for a resource. authorizations: [{ agents?, agentClasses?, modes, isDefault? }]. Requires acl:Control.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        authorizations: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              agents: { type: 'array', items: { type: 'string' } },
              agentClasses: { type: 'array', items: { type: 'string', enum: ['foaf:Agent', 'acl:AuthenticatedAgent'] } },
              modes: { type: 'array', items: { type: 'string', enum: ['Read', 'Write', 'Append', 'Control'] } },
              isDefault: { type: 'boolean' }
            },
            required: ['modes']
          }
        }
      },
      required: ['path', 'authorizations']
    },
    handler: write_acl
  },
  subscribe: {
    description: 'Subscribe to change events on a resource or container subtree. Returns an SSE stream of MCP notifications as resources change. WAC-filtered per event.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Container path (with trailing /) to watch a subtree, or exact resource path. Default: / (whole pod, filtered by Read access).' }
      }
    },
    handler: subscribe
  },
  call_remote_pod: {
    description: 'Invoke an MCP tool on another pod. Caller must have acl:Write on /private/federation/ on this pod. Depth-capped at 3.',
    inputSchema: {
      type: 'object',
      properties: {
        pod_url: { type: 'string', description: 'Origin of the remote pod (e.g. https://alice.example.com)' },
        tool: { type: 'string', description: 'Tool name to invoke on the remote' },
        arguments: { type: 'object', description: 'Arguments to pass to the remote tool' },
        auth: {
          type: 'object',
          description: 'Auth for the remote call. Currently { type: "bearer", token } or { type: "header", name, value }. Omit for anonymous.',
          properties: {
            type: { type: 'string', enum: ['bearer', 'header'] },
            token: { type: 'string' },
            name: { type: 'string' },
            value: { type: 'string' }
          }
        }
      },
      required: ['pod_url', 'tool']
    },
    handler: call_remote_pod
  }
};

/**
 * Return the list of tools in MCP tools/list shape.
 */
export function listToolsForRpc() {
  return Object.entries(TOOLS).map(([name, t]) => ({
    name,
    description: t.description,
    inputSchema: t.inputSchema
  }));
}

/**
 * Dispatch a tools/call request.
 */
export async function callTool(name, args, ctx) {
  const tool = TOOLS[name];
  if (!tool) {
    return toolError(`unknown tool: ${name}`);
  }
  try {
    return await tool.handler(args || {}, ctx);
  } catch (e) {
    return toolError(`tool ${name} threw: ${e.message}`);
  }
}
