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
import { AccessMode } from '../wac/parser.js';
import { toolText, toolError, toolJson } from './protocol.js';
import { discoverSkills, readSkill, readPodSkill } from './skills.js';
import { readFile, readdir, stat as fsStat } from 'fs/promises';
import { join, dirname, resolve as pathResolve } from 'path';
import { fileURLToPath } from 'url';

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
    items: entries.map(e => ({
      name: e.name,
      path: `${path}${e.name}${e.isContainer ? '/' : ''}`,
      isContainer: e.isContainer,
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
    return toolText(`created container ${childPath}`);
  }
  await storage.write(childPath, Buffer.from(content || '', 'utf8'), {
    contentType: contentType || 'text/plain'
  });
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
