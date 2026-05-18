/**
 * Skill discovery for the MCP server.
 *
 * Skills are SKILL.md files (or SKILL.jsonld) at well-known paths:
 *
 *   <pod>/SKILL.md                       pod-wide
 *   <pod>/public/apps/<name>/SKILL.md    per-app
 *   <pod>/private/bots/<name>/SKILL.md   per-bot
 *
 * The discovery channel (list_skills) is stable; the payload format
 * declared via `skill:format` evolves (anthropic.skill.v1 today,
 * future vocabularies plug in by name).
 */

import * as storage from '../storage/filesystem.js';

const POD_ROOT_SKILL = ['/SKILL.md', '/SKILL.jsonld'];
const APPS_BASE = '/public/apps/';
const BOTS_BASE = '/private/bots/';

function formatForPath(path) {
  if (path.endsWith('.jsonld')) return 'jsonld';
  return 'anthropic.skill.v1';
}

function scopeFromPath(path) {
  if (path.startsWith(APPS_BASE)) return 'app';
  if (path.startsWith(BOTS_BASE)) return 'bot';
  return 'pod';
}

async function tryEntry(path) {
  for (const variant of [path, path.replace(/\.md$/, '.jsonld')]) {
    if (await storage.exists(variant)) {
      const s = await storage.stat(variant).catch(() => null);
      return {
        '@id': variant,
        'skill:scope': scopeFromPath(variant),
        'skill:format': formatForPath(variant),
        'skill:source': variant,
        'schema:contentSize': s?.size ?? null
      };
    }
  }
  return null;
}

async function listContainerNames(containerPath) {
  if (!(await storage.exists(containerPath))) return [];
  try {
    const entries = await storage.listContainer(containerPath);
    return entries
      .filter(e => e.isDirectory)
      .map(e => e.name);
  } catch {
    return [];
  }
}

/**
 * Walk the conventional skill locations and return discovered skills.
 */
export async function discoverSkills() {
  const items = [];

  // Pod-wide
  for (const p of POD_ROOT_SKILL) {
    if (await storage.exists(p)) {
      items.push({
        '@id': p,
        'skill:scope': 'pod',
        'skill:format': formatForPath(p),
        'skill:source': p,
        'schema:name': 'pod'
      });
      break;
    }
  }

  // Apps
  for (const name of await listContainerNames(APPS_BASE)) {
    const skill = await tryEntry(`${APPS_BASE}${name}/SKILL.md`);
    if (skill) {
      skill['schema:name'] = name;
      items.push(skill);
    }
  }

  // Bots
  for (const name of await listContainerNames(BOTS_BASE)) {
    const skill = await tryEntry(`${BOTS_BASE}${name}/SKILL.md`);
    if (skill) {
      skill['schema:name'] = name;
      items.push(skill);
    }
  }

  return {
    '@context': {
      skill: 'urn:skill:',
      schema: 'https://schema.org/'
    },
    '@type': 'skill:SkillIndex',
    'skill:items': items
  };
}

/**
 * Read a single skill file by path (relative to pod root).
 */
export async function readSkill(path) {
  if (!path || typeof path !== 'string') {
    throw new Error('skill path required');
  }
  if (!path.startsWith('/')) path = '/' + path;
  if (!(await storage.exists(path))) {
    throw new Error(`skill not found: ${path}`);
  }
  const content = await storage.read(path);
  return {
    path,
    format: formatForPath(path),
    scope: scopeFromPath(path),
    body: content.toString('utf8')
  };
}

/**
 * Read the pod-wide SKILL.md (or .jsonld). Returns null if none exists.
 */
export async function readPodSkill() {
  for (const p of POD_ROOT_SKILL) {
    if (await storage.exists(p)) {
      return readSkill(p);
    }
  }
  return null;
}
