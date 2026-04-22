/**
 * Server-root landing page.
 *
 * Renders src/ui/server-root.html with runtime values, and seeds
 * DATA_ROOT/index.html + DATA_ROOT/.acl on first start (skip-if-exists,
 * so operator customisation is preserved).
 *
 * See issue #276.
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import * as storage from '../storage/filesystem.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATE_PATH = join(__dirname, 'server-root.html');

/**
 * Collect the list of enabled features for display on the landing page.
 */
function listFeatures(options = {}) {
  const f = [];
  if (options.idp) f.push('idp');
  if (options.nostr) f.push('nostr');
  if (options.webrtc) f.push('webrtc');
  if (options.activitypub) f.push('activitypub');
  if (options.git) f.push('git');
  if (options.pay) f.push('payments');
  if (options.notifications) f.push('notifications');
  if (options.mashlib) f.push('mashlib');
  if (options.mongo) f.push('mongo');
  if (options.tunnel) f.push('tunnel');
  return f;
}

/**
 * Build an HTML snippet of action buttons based on server mode.
 */
function renderActions({ singleUser, idp }) {
  const buttons = [];
  if (!singleUser && idp) {
    buttons.push('<a href="/.account/new" class="btn btn-primary">Create a pod</a>');
    buttons.push('<a href="/idp/auth" class="btn btn-secondary">Sign in</a>');
  } else if (singleUser && idp) {
    buttons.push('<a href="/idp/auth" class="btn btn-primary">Sign in</a>');
  }
  buttons.push('<a href="https://javascriptsolidserver.github.io/docs/" class="btn btn-secondary">Docs</a>');
  return `<div class="actions">${buttons.join('\n      ')}</div>`;
}

/**
 * Render the landing page as an HTML string.
 *
 * @param {object} ctx
 * @param {string} ctx.version - JSS version
 * @param {boolean} [ctx.singleUser]
 * @param {boolean} [ctx.idp]
 * @param {string} [ctx.singleUserName]
 * @param {object} [ctx.enabled] - Map of feature flags
 * @returns {string} HTML
 */
export function renderServerRoot(ctx = {}) {
  const { version = 'unknown', singleUser = false, idp = false, singleUserName, enabled = {} } = ctx;

  const tpl = readFileSync(TEMPLATE_PATH, 'utf8');
  const mode = singleUser ? 'single-user' : 'multi-user';
  const features = listFeatures(enabled)
    .map(f => `<span>${f}</span>`)
    .join(' ');

  const heading = 'JSS';
  const subtitle = singleUser
    ? `Personal pod${singleUserName && singleUserName !== '/' ? ` for ${escape(singleUserName)}` : ''}`
    : 'A personal data server';
  const description = singleUser
    ? 'This server hosts a personal data pod. Apps come to the data rather than the other way around.'
    : 'This server hosts personal data pods on the web. Each pod is a space you own, with your own identity and access control.';

  return tpl
    .replace(/{{title}}/g, heading)
    .replace(/{{heading}}/g, heading)
    .replace(/{{subtitle}}/g, subtitle)
    .replace(/{{description}}/g, description)
    .replace(/{{actions}}/g, renderActions({ singleUser, idp }))
    .replace(/{{version}}/g, escape(version))
    .replace(/{{mode}}/g, mode)
    .replace(/{{features}}/g, features);
}

function escape(s = '') {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Seed DATA_ROOT/index.html and DATA_ROOT/.acl if they don't already
 * exist. Operator's own files are never overwritten.
 *
 * Default ACL at root: public read. Write access is not granted — the
 * operator edits the file on disk, not via the web.
 *
 * @param {object} ctx - Same context passed to renderServerRoot
 * @returns {Promise<{seeded: boolean}>}
 */
export async function seedServerRoot(ctx = {}) {
  let seededHtml = false;
  let seededAcl = false;

  // Seed /index.html if operator hasn't written one.
  if (!(await storage.exists('/index.html'))) {
    const html = renderServerRoot(ctx);
    await storage.write('/index.html', html);
    seededHtml = true;
  }

  // Seed /.acl if one doesn't already exist. Public read on the container
  // itself — so GET / serves the landing page. Independent of index.html.
  // (createRootPodStructure in single-user mode writes its own ACL and
  // runs in a later hook, which will overwrite this if needed.)
  if (!(await storage.exists('/.acl'))) {
    const acl = JSON.stringify({
      '@context': { acl: 'http://www.w3.org/ns/auth/acl#', foaf: 'http://xmlns.com/foaf/0.1/' },
      '@graph': [
        {
          '@id': '#public',
          '@type': 'acl:Authorization',
          'acl:agentClass': { '@id': 'foaf:Agent' },
          'acl:accessTo': { '@id': '/' },
          'acl:mode': [{ '@id': 'acl:Read' }]
        }
      ]
    }, null, 2);
    await storage.write('/.acl', acl);
    seededAcl = true;
  }

  // Dedicated ACL for the landing page itself — public read. The container
  // ACL above has no acl:default (we don't want to implicitly publish all
  // children), so /index.html needs its own rule when fetched directly.
  if (!(await storage.exists('/index.html.acl'))) {
    const pageAcl = JSON.stringify({
      '@context': { acl: 'http://www.w3.org/ns/auth/acl#', foaf: 'http://xmlns.com/foaf/0.1/' },
      '@graph': [
        {
          '@id': '#public',
          '@type': 'acl:Authorization',
          'acl:agentClass': { '@id': 'foaf:Agent' },
          'acl:accessTo': { '@id': '/index.html' },
          'acl:mode': [{ '@id': 'acl:Read' }]
        }
      ]
    }, null, 2);
    await storage.write('/index.html.acl', pageAcl);
  }

  return { seededHtml, seededAcl };
}
