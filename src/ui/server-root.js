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
import { generatePublicReadAcl, serializeAcl } from '../wac/parser.js';

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
  if (options.terminal) f.push('terminal');
  return f;
}

/**
 * Build an HTML snippet of action buttons based on server mode.
 */
function renderActions({ singleUser, idp }) {
  const buttons = [];
  if (!singleUser && idp) {
    buttons.push('<a href="/idp/register" class="btn btn-primary">Create a pod</a>');
    buttons.push('<a href="/idp" class="btn btn-secondary">Sign in</a>');
  } else if (singleUser && idp) {
    buttons.push('<a href="/idp" class="btn btn-primary">Sign in</a>');
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

  // Replacements use the function form, not the string form: a string
  // replacement interprets `$&`, `$1`, etc. as substitution patterns,
  // which would corrupt any interpolated value containing a `$` (e.g.
  // a single-user name). The function form skips that interpretation
  // entirely. See #433.
  return tpl
    .replace(/{{title}}/g, () => heading)
    .replace(/{{heading}}/g, () => heading)
    .replace(/{{subtitle}}/g, () => subtitle)
    .replace(/{{description}}/g, () => description)
    .replace(/{{actions}}/g, () => renderActions({ singleUser, idp }))
    .replace(/{{version}}/g, () => escape(version))
    .replace(/{{mode}}/g, () => mode)
    .replace(/{{features}}/g, () => features);
}

function escape(s = '') {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}


/**
 * Seed DATA_ROOT/index.html, DATA_ROOT/.acl and DATA_ROOT/index.html.acl
 * if they don't already exist. Operator's own files are never overwritten.
 *
 * Default ACL: public read. No write access — the operator edits
 * /index.html on disk, not via the web.
 *
 * If the HTML write fails (permissions, full disk, read-only DATA_ROOT),
 * ACL seeding is aborted to avoid leaving the server with a public-read
 * root ACL and no index page.
 *
 * @param {object} ctx - Same context passed to renderServerRoot
 * @returns {Promise<{seededHtml: boolean, seededAcl: boolean, seededPageAcl: boolean}>}
 */
export async function seedServerRoot(ctx = {}) {
  let seededHtml = false;
  let seededAcl = false;
  let seededPageAcl = false;

  // Seed /index.html if operator hasn't written one.
  if (!(await storage.exists('/index.html'))) {
    const html = renderServerRoot(ctx);
    const ok = await storage.write('/index.html', html);
    if (!ok) {
      // Don't proceed with ACLs if the page itself failed to write —
      // leaves us in a consistent unchanged state.
      return { seededHtml: false, seededAcl: false, seededPageAcl: false };
    }
    seededHtml = true;
  }

  // Seed /.acl if one doesn't already exist. Public read on the container
  // itself — so GET / serves the landing page. Independent of index.html.
  // (createRootPodStructure in single-user mode writes its own ACL and
  // runs in a later hook, which will overwrite this if needed.)
  if (!(await storage.exists('/.acl'))) {
    const ok = await storage.write('/.acl', serializeAcl(generatePublicReadAcl('/')));
    if (ok) seededAcl = true;
  }

  // Dedicated ACL for the landing page itself — public read. The container
  // ACL above has no acl:default (we don't want to implicitly publish all
  // children), so /index.html needs its own rule when fetched directly.
  if (!(await storage.exists('/index.html.acl'))) {
    const ok = await storage.write('/index.html.acl', serializeAcl(generatePublicReadAcl('/index.html')));
    if (ok) seededPageAcl = true;
  }

  return { seededHtml, seededAcl, seededPageAcl };
}
