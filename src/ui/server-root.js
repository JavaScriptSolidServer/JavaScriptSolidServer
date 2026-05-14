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
 * Render the landing page as an HTML string.
 *
 * The page itself is mode-agnostic — it doesn't change based on
 * single-user vs multi-user, and Sign up / Sign in are revealed at
 * load time by an inline HEAD probe against /idp/register. So the
 * same seeded HTML keeps working when the operator changes modes
 * without regenerating the file. See #435.
 *
 * @param {object} ctx
 * @param {string} [ctx.version]   - JSS version (rendered into the info box)
 * @param {boolean} [ctx.singleUser] - Drives the "Mode" label only
 * @param {object} [ctx.enabled]   - Map of feature flags for the pills row
 * @returns {string} HTML
 */
export function renderServerRoot(ctx = {}) {
  const { version = 'unknown', singleUser = false, enabled = {} } = ctx;

  const tpl = readFileSync(TEMPLATE_PATH, 'utf8');
  const mode = singleUser ? 'single-user' : 'multi-user';
  const features = listFeatures(enabled)
    .map(f => `<span>${f}</span>`)
    .join(' ');

  // Single-pass token substitution. Each {{token}} in the original
  // template is matched once and replaced from `values`; substituted
  // text is not re-scanned, so a `$` or stray `{{…}}` in a value
  // can't cause re-substitution or hit String.prototype.replace's
  // `$&` substitution patterns. See #433 review thread.
  const values = {
    title: 'JSS Solid pod',
    version: escape(version),
    mode,
    features
  };
  return tpl.replace(/{{(\w+)}}/g, (match, key) =>
    Object.prototype.hasOwnProperty.call(values, key) ? values[key] : match
  );
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
  //
  // Use './' (relative to the .acl's own URL) rather than '/' (the
  // origin root). The two coincide when JSS is mounted at the origin
  // root, but only the relative form survives reverse-proxy mounts at
  // a path prefix (e.g. https://example/jss/). This matches the
  // pattern used by createPodStructure / createRootPodStructure since
  // #428 / #430.
  //
  // (createRootPodStructure in single-user mode writes its own ACL and
  // runs in a later hook, which will overwrite this if needed.)
  if (!(await storage.exists('/.acl'))) {
    const ok = await storage.write('/.acl', serializeAcl(generatePublicReadAcl('./')));
    if (ok) seededAcl = true;
  }

  // Dedicated ACL for the landing page itself — public read. The container
  // ACL above has no acl:default (we don't want to implicitly publish all
  // children), so /index.html needs its own rule when fetched directly.
  // Same relative-form rationale as above.
  if (!(await storage.exists('/index.html.acl'))) {
    const ok = await storage.write('/index.html.acl', serializeAcl(generatePublicReadAcl('./index.html')));
    if (ok) seededPageAcl = true;
  }

  return { seededHtml, seededAcl, seededPageAcl };
}
