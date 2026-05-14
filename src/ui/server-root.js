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
 * Render the landing page as an HTML string.
 *
 * The page is mode-agnostic — same HTML for single-user and multi-user.
 * Sign up / Sign in are revealed at load time by an inline HEAD probe
 * against /idp/register, so the seeded file keeps working across mode
 * changes without regeneration. See #435.
 *
 * Only `version` is rendered into the seeded HTML — anything else that
 * varies with server state (mode, enabled features) would go stale on
 * the next mode change because of skip-if-exists.
 *
 * @param {object} ctx
 * @param {string} [ctx.version] - JSS version (shown in the info box)
 * @returns {string} HTML
 */
export function renderServerRoot(ctx = {}) {
  const { version = 'unknown' } = ctx;
  const tpl = readFileSync(TEMPLATE_PATH, 'utf8');

  // Single-pass token substitution. Each {{token}} is matched once
  // against the original template and replaced from `values`;
  // substituted text isn't re-scanned (a `$` or stray `{{…}}` in a
  // value can't cause re-substitution or hit String.prototype.replace's
  // `$&` substitution patterns). See #433 review thread.
  const values = {
    title: 'JSS Solid pod',
    version: escape(version)
  };
  return tpl.replace(/{{(\w+)}}/g, (match, key) =>
    Object.prototype.hasOwnProperty.call(values, key) ? values[key] : match
  );
}

/**
 * Decide which conditional buttons (Sign up, Sign in) to reveal based
 * on the response status of `HEAD /idp/register`. Pure function so the
 * 200 / 403 / 404 matrix can be unit-tested without DOM. The inline
 * script in server-root.html implements the same matrix literally;
 * keep them in sync.
 *
 *   200 → registration open: reveal both Sign up and Sign in
 *   403 → IDP enabled but registration disabled (single-user mode):
 *         reveal Sign in only
 *   anything else (404, network error) → reveal neither (no IDP)
 *
 * @param {number|undefined} status - HTTP status code, or undefined for
 *   network error.
 * @returns {{ register: boolean, login: boolean }}
 */
export function decideRevealForRegisterStatus(status) {
  if (status === 200) return { register: true, login: true };
  if (status === 403) return { register: false, login: true };
  return { register: false, login: false };
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
