/**
 * `jss install <name>` — install a Solid app into a running pod.
 *
 * Phase 1 of #464 (see #478 for the scoped issue). Hardcodes the
 * default registry to `github.com/solid-apps/<name>`. Later phases
 * add `<org>/<repo>` shorthand, full URLs, `#<ref>` pinning,
 * `=<name>` rename, `--did` resolution, `--nostr-privkey` NIP-98
 * auth, a curated default set, and `--bundle`.
 *
 * The install is a thin shell over the auto-init + updateInstead +
 * regular-repo machinery already in `src/handlers/git.js`:
 *
 *   1. POST <pod>/idp/credentials with the supplied creds → bearer token
 *   2. `git clone <source> /tmp/<name>` (full clone — shallow pushes
 *      are rejected by JSS git-receive)
 *   3. Push the clone to `<pod>/public/apps/<name>` with the bearer
 *      header, on BOTH `HEAD:main` and `HEAD:gh-pages` so it works
 *      regardless of the operator's `init.defaultBranch`. Whichever
 *      matches server-side HEAD triggers `updateInstead` and extracts
 *      the working tree; the other creates a stranded ref.
 *
 * Idempotent on re-run (existing repo at the path accepts the push
 * normally). Skip-on-existing-non-repo translates auto-init's
 * "won't init a non-empty path" 404 into a friendly message.
 */

import { spawnSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';
import { nip98Token } from '../nostr/event.js';

// ANSI helpers — keep zero-dep so this works in any embedded usage.
const c = (n) => (s) => `\x1b[${n}m${s}\x1b[0m`;
const green = c(32);
const yellow = c(33);
const red = c(31);
const dim = c(2);
const bold = c(1);

/**
 * Parse an app spec. Accepts (Phase 2 of #464):
 *   - bare name              → github.com/solid-apps/<name>  (default registry)
 *   - "<org>/<repo>"         → github.com/<org>/<repo>
 *   - "https://..." full URL → as-is (must point at a git repo)
 * Each form may carry an optional "#<ref>" suffix to pin a tag or branch:
 *   chrome#v1.2 / solid-apps/chrome#main / https://...#v2
 * And an optional "=<name>" suffix to override the pod-path name:
 *   litecut/litecut.github.io=litecut
 */
function parseAppSpec(input) {
  // Pull off the rename suffix first, then the ref suffix.
  let base = input;
  let renameName = null;
  const eqIx = base.lastIndexOf('=');
  if (eqIx > 0) {
    renameName = base.slice(eqIx + 1);
    base = base.slice(0, eqIx);
  }
  let ref = null;
  const hashIx = base.lastIndexOf('#');
  if (hashIx > 0) {
    ref = base.slice(hashIx + 1) || null;
    base = base.slice(0, hashIx);
  }
  let source, name;
  if (/^https?:\/\//.test(base)) {
    source = base.replace(/\.git$/, '').replace(/\/$/, '');
    name = source.split('/').pop();
  } else if (base.includes('/')) {
    const cleaned = base.replace(/\.git$/, '').replace(/^\/+|\/+$/g, '');
    if (cleaned.split('/').length !== 2) {
      return { error: 'expected <org>/<repo> shorthand' };
    }
    source = `https://github.com/${cleaned}`;
    name = cleaned.split('/').pop();
  } else {
    source = `https://github.com/solid-apps/${base}`;
    name = base;
  }
  if (renameName) name = renameName;
  if (!/^[a-z0-9][a-z0-9_.-]*$/i.test(name)) {
    return { error: `invalid pod-path name "${name}"` };
  }
  if (ref && !/^[a-z0-9][a-z0-9_./-]*$/i.test(ref)) {
    return { error: `invalid ref "${ref}"` };
  }
  return { source, name, ref };
}

/**
 * Fetch a bearer token from the pod's IDP, or null if the pod runs
 * with `--public` (no auth required for writes).
 */
async function fetchToken({ pod, user, password }) {
  // First check whether the pod accepts unauthenticated writes — if so,
  // we don't need a token. Probe with HEAD on /public/ (which any pod
  // exposes); if writes there require auth, we'll need the token.
  // For Phase 1 we just always try to fetch a token; if the IDP isn't
  // running, we fall through with a clear error.
  try {
    const r = await fetch(`${pod}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: user, password })
    });
    if (r.status === 404) {
      // No IDP — pod is likely in --public mode. Proceed without a token.
      return null;
    }
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    if (!j.access_token) throw new Error('no access_token in response');
    return j.access_token;
  } catch (e) {
    throw new Error(`Could not authenticate against ${pod}: ${e.message}`);
  }
}

/**
 * Install one app spec to one pod. Returns a status object the caller
 * uses for per-app output + exit-code aggregation.
 */
async function installOne({ spec, pod, token, nostrPrivkey }) {
  const { source, name, ref } = spec;
  const dest = `${pod}/public/apps/${name}`;
  const tmp = join('/tmp', `jss-install-${name}-${process.pid}`);

  // Clean any stale tmp from a prior failed run.
  if (existsSync(tmp)) spawnSync('rm', ['-rf', tmp], { stdio: 'ignore' });

  // Clone (no --depth: shallow pushes are rejected by JSS git-receive).
  // --branch picks a tag or branch when pinned (e.g. `foo/bar#v2`).
  const cloneArgs = ['clone', '--quiet'];
  if (ref) cloneArgs.push('--branch', ref);
  cloneArgs.push(source, tmp);
  const clone = spawnSync('git', cloneArgs, {
    stdio: ['ignore', 'pipe', 'pipe']
  });
  if (clone.status !== 0) {
    const err = clone.stderr?.toString?.().trim() || '';
    return { name, status: 'failed', reason: `clone failed${err ? `: ${err.slice(0, 300)}` : ''}` };
  }

  // Build the Authorization header for the push. NIP-98 (Phase 4)
  // signs a Nostr event with the user's Schnorr key — no IDP creds
  // needed; JSS verifies via src/auth/token.js and returns a
  // did:nostr:<hex> identity for ACL matching.
  //
  // Git makes BOTH an advertise GET (`info/refs?service=git-receive-pack`)
  // and a receive POST (`git-receive-pack`) on the same http.extraHeader.
  // JSS is lenient for git clients (src/auth/nostr.js): it accepts a
  // NIP-98 event whose `u` is a prefix of the request URL, and whose
  // `method` is `*` as a wildcard. Sign the base URL with method `*`
  // so the same event passes auth on both requests.
  const authHeader = () => {
    if (nostrPrivkey) {
      const b64 = nip98Token(dest, '*', nostrPrivkey);
      return `Authorization: Nostr ${b64}`;
    }
    if (token) return `Authorization: Bearer ${token}`;
    return null;
  };

  // Dual push: HEAD:main and HEAD:gh-pages. Whichever matches server-
  // side HEAD triggers updateInstead and extracts the working tree.
  // The other just creates a stranded ref (harmless). Idempotent.
  // Each push gets a freshly-signed NIP-98 event (the signature is
  // tied to a specific u + method + timestamp window).
  const pushArgs = (branch) => {
    const args = ['-C', tmp];
    const auth = authHeader();
    if (auth) args.push('-c', `http.extraHeader=${auth}`);
    args.push('push', dest, `HEAD:${branch}`);
    return args;
  };

  const pushMain = spawnSync('git', pushArgs('main'), { stdio: ['ignore', 'pipe', 'pipe'] });
  const errMain = pushMain.stderr?.toString?.() || '';

  // Auto-init refuses on a non-empty target dir → 404 / "not found".
  // Distinguish "path already in use" from real errors.
  if (pushMain.status !== 0 && (errMain.includes('not found') || errMain.includes('404'))) {
    spawnSync('rm', ['-rf', tmp], { stdio: 'ignore' });
    return { name, status: 'skipped', reason: 'path already in use' };
  }

  const pushPages = spawnSync('git', pushArgs('gh-pages'), { stdio: ['ignore', 'pipe', 'pipe'] });

  if (pushMain.status !== 0 && pushPages.status !== 0) {
    const err = (errMain + '\n' + (pushPages.stderr?.toString?.() || '')).trim();
    spawnSync('rm', ['-rf', tmp], { stdio: 'ignore' });
    return { name, status: 'failed', reason: `push failed: ${err.slice(0, 400)}` };
  }

  spawnSync('rm', ['-rf', tmp], { stdio: 'ignore' });
  return { name, status: 'installed', dest: `${dest}/` };
}

/**
 * Public entry point. Called from bin/jss.js's `install` subcommand
 * action. Throws to signal a non-zero exit; returns normally for
 * partial success (per-app errors are reported but don't fail-fast).
 */
export async function runInstall(names, options) {
  const pod = (options.pod || 'http://localhost:4443').replace(/\/$/, '');
  const user = options.user || 'me';
  const password = options.password || process.env.JSS_SINGLE_USER_PASSWORD || 'me';
  const nostrPrivkey = options.nostrPrivkey || process.env.NOSTR_PRIVKEY || null;

  if (!names || names.length === 0) {
    throw new Error('expected at least one app name. Try: `jss install chrome`');
  }

  // Validate Nostr privkey if supplied (64 lowercase-hex chars).
  if (nostrPrivkey && !/^[0-9a-f]{64}$/i.test(nostrPrivkey)) {
    console.error(red('✗ --nostr-privkey must be 64 hex chars'));
    throw new Error('invalid --nostr-privkey');
  }

  // Validate every spec up front so we report invalid names before
  // doing any network work.
  const specs = [];
  for (const n of names) {
    const spec = parseAppSpec(n);
    if (spec.error) {
      console.error(red(`✗ ${n}: ${spec.error}`));
      throw new Error(`invalid app spec: ${n}`);
    }
    specs.push(spec);
  }

  console.log(bold(`\nInstalling ${specs.length} app${specs.length === 1 ? '' : 's'} → `) + green(pod));
  if (nostrPrivkey) console.log(dim('  (signing with Nostr privkey — NIP-98)'));
  console.log('');

  // With --nostr-privkey we sign each push as NIP-98; no bearer token
  // needed. Otherwise fetch the bearer token from the pod's IDP.
  let token = null;
  if (!nostrPrivkey) try {
    token = await fetchToken({ pod, user, password });
  } catch (e) {
    console.error(red(`✗ ${e.message}`));
    console.error(dim('  Is the pod running? Try: `jss start`'));
    throw e;
  }

  // Decode hex privkey once for installOne (nip98Token wants bytes).
  const privkeyBytes = nostrPrivkey
    ? Uint8Array.from(Buffer.from(nostrPrivkey, 'hex'))
    : null;

  let okCount = 0;
  let failCount = 0;
  for (const spec of specs) {
    const result = await installOne({ spec, pod, token, nostrPrivkey: privkeyBytes });
    switch (result.status) {
      case 'installed':
        console.log(green(`✓ ${result.name}`) + dim(` → ${result.dest}`));
        okCount++;
        break;
      case 'skipped':
        console.log(yellow(`⊘ ${result.name}`) + dim(`: skipped (${result.reason})`));
        break;
      case 'failed':
        console.error(red(`✗ ${result.name}: ${result.reason.split(':')[0]}`));
        if (result.reason.includes(':')) {
          console.error(dim(`  ${result.reason.slice(result.reason.indexOf(':') + 1).trim()}`));
        }
        failCount++;
        break;
    }
  }

  console.log('');
  console.log(bold(`${okCount}/${specs.length} installed.`));
  if (okCount > 0) {
    console.log(dim('Open in browser: ') + `${pod}/public/apps/`);
  }

  if (failCount > 0) {
    throw new Error(`${failCount} of ${specs.length} install(s) failed`);
  }
}
