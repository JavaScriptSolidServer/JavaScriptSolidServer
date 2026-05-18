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

// ANSI helpers — keep zero-dep so this works in any embedded usage.
const c = (n) => (s) => `\x1b[${n}m${s}\x1b[0m`;
const green = c(32);
const yellow = c(33);
const red = c(31);
const dim = c(2);
const bold = c(1);

/**
 * Parse a Phase-1 app name. Strict: lowercase alphanumeric with
 * underscore / dot / dash, must start with alphanumeric. Phase 2 will
 * relax this to accept `<org>/<repo>`, URLs, `#ref`, `=rename`.
 */
function parseAppSpec(input) {
  if (!/^[a-z0-9][a-z0-9_.-]*$/i.test(input)) {
    return { error: `invalid app name "${input}" (expected lowercase alphanumeric, dots, dashes, underscores)` };
  }
  return {
    source: `https://github.com/solid-apps/${input}`,
    name: input
  };
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
async function installOne({ spec, pod, token }) {
  const { source, name } = spec;
  const dest = `${pod}/public/apps/${name}`;
  const tmp = join('/tmp', `jss-install-${name}-${process.pid}`);

  // Clean any stale tmp from a prior failed run.
  if (existsSync(tmp)) spawnSync('rm', ['-rf', tmp], { stdio: 'ignore' });

  // Clone (no --depth: shallow pushes are rejected by JSS git-receive).
  const clone = spawnSync('git', ['clone', '--quiet', source, tmp], {
    stdio: ['ignore', 'pipe', 'pipe']
  });
  if (clone.status !== 0) {
    const err = clone.stderr?.toString?.().trim() || '';
    return { name, status: 'failed', reason: `clone failed${err ? `: ${err.slice(0, 300)}` : ''}` };
  }

  // Dual push: HEAD:main and HEAD:gh-pages. Whichever matches server-
  // side HEAD triggers updateInstead and extracts the working tree.
  // The other just creates a stranded ref (harmless). Idempotent.
  const pushArgs = (branch) => {
    const args = ['-C', tmp];
    if (token) args.push('-c', `http.extraHeader=Authorization: Bearer ${token}`);
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

  if (!names || names.length === 0) {
    throw new Error('expected at least one app name. Try: `jss install chrome`');
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
  console.log('');

  let token;
  try {
    token = await fetchToken({ pod, user, password });
  } catch (e) {
    console.error(red(`✗ ${e.message}`));
    console.error(dim('  Is the pod running? Try: `jss start`'));
    throw e;
  }

  let okCount = 0;
  let failCount = 0;
  for (const spec of specs) {
    const result = await installOne({ spec, pod, token });
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
