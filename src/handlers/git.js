import { spawn, spawnSync, execSync } from 'child_process';
import { existsSync, statSync, mkdirSync, readdirSync, writeFileSync } from 'fs';
import { join, resolve, dirname } from 'path';
import { getDataRoot } from '../utils/url.js';

/**
 * Check if a URL path is a Git protocol request
 * @param {string} urlPath - The URL path
 * @returns {boolean}
 */
export function isGitRequest(urlPath) {
  return urlPath.includes('/info/refs') ||
    urlPath.includes('/git-upload-pack') ||
    urlPath.includes('/git-receive-pack');
}

/**
 * Determine if this is a write operation (push)
 * @param {string} urlPath - The URL path
 * @returns {boolean}
 */
export function isGitWriteOperation(urlPath) {
  return urlPath.includes('/git-receive-pack') || urlPath.includes('service=git-receive-pack');
}

/**
 * Extract the repository path from the URL with path traversal protection.
 * Always returns a non-empty string: '.' for root/empty URL paths, the
 * cleaned relative path otherwise.
 * @param {string} urlPath - The URL path
 * @returns {string} The repository relative path ('.' for root)
 */
function extractRepoPath(urlPath) {
  // Remove git service suffixes to get the repo path
  let cleanPath = urlPath
    .replace(/\/info\/refs.*$/, '')
    .replace(/\/git-upload-pack$/, '')
    .replace(/\/git-receive-pack$/, '');

  // Remove leading slash
  cleanPath = cleanPath.replace(/^\//, '');

  // Security: remove path traversal attempts (multiple passes for ....// bypass)
  let previous;
  do {
    previous = cleanPath;
    cleanPath = cleanPath.replace(/\.\./g, '');
  } while (cleanPath !== previous);

  // Use '.' for root/empty path
  return cleanPath === '' ? '.' : cleanPath;
}

/**
 * Validate that a resolved path is within the data root
 * @param {string} resolvedPath - Absolute path to validate
 * @param {string} dataRoot - The data root directory
 * @returns {boolean} - true if path is safe
 */
function isPathWithinDataRoot(resolvedPath, dataRoot) {
  const normalizedRoot = resolve(dataRoot);
  const normalizedPath = resolve(resolvedPath);
  return normalizedPath.startsWith(normalizedRoot + '/') || normalizedPath === normalizedRoot;
}

/**
 * Find the git directory for a path
 * @param {string} repoPath - Absolute path to check
 * @returns {{gitDir: string, isRegular: boolean}|null}
 */
function findGitDir(repoPath) {
  if (!existsSync(repoPath) || !statSync(repoPath).isDirectory()) {
    return null;
  }

  // Check for regular repo with .git subdirectory
  const dotGitPath = join(repoPath, '.git');
  if (existsSync(dotGitPath) && statSync(dotGitPath).isDirectory()) {
    return { gitDir: dotGitPath, isRegular: true };
  }

  // Check for bare repository
  const objectsPath = join(repoPath, 'objects');
  const refsPath = join(repoPath, 'refs');
  if (existsSync(objectsPath) && existsSync(refsPath)) {
    return { gitDir: repoPath, isRegular: false };
  }

  return null;
}

/**
 * Auto-initialize a regular (non-bare) git repo at repoAbs to accept a
 * first push, but only when it's safe to do so. The caller must invoke
 * this *after* the standard ACL Write check has passed (i.e. inside the
 * existing preHandler-gated path for `git-receive-pack`), so
 * authorization is already enforced.
 *
 * Regular (not bare): the repo has a `.git/` subdirectory plus a
 * working tree. Combined with the `receive.denyCurrentBranch
 * updateInstead` config the main handler sets on every push, the
 * working tree is auto-extracted on each push. This means pushed files
 * appear as static resources at the corresponding pod URL — the "apps
 * live in pods" install pattern works end-to-end. (Bare repos store
 * content in pack files only, so a pushed `index.html` wouldn't be
 * servable as HTTP.)
 *
 * Safe iff one of:
 *   - the target path does not exist (we create it), or
 *   - the target path exists, is a directory, and is empty.
 *
 * Refuses (returns null) for any other state — most importantly when the
 * directory contains non-`.git` files, so we don't risk corrupting a
 * user-content directory (e.g. /public/apps/foo with regular files) by
 * promoting it into a git repo.
 *
 * Uses spawnSync with an arg array (no shell interpolation). On any
 * failure (missing `git`, permission denied, init exits non-zero) the
 * caller falls through to the normal 404, with the underlying cause
 * surfaced to the request logger so operators can diagnose.
 *
 * SYMLINK CAVEAT: this function relies on the caller's path-string
 * containment check (isPathWithinDataRoot) which does not follow
 * symlinks. If an attacker with Write ACL has placed a symlink under
 * dataRoot pointing outside, statSync/readdirSync/spawnSync here will
 * dereference it. That's a pre-existing weakness of the JSS handler,
 * not introduced by auto-init — fixing it requires realpath
 * normalisation across every write path in the handler, out of scope
 * for this PR. Hardening tracked for a follow-up.
 *
 * @param {string} repoAbs - absolute path to the candidate repo
 * @param {object} [log] - optional Fastify request logger for diagnostics
 * @returns {{gitDir: string, isRegular: boolean}|null}
 */
function tryAutoInitRepo(repoAbs, log) {
  try {
    if (existsSync(repoAbs)) {
      if (!statSync(repoAbs).isDirectory()) return null;
      if (readdirSync(repoAbs).length > 0) return null;
    } else {
      mkdirSync(repoAbs, { recursive: true });
    }
    // Pin the initial branch to `main` regardless of the server's
    // `init.defaultBranch` config. `receive.denyCurrentBranch
    // updateInstead` only extracts the working tree when the push
    // targets the branch HEAD points at, so a deterministic default
    // keeps `git push pod HEAD:main` working on every deployment. See
    // #471.
    const result = spawnSync('git', ['init', '-b', 'main', repoAbs], {
      stdio: ['ignore', 'pipe', 'pipe']
    });
    if (result.status !== 0) {
      log?.warn?.(
        { repoAbs, status: result.status, stderr: result.stderr?.toString?.().slice(0, 500) },
        'git auto-init: `git init` exited non-zero'
      );
      return null;
    }
    const info = findGitDir(repoAbs);
    if (info) log?.info?.({ repoAbs }, 'git auto-init: repo created on first push');
    return info;
  } catch (err) {
    log?.warn?.({ err, repoAbs }, 'git auto-init: refusing to init (filesystem error)');
    return null;
  }
}

// CORS headers for git responses. Single source of truth — used by the
// success path (Fastify reply on the OPTIONS preflight, raw stream on
// http-backend output), by every 4xx early-return in this module, and
// by the WAC preHandler's 401/402/403 returns in src/server.js (#548).
// Without these, browser-based git clients (e.g. jss.live/git/) see a
// generic CORS/network error instead of the actual status,
// undermining #371.
const GIT_CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, Git-Protocol',
};

export function setGitCorsHeaders(reply) {
  for (const [k, v] of Object.entries(GIT_CORS_HEADERS)) {
    reply.header(k, v);
  }
}

/**
 * Handle Git HTTP requests using git http-backend
 * @param {FastifyRequest} request
 * @param {FastifyReply} reply
 */
export async function handleGit(request, reply) {
  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    setGitCorsHeaders(reply);
    return reply.code(200).send();
  }

  // Collapse multi-slash sequences before they reach extractRepoPath or
  // get forwarded as PATH_INFO. git http-backend rejects paths like
  // `/foo/test//info/refs` as "aliased" and JSS would otherwise 500.
  // Frontends and bots both produce these (frontend appends `/info/refs`
  // to a URL the user ended with `/`, bots probe `///wp-admin/...`).
  // Same shape as the LDP fix in src/utils/url.js (#131).
  //
  // Note: Fastify's URL parser rejects malformed percent-encoding
  // (`%g1`, truncated `%E0%`, invalid UTF-8 like `%C3%28`) with a 400
  // FST_ERR_BAD_URL before this handler runs — verified empirically — so
  // decodeURIComponent here is safe in practice on current Fastify.
  let urlPath = decodeURIComponent(request.url.split('?')[0]);
  urlPath = urlPath.replace(/\/{2,}/g, '/');
  const queryString = request.url.split('?')[1] || '';

  // extractRepoPath always returns a non-empty string ('.' for root) —
  // no null check needed.
  const repoRelative = extractRepoPath(urlPath);

  // Handle subdomain mode
  let dataRoot = getDataRoot();
  if (request.podName) {
    dataRoot = join(dataRoot, request.podName);
  }

  const repoAbs = resolve(dataRoot, repoRelative);

  // Security: verify resolved path is within data root (path traversal protection)
  if (!isPathWithinDataRoot(repoAbs, getDataRoot())) {
    setGitCorsHeaders(reply);
    return reply.code(403).send({ error: 'Path traversal detected' });
  }

  // Find git directory. On a push (`git-receive-pack`) to a path that
  // doesn't yet contain a repo, auto-init one if the location is safe
  // to claim — the standard preHandler has already verified ACL Write
  // on this path, so authorization is enforced. See tryAutoInitRepo
  // for the safety conditions (empty / non-existent path only; refuses
  // to clobber existing files). Auto-init creates a regular (non-bare)
  // repo so the `denyCurrentBranch updateInstead` config below
  // auto-extracts the working tree on each push — pushed files become
  // static resources at the corresponding pod URL.
  let gitInfo = findGitDir(repoAbs);
  if (!gitInfo && isGitWriteOperation(request.url)) {
    gitInfo = tryAutoInitRepo(repoAbs, request.log);
  }
  if (!gitInfo) {
    setGitCorsHeaders(reply);
    return reply.code(404).send({ error: 'Not a git repository' });
  }

  // Auto-configure repos to accept pushes (check full URL for query string)
  if (isGitWriteOperation(request.url)) {
    try {
      // Enable receive-pack for HTTP push
      execSync('git config http.receivepack true', {
        cwd: repoAbs,
        env: { ...process.env, GIT_DIR: gitInfo.gitDir }
      });
      // For non-bare repos, auto-update working directory after push
      if (gitInfo.isRegular) {
        execSync('git config receive.denyCurrentBranch updateInstead', {
          cwd: repoAbs,
          env: { ...process.env, GIT_DIR: gitInfo.gitDir }
        });
      }
    } catch (e) {
      // Ignore config errors - repo may still work
    }
  }

  // Build CGI environment
  const env = {
    ...process.env,
    GIT_PROJECT_ROOT: dataRoot,
    GIT_HTTP_EXPORT_ALL: '',                    // Allow read access
    GIT_HTTP_RECEIVE_PACK: 'true',              // Enable push
    GIT_CONFIG_PARAMETERS: "'uploadpack.allowTipSHA1InWant=true'",
    PATH_INFO: urlPath,
    REQUEST_METHOD: request.method,
    CONTENT_TYPE: request.headers['content-type'] || '',
    QUERY_STRING: queryString,
    REMOTE_USER: request.webId || '',           // Pass authenticated user
    CONTENT_LENGTH: request.headers['content-length'] || '0',
  };

  // For regular repositories, set GIT_DIR
  if (gitInfo.isRegular) {
    env.GIT_DIR = gitInfo.gitDir;
  }

  // Spawn git http-backend
  return new Promise((resolve, reject) => {
    const child = spawn('git', ['http-backend'], { env });

    let buffer = Buffer.alloc(0);
    let headersSent = false;

    child.stdout.on('data', (data) => {
      buffer = Buffer.concat([buffer, data]);

      if (!headersSent) {
        // Look for end of CGI headers (try both \r\n\r\n and \n\n)
        let headerEnd = buffer.indexOf('\r\n\r\n');
        let headerSep = '\r\n';
        let headerEndLen = 4;

        if (headerEnd === -1) {
          headerEnd = buffer.indexOf('\n\n');
          headerSep = '\n';
          headerEndLen = 2;
        }

        if (headerEnd !== -1) {
          const headerSection = buffer.subarray(0, headerEnd).toString();
          const bodySection = buffer.subarray(headerEnd + headerEndLen);

          // Parse CGI headers and set on raw response
          const lines = headerSection.split(headerSep);
          let statusCode = 200;

          for (const line of lines) {
            const colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
              const key = line.substring(0, colonIndex).trim();
              const value = line.substring(colonIndex + 1).trim();

              // Handle Status header specially
              if (key.toLowerCase() === 'status') {
                statusCode = parseInt(value.split(' ')[0], 10);
              } else {
                reply.raw.setHeader(key, value);
              }
            }
          }

          // Add CORS headers for browser git clients (same set as the
          // 4xx return paths, kept in sync via GIT_CORS_HEADERS).
          for (const [k, v] of Object.entries(GIT_CORS_HEADERS)) {
            reply.raw.setHeader(k, v);
          }

          reply.raw.writeHead(statusCode);
          headersSent = true;
          reply.raw.write(bodySection);
          buffer = Buffer.alloc(0);
        }
      } else {
        reply.raw.write(buffer);
        buffer = Buffer.alloc(0);
      }
    });

    child.stdout.on('end', () => {
      reply.raw.end();
      resolve();
    });

    // Send request body to git
    // For POST requests, Fastify has already parsed the body into request.body
    if (request.body && request.body.length > 0) {
      child.stdin.write(request.body);
      child.stdin.end();
    } else {
      // For GET requests or empty bodies, just close stdin
      child.stdin.end();
    }

    // Log errors
    child.stderr.on('data', (data) => {
      console.error('git http-backend stderr:', data.toString());
    });

    child.on('error', (err) => {
      console.error('Failed to spawn git http-backend:', err);
      if (!headersSent) {
        reply.code(500).send({ error: 'Git backend error' });
      }
      resolve();
    });

    child.on('close', (code) => {
      if (code !== 0 && !headersSent) {
        reply.code(500).send({ error: 'Git operation failed' });
      }

      resolve();
    });
  });
}
