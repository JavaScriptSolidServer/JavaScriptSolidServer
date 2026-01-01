import { spawn } from 'child_process';
import { existsSync, statSync } from 'fs';
import { join } from 'path';

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
 * Extract the repository path from the URL
 * @param {string} urlPath - The URL path
 * @returns {string|null} The repository relative path or null
 */
function extractRepoPath(urlPath) {
  // Remove git service suffixes to get the repo path
  const cleanPath = urlPath
    .replace(/\/info\/refs.*$/, '')
    .replace(/\/git-upload-pack$/, '')
    .replace(/\/git-receive-pack$/, '');

  // Remove leading slash
  return cleanPath.replace(/^\//, '') || null;
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
 * Handle Git HTTP requests using git http-backend
 * @param {FastifyRequest} request
 * @param {FastifyReply} reply
 */
export async function handleGit(request, reply) {
  const urlPath = decodeURIComponent(request.url.split('?')[0]);
  const queryString = request.url.split('?')[1] || '';

  // Extract repository path
  const repoRelative = extractRepoPath(urlPath);
  if (!repoRelative) {
    return reply.code(400).send({ error: 'Invalid git request' });
  }

  // Handle subdomain mode
  let dataRoot = process.env.DATA_ROOT || './data';
  if (request.podName) {
    dataRoot = join(dataRoot, request.podName);
  }

  const repoAbs = join(dataRoot, repoRelative);

  // Find git directory
  const gitInfo = findGitDir(repoAbs);
  if (!gitInfo) {
    return reply.code(404).send({ error: 'Not a git repository' });
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

      // Auto-checkout working directory after successful push to non-bare repo
      if (code === 0 && isGitWriteOperation(urlPath) && gitInfo.isRegular) {
        const checkout = spawn('git', ['checkout', '-f'], {
          cwd: repoAbs,
          env: {
            ...process.env,
            GIT_DIR: gitInfo.gitDir,
            GIT_WORK_TREE: repoAbs
          }
        });
        checkout.on('error', (err) => {
          console.error('Auto-checkout failed:', err.message);
        });
        checkout.on('close', (checkoutCode) => {
          if (checkoutCode !== 0) {
            console.error('Auto-checkout exited with code:', checkoutCode);
          }
        });
      }

      resolve();
    });
  });
}
