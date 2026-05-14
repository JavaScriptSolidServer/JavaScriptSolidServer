import fs from 'fs-extra';
import path from 'path';
import crypto from 'crypto';
import { getDataRoot, urlToPath, isContainer } from '../utils/url.js';

// Note: Data directory is ensured in server.js after DATA_ROOT is set

/**
 * Check if resource exists
 * @param {string} urlPath
 * @returns {Promise<boolean>}
 */
export async function exists(urlPath) {
  const filePath = urlToPath(urlPath);
  return fs.pathExists(filePath);
}

/**
 * Get resource stats
 * @param {string} urlPath
 * @returns {Promise<{isDirectory: boolean, size: number, mtime: Date, etag: string} | null>}
 */
export async function stat(urlPath) {
  const filePath = urlToPath(urlPath);

  try {
    const stats = await fs.stat(filePath);
    return {
      isDirectory: stats.isDirectory(),
      size: stats.size,
      mtime: stats.mtime,
      etag: `"${crypto.createHash('md5').update(stats.mtime.toISOString() + stats.size).digest('hex')}"`
    };
  } catch {
    return null;
  }
}

/**
 * Read resource content
 * @param {string} urlPath
 * @returns {Promise<Buffer | null>}
 */
export async function read(urlPath) {
  const filePath = urlToPath(urlPath);

  try {
    return await fs.readFile(filePath);
  } catch {
    return null;
  }
}

/**
 * Create a readable stream for a resource (supports range requests)
 * @param {string} urlPath
 * @param {object} options - { start, end } byte range options
 * @returns {{ stream: ReadStream, filePath: string } | null}
 */
export function createReadStream(urlPath, options = {}) {
  const filePath = urlToPath(urlPath);

  // Check file exists before creating stream (createReadStream doesn't throw sync)
  if (!fs.pathExistsSync(filePath)) {
    return null;
  }

  try {
    const stream = fs.createReadStream(filePath, options);
    return { stream, filePath };
  } catch {
    return null;
  }
}

/**
 * Write resource content.
 *
 * @param {string} urlPath - URL path of the resource being written
 *   (translated to a filesystem path internally).
 * @param {Buffer | string} content - Bytes / text to write. Replaces
 *   the file if it already exists.
 * @param {object} [options]
 * @param {number} [options.mode] - POSIX file mode (e.g. `0o600`) to
 *   apply to the created file. Passed to `fs.writeFile` at create
 *   time so the file is never visible to other unix users with a
 *   looser default; an additional `chmod` runs afterward to tighten
 *   the file when overwriting an existing path that was created with
 *   a wider mode. On Windows, NTFS approximates POSIX modes coarsely
 *   (effectively read-only flag based on owner perms) — `chmod` is
 *   still attempted there but should not be relied on for
 *   cross-platform secrecy. See #437 for the secret-material use case.
 * @returns {Promise<boolean>} `true` on success, `false` on write
 *   failure (chmod failures are logged but do not fail the write).
 */
export async function write(urlPath, content, options = {}) {
  const filePath = urlToPath(urlPath);

  try {
    // Ensure parent directory exists
    await fs.ensureDir(path.dirname(filePath));

    // Pass `mode` to writeFile so the file is *created* with the
    // requested permissions, closing the race window where another
    // local process could read a freshly created secret-material
    // file before a follow-up `chmod` ran. (Node only honours `mode`
    // at create time, never on overwrite.)
    if (typeof options.mode === 'number') {
      await fs.writeFile(filePath, content, { mode: options.mode });
    } else {
      await fs.writeFile(filePath, content);
    }

    // Belt-and-braces: when overwriting an existing file, writeFile
    // does NOT change the existing mode — apply chmod so a stale 0644
    // file gets tightened to 0600 on subsequent writes. Logged but
    // non-fatal: chmod is attempted on every platform (incl. Windows,
    // where NTFS approximates POSIX modes coarsely) but callers that
    // care about strict permissions should also rely on filesystem-
    // level protection (FDE / OS keyring / container user namespacing).
    if (typeof options.mode === 'number') {
      try {
        await fs.chmod(filePath, options.mode);
      } catch (chmodErr) {
        console.warn(`chmod ${options.mode.toString(8)} on ${filePath} failed:`, chmodErr.message);
      }
    }
    return true;
  } catch (err) {
    console.error('Write error:', err);
    return false;
  }
}

/**
 * Delete resource
 * @param {string} urlPath
 * @returns {Promise<boolean>}
 */
export async function remove(urlPath) {
  const filePath = urlToPath(urlPath);

  try {
    await fs.remove(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Create container (directory)
 * @param {string} urlPath
 * @returns {Promise<boolean>}
 */
export async function createContainer(urlPath) {
  const filePath = urlToPath(urlPath);

  try {
    await fs.ensureDir(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * List container contents with stat metadata
 * @param {string} urlPath
 * @returns {Promise<Array<{name: string, isDirectory: boolean, size?: number, modified?: string}> | null>}
 */
export async function listContainer(urlPath) {
  const filePath = urlToPath(urlPath);

  try {
    const entries = await fs.readdir(filePath, { withFileTypes: true });
    const results = await Promise.all(entries.map(async (entry) => {
      const result = {
        name: entry.name,
        isDirectory: entry.isDirectory()
      };
      try {
        const stat = await fs.stat(path.join(filePath, entry.name));
        result.size = stat.size;
        result.modified = stat.mtime.toISOString();
      } catch { /* stat failed, skip metadata */ }
      return result;
    }));
    return results;
  } catch {
    return null;
  }
}

/**
 * Generate unique filename for POST
 * @param {string} containerPath
 * @param {string} slug
 * @param {boolean} isDir
 * @returns {Promise<string>}
 */
export async function generateUniqueFilename(containerPath, slug, isDir = false) {
  const basePath = urlToPath(containerPath);
  let name = slug || crypto.randomUUID();

  // Security: Remove any path traversal attempts and problematic characters
  name = name.replace(/[/\\]/g, '-');
  name = name.replace(/\.\./g, ''); // Remove .. sequences

  // Security: Limit filename length
  if (name.length > 255) {
    name = name.substring(0, 255);
  }

  let candidate = path.join(basePath, name);
  let counter = 1;

  while (await fs.pathExists(candidate)) {
    const ext = path.extname(name);
    const base = path.basename(name, ext);
    candidate = path.join(basePath, `${base}-${counter}${ext}`);
    counter++;
  }

  return path.basename(candidate);
}
