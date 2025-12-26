import fs from 'fs-extra';
import path from 'path';
import crypto from 'crypto';
import { DATA_ROOT, urlToPath, isContainer } from '../utils/url.js';

// Ensure data directory exists
fs.ensureDirSync(DATA_ROOT);

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
 * Write resource content
 * @param {string} urlPath
 * @param {Buffer | string} content
 * @returns {Promise<boolean>}
 */
export async function write(urlPath, content) {
  const filePath = urlToPath(urlPath);

  try {
    // Ensure parent directory exists
    await fs.ensureDir(path.dirname(filePath));
    await fs.writeFile(filePath, content);
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
 * List container contents
 * @param {string} urlPath
 * @returns {Promise<Array<{name: string, isDirectory: boolean}> | null>}
 */
export async function listContainer(urlPath) {
  const filePath = urlToPath(urlPath);

  try {
    const entries = await fs.readdir(filePath, { withFileTypes: true });
    return entries.map(entry => ({
      name: entry.name,
      isDirectory: entry.isDirectory()
    }));
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

  // Remove any path traversal attempts
  name = name.replace(/[/\\]/g, '-');

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
