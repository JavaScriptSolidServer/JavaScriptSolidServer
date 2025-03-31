import fs from 'fs-extra';
import path from 'path';
import { Readable } from 'stream';

// Base directory for storing all pods
const DATA_ROOT = process.env.DATA_ROOT || './data';

// Ensure data directory exists
fs.ensureDirSync(DATA_ROOT);

// Map content types
const contentTypeMap = {
  '.ttl': 'text/turtle',
  '.json': 'application/json',
  '.jsonld': 'application/ld+json',
  '.html': 'text/html',
  '.txt': 'text/plain',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml'
};

// Helper to determine content type
function getContentType (filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return contentTypeMap[ext] || 'application/octet-stream';
}

// Resolve URL path to file system path
function resolveFilePath (urlPath) {
  // Remove initial slash and normalize
  const normalized = urlPath.startsWith('/') ? urlPath.substring(1) : urlPath;

  // Default to index.ttl for directory requests
  if (normalized.endsWith('/') || normalized === '') {
    return path.join(DATA_ROOT, normalized, 'index.ttl');
  }

  return path.join(DATA_ROOT, normalized);
}

// Ensure container exists
async function ensureContainer (filePath) {
  const dirPath = path.dirname(filePath);
  await fs.ensureDir(dirPath);
}

export const handleStorage = {
  // GET resource
  get: async (request, reply) => {
    const filePath = resolveFilePath(request.url);

    try {
      if (!await fs.pathExists(filePath)) {
        reply.code(404);
        return { error: 'Resource not found' };
      }

      const stats = await fs.stat(filePath);

      // Handle container (directory)
      if (stats.isDirectory()) {
        const indexPath = path.join(filePath, 'index.ttl');
        if (await fs.pathExists(indexPath)) {
          const content = await fs.readFile(indexPath, 'utf8');
          reply.header('Content-Type', 'text/turtle');
          return content;
        } else {
          // Return container listing (simplified for MVP)
          reply.header('Content-Type', 'text/turtle');
          return `@prefix ldp: <http://www.w3.org/ns/ldp#>.\n<> a ldp:Container.`;
        }
      }

      // Handle file resource
      const content = await fs.readFile(filePath);
      reply.header('Content-Type', getContentType(filePath));
      reply.header('ETag', `"${stats.mtimeMs.toString(16)}"`);
      return content;
    } catch (error) {
      request.log.error(error);
      reply.code(500);
      return { error: 'Server error' };
    }
  },

  // PUT resource
  put: async (request, reply) => {
    const filePath = resolveFilePath(request.url);

    try {
      await ensureContainer(filePath);

      // Write file
      await fs.writeFile(filePath, request.body);

      const isNew = !await fs.pathExists(filePath);
      reply.code(isNew ? 201 : 200);
      reply.header('Location', request.url);
      return { success: true };
    } catch (error) {
      request.log.error(error);
      reply.code(500);
      return { error: 'Server error' };
    }
  },

  // DELETE resource
  delete: async (request, reply) => {
    const filePath = resolveFilePath(request.url);

    try {
      if (!await fs.pathExists(filePath)) {
        reply.code(404);
        return { error: 'Resource not found' };
      }

      await fs.remove(filePath);
      reply.code(204);
      return '';
    } catch (error) {
      request.log.error(error);
      reply.code(500);
      return { error: 'Server error' };
    }
  },

  // PATCH resource (simplified for MVP)
  patch: async (request, reply) => {
    // For MVP, we'll implement a very simple PATCH
    // In production, this would support SPARQL, N3 Patch, etc.

    const filePath = resolveFilePath(request.url);

    try {
      if (!await fs.pathExists(filePath)) {
        reply.code(404);
        return { error: 'Resource not found' };
      }

      // For MVP, we'll just replace the content
      await fs.writeFile(filePath, request.body);

      reply.code(204);
      return '';
    } catch (error) {
      request.log.error(error);
      reply.code(500);
      return { error: 'Server error' };
    }
  },

  // HEAD resource
  head: async (request, reply) => {
    const filePath = resolveFilePath(request.url);

    try {
      if (!await fs.pathExists(filePath)) {
        reply.code(404);
        return '';
      }

      const stats = await fs.stat(filePath);

      reply.header('Content-Type', getContentType(filePath));
      reply.header('ETag', `"${stats.mtimeMs.toString(16)}"`);
      reply.header('Content-Length', stats.size);

      reply.code(200);
      return '';
    } catch (error) {
      request.log.error(error);
      reply.code(500);
      return '';
    }
  }
};
