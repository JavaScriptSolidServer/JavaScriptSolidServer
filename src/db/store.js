/**
 * MongoDB Storage Layer for /db/ route
 *
 * Optional dependency — dynamically imports 'mongodb'.
 * Provides document-level CRUD keyed by URI.
 */

import crypto from 'crypto';

let client = null;
let db = null;
let col = null;

/**
 * Connect to MongoDB
 * @param {object} options
 * @param {string} options.url - MongoDB connection URL
 * @param {string} options.database - Database name
 * @returns {Promise<void>}
 */
export async function connect({ url, database }) {
  let MongoClient;
  try {
    ({ MongoClient } = await import('mongodb'));
  } catch {
    throw new Error(
      'MongoDB driver not installed. Install it with: npm install mongodb\n' +
      'The mongodb package is optional and only needed when using --mongo.'
    );
  }

  client = new MongoClient(url);
  await client.connect();
  db = client.db(database);
  col = db.collection('resources');

  // Create unique index on URI for fast lookups
  await col.createIndex({ uri: 1 }, { unique: true });
}

/**
 * Disconnect from MongoDB
 * @returns {Promise<void>}
 */
export async function disconnect() {
  if (client) {
    await client.close();
    client = null;
    db = null;
    col = null;
  }
}

/**
 * Generate ETag from data
 */
function generateEtag(data) {
  const hash = crypto.createHash('md5').update(JSON.stringify(data)).digest('hex');
  return `"${hash}"`;
}

/**
 * Find a single document by URI
 * @param {string} uri - The resource URI
 * @returns {Promise<{data: object, contentType: string, etag: string, modified: Date} | null>}
 */
export async function findOne(uri) {
  const doc = await col.findOne({ uri });
  if (!doc) return null;
  return {
    data: doc.data,
    contentType: doc.contentType,
    etag: doc.etag,
    modified: doc.modified
  };
}

/**
 * Upsert a document by URI
 * @param {string} uri - The resource URI
 * @param {object} data - The document data (JSON-LD)
 * @param {string} contentType - The content type
 * @returns {Promise<{created: boolean, etag: string}>}
 */
export async function upsertOne(uri, data, contentType) {
  const etag = generateEtag(data);
  const now = new Date();

  const result = await col.updateOne(
    { uri },
    {
      $set: { data, contentType, etag, modified: now },
      $setOnInsert: { created: now }
    },
    { upsert: true }
  );

  return {
    created: result.upsertedCount > 0,
    etag
  };
}

/**
 * Delete a document by URI
 * @param {string} uri - The resource URI
 * @returns {Promise<boolean>} - true if deleted, false if not found
 */
export async function deleteOne(uri) {
  const result = await col.deleteOne({ uri });
  return result.deletedCount > 0;
}

/**
 * Escape special regex characters in a string
 */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * List immediate children whose URI starts with a prefix (for container listings)
 * @param {string} prefix - URI prefix (must end with '/')
 * @returns {Promise<Array<{name: string, isDirectory: boolean}>>}
 */
export async function listByPrefix(prefix) {
  const regex = new RegExp('^' + escapeRegex(prefix));
  const docs = await col.find({ uri: regex }, { projection: { uri: 1 } }).toArray();

  const children = new Map();
  for (const doc of docs) {
    const remainder = doc.uri.slice(prefix.length);
    if (!remainder) continue;
    const slashIndex = remainder.indexOf('/');
    if (slashIndex === -1) {
      // Direct child resource
      children.set(remainder, false);
    } else {
      // Nested under a sub-container
      const containerName = remainder.slice(0, slashIndex);
      children.set(containerName, true);
    }
  }

  return Array.from(children.entries()).map(([name, isDirectory]) => ({ name, isDirectory }));
}

/**
 * Check if MongoDB is connected
 * @returns {boolean}
 */
export function isConnected() {
  return client !== null;
}
