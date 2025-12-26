/**
 * Filesystem adapter for oidc-provider
 * Stores OIDC data (tokens, sessions, clients, etc.) as JSON files
 */

import fs from 'fs-extra';
import path from 'path';

/**
 * Get IDP root directory (dynamic to support changing DATA_ROOT)
 */
function getIdpRoot() {
  const dataRoot = process.env.DATA_ROOT || './data';
  return path.join(dataRoot, '.idp');
}

/**
 * Convert model name to directory name
 * e.g., 'AccessToken' -> 'access_token'
 */
function modelToDir(model) {
  return model.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
}

/**
 * Filesystem adapter for oidc-provider
 * Implements the adapter interface required by oidc-provider
 */
class FilesystemAdapter {
  constructor(model) {
    this.model = model;
  }

  /**
   * Get directory for this model (computed dynamically)
   */
  get dir() {
    return path.join(getIdpRoot(), modelToDir(this.model));
  }

  /**
   * Get file path for an ID
   */
  _path(id) {
    // Sanitize ID to prevent path traversal
    const safeId = id.replace(/[^a-zA-Z0-9_-]/g, '_');
    return path.join(this.dir, `${safeId}.json`);
  }

  /**
   * Create or update a stored item
   * @param {string} id - Unique identifier
   * @param {object} payload - Data to store
   * @param {number} expiresIn - TTL in seconds
   */
  async upsert(id, payload, expiresIn) {
    await fs.ensureDir(this.dir);

    const data = {
      ...payload,
      _id: id,
    };

    // Set expiration if provided
    if (expiresIn) {
      data._expiresAt = Date.now() + (expiresIn * 1000);
    }

    await fs.writeJson(this._path(id), data, { spaces: 2 });
  }

  /**
   * Find an item by ID
   * @param {string} id - Unique identifier
   * @returns {object|undefined} - The payload or undefined if not found/expired
   */
  async find(id) {
    try {
      const data = await fs.readJson(this._path(id));

      // Check if expired
      if (data._expiresAt && data._expiresAt < Date.now()) {
        await this.destroy(id);
        return undefined;
      }

      return data;
    } catch (err) {
      if (err.code === 'ENOENT') {
        return undefined;
      }
      throw err;
    }
  }

  /**
   * Find by user code (for device flow)
   * @param {string} userCode - Device flow user code
   */
  async findByUserCode(userCode) {
    try {
      const files = await fs.readdir(this.dir);
      for (const file of files) {
        if (file.startsWith('_')) continue; // Skip index files
        const data = await fs.readJson(path.join(this.dir, file));
        if (data.userCode === userCode) {
          // Check expiry
          if (data._expiresAt && data._expiresAt < Date.now()) {
            await this.destroy(data._id);
            continue;
          }
          return data;
        }
      }
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
    return undefined;
  }

  /**
   * Find by UID (for sessions/interactions)
   * @param {string} uid - Session/interaction UID
   */
  async findByUid(uid) {
    try {
      const files = await fs.readdir(this.dir);
      for (const file of files) {
        if (file.startsWith('_')) continue; // Skip index files
        const data = await fs.readJson(path.join(this.dir, file));
        if (data.uid === uid) {
          // Check expiry
          if (data._expiresAt && data._expiresAt < Date.now()) {
            await this.destroy(data._id);
            continue;
          }
          return data;
        }
      }
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
    return undefined;
  }

  /**
   * Delete an item
   * @param {string} id - Unique identifier
   */
  async destroy(id) {
    try {
      await fs.remove(this._path(id));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
  }

  /**
   * Mark a token as consumed (one-time use)
   * @param {string} id - Token identifier
   */
  async consume(id) {
    const data = await this.find(id);
    if (data) {
      data.consumed = Date.now() / 1000; // oidc-provider expects seconds
      await this.upsert(id, data);
    }
  }

  /**
   * Revoke all tokens for a grant
   * Used when user revokes consent or logs out
   * @param {string} grantId - Grant identifier
   */
  async revokeByGrantId(grantId) {
    try {
      const files = await fs.readdir(this.dir);
      for (const file of files) {
        if (file.startsWith('_')) continue; // Skip index files
        try {
          const data = await fs.readJson(path.join(this.dir, file));
          if (data.grantId === grantId) {
            await fs.remove(path.join(this.dir, file));
          }
        } catch (err) {
          // Skip files that can't be read
        }
      }
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
  }
}

/**
 * Adapter factory for oidc-provider
 * @param {string} model - Model name (e.g., 'AccessToken', 'Client')
 * @returns {FilesystemAdapter} - Adapter instance
 */
export function createAdapter(model) {
  return new FilesystemAdapter(model);
}

export default FilesystemAdapter;
