/**
 * Resource Events Emitter
 *
 * Singleton EventEmitter for resource change notifications.
 * Handlers emit 'change' events here, WebSocket broadcasts to subscribers.
 */

import { EventEmitter } from 'events';
import { watch } from 'fs';
import { join, relative } from 'path';

// Singleton event emitter for resource changes
export const resourceEvents = new EventEmitter();

// Increase max listeners since many WebSocket connections may subscribe
resourceEvents.setMaxListeners(1000);

/**
 * Emit a resource change event
 * @param {string} resourceUrl - Full URL of the changed resource
 */
export function emitChange(resourceUrl) {
  resourceEvents.emit('change', resourceUrl);
}

/**
 * Start watching filesystem for changes and emit notifications
 * @param {string} rootDir - Directory to watch
 * @param {string} baseUrl - Base URL for constructing resource URLs (e.g., http://localhost:3000)
 */
export function startFileWatcher(rootDir, baseUrl) {
  // Debounce map to avoid duplicate events (editors often save multiple times)
  const debounceMap = new Map();
  const DEBOUNCE_MS = 100;

  try {
    const watcher = watch(rootDir, { recursive: true }, (eventType, filename) => {
      if (!filename) return;

      // Skip hidden files and common temp files
      if (filename.startsWith('.') || filename.endsWith('~') || filename.endsWith('.swp')) {
        return;
      }

      // Debounce: skip if we just emitted for this file
      const now = Date.now();
      const lastEmit = debounceMap.get(filename);
      if (lastEmit && now - lastEmit < DEBOUNCE_MS) {
        return;
      }
      debounceMap.set(filename, now);

      // Clean up old debounce entries periodically
      if (debounceMap.size > 1000) {
        for (const [key, time] of debounceMap) {
          if (now - time > 5000) debounceMap.delete(key);
        }
      }

      // Construct resource URL
      const resourcePath = '/' + filename.replace(/\\/g, '/');
      const resourceUrl = baseUrl.replace(/\/$/, '') + resourcePath;

      emitChange(resourceUrl);
    });

    // Handle watcher errors gracefully
    watcher.on('error', (err) => {
      console.error('File watcher error:', err.message);
    });

    return watcher;
  } catch (err) {
    console.error('Failed to start file watcher:', err.message);
    return null;
  }
}
