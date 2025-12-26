/**
 * Resource Events Emitter
 *
 * Singleton EventEmitter for resource change notifications.
 * Handlers emit 'change' events here, WebSocket broadcasts to subscribers.
 */

import { EventEmitter } from 'events';

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
