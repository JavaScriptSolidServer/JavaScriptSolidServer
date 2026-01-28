/**
 * WebSocket Handler for Solid Notifications
 *
 * Implements the legacy "solid-0.1" protocol used by SolidOS/mashlib.
 *
 * Protocol:
 * - Server sends: "protocol solid-0.1" on connect
 * - Client sends: "sub <uri>" to subscribe
 * - Server sends: "ack <uri>" to acknowledge (if authorized)
 * - Server sends: "err <uri> forbidden" if not authorized
 * - Server sends: "pub <uri>" when resource changes
 *
 * Security:
 * - ACL is checked on every subscription request
 * - Only subscribers with read access receive notifications
 */

import { resourceEvents } from './events.js';
import { checkAccess } from '../wac/checker.js';
import { AccessMode } from '../wac/parser.js';
import * as storage from '../storage/filesystem.js';

// Security limits
const MAX_SUBSCRIPTIONS_PER_CONNECTION = 100;
const MAX_URL_LENGTH = 2048;

// Track subscriptions: WebSocket -> Set<url>
const subscriptions = new Map();

// Reverse lookup: url -> Set<WebSocket>
const subscribers = new Map();

/**
 * Handle new WebSocket connection
 * @param {WebSocket} socket - The WebSocket connection
 * @param {Request} request - The HTTP request
 * @param {string|null} webId - Authenticated WebID (null for anonymous)
 */
export function handleWebSocket(socket, request, webId = null) {
  // Store webId and server info on socket for ACL checks
  socket.webId = webId;
  socket.serverOrigin = `${request.protocol}://${request.hostname}`;
  socket.publicMode = request.config?.public || false;

  // Send protocol greeting
  socket.send('protocol solid-0.1');

  // Initialize subscription set for this socket
  subscriptions.set(socket, new Set());

  // Handle incoming messages
  socket.on('message', async (message) => {
    const msg = message.toString().trim();

    // Handle subscription request
    if (msg.startsWith('sub ')) {
      const url = msg.slice(4).trim();
      if (url) {
        // Security: validate URL length
        if (url.length > MAX_URL_LENGTH) {
          socket.send('error: URL too long');
          return;
        }

        // Security: check subscription limit
        const socketSubs = subscriptions.get(socket);
        if (socketSubs && socketSubs.size >= MAX_SUBSCRIPTIONS_PER_CONNECTION) {
          socket.send('error: Subscription limit exceeded');
          return;
        }

        // Security: check ACL read permission before allowing subscription
        const canSubscribe = await checkSubscriptionAccess(url, socket);
        if (!canSubscribe) {
          socket.send(`err ${url} forbidden`);
          return;
        }

        subscribe(socket, url);
        socket.send(`ack ${url}`);
      }
    }

    // Handle unsubscribe (optional extension)
    if (msg.startsWith('unsub ')) {
      const url = msg.slice(6).trim();
      if (url) {
        unsubscribe(socket, url);
      }
    }
  });

  // Clean up on close
  socket.on('close', () => {
    cleanup(socket);
  });

  // Clean up on error
  socket.on('error', () => {
    cleanup(socket);
  });
}

/**
 * Check if socket has read access to subscribe to a URL
 * @param {string} url - The URL to subscribe to
 * @param {WebSocket} socket - The WebSocket connection (with webId attached)
 * @returns {Promise<boolean>} - true if subscription is allowed
 */
async function checkSubscriptionAccess(url, socket) {
  try {
    // Parse the subscription URL
    const parsedUrl = new URL(url);

    // Security: Only allow subscriptions to URLs on this server
    // This prevents using the server as a proxy to probe other servers
    if (parsedUrl.origin !== socket.serverOrigin) {
      return false;
    }

    const resourcePath = decodeURIComponent(parsedUrl.pathname);

    // Check if resource exists and if it's a container
    const stats = await storage.stat(resourcePath);
    const isContainer = stats?.isDirectory || resourcePath.endsWith('/');

    // Skip WAC check in public mode
    if (socket.publicMode) {
      return true;
    }

    // Check WAC read permission
    const { allowed } = await checkAccess({
      resourceUrl: url,
      resourcePath,
      isContainer,
      agentWebId: socket.webId,
      requiredMode: AccessMode.READ
    });

    return allowed;
  } catch (err) {
    // On any error (invalid URL, storage error, etc.), deny subscription
    // This prevents information leakage through error messages
    return false;
  }
}

/**
 * Subscribe a socket to a resource URL
 */
function subscribe(socket, url) {
  // Add to socket's subscriptions
  const socketSubs = subscriptions.get(socket);
  if (socketSubs) {
    socketSubs.add(url);
  }

  // Add to URL's subscribers
  if (!subscribers.has(url)) {
    subscribers.set(url, new Set());
  }
  subscribers.get(url).add(socket);
}

/**
 * Unsubscribe a socket from a resource URL
 */
function unsubscribe(socket, url) {
  // Remove from socket's subscriptions
  const socketSubs = subscriptions.get(socket);
  if (socketSubs) {
    socketSubs.delete(url);
  }

  // Remove from URL's subscribers
  const urlSubs = subscribers.get(url);
  if (urlSubs) {
    urlSubs.delete(socket);
    if (urlSubs.size === 0) {
      subscribers.delete(url);
    }
  }
}

/**
 * Clean up all subscriptions for a socket
 */
function cleanup(socket) {
  const urls = subscriptions.get(socket);
  if (urls) {
    for (const url of urls) {
      unsubscribe(socket, url);
    }
  }
  subscriptions.delete(socket);
}

/**
 * Broadcast a change notification to all subscribers of a URL
 * Also notifies subscribers of parent containers
 */
export function broadcast(url) {
  // Notify direct subscribers
  notifySubscribers(url);

  // Also notify container subscribers (parent directory)
  // This allows subscribing to a container and getting notified of all child changes
  const containerUrl = getParentContainer(url);
  if (containerUrl && containerUrl !== url) {
    notifySubscribers(containerUrl);
  }
}

/**
 * Send pub message to all subscribers of a URL
 */
function notifySubscribers(url) {
  const subs = subscribers.get(url);
  if (subs) {
    const message = `pub ${url}`;
    for (const socket of subs) {
      if (socket.readyState === 1) { // WebSocket.OPEN
        try {
          socket.send(message);
        } catch (e) {
          // Socket may have closed, will be cleaned up on close event
        }
      }
    }
  }
}

/**
 * Get parent container URL from a resource URL
 */
function getParentContainer(url) {
  // Remove trailing slash if present
  const normalized = url.endsWith('/') ? url.slice(0, -1) : url;
  const lastSlash = normalized.lastIndexOf('/');
  if (lastSlash > 0) {
    return normalized.substring(0, lastSlash + 1);
  }
  return null;
}

/**
 * Get count of active subscriptions (for monitoring)
 */
export function getSubscriptionCount() {
  let count = 0;
  for (const urls of subscriptions.values()) {
    count += urls.size;
  }
  return count;
}

/**
 * Get count of active connections (for monitoring)
 */
export function getConnectionCount() {
  return subscriptions.size;
}

// Listen to resource change events and broadcast
resourceEvents.on('change', broadcast);
