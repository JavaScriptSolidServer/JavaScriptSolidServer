/**
 * WebSocket Handler for Solid Notifications
 *
 * Implements the legacy "solid-0.1" protocol used by SolidOS/mashlib.
 *
 * Protocol:
 * - Server sends: "protocol solid-0.1" on connect
 * - Client sends: "sub <uri>" to subscribe
 * - Server sends: "ack <uri>" to acknowledge
 * - Server sends: "pub <uri>" when resource changes
 */

import { resourceEvents } from './events.js';

// Track subscriptions: WebSocket -> Set<url>
const subscriptions = new Map();

// Reverse lookup: url -> Set<WebSocket>
const subscribers = new Map();

/**
 * Handle new WebSocket connection
 * @param {WebSocket} socket - The WebSocket connection
 * @param {Request} request - The HTTP request
 */
export function handleWebSocket(socket, request) {
  // Send protocol greeting
  socket.send('protocol solid-0.1');

  // Initialize subscription set for this socket
  subscriptions.set(socket, new Set());

  // Handle incoming messages
  socket.on('message', (message) => {
    const msg = message.toString().trim();

    // Handle subscription request
    if (msg.startsWith('sub ')) {
      const url = msg.slice(4).trim();
      if (url) {
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
