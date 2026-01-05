/**
 * Nostr Relay Module
 *
 * Lightweight Nostr relay (NIP-01) integrated into JSS.
 * Based on Fonstr (https://github.com/nostrapps/fonstr)
 *
 * Usage: jss start --nostr
 * Endpoint: wss://your.pod/relay
 */

import { validateEvent, verifyEvent } from 'nostr-tools';
import websocket from '@fastify/websocket';

// Default max events to prevent memory exhaustion
const DEFAULT_MAX_EVENTS = 1000;
// Rate limiting: max events per socket per minute
const DEFAULT_RATE_LIMIT = 60;
const RATE_WINDOW_MS = 60000;

/**
 * Check if event passes filter (NIP-01)
 */
function eventPassesFilter(event, filter) {
  if (filter.ids && !filter.ids.includes(event.id)) {
    return false;
  }

  if (filter.authors && !filter.authors.includes(event.pubkey)) {
    return false;
  }

  if (filter.kinds && !filter.kinds.includes(event.kind)) {
    return false;
  }

  if (filter.since && event.created_at < filter.since) {
    return false;
  }

  if (filter.until && event.created_at > filter.until) {
    return false;
  }

  // Tag filters (#e, #p, etc.)
  for (const [key, values] of Object.entries(filter)) {
    if (key.startsWith('#') && key.length === 2) {
      const tagName = key[1];
      const eventTagValues = event.tags
        .filter(tag => tag[0] === tagName)
        .map(tag => tag[1]);

      if (!values.some(v => eventTagValues.includes(v))) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Event kind helpers (NIP-01, NIP-16)
 */
function isReplaceableKind(kind) {
  return (kind >= 10000 && kind < 20000) || kind === 0 || kind === 3;
}

function isEphemeralKind(kind) {
  return kind >= 20000 && kind < 30000;
}

function isParameterizedReplaceable(kind) {
  return kind >= 30000 && kind < 40000;
}

function getDTagValue(tags) {
  for (const tag of tags) {
    if (tag[0] === 'd') {
      return tag[1];
    }
  }
  return null;
}

/**
 * Register Nostr relay routes on Fastify instance
 *
 * @param {object} fastify - Fastify instance
 * @param {object} options - Options
 * @param {string} options.path - WebSocket path (default: '/relay')
 * @param {number} options.maxEvents - Max events in memory (default: 1000)
 */
export async function registerNostrRelay(fastify, options = {}) {
  const path = options.path || '/relay';
  const maxEvents = options.maxEvents || DEFAULT_MAX_EVENTS;

  // In-memory storage
  const events = [];
  const subscribers = new Map();
  const rateLimits = new Map(); // socket -> { count, resetTime }

  /**
   * Check rate limit for socket
   */
  function checkRateLimit(socket) {
    const now = Date.now();
    let limit = rateLimits.get(socket);

    if (!limit || now > limit.resetTime) {
      limit = { count: 0, resetTime: now + RATE_WINDOW_MS };
      rateLimits.set(socket, limit);
    }

    limit.count++;
    return limit.count <= DEFAULT_RATE_LIMIT;
  }

  /**
   * Process incoming message
   */
  async function processMessage(type, value, rest, socket) {
    switch (type) {
      case 'EVENT': {
        // Rate limit check
        if (!checkRateLimit(socket)) {
          socket.send(JSON.stringify(['OK', value?.id || '', false, 'rate-limited: too many events']));
          return;
        }

        const event = value;
        const isValid = validateEvent(event) && verifyEvent(event);

        if (!isValid) {
          socket.send(JSON.stringify(['OK', event?.id || '', false, 'invalid: bad signature or format']));
          return;
        }

        // Handle different event kinds
        if (isEphemeralKind(event.kind)) {
          // Ephemeral: don't store, just broadcast
        } else if (isReplaceableKind(event.kind) || isParameterizedReplaceable(event.kind)) {
          // Replaceable: find and update existing
          let indexToReplace = -1;
          for (let i = 0; i < events.length; i++) {
            if (events[i].pubkey === event.pubkey && events[i].kind === event.kind) {
              if (isParameterizedReplaceable(event.kind)) {
                const dTagValue = getDTagValue(event.tags);
                const existingDTagValue = getDTagValue(events[i].tags);
                if (dTagValue === existingDTagValue) {
                  indexToReplace = i;
                  break;
                }
              } else {
                indexToReplace = i;
                break;
              }
            }
          }

          if (indexToReplace !== -1) {
            events[indexToReplace] = event;
          } else {
            if (events.length >= maxEvents) {
              events.shift();
            }
            events.push(event);
          }
        } else {
          // Regular event
          if (events.length >= maxEvents) {
            events.shift();
          }
          events.push(event);
        }

        // Broadcast to matching subscribers
        subscribers.forEach((filters, subscriber) => {
          filters.forEach(filter => {
            if (eventPassesFilter(event, filter)) {
              try {
                subscriber.send(JSON.stringify(['EVENT', filter.subscription_id, event]));
              } catch (e) {
                // Socket closed, will be cleaned up
              }
            }
          });
        });

        socket.send(JSON.stringify(['OK', event.id, true, '']));
        break;
      }

      case 'REQ': {
        const subscriptionId = value;
        const filters = rest.map(filter => ({ ...filter, subscription_id: subscriptionId }));
        subscribers.set(socket, filters);

        // Send matching historical events
        filters.forEach(filter => {
          const matchingEvents = events.filter(event => eventPassesFilter(event, filter));
          const limited = filter.limit ? matchingEvents.slice(-filter.limit) : matchingEvents;
          limited.forEach(event => {
            socket.send(JSON.stringify(['EVENT', filter.subscription_id, event]));
          });
        });

        socket.send(JSON.stringify(['EOSE', subscriptionId]));
        break;
      }

      case 'CLOSE': {
        const subId = value;
        if (subscribers.has(socket)) {
          const updatedFilters = subscribers.get(socket).filter(
            filter => filter.subscription_id !== subId
          );
          if (updatedFilters.length === 0) {
            subscribers.delete(socket);
          } else {
            subscribers.set(socket, updatedFilters);
          }
        }
        break;
      }

      default:
        socket.send(JSON.stringify(['NOTICE', `Unknown message type: ${type}`]));
    }
  }

  // Register websocket plugin if not already registered
  if (!fastify.websocketServer) {
    await fastify.register(websocket);
  }

  // Register WebSocket route for Nostr relay
  fastify.get(path, { websocket: true }, (connection, request) => {
    const socket = connection.socket;

    socket.on('message', async (data) => {
      try {
        const message = JSON.parse(data.toString());
        const [type, value, ...rest] = message;
        await processMessage(type, value, rest, socket);
      } catch (e) {
        socket.send(JSON.stringify(['NOTICE', `Error: ${e.message}`]));
      }
    });

    socket.on('close', () => {
      subscribers.delete(socket);
      rateLimits.delete(socket);
    });

    socket.on('error', () => {
      subscribers.delete(socket);
      rateLimits.delete(socket);
    });
  });

  // NIP-11: Relay Information Document at /relay/info
  fastify.get(path + '/info', (request, reply) => {
    const relayInfo = {
      name: 'JSS Nostr Relay',
      description: 'Nostr relay integrated with JavaScript Solid Server',
      pubkey: '',
      contact: '',
      supported_nips: [1, 11, 16],
      software: 'https://github.com/JavaScriptSolidServer/JavaScriptSolidServer',
      version: '0.0.1'
    };

    return reply
      .header('Access-Control-Allow-Origin', '*')
      .header('Content-Type', 'application/json')
      .send(relayInfo);
  });

  return {
    getEventCount: () => events.length,
    getSubscriberCount: () => subscribers.size
  };
}
