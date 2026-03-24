/**
 * Terminal Plugin — WebSocket Shell Access
 *
 * Provides a remote shell over WebSocket for authenticated pod owners.
 * Spawns /bin/sh on connection and pipes stdin/stdout/stderr between
 * the WebSocket and the shell process.
 *
 * SECURITY: Requires authentication. The connecting user's webId must
 * be present (verified via token). This is a privileged endpoint.
 *
 * Usage: jss start --terminal
 * Endpoint: wss://your.pod/.terminal
 *
 * Protocol (binary/text over WebSocket):
 *   -> (text/binary)  stdin data sent to shell
 *   <- (text/binary)  stdout/stderr data from shell
 *   <- JSON { type: "exit", code: <n> }  shell exited
 *   <- JSON { type: "error", message: "..." }
 */

import websocket from '@fastify/websocket';
import { getWebIdFromRequestAsync } from '../auth/token.js';
import { spawn } from 'child_process';

/**
 * Register terminal WebSocket route on Fastify instance
 *
 * @param {object} fastify - Fastify instance
 * @param {object} options - Options
 * @param {string} options.path - WebSocket path (default: '/.terminal')
 */
export async function terminalPlugin(fastify, options = {}) {
  const wsPath = options.path || '/.terminal';

  // Track active shell processes for cleanup
  const shells = new Set();

  if (!fastify.websocketServer) {
    await fastify.register(websocket);
  }

  // Clean up all shells on server close
  fastify.addHook('onClose', async () => {
    for (const proc of shells) {
      try { proc.kill(); } catch { /* already dead */ }
    }
    shells.clear();
  });

  fastify.get(wsPath, { websocket: true }, async (connection, request) => {
    const socket = connection.socket;

    // Authenticate — query param token support for browser WebSocket
    const queryToken = request.query?.token;
    if (queryToken && !request.headers.authorization) {
      request.headers.authorization = `Bearer ${queryToken}`;
    }
    const { webId } = await getWebIdFromRequestAsync(request);

    if (!webId) {
      socket.send(JSON.stringify({ type: 'error', message: 'Authentication required' }));
      socket.close();
      return;
    }

    // Spawn shell
    const shell = spawn('/bin/sh', [], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, TERM: 'xterm-256color' },
    });

    shells.add(shell);

    // Pipe shell stdout to WebSocket
    shell.stdout.on('data', (data) => {
      if (socket.readyState === 1) {
        try { socket.send(data); } catch { /* socket closed */ }
      }
    });

    // Pipe shell stderr to WebSocket
    shell.stderr.on('data', (data) => {
      if (socket.readyState === 1) {
        try { socket.send(data); } catch { /* socket closed */ }
      }
    });

    // Shell exited
    shell.on('close', (code) => {
      shells.delete(shell);
      if (socket.readyState === 1) {
        try {
          socket.send(JSON.stringify({ type: 'exit', code: code ?? 1 }));
          socket.close();
        } catch { /* socket already closed */ }
      }
    });

    shell.on('error', (err) => {
      shells.delete(shell);
      if (socket.readyState === 1) {
        try {
          socket.send(JSON.stringify({ type: 'error', message: err.message }));
          socket.close();
        } catch { /* socket already closed */ }
      }
    });

    // Pipe WebSocket messages to shell stdin
    socket.on('message', (data) => {
      if (shell.stdin.writable) {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        try { shell.stdin.write(buf); } catch { /* stdin closed */ }
      }
    });

    // WebSocket closed — kill the shell
    socket.on('close', () => {
      shells.delete(shell);
      try { shell.kill(); } catch { /* already dead */ }
    });

    socket.on('error', () => {});
  });
}

export default terminalPlugin;
