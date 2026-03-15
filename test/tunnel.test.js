/**
 * Tunnel Proxy Tests
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { WebSocket } from 'ws';
import {
  startTestServer,
  stopTestServer,
  createTestPod,
  getBaseUrl,
  getPodToken
} from './helpers.js';

describe('Tunnel Proxy', () => {
  let wsUrl, baseUrl;

  before(async () => {
    await startTestServer({ tunnel: true });
    await createTestPod('tunneler');
    baseUrl = getBaseUrl();
    wsUrl = baseUrl.replace('http', 'ws') + '/.tunnel';
  });

  after(async () => {
    await stopTestServer();
  });

  function connectTunnel() {
    const token = getPodToken('tunneler');
    return new WebSocket(wsUrl, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
  }

  function waitMsg(ws, type, timeout = 5000) {
    return new Promise((resolve, reject) => {
      function handler(data) {
        const msg = JSON.parse(data.toString());
        if (msg.type === type) {
          clearTimeout(timer);
          ws.removeListener('message', handler);
          ws.removeListener('close', onClose);
          resolve(msg);
        }
      }
      function onClose() {
        clearTimeout(timer);
        ws.removeListener('message', handler);
        reject(new Error(`WebSocket closed while waiting for "${type}"`));
      }
      const timer = setTimeout(() => {
        ws.removeListener('message', handler);
        ws.removeListener('close', onClose);
        reject(new Error(`Timeout waiting for "${type}"`));
      }, timeout);
      ws.on('message', handler);
      ws.on('close', onClose);
    });
  }

  describe('Registration', () => {
    it('should reject unauthenticated connections', async () => {
      const ws = new WebSocket(wsUrl);
      const msg = await waitMsg(ws, 'error');
      assert.ok(msg.message.includes('Authentication'));
      ws.close();
    });

    it('should register a tunnel name', async () => {
      const ws = connectTunnel();
      await new Promise(r => ws.on('open', r));

      ws.send(JSON.stringify({ type: 'register', name: 'myapp' }));
      const msg = await waitMsg(ws, 'registered');
      assert.strictEqual(msg.name, 'myapp');
      assert.strictEqual(msg.url, '/tunnel/myapp/');

      ws.close();
      await new Promise(r => setTimeout(r, 50));
    });

    it('should reject invalid tunnel names', async () => {
      const ws = connectTunnel();
      await new Promise(r => ws.on('open', r));

      ws.send(JSON.stringify({ type: 'register', name: '...' }));
      const msg = await waitMsg(ws, 'error');
      assert.ok(msg.message.includes('Invalid'));

      ws.close();
      await new Promise(r => setTimeout(r, 50));
    });
  });

  describe('HTTP Proxying', () => {
    it('should proxy GET requests through the tunnel', async () => {
      const ws = connectTunnel();
      await new Promise(r => ws.on('open', r));

      // Register tunnel
      ws.send(JSON.stringify({ type: 'register', name: 'testapp' }));
      await waitMsg(ws, 'registered');

      // Listen for tunnel requests and respond
      ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'request') {
          ws.send(JSON.stringify({
            type: 'response',
            id: msg.id,
            status: 200,
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ hello: 'world', path: msg.path })
          }));
        }
      });

      // Make HTTP request through the tunnel
      const res = await fetch(`${baseUrl}/tunnel/testapp/api/hello`);
      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert.strictEqual(body.hello, 'world');
      assert.strictEqual(body.path, '/api/hello');

      ws.close();
      await new Promise(r => setTimeout(r, 50));
    });

    it('should proxy POST requests with body', async () => {
      const ws = connectTunnel();
      await new Promise(r => ws.on('open', r));

      ws.send(JSON.stringify({ type: 'register', name: 'postapp' }));
      await waitMsg(ws, 'registered');

      ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'request') {
          assert.strictEqual(msg.method, 'POST');
          ws.send(JSON.stringify({
            type: 'response',
            id: msg.id,
            status: 201,
            headers: { 'content-type': 'text/plain' },
            body: 'Created'
          }));
        }
      });

      const res = await fetch(`${baseUrl}/tunnel/postapp/items`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'test' })
      });
      assert.strictEqual(res.status, 201);
      assert.strictEqual(await res.text(), 'Created');

      ws.close();
      await new Promise(r => setTimeout(r, 50));
    });

    it('should return 502 for unregistered tunnel', async () => {
      const res = await fetch(`${baseUrl}/tunnel/nonexistent/path`);
      assert.strictEqual(res.status, 502);
    });

    it('should forward custom headers', async () => {
      const ws = connectTunnel();
      await new Promise(r => ws.on('open', r));

      ws.send(JSON.stringify({ type: 'register', name: 'headerapp' }));
      await waitMsg(ws, 'registered');

      let receivedHeaders;
      ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'request') {
          receivedHeaders = msg.headers;
          ws.send(JSON.stringify({
            type: 'response',
            id: msg.id,
            status: 200,
            headers: { 'x-custom-response': 'from-tunnel' },
            body: 'ok'
          }));
        }
      });

      const res = await fetch(`${baseUrl}/tunnel/headerapp/`, {
        headers: { 'X-Custom-Request': 'to-tunnel' }
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers.get('x-custom-response'), 'from-tunnel');
      assert.strictEqual(receivedHeaders['x-custom-request'], 'to-tunnel');

      ws.close();
      await new Promise(r => setTimeout(r, 50));
    });
  });
});
