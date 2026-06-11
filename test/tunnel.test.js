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

  describe('Credential passthrough (#530)', () => {
    // Register a tunnel, echo each request's received headers back in
    // the response body, and attach the given response headers — lets
    // tests assert both directions of the credential flow.
    function echoTunnel(ws, name, { passthrough, responseHeaders = {} } = {}) {
      ws.send(JSON.stringify({ type: 'register', name, ...(passthrough !== undefined && { passthrough }) }));
      ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'request') {
          ws.send(JSON.stringify({
            type: 'response',
            id: msg.id,
            status: 200,
            headers: { 'content-type': 'application/json', ...responseHeaders },
            body: JSON.stringify({ receivedHeaders: msg.headers })
          }));
        }
      });
      return waitMsg(ws, 'registered');
    }

    it('default registration strips credentials both ways (the security default)', async () => {
      const ws = connectTunnel();
      await new Promise(r => ws.on('open', r));

      const ack = await echoTunnel(ws, 'noauth', {
        responseHeaders: { 'set-cookie': 'leak=1; Path=/' }
      });
      assert.strictEqual(ack.passthrough, false,
        'ack must state passthrough is off');

      const res = await fetch(`${baseUrl}/tunnel/noauth/`, {
        headers: { Cookie: 'session=secret', Authorization: 'Bearer visitor-token' }
      });
      assert.strictEqual(res.status, 200);
      const { receivedHeaders } = await res.json();
      assert.strictEqual(receivedHeaders.cookie, undefined,
        'cookie must NOT reach the tunnel client by default');
      assert.strictEqual(receivedHeaders.authorization, undefined,
        'authorization must NOT reach the tunnel client by default');
      // Feature-detect here too: on some undici versions get('set-cookie')
      // is null even when Set-Cookie headers ARE present (only readable
      // via getSetCookie), which would make a null assertion vacuous and
      // could mask a regression in the default strip mode.
      if (typeof res.headers.getSetCookie === 'function') {
        assert.deepStrictEqual(res.headers.getSetCookie(), [],
          'set-cookie from the tunnel client must NOT reach the visitor by default');
      } else {
        assert.strictEqual(res.headers.get('set-cookie'), null,
          'set-cookie from the tunnel client must NOT reach the visitor by default');
      }

      ws.close();
      await new Promise(r => setTimeout(r, 50));
    });

    it('passthrough registration forwards Cookie/Authorization in and Set-Cookie out', async () => {
      const ws = connectTunnel();
      await new Promise(r => ws.on('open', r));

      const ack = await echoTunnel(ws, 'authapp', {
        passthrough: true,
        // Array value: JSON serialization preserves it and Fastify
        // emits one Set-Cookie header per entry.
        responseHeaders: { 'set-cookie': ['sess=abc; Path=/', 'csrf=xyz; Path=/'] }
      });
      assert.strictEqual(ack.passthrough, true, 'ack must confirm passthrough');

      const res = await fetch(`${baseUrl}/tunnel/authapp/`, {
        headers: { Cookie: 'session=secret', Authorization: 'Bearer visitor-token' }
      });
      assert.strictEqual(res.status, 200);
      const { receivedHeaders } = await res.json();
      assert.strictEqual(receivedHeaders.cookie, 'session=secret',
        'cookie must reach the tunnel client with passthrough');
      assert.strictEqual(receivedHeaders.authorization, 'Bearer visitor-token',
        'authorization must reach the tunnel client with passthrough');
      // Headers#getSetCookie() (Node ≥18.15) is the supported way to
      // read multiple Set-Cookie values; get('set-cookie') behaviour
      // varies by undici version and may expose only one value. Feature-
      // detect: assert the full pair on the real API, degrade to a
      // single-cookie assertion on older runtimes (engines floor bump
      // tracked in #541).
      const hasGetSetCookie = typeof res.headers.getSetCookie === 'function';
      const setCookie = hasGetSetCookie
        ? res.headers.getSetCookie().join('; ')
        : (res.headers.get('set-cookie') || '');
      assert.ok(setCookie.includes('sess=abc'), `sess cookie must survive; got: ${setCookie}`);
      if (hasGetSetCookie) {
        assert.ok(setCookie.includes('csrf=xyz'), `csrf cookie must survive; got: ${setCookie}`);
      }

      ws.close();
      await new Promise(r => setTimeout(r, 50));
    });

    it('passthrough never forwards Proxy-Authorization (relay-directed credential)', async () => {
      const ws = connectTunnel();
      await new Promise(r => ws.on('open', r));

      await echoTunnel(ws, 'proxyauth', { passthrough: true });

      const res = await fetch(`${baseUrl}/tunnel/proxyauth/`, {
        headers: { 'Proxy-Authorization': 'Basic cmVsYXk6c2VjcmV0' }
      });
      assert.strictEqual(res.status, 200);
      const { receivedHeaders } = await res.json();
      assert.strictEqual(receivedHeaders['proxy-authorization'], undefined,
        'proxy-authorization is addressed to the relay and must never be forwarded');

      ws.close();
      await new Promise(r => setTimeout(r, 50));
    });

    it('non-boolean passthrough values do not enable forwarding (strict === true)', async () => {
      const ws = connectTunnel();
      await new Promise(r => ws.on('open', r));

      // "true" (string) must not opt a tunnel into credential forwarding.
      const ack = await echoTunnel(ws, 'stringy', { passthrough: 'true' });
      assert.strictEqual(ack.passthrough, false,
        'string "true" must not enable passthrough');

      const res = await fetch(`${baseUrl}/tunnel/stringy/`, {
        headers: { Cookie: 'session=secret' }
      });
      const { receivedHeaders } = await res.json();
      assert.strictEqual(receivedHeaders.cookie, undefined,
        'credentials stay stripped for non-boolean opt-in values');

      ws.close();
      await new Promise(r => setTimeout(r, 50));
    });
  });
});
