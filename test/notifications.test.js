/**
 * WebSocket Notifications Tests
 *
 * Tests the solid-0.1 WebSocket notification protocol.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { WebSocket } from 'ws';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  getBaseUrl,
  assertStatus,
  assertHeader,
  assertHeaderContains
} from './helpers.js';

describe('WebSocket Notifications (notifications enabled)', () => {
  let wsUrl;

  before(async () => {
    // Start server with notifications ENABLED
    await startTestServer({ notifications: true });
    await createTestPod('notifytest');

    // Get WebSocket URL from Updates-Via header
    const res = await request('/notifytest/', { method: 'OPTIONS' });
    wsUrl = res.headers.get('Updates-Via');
  });

  after(async () => {
    await stopTestServer();
  });

  describe('Discovery', () => {
    it('should return Updates-Via header in OPTIONS response', async () => {
      const res = await request('/notifytest/public/', { method: 'OPTIONS' });
      assertStatus(res, 204);
      const updatesVia = res.headers.get('Updates-Via');
      assert.ok(updatesVia, 'Should have Updates-Via header');
      assert.ok(updatesVia.startsWith('ws://') || updatesVia.startsWith('wss://'),
        'Updates-Via should be a WebSocket URL');
    });

    it('should return Updates-Via header in GET response', async () => {
      const res = await request('/notifytest/');
      assertStatus(res, 200);
      const updatesVia = res.headers.get('Updates-Via');
      assert.ok(updatesVia, 'GET response should have Updates-Via header');
    });

    it('should expose Updates-Via in CORS headers', async () => {
      const res = await request('/notifytest/', {
        headers: { 'Origin': 'http://example.org' }
      });
      const expose = res.headers.get('Access-Control-Expose-Headers');
      assert.ok(expose && expose.includes('Updates-Via'),
        'Updates-Via should be in exposed headers');
    });
  });

  describe('WebSocket Protocol', () => {
    it('should connect and receive protocol greeting', async () => {
      const ws = new WebSocket(wsUrl);

      const message = await new Promise((resolve, reject) => {
        ws.on('open', () => {});
        ws.on('message', (data) => resolve(data.toString()));
        ws.on('error', reject);
        setTimeout(() => reject(new Error('Timeout')), 5000);
      });

      assert.strictEqual(message, 'protocol solid-0.1');
      ws.close();
    });

    it('should acknowledge subscription', async () => {
      const ws = new WebSocket(wsUrl);
      const baseUrl = getBaseUrl();
      const resourceUrl = `${baseUrl}/notifytest/public/test.json`;

      const messages = [];

      await new Promise((resolve, reject) => {
        ws.on('open', () => {
          ws.send(`sub ${resourceUrl}`);
        });
        ws.on('message', (data) => {
          messages.push(data.toString());
          if (messages.length >= 2) resolve();
        });
        ws.on('error', reject);
        setTimeout(() => resolve(), 2000);
      });

      assert.ok(messages.includes('protocol solid-0.1'), 'Should receive protocol greeting');
      assert.ok(messages.some(m => m.startsWith('ack ')), 'Should receive ack');
      ws.close();
    });
  });

  describe('Notifications', () => {
    it('should receive pub notification on PUT', async () => {
      const ws = new WebSocket(wsUrl);
      const baseUrl = getBaseUrl();
      const resourceUrl = `${baseUrl}/notifytest/public/notify-put.json`;

      const notifications = [];

      await new Promise((resolve) => {
        ws.on('open', () => {
          ws.send(`sub ${resourceUrl}`);
        });
        ws.on('message', (data) => {
          const msg = data.toString();
          if (msg.startsWith('pub ')) {
            notifications.push(msg);
            resolve();
          }
        });

        // Wait for subscription to be established
        setTimeout(async () => {
          // Create the resource
          await request('/notifytest/public/notify-put.json', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/ld+json' },
            body: JSON.stringify({ '@id': '#test', 'http://example.org/p': 'value' }),
            auth: 'notifytest'
          });
        }, 500);

        setTimeout(() => resolve(), 3000);
      });

      assert.ok(notifications.length > 0, 'Should receive pub notification');
      assert.ok(notifications[0].includes(resourceUrl), 'Notification should include resource URL');
      ws.close();
    });

    it('should receive pub notification on PATCH', async () => {
      const baseUrl = getBaseUrl();
      const resourceUrl = `${baseUrl}/notifytest/public/notify-patch2.json`;

      // First create the resource
      await request('/notifytest/public/notify-patch2.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#test', 'http://example.org/name': 'Original' }),
        auth: 'notifytest'
      });

      // Create WebSocket AFTER the initial PUT to avoid race condition
      const ws = new WebSocket(wsUrl);
      const notifications = [];

      await new Promise((resolve) => {
        ws.on('open', () => {
          ws.send(`sub ${resourceUrl}`);
        });
        ws.on('message', (data) => {
          const msg = data.toString();
          if (msg.startsWith('pub ')) {
            notifications.push(msg);
            resolve();
          }
        });

        // Wait for subscription to be established, then patch
        setTimeout(async () => {
          const patch = `
            @prefix solid: <http://www.w3.org/ns/solid/terms#>.
            _:patch a solid:InsertDeletePatch;
              solid:inserts { <#test> <http://example.org/name> "Updated" }.
          `;
          await request('/notifytest/public/notify-patch2.json', {
            method: 'PATCH',
            headers: { 'Content-Type': 'text/n3' },
            body: patch,
            auth: 'notifytest'
          });
        }, 500);

        setTimeout(() => resolve(), 3000);
      });

      assert.ok(notifications.length > 0, 'Should receive pub notification for PATCH');
      ws.close();
    });

    it('should receive pub notification on DELETE', async () => {
      const baseUrl = getBaseUrl();
      const resourceUrl = `${baseUrl}/notifytest/public/notify-delete2.json`;

      // First create the resource
      await request('/notifytest/public/notify-delete2.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#test' }),
        auth: 'notifytest'
      });

      // Create WebSocket AFTER the initial PUT to avoid race condition
      const ws = new WebSocket(wsUrl);
      const notifications = [];

      await new Promise((resolve) => {
        ws.on('open', () => {
          ws.send(`sub ${resourceUrl}`);
        });
        ws.on('message', (data) => {
          const msg = data.toString();
          if (msg.startsWith('pub ')) {
            notifications.push(msg);
            resolve();
          }
        });

        // Wait for subscription, then delete
        setTimeout(async () => {
          await request('/notifytest/public/notify-delete2.json', {
            method: 'DELETE',
            auth: 'notifytest'
          });
        }, 500);

        setTimeout(() => resolve(), 3000);
      });

      assert.ok(notifications.length > 0, 'Should receive pub notification for DELETE');
      ws.close();
    });

    it('should receive container notification when child changes', async () => {
      const ws = new WebSocket(wsUrl);
      const baseUrl = getBaseUrl();
      const containerUrl = `${baseUrl}/notifytest/public/`;

      const notifications = [];

      await new Promise((resolve) => {
        ws.on('open', () => {
          // Subscribe to container
          ws.send(`sub ${containerUrl}`);
        });
        ws.on('message', (data) => {
          const msg = data.toString();
          if (msg.startsWith('pub ')) {
            notifications.push(msg);
            resolve();
          }
        });

        // Wait for subscription, then create a child resource
        setTimeout(async () => {
          await request('/notifytest/public/child-resource.json', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/ld+json' },
            body: JSON.stringify({ '@id': '#child' }),
            auth: 'notifytest'
          });
        }, 500);

        setTimeout(() => resolve(), 3000);
      });

      assert.ok(notifications.length > 0, 'Container should receive notification for child changes');
      ws.close();
    });
  });

  describe('Multiple Subscribers', () => {
    it('should notify all subscribers', async () => {
      const ws1 = new WebSocket(wsUrl);
      const ws2 = new WebSocket(wsUrl);
      const baseUrl = getBaseUrl();
      const resourceUrl = `${baseUrl}/notifytest/public/multi-sub.json`;

      const notifications1 = [];
      const notifications2 = [];

      await new Promise((resolve) => {
        let ready = 0;

        const setupWs = (ws, notifications) => {
          ws.on('open', () => {
            ws.send(`sub ${resourceUrl}`);
          });
          ws.on('message', (data) => {
            const msg = data.toString();
            if (msg.startsWith('ack ')) {
              ready++;
              if (ready === 2) {
                // Both subscribed, trigger change
                setTimeout(async () => {
                  await request('/notifytest/public/multi-sub.json', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ test: true }),
                    auth: 'notifytest'
                  });
                }, 100);
              }
            }
            if (msg.startsWith('pub ')) {
              notifications.push(msg);
              if (notifications1.length > 0 && notifications2.length > 0) {
                resolve();
              }
            }
          });
        };

        setupWs(ws1, notifications1);
        setupWs(ws2, notifications2);

        setTimeout(() => resolve(), 4000);
      });

      assert.ok(notifications1.length > 0, 'First subscriber should receive notification');
      assert.ok(notifications2.length > 0, 'Second subscriber should receive notification');
      ws1.close();
      ws2.close();
    });
  });
});

describe('WebSocket ACL Enforcement', () => {
  let wsUrl;

  before(async () => {
    await startTestServer({ notifications: true });
    await createTestPod('aclnotify');
    const res = await request('/aclnotify/', { method: 'OPTIONS' });
    wsUrl = res.headers.get('Updates-Via');
  });

  after(async () => {
    await stopTestServer();
  });

  it('should allow anonymous subscription to public resources', async () => {
    const ws = new WebSocket(wsUrl);
    const baseUrl = getBaseUrl();
    const resourceUrl = `${baseUrl}/aclnotify/public/anon-allowed.json`;

    const messages = [];

    await new Promise((resolve, reject) => {
      ws.on('open', () => {
        ws.send(`sub ${resourceUrl}`);
      });
      ws.on('message', (data) => {
        messages.push(data.toString());
        if (messages.length >= 2) resolve();
      });
      ws.on('error', reject);
      setTimeout(() => resolve(), 2000);
    });

    assert.ok(messages.includes('protocol solid-0.1'), 'Should receive protocol greeting');
    assert.ok(messages.some(m => m === `ack ${resourceUrl}`), 'Should receive ack for public resource');
    ws.close();
    await new Promise(r => setTimeout(r, 50)); // Allow WebSocket to fully close
  });

  it('should deny anonymous subscription to private resources', async () => {
    const ws = new WebSocket(wsUrl);
    const baseUrl = getBaseUrl();
    const resourceUrl = `${baseUrl}/aclnotify/private/secret.json`;

    const messages = [];

    await new Promise((resolve, reject) => {
      ws.on('open', () => {
        ws.send(`sub ${resourceUrl}`);
      });
      ws.on('message', (data) => {
        messages.push(data.toString());
        if (messages.some(m => m.startsWith('err '))) resolve();
      });
      ws.on('error', reject);
      setTimeout(() => resolve(), 2000);
    });

    assert.ok(messages.includes('protocol solid-0.1'), 'Should receive protocol greeting');
    assert.ok(messages.some(m => m === `err ${resourceUrl} forbidden`),
      `Should receive err forbidden for private resource. Got: ${messages.join(', ')}`);
    ws.close();
    await new Promise(r => setTimeout(r, 50)); // Allow WebSocket to fully close
  });

  it('should deny subscription to resources on other servers', async () => {
    const ws = new WebSocket(wsUrl);
    const externalUrl = 'https://evil.example.com/steal/data.json';

    const messages = [];

    await new Promise((resolve, reject) => {
      ws.on('open', () => {
        ws.send(`sub ${externalUrl}`);
      });
      ws.on('message', (data) => {
        messages.push(data.toString());
        if (messages.some(m => m.startsWith('err '))) resolve();
      });
      ws.on('error', reject);
      setTimeout(() => resolve(), 2000);
    });

    assert.ok(messages.some(m => m === `err ${externalUrl} forbidden`),
      'Should deny subscription to external URLs');
    ws.close();
    await new Promise(r => setTimeout(r, 50)); // Allow WebSocket to fully close
  });
});

describe('WebSocket Notifications (notifications disabled - default)', () => {
  before(async () => {
    // Start server with notifications DISABLED (default)
    await startTestServer({ notifications: false });
    await createTestPod('nonotify');
  });

  after(async () => {
    await stopTestServer();
  });

  it('should NOT return Updates-Via header when notifications disabled', async () => {
    const res = await request('/nonotify/', { method: 'OPTIONS' });
    assertStatus(res, 204);
    const updatesVia = res.headers.get('Updates-Via');
    assert.strictEqual(updatesVia, null, 'Should NOT have Updates-Via header when disabled');
  });
});
