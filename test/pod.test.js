/**
 * Pod lifecycle tests
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  assertStatus,
  assertHeader,
  assertHeaderContains
} from './helpers.js';

describe('Pod Lifecycle', () => {
  before(async () => {
    await startTestServer();
  });

  after(async () => {
    await stopTestServer();
  });

  describe('POST /.pods', () => {
    it('should create a new pod', async () => {
      const res = await request('/.pods', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'alice' })
      });

      assertStatus(res, 201);
      assertHeader(res, 'Location');

      const data = await res.json();
      assert.strictEqual(data.name, 'alice');
      assert.ok(data.webId.endsWith('/alice/profile/card#me'));
      assert.ok(data.podUri.endsWith('/alice/'));
    });

    it('should reject duplicate pod names', async () => {
      // First create
      await request('/.pods', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'bob' })
      });

      // Duplicate attempt
      const res = await request('/.pods', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'bob' })
      });

      assertStatus(res, 409);
    });

    it('should reject invalid pod names', async () => {
      const res = await request('/.pods', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: '../evil' })
      });

      assertStatus(res, 400);
    });

    it('should reject empty pod name', async () => {
      const res = await request('/.pods', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });

      assertStatus(res, 400);
    });
  });

  describe('Pod Structure', () => {
    it('should create standard folders', async () => {
      await createTestPod('carol');

      // Check inbox exists (needs auth - inbox only allows public append, not read)
      const inbox = await request('/carol/inbox/', { auth: 'carol' });
      assertStatus(inbox, 200);

      // Check public exists (public read via root ACL default)
      const pub = await request('/carol/public/');
      assertStatus(pub, 200);

      // Check private exists (needs auth)
      const priv = await request('/carol/private/', { auth: 'carol' });
      assertStatus(priv, 200);

      // Check Settings exists (needs auth)
      const settings = await request('/carol/Settings/', { auth: 'carol' });
      assertStatus(settings, 200);
    });

    it('should create settings files', async () => {
      await createTestPod('dan');

      // Check Preferences.ttl (needs auth - Settings is private)
      const prefs = await request('/dan/Settings/Preferences.ttl', { auth: 'dan' });
      assertStatus(prefs, 200);

      // Check public type index (needs auth)
      const pubIndex = await request('/dan/Settings/publicTypeIndex.ttl', { auth: 'dan' });
      assertStatus(pubIndex, 200);

      // Check private type index (needs auth)
      const privIndex = await request('/dan/Settings/privateTypeIndex.ttl', { auth: 'dan' });
      assertStatus(privIndex, 200);
    });
  });
});
