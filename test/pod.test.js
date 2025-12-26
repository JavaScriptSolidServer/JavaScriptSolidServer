/**
 * Pod lifecycle tests
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
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
      assert.ok(data.webId.endsWith('/alice/#me'));
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
      await request('/.pods', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'carol' })
      });

      // Check inbox exists
      const inbox = await request('/carol/inbox/');
      assertStatus(inbox, 200);

      // Check public exists
      const pub = await request('/carol/public/');
      assertStatus(pub, 200);

      // Check private exists
      const priv = await request('/carol/private/');
      assertStatus(priv, 200);

      // Check settings exists
      const settings = await request('/carol/settings/');
      assertStatus(settings, 200);
    });

    it('should create settings files', async () => {
      await request('/.pods', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'dan' })
      });

      // Check prefs
      const prefs = await request('/dan/settings/prefs');
      assertStatus(prefs, 200);

      // Check public type index
      const pubIndex = await request('/dan/settings/publicTypeIndex');
      assertStatus(pubIndex, 200);

      // Check private type index
      const privIndex = await request('/dan/settings/privateTypeIndex');
      assertStatus(privIndex, 200);
    });
  });
});
