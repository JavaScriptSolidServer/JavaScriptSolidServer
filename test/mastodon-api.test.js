/**
 * Mastodon-compatible API Tests
 *
 * Tests the Mastodon API endpoints exposed by the ActivityPub plugin.
 * Covers: verify_credentials, statuses, follow, notifications.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  getPodToken,
  assertStatus
} from './helpers.js';

describe('Mastodon API (activitypub enabled)', () => {
  let alicePostUrl = null;

  before(async () => {
    await startTestServer({ activitypub: true, subdomains: false });
    await createTestPod('alice');
    await createTestPod('bob');
  });

  after(async () => {
    await stopTestServer();
  });

  // ── verify_credentials ──────────────────────────────────────────────────

  describe('GET /api/v1/accounts/verify_credentials', () => {
    it('should return 401 without token', async () => {
      const res = await request('/api/v1/accounts/verify_credentials');
      assertStatus(res, 401);
    });

    it('should return authenticated user profile', async () => {
      const res = await request('/api/v1/accounts/verify_credentials', { auth: 'alice' });
      assertStatus(res, 200);
      const body = await res.json();
      assert.strictEqual(body.username, 'alice', 'username should be alice');
      assert.strictEqual(body.id, 'alice', 'id should be alice not "1"');
      assert.ok(typeof body.followers_count === 'number', 'followers_count should be a number');
      assert.ok(typeof body.following_count === 'number', 'following_count should be a number');
      assert.ok(typeof body.statuses_count === 'number', 'statuses_count should be a number');
      assert.ok(body.source, 'should have source field');
    });
  });

  // ── instance ─────────────────────────────────────────────────────────────

  describe('GET /api/v2/instance', () => {
    it('should return instance metadata', async () => {
      const res = await request('/api/v2/instance');
      assertStatus(res, 200);
      const body = await res.json();
      assert.ok(body.domain, 'should have domain');
      assert.ok(body.title, 'should have title');
      assert.ok(body.version, 'should have version');
      assert.ok(body.configuration?.statuses?.max_characters, 'should have statuses config');
    });
  });

  // ── account lookup ───────────────────────────────────────────────────────

  describe('GET /api/v1/accounts/lookup', () => {
    it('should resolve account by acct handle', async () => {
      const res = await request('/api/v1/accounts/lookup?acct=alice');
      assertStatus(res, 200);
      const body = await res.json();
      assert.strictEqual(body.username, 'alice', 'lookup should resolve alice');
    });

    it('should resolve account by full acct handle with domain', async () => {
      const res = await request('/api/v1/accounts/lookup?acct=alice@alice.pivot-test.local:4443');
      assertStatus(res, 200);
      const body = await res.json();
      assert.strictEqual(body.username, 'alice', 'lookup should normalize alice@domain to alice');
    });
  });

  // ── update credentials ───────────────────────────────────────────────────

  describe('PATCH /api/v1/accounts/update_credentials', () => {
    it('should return 401 without token', async () => {
      const res = await request('/api/v1/accounts/update_credentials', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ display_name: 'Alice New' }).toString()
      });
      assertStatus(res, 401);
    });

    it('should update profile fields and return updated account', async () => {
      const res = await request('/api/v1/accounts/update_credentials', {
        method: 'PATCH',
        auth: 'alice',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ display_name: 'Alice New', note: 'Bio from test' }).toString()
      });
      assertStatus(res, 200);
      const body = await res.json();
      assert.strictEqual(body.display_name, 'Alice New', 'display_name should update');
      assert.ok(body.note.includes('Bio from test'), 'note should update');

      const verifyRes = await request('/api/v1/accounts/verify_credentials', { auth: 'alice' });
      assertStatus(verifyRes, 200);
      const verified = await verifyRes.json();
      assert.strictEqual(verified.display_name, 'Alice New', 'verify_credentials should reflect updated display_name');
      assert.strictEqual(verified.source.note, 'Bio from test', 'verify_credentials source.note should reflect updated note');
    });

    it('should accept jpg avatar upload and serve it from profile/avatar.png', async () => {
      const boundary = '----jss-test-boundary';
      const jpegHeader = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]);
      const parts = [
        Buffer.from(`--${boundary}\r\n`),
        Buffer.from('Content-Disposition: form-data; name="display_name"\r\n\r\n'),
        Buffer.from('Alice Avatar\r\n'),
        Buffer.from(`--${boundary}\r\n`),
        Buffer.from('Content-Disposition: form-data; name="avatar"; filename="avatar.jpg"\r\n'),
        Buffer.from('Content-Type: image/jpeg\r\n\r\n'),
        jpegHeader,
        Buffer.from('\r\n'),
        Buffer.from(`--${boundary}--\r\n`)
      ];
      const body = Buffer.concat(parts);

      const updateRes = await request('/api/v1/accounts/update_credentials', {
        method: 'PATCH',
        auth: 'alice',
        headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
        body
      });
      assertStatus(updateRes, 200);

      const avatarRes = await request('/profile/avatar.png', { auth: 'alice' });
      assertStatus(avatarRes, 200);
      const ct = avatarRes.headers.get('content-type') || '';
      assert.ok(ct.startsWith('image/'), 'avatar route should serve an image');
    });
  });

  // ── preferences / relationships ──────────────────────────────────────────

  describe('GET /api/v1/preferences', () => {
    it('should return 401 without token', async () => {
      const res = await request('/api/v1/preferences');
      assertStatus(res, 401);
    });

    it('should return Mastodon preference payload', async () => {
      const res = await request('/api/v1/preferences', { auth: 'alice' });
      assertStatus(res, 200);
      const body = await res.json();
      assert.ok(Object.prototype.hasOwnProperty.call(body, 'posting:default:visibility'), 'preferences should include visibility key');
    });
  });

  describe('GET /api/v1/lists', () => {
    it('should return 401 without token', async () => {
      const res = await request('/api/v1/lists');
      assertStatus(res, 401);
    });

    it('should return an empty array when authenticated', async () => {
      const res = await request('/api/v1/lists', { auth: 'alice' });
      assertStatus(res, 200);
      const body = await res.json();
      assert.ok(Array.isArray(body), 'lists should be an array');
      assert.strictEqual(body.length, 0, 'lists should default to empty');
    });
  });

  describe('GET /api/v1/accounts/relationships', () => {
    it('should return relationship entries for requested IDs', async () => {
      const res = await request('/api/v1/accounts/relationships?id[]=alice', { auth: 'bob' });
      assertStatus(res, 200);
      const body = await res.json();
      assert.ok(Array.isArray(body), 'relationships should be an array');
      assert.strictEqual(body.length, 1, 'should return one relationship object');
      assert.strictEqual(body[0].id, 'alice', 'relationship id should match query');
      assert.ok(Object.prototype.hasOwnProperty.call(body[0], 'following'), 'relationship should include following field');
    });
  });

  // ── search ───────────────────────────────────────────────────────────────

  describe('GET /api/v2/search', () => {
    it('should resolve a status URL to a status result', async () => {
      // Create a post first so it can be found by URL search
      const createRes = await request('/api/v1/statuses', {
        method: 'POST',
        auth: 'alice',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ status: 'searchable post' }).toString()
      });
      assertStatus(createRes, 200);
      const created = await createRes.json();

      const q = encodeURIComponent(created.uri);
      const res = await request(`/api/v2/search?q=${q}&limit=1&resolve=true`);
      assertStatus(res, 200);
      const body = await res.json();
      assert.ok(Array.isArray(body.accounts), 'accounts should be an array');
      assert.ok(Array.isArray(body.statuses), 'statuses should be an array');
      assert.ok(Array.isArray(body.hashtags), 'hashtags should be an array');
      assert.ok(body.statuses.length >= 1, 'should return at least one status');
      assert.strictEqual(body.statuses[0].uri, created.uri, 'resolved status URI should match');
    });
  });

  // ── statuses ─────────────────────────────────────────────────────────────

  describe('POST /api/v1/statuses', () => {
    it('should return 401 without token', async () => {
      const res = await request('/api/v1/statuses', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'status=test'
      });
      assertStatus(res, 401);
    });

    it('should create a status and return Mastodon status object', async () => {
      const res = await request('/api/v1/statuses', {
        method: 'POST',
        auth: 'alice',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ status: 'hello from alice test' }).toString()
      });
      assertStatus(res, 200);
      const body = await res.json();
      assert.ok(body.id, 'should have id');
      alicePostUrl = body.uri;
      assert.ok(alicePostUrl, 'should return canonical uri');
      assert.strictEqual(body.content, 'hello from alice test', 'content should match');
      assert.strictEqual(body.account.username, 'alice', 'account username should be alice');
      assert.strictEqual(body.visibility, 'public');
    });

    it('should update statuses_count after posting', async () => {
      // Post as bob
      await request('/api/v1/statuses', {
        method: 'POST',
        auth: 'bob',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ status: 'hello from bob test' }).toString()
      });

      const res = await request('/api/v1/accounts/verify_credentials', { auth: 'bob' });
      const body = await res.json();
      assert.ok(body.statuses_count >= 1, 'statuses_count should be at least 1 after posting');
    });

    it('should edit a status using full URL ID path', async () => {
      const createRes = await request('/api/v1/statuses', {
        method: 'POST',
        auth: 'alice',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ status: 'edit me' }).toString()
      });
      assertStatus(createRes, 200);
      const created = await createRes.json();

      const editRes = await request(`/api/v1/statuses/${created.id}`, {
        method: 'PUT',
        auth: 'alice',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ status: 'edited text', language: 'fr', sensitive: 'false' }).toString()
      });
      assertStatus(editRes, 200);
      const edited = await editRes.json();
      assert.strictEqual(edited.content, 'edited text', 'status content should be updated');

      const postUrl = new URL(created.uri);
      const postId = postUrl.pathname.split('/').filter(Boolean).pop();
      const permalinkRes = await request(`/posts/${postId}`);
      assertStatus(permalinkRes, 200);
      const permalink = await permalinkRes.json();
      assert.strictEqual(permalink.content, 'edited text', 'permalink should reflect edited content');
    });

    it('should fetch status source using full URL ID path', async () => {
      const createRes = await request('/api/v1/statuses', {
        method: 'POST',
        auth: 'alice',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ status: 'source me' }).toString()
      });
      assertStatus(createRes, 200);
      const created = await createRes.json();

      const sourceRes = await request(`/api/v1/statuses/${created.id}/source`, {
        method: 'GET',
        auth: 'alice'
      });
      assertStatus(sourceRes, 200);
      const source = await sourceRes.json();
      assert.strictEqual(source.text, 'source me', 'source endpoint should return editable text');
      assert.ok(Object.prototype.hasOwnProperty.call(source, 'spoiler_text'), 'source should include spoiler_text');
      assert.ok(Object.prototype.hasOwnProperty.call(source, 'sensitive'), 'source should include sensitive');
    });

    it('should fetch status by full URL ID path', async () => {
      const createRes = await request('/api/v1/statuses', {
        method: 'POST',
        auth: 'alice',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ status: 'status endpoint me' }).toString()
      });
      assertStatus(createRes, 200);
      const created = await createRes.json();

      const statusRes = await request(`/api/v1/statuses/${created.id}`);
      assertStatus(statusRes, 200);
      const fetched = await statusRes.json();
      assert.strictEqual(fetched.uri, created.uri, 'status URI should match');
      assert.strictEqual(fetched.content, 'status endpoint me', 'status content should match');
    });

    it('should fetch status history by full URL ID path', async () => {
      const createRes = await request('/api/v1/statuses', {
        method: 'POST',
        auth: 'alice',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ status: 'history endpoint me' }).toString()
      });
      assertStatus(createRes, 200);
      const created = await createRes.json();

      const historyRes = await request(`/api/v1/statuses/${created.id}/history`);
      assertStatus(historyRes, 200);
      const history = await historyRes.json();
      assert.ok(Array.isArray(history), 'history should be an array');
      assert.ok(history.length >= 1, 'history should have at least one entry');
      assert.strictEqual(history[0].content, 'history endpoint me', 'history should include current content');
    });

    it('should favourite a status by full URL ID path', async () => {
      const createRes = await request('/api/v1/statuses', {
        method: 'POST',
        auth: 'bob',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ status: 'like me' }).toString()
      });
      assertStatus(createRes, 200);
      const created = await createRes.json();

      const favRes = await request(`/api/v1/statuses/${created.id}/favourite`, {
        method: 'POST',
        auth: 'alice'
      });
      assertStatus(favRes, 200);
      const liked = await favRes.json();
      assert.strictEqual(liked.uri, created.uri, 'favourited status should preserve URI');
      assert.strictEqual(liked.favourited, true, 'favourited should be true');
      assert.ok(liked.favourites_count >= 1, 'favourites_count should be incremented');
    });
  });

  // ── permalink post object ────────────────────────────────────────────────

  describe('GET /posts/:id', () => {
    it('should return Note object for a created status permalink', async () => {
      assert.ok(alicePostUrl, 'alice post URL should exist from previous status test');
      const res = await request(alicePostUrl);
      assertStatus(res, 200);
      const body = await res.json();
      assert.strictEqual(body.type, 'Note', 'should return ActivityStreams Note');
      assert.strictEqual(body.id, alicePostUrl, 'note id should match canonical post URL');
      assert.strictEqual(body.content, 'hello from alice test', 'note content should match created status');
    });
  });

  // ── follow ────────────────────────────────────────────────────────────────

  describe('POST /api/v1/accounts/:id/follow', () => {
    it('should return 401 without token', async () => {
      const res = await request('/api/v1/accounts/alice/follow', { method: 'POST' });
      assertStatus(res, 401);
    });

    it('should follow a user and return relationship with requested: false', async () => {
      const res = await request('/api/v1/accounts/alice/follow', {
        method: 'POST',
        auth: 'bob'
      });
      assertStatus(res, 200);
      const body = await res.json();
      assert.strictEqual(body.id, 'alice');
      assert.strictEqual(body.following, true);
      assert.strictEqual(body.requested, false, 'should be immediately accepted');
    });

    it('should increment following_count for bob', async () => {
      const res = await request('/api/v1/accounts/verify_credentials', { auth: 'bob' });
      const body = await res.json();
      assert.ok(body.following_count >= 1, 'bob following_count should be at least 1');
    });

    it('should increment followers_count for alice', async () => {
      const res = await request('/api/v1/accounts/verify_credentials', { auth: 'alice' });
      const body = await res.json();
      assert.ok(body.followers_count >= 1, 'alice followers_count should be at least 1');
    });
  });

  // ── notifications ─────────────────────────────────────────────────────────

  describe('GET /api/v1/notifications', () => {
    it('should return 401 without token', async () => {
      const res = await request('/api/v1/notifications');
      assertStatus(res, 401);
    });

    it('should return follow notification for alice with bob as follower', async () => {
      const res = await request('/api/v1/notifications', { auth: 'alice' });
      assertStatus(res, 200);
      const body = await res.json();
      assert.ok(Array.isArray(body), 'should be an array');
      const followNotif = body.find(n => n.type === 'follow')
      assert.ok(followNotif, 'should have a follow notification');
      assert.strictEqual(followNotif.account.username, 'bob', 'follower should be bob not alice');
      assert.ok(followNotif.created_at, 'should have created_at');
    });

    it('should return empty notifications for bob (nobody follows bob)', async () => {
      const res = await request('/api/v1/notifications', { auth: 'bob' });
      assertStatus(res, 200);
      const body = await res.json();
      assert.ok(Array.isArray(body), 'should be an array');
      assert.strictEqual(body.length, 0, 'bob should have no notifications');
    });
  });

  // ── home timeline ─────────────────────────────────────────────────────────

  describe('GET /api/v1/timelines/home', () => {
    it('should return 401 without token', async () => {
      const res = await request('/api/v1/timelines/home');
      assertStatus(res, 401);
    });

    it('should return posts from followed users and self', async () => {
      const res = await request('/api/v1/timelines/home', { auth: 'alice' });
      assertStatus(res, 200);
      const body = await res.json();
      assert.ok(Array.isArray(body), 'should be an array');
      assert.ok(body.length >= 1, 'should have at least one post');
      // All posts should have required fields
      for (const post of body) {
        assert.ok(post.id, 'post should have id');
        assert.ok(post.content, 'post should have content');
        assert.ok(post.account?.username, 'post should have account.username');
        assert.ok(post.created_at, 'post should have created_at');
      }
    });
  });

  describe('GET /api/v1/accounts/:id/statuses', () => {
    it('should accept handle-like account identifiers', async () => {
      const res = await request('/api/v1/accounts/alice@alice.pivot-test.local:4443/statuses');
      assertStatus(res, 200);
      const body = await res.json();
      assert.ok(Array.isArray(body), 'statuses should be an array');
    });
  });

  describe('GET /api/v1/accounts/:id/lists', () => {
    it('should return empty list memberships for account identifiers', async () => {
      const res = await request('/api/v1/accounts/bob@bob.pivot-test.local:4443/lists', { auth: 'alice' });
      assertStatus(res, 200);
      const body = await res.json();
      assert.ok(Array.isArray(body), 'account lists should be an array');
      assert.strictEqual(body.length, 0, 'account lists should default to empty');
    });
  });
});
