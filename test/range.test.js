/**
 * Range Request Tests
 *
 * Tests HTTP Range header support for partial content delivery.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  assertStatus
} from './helpers.js';

describe('Range Requests', () => {
  const testContent = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; // 36 bytes

  before(async () => {
    await startTestServer();
    await createTestPod('rangetest');

    // Create a test file with known content
    await request('/rangetest/public/test.txt', {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain' },
      body: testContent,
      auth: 'rangetest'
    });
  });

  after(async () => {
    await stopTestServer();
  });

  describe('Accept-Ranges header', () => {
    it('should include Accept-Ranges: bytes for files', async () => {
      const res = await request('/rangetest/public/test.txt');
      assertStatus(res, 200);
      assert.strictEqual(res.headers.get('Accept-Ranges'), 'bytes');
    });

    it('should include Accept-Ranges: none for containers', async () => {
      const res = await request('/rangetest/public/');
      assertStatus(res, 200);
      assert.strictEqual(res.headers.get('Accept-Ranges'), 'none');
    });
  });

  describe('Range header parsing', () => {
    it('should return 206 for valid range bytes=0-9', async () => {
      const res = await request('/rangetest/public/test.txt', {
        headers: { 'Range': 'bytes=0-9' }
      });
      assertStatus(res, 206);

      const body = await res.text();
      assert.strictEqual(body, 'ABCDEFGHIJ');
      assert.strictEqual(res.headers.get('Content-Range'), 'bytes 0-9/36');
      assert.strictEqual(res.headers.get('Content-Length'), '10');
    });

    it('should return 206 for open-ended range bytes=30-', async () => {
      const res = await request('/rangetest/public/test.txt', {
        headers: { 'Range': 'bytes=30-' }
      });
      assertStatus(res, 206);

      const body = await res.text();
      assert.strictEqual(body, '456789');
      assert.strictEqual(res.headers.get('Content-Range'), 'bytes 30-35/36');
    });

    it('should return 206 for suffix range bytes=-6', async () => {
      const res = await request('/rangetest/public/test.txt', {
        headers: { 'Range': 'bytes=-6' }
      });
      assertStatus(res, 206);

      const body = await res.text();
      assert.strictEqual(body, '456789');
      assert.strictEqual(res.headers.get('Content-Range'), 'bytes 30-35/36');
    });

    it('should clamp end to file size for range exceeding file', async () => {
      const res = await request('/rangetest/public/test.txt', {
        headers: { 'Range': 'bytes=30-1000' }
      });
      assertStatus(res, 206);

      const body = await res.text();
      assert.strictEqual(body, '456789');
      assert.strictEqual(res.headers.get('Content-Range'), 'bytes 30-35/36');
    });
  });

  describe('Multi-range requests', () => {
    it('should ignore multi-range and return 200 with full content', async () => {
      const res = await request('/rangetest/public/test.txt', {
        headers: { 'Range': 'bytes=0-5,10-15' }
      });
      // Multi-range is not supported, should fall back to 200
      assertStatus(res, 200);

      const body = await res.text();
      assert.strictEqual(body, testContent);
    });
  });

  describe('Invalid ranges', () => {
    it('should return 200 for invalid range format', async () => {
      const res = await request('/rangetest/public/test.txt', {
        headers: { 'Range': 'invalid' }
      });
      // Invalid format, ignore Range header
      assertStatus(res, 200);
    });

    it('should return 200 for non-bytes range unit', async () => {
      const res = await request('/rangetest/public/test.txt', {
        headers: { 'Range': 'chars=0-10' }
      });
      assertStatus(res, 200);
    });
  });

  describe('RDF resources', () => {
    it('should ignore Range header for RDF resources', async () => {
      // Create an RDF resource
      await request('/rangetest/public/data.jsonld', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#test', 'http://example.org/name': 'Test' }),
        auth: 'rangetest'
      });

      const res = await request('/rangetest/public/data.jsonld', {
        headers: { 'Range': 'bytes=0-10' }
      });
      // RDF resources don't support range requests
      assertStatus(res, 200);
    });
  });
});
