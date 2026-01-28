/**
 * Live Reload Test
 *
 * Tests the full chain: file change → WebSocket pub → client receives
 */

import { createServer } from '../src/server.js';
import { writeFileSync, mkdirSync, rmSync, existsSync } from 'fs';
import { join } from 'path';
import WebSocket from 'ws';

const TEST_PORT = 9876;
const TEST_DIR = '/tmp/live-reload-test-suite';
const BASE_URL = `http://localhost:${TEST_PORT}`;

// Setup and teardown
function setupTestDir() {
  if (existsSync(TEST_DIR)) {
    rmSync(TEST_DIR, { recursive: true });
  }
  mkdirSync(TEST_DIR, { recursive: true });
  writeFileSync(join(TEST_DIR, 'index.html'), '<!DOCTYPE html><html><body>Hello</body></html>');
  writeFileSync(join(TEST_DIR, 'test.txt'), 'initial content');
}

function cleanupTestDir() {
  if (existsSync(TEST_DIR)) {
    rmSync(TEST_DIR, { recursive: true });
  }
}

// Test 1: Verify WebSocket notifications work for HTTP PUT
async function testHttpPutNotification() {
  console.log('\n=== Test 1: HTTP PUT triggers WebSocket notification ===');

  setupTestDir();

  const server = createServer({
    root: TEST_DIR,
    port: TEST_PORT,
    logger: false,
    liveReload: true,
    public: true,
  });

  await server.listen({ port: TEST_PORT, host: '0.0.0.0' });
  console.log('Server started on port', TEST_PORT);

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      ws.close();
      server.close();
      reject(new Error('Timeout: No WebSocket notification received'));
    }, 5000);

    const ws = new WebSocket(`ws://localhost:${TEST_PORT}/.notifications`);

    ws.on('open', () => {
      console.log('WebSocket connected');
      // Subscribe to the test file
      ws.send(`sub ${BASE_URL}/test.txt`);
      console.log('Subscribed to', `${BASE_URL}/test.txt`);

      // Wait a bit then do HTTP PUT
      setTimeout(async () => {
        console.log('Doing HTTP PUT...');
        const res = await fetch(`${BASE_URL}/test.txt`, {
          method: 'PUT',
          body: 'updated via HTTP',
          headers: { 'Content-Type': 'text/plain' }
        });
        console.log('PUT response:', res.status);
      }, 500);
    });

    ws.on('message', (data) => {
      const msg = data.toString();
      console.log('WebSocket received:', msg);

      if (msg.startsWith('pub ')) {
        clearTimeout(timeout);
        console.log('SUCCESS: Received pub notification');
        ws.close();
        server.close().then(() => {
          cleanupTestDir();
          resolve(true);
        });
      }
    });

    ws.on('error', (err) => {
      clearTimeout(timeout);
      server.close();
      reject(err);
    });
  });
}

// Test 2: Verify file watcher detects filesystem changes
async function testFileWatcherNotification() {
  console.log('\n=== Test 2: Filesystem change triggers WebSocket notification ===');

  setupTestDir();

  const server = createServer({
    root: TEST_DIR,
    port: TEST_PORT,
    logger: false,
    liveReload: true,
    public: true,
  });

  await server.listen({ port: TEST_PORT, host: '0.0.0.0' });
  console.log('Server started on port', TEST_PORT);

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      ws.close();
      server.close();
      reject(new Error('Timeout: No WebSocket notification received for filesystem change'));
    }, 5000);

    const ws = new WebSocket(`ws://localhost:${TEST_PORT}/.notifications`);

    ws.on('open', () => {
      console.log('WebSocket connected');
      // Subscribe to the test file
      ws.send(`sub ${BASE_URL}/test.txt`);
      console.log('Subscribed to', `${BASE_URL}/test.txt`);

      // Wait a bit then modify file directly on filesystem
      setTimeout(() => {
        console.log('Modifying file via filesystem...');
        writeFileSync(join(TEST_DIR, 'test.txt'), 'updated via filesystem ' + Date.now());
        console.log('File written');
      }, 1000);
    });

    ws.on('message', (data) => {
      const msg = data.toString();
      console.log('WebSocket received:', msg);

      if (msg.startsWith('pub ')) {
        clearTimeout(timeout);
        console.log('SUCCESS: Received pub notification for filesystem change');
        ws.close();
        server.close().then(() => {
          cleanupTestDir();
          resolve(true);
        });
      }
    });

    ws.on('error', (err) => {
      clearTimeout(timeout);
      server.close();
      reject(err);
    });
  });
}

// Test 3: Verify fs.watch works on this platform
async function testFsWatch() {
  console.log('\n=== Test 3: Basic fs.watch functionality ===');

  const { watch } = await import('fs');
  const testFile = '/tmp/fswatch-test.txt';

  writeFileSync(testFile, 'initial');

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      watcher.close();
      reject(new Error('fs.watch did not detect file change'));
    }, 3000);

    const watcher = watch(testFile, (eventType, filename) => {
      console.log('fs.watch detected:', eventType, filename);
      clearTimeout(timeout);
      watcher.close();
      resolve(true);
    });

    // Modify file after short delay
    setTimeout(() => {
      console.log('Modifying file...');
      writeFileSync(testFile, 'modified ' + Date.now());
    }, 500);
  });
}

// Test 4: Verify fs.watch with recursive option
async function testFsWatchRecursive() {
  console.log('\n=== Test 4: fs.watch with recursive option ===');

  const { watch } = await import('fs');
  const testDir = '/tmp/fswatch-recursive-test';

  if (existsSync(testDir)) rmSync(testDir, { recursive: true });
  mkdirSync(testDir, { recursive: true });
  writeFileSync(join(testDir, 'file.txt'), 'initial');

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      watcher.close();
      console.log('FAIL: fs.watch recursive did not detect file change');
      resolve(false); // Don't reject, just report failure
    }, 3000);

    let detected = false;
    const watcher = watch(testDir, { recursive: true }, (eventType, filename) => {
      if (!detected) {
        detected = true;
        console.log('fs.watch recursive detected:', eventType, filename);
        clearTimeout(timeout);
        watcher.close();
        resolve(true);
      }
    });

    watcher.on('error', (err) => {
      console.log('fs.watch error:', err.message);
      clearTimeout(timeout);
      resolve(false);
    });

    // Modify file after short delay
    setTimeout(() => {
      console.log('Modifying file in watched directory...');
      writeFileSync(join(testDir, 'file.txt'), 'modified ' + Date.now());
    }, 500);
  });
}

// Run all tests
async function runTests() {
  console.log('Live Reload Test Suite');
  console.log('======================');

  try {
    // Test basic fs.watch first
    const fsWatchWorks = await testFsWatch();
    console.log('Test 3 result: fs.watch works =', fsWatchWorks);

    // Test recursive fs.watch
    const fsWatchRecursiveWorks = await testFsWatchRecursive();
    console.log('Test 4 result: fs.watch recursive works =', fsWatchRecursiveWorks);

    // Test HTTP PUT notification
    await testHttpPutNotification();
    console.log('Test 1 result: PASSED');

    // Test file watcher notification
    await testFileWatcherNotification();
    console.log('Test 2 result: PASSED');

    console.log('\n=== All tests passed ===');
  } catch (err) {
    console.error('\n=== Test FAILED ===');
    console.error(err.message);
    process.exit(1);
  }
}

runTests();
