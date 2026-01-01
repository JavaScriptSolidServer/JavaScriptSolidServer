#!/usr/bin/env node
/**
 * Test git push/pull with Nostr NIP-98 authentication
 *
 * Usage: node test-git-nostr-auth.js
 *
 * Prerequisites:
 * - JSS server running on localhost:4000 with --git flag
 * - git-credential-nostr installed globally
 * - git config --global credential.helper nostr
 *
 * This script:
 * 1. Creates a test git repo on the server
 * 2. Sets up ACL with authorized Nostr DID
 * 3. Tests clone (public read)
 * 4. Tests push with authorized key (should succeed)
 * 5. Tests push with unauthorized key (should fail with 403)
 * 6. Cleans up
 */

import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { bytesToHex } from '@noble/hashes/utils';
import { execSync, spawn } from 'child_process';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';

const BASE_URL = process.env.TEST_URL || 'http://localhost:4000';
const DATA_ROOT = process.env.DATA_ROOT || '/home/melvin/jss/data';
const TEST_POD = 'test-git-nostr';
const TEST_REPO = 'test-repo';

// Generate keypairs for testing
const authorizedSk = generateSecretKey();
const authorizedPk = getPublicKey(authorizedSk);
const authorizedPrivHex = bytesToHex(authorizedSk);

const unauthorizedSk = generateSecretKey();
const unauthorizedPk = getPublicKey(unauthorizedSk);
const unauthorizedPrivHex = bytesToHex(unauthorizedSk);

let tempDir;
let passed = 0;
let failed = 0;

function log(msg) {
  console.log(`  ${msg}`);
}

function pass(test) {
  console.log(`✓ ${test}`);
  passed++;
}

function fail(test, error) {
  console.log(`✗ ${test}`);
  console.log(`  Error: ${error}`);
  failed++;
}

function exec(cmd, options = {}) {
  try {
    return execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], ...options });
  } catch (e) {
    if (options.allowFail) {
      return { error: true, stderr: e.stderr, stdout: e.stdout, status: e.status };
    }
    throw e;
  }
}

async function setup() {
  console.log('\n=== Setup ===\n');

  // Create temp directory for client repos
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'git-nostr-test-'));
  log(`Temp directory: ${tempDir}`);

  // Create test pod directory
  const podPath = path.join(DATA_ROOT, TEST_POD);
  fs.ensureDirSync(podPath);
  log(`Created pod: ${podPath}`);

  // Create bare git repo
  const repoPath = path.join(podPath, TEST_REPO);
  fs.ensureDirSync(repoPath);
  exec(`git init --bare`, { cwd: repoPath });
  exec(`git config --local receive.denyCurrentBranch ignore`, { cwd: repoPath });
  exec(`git config --local http.receivepack true`, { cwd: repoPath });
  exec(`git symbolic-ref HEAD refs/heads/main`, { cwd: repoPath });
  log(`Created bare repo: ${repoPath}`);

  // Create ACL with authorized Nostr DID
  const acl = {
    "@context": {
      "acl": "http://www.w3.org/ns/auth/acl#",
      "foaf": "http://xmlns.com/foaf/0.1/"
    },
    "@graph": [
      {
        "@id": "#nostr",
        "@type": "acl:Authorization",
        "acl:agent": { "@id": `did:nostr:${authorizedPk}` },
        "acl:accessTo": { "@id": `${BASE_URL}/${TEST_POD}/` },
        "acl:mode": [
          { "@id": "acl:Read" },
          { "@id": "acl:Write" }
        ],
        "acl:default": { "@id": `${BASE_URL}/${TEST_POD}/` }
      },
      {
        "@id": "#public",
        "@type": "acl:Authorization",
        "acl:agentClass": { "@id": "foaf:Agent" },
        "acl:accessTo": { "@id": `${BASE_URL}/${TEST_POD}/` },
        "acl:mode": [{ "@id": "acl:Read" }],
        "acl:default": { "@id": `${BASE_URL}/${TEST_POD}/` }
      }
    ]
  };

  fs.writeJsonSync(path.join(podPath, '.acl'), acl, { spaces: 2 });
  log(`Created ACL with authorized DID: did:nostr:${authorizedPk.slice(0, 16)}...`);

  // Create initial commit in a temp client repo
  const initRepo = path.join(tempDir, 'init');
  fs.ensureDirSync(initRepo);
  exec('git init', { cwd: initRepo });
  exec('git config user.email "test@example.com"', { cwd: initRepo });
  exec('git config user.name "Test User"', { cwd: initRepo });
  fs.writeFileSync(path.join(initRepo, 'README.md'), '# Test Repo\n');
  exec('git add .', { cwd: initRepo });
  exec('git commit -m "Initial commit"', { cwd: initRepo });
  exec('git branch -m main', { cwd: initRepo });
  exec(`git remote add origin ${BASE_URL}/${TEST_POD}/${TEST_REPO}/`, { cwd: initRepo });

  // Configure authorized key for initial push
  exec(`git config nostr.privkey ${authorizedPrivHex}`, { cwd: initRepo });

  log('Created initial commit');
}

async function testClone() {
  console.log('\n=== Test: Clone (public read) ===\n');

  const cloneDir = path.join(tempDir, 'clone-test');
  try {
    exec(`git clone ${BASE_URL}/${TEST_POD}/${TEST_REPO}/ ${cloneDir}`);
    if (fs.existsSync(path.join(cloneDir, '.git'))) {
      pass('Clone succeeded (public read works)');
    } else {
      fail('Clone', 'No .git directory created');
    }
  } catch (e) {
    // Clone might fail if repo is empty, that's ok
    if (e.message.includes('empty repository')) {
      pass('Clone of empty repo handled correctly');
    } else {
      fail('Clone', e.message);
    }
  }
}

async function testPushAuthorized() {
  console.log('\n=== Test: Push with authorized key ===\n');

  const initRepo = path.join(tempDir, 'init');
  try {
    // Push should work with authorized key
    exec('git push -u origin main', { cwd: initRepo });
    pass('Push with authorized key succeeded');
  } catch (e) {
    fail('Push with authorized key', e.stderr || e.message);
  }
}

async function testPushUnauthorized() {
  console.log('\n=== Test: Push with unauthorized key ===\n');

  const cloneDir = path.join(tempDir, 'unauthorized-test');

  try {
    // Clone first (should work - public read)
    exec(`git clone ${BASE_URL}/${TEST_POD}/${TEST_REPO}/ ${cloneDir}`);
    exec('git config user.email "test@example.com"', { cwd: cloneDir });
    exec('git config user.name "Test User"', { cwd: cloneDir });

    // Configure unauthorized key
    exec(`git config nostr.privkey ${unauthorizedPrivHex}`, { cwd: cloneDir });

    // Make a change
    fs.appendFileSync(path.join(cloneDir, 'README.md'), '\nUnauthorized change\n');
    exec('git add .', { cwd: cloneDir });
    exec('git commit -m "Unauthorized change"', { cwd: cloneDir });

    // Push should fail with 403
    const result = exec('git push 2>&1', { cwd: cloneDir, allowFail: true });

    if (result.error && (result.stderr?.includes('403') || result.stdout?.includes('403'))) {
      pass('Push with unauthorized key correctly rejected (403)');
    } else if (result.error) {
      // Check if it failed for the right reason
      if (result.stderr?.includes('Authentication failed') || result.stderr?.includes('403')) {
        pass('Push with unauthorized key correctly rejected');
      } else {
        fail('Push with unauthorized key', `Unexpected error: ${result.stderr}`);
      }
    } else {
      fail('Push with unauthorized key', 'Push should have failed but succeeded');
    }
  } catch (e) {
    if (e.stderr?.includes('403') || e.message?.includes('403')) {
      pass('Push with unauthorized key correctly rejected (403)');
    } else {
      fail('Push with unauthorized key', e.stderr || e.message);
    }
  }
}

async function testPullAfterPush() {
  console.log('\n=== Test: Pull after push ===\n');

  const pullDir = path.join(tempDir, 'pull-test');

  try {
    exec(`git clone ${BASE_URL}/${TEST_POD}/${TEST_REPO}/ ${pullDir}`);
    const readme = fs.readFileSync(path.join(pullDir, 'README.md'), 'utf8');

    if (readme.includes('Test Repo')) {
      pass('Pull retrieved pushed content');
    } else {
      fail('Pull after push', 'Content mismatch');
    }
  } catch (e) {
    fail('Pull after push', e.stderr || e.message);
  }
}

async function cleanup() {
  console.log('\n=== Cleanup ===\n');

  // Remove temp directory
  if (tempDir) {
    fs.removeSync(tempDir);
    log(`Removed temp directory: ${tempDir}`);
  }

  // Remove test pod
  const podPath = path.join(DATA_ROOT, TEST_POD);
  if (fs.existsSync(podPath)) {
    fs.removeSync(podPath);
    log(`Removed test pod: ${podPath}`);
  }
}

async function main() {
  console.log('╔════════════════════════════════════════════════════╗');
  console.log('║   Git Push/Pull with Nostr Authentication Test    ║');
  console.log('╚════════════════════════════════════════════════════╝');

  console.log(`\nServer: ${BASE_URL}`);
  console.log(`Data root: ${DATA_ROOT}`);
  console.log(`Authorized pubkey: ${authorizedPk.slice(0, 16)}...`);
  console.log(`Unauthorized pubkey: ${unauthorizedPk.slice(0, 16)}...`);

  try {
    await setup();
    await testPushAuthorized();
    await testClone();
    await testPullAfterPush();
    await testPushUnauthorized();
  } catch (e) {
    console.error('\nFatal error:', e.message);
  } finally {
    await cleanup();
  }

  console.log('\n╔════════════════════════════════════════════════════╗');
  console.log(`║   Results: ${passed} passed, ${failed} failed${' '.repeat(27 - String(passed).length - String(failed).length)}║`);
  console.log('╚════════════════════════════════════════════════════╝\n');

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(console.error);
