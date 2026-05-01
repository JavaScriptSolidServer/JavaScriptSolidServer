/**
 * Config / env-var parsing tests.
 *
 * Regression coverage for the env-coercion fix in #323: only known
 * boolean keys may have their string values coerced to booleans.
 * Otherwise an env var like JSS_SINGLE_USER_PASSWORD="true" would silently
 * become a real boolean and break downstream code (bcrypt, etc.).
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import { loadConfig } from '../src/config.js';

describe('config — env var boolean coercion', () => {
  // Save/restore the env vars we touch so this test is hermetic.
  const KEYS = ['JSS_SINGLE_USER_PASSWORD', 'JSS_IDP', 'JSS_BASE_DOMAIN', 'JSS_MULTIUSER'];
  const original = {};
  before(() => { for (const k of KEYS) original[k] = process.env[k]; });
  after(() => {
    for (const k of KEYS) {
      if (original[k] === undefined) delete process.env[k];
      else process.env[k] = original[k];
    }
  });

  it('preserves string-valued env vars when their value is "true"', async () => {
    process.env.JSS_SINGLE_USER_PASSWORD = 'true';
    const cfg = await loadConfig({}, null);
    assert.strictEqual(cfg.singleUserPassword, 'true',
      'password env var must remain a string, not be coerced to boolean true');
  });

  it('preserves string-valued env vars when their value is "false"', async () => {
    process.env.JSS_SINGLE_USER_PASSWORD = 'false';
    const cfg = await loadConfig({}, null);
    assert.strictEqual(cfg.singleUserPassword, 'false');
  });

  it('preserves string-valued env vars when set to other strings', async () => {
    process.env.JSS_BASE_DOMAIN = 'example.com';
    const cfg = await loadConfig({}, null);
    assert.strictEqual(cfg.baseDomain, 'example.com');
  });

  it('still coerces known boolean keys', async () => {
    process.env.JSS_IDP = 'true';
    const cfg = await loadConfig({}, null);
    assert.strictEqual(cfg.idp, true, 'idp env var should be coerced to boolean');
  });

  it('still coerces known boolean keys when "false"', async () => {
    process.env.JSS_IDP = 'false';
    const cfg = await loadConfig({}, null);
    assert.strictEqual(cfg.idp, false);
  });

  it('coerces JSS_MULTIUSER to a boolean (regression for missed entry)', async () => {
    process.env.JSS_MULTIUSER = 'false';
    const cfg = await loadConfig({}, null);
    assert.strictEqual(cfg.multiuser, false,
      'multiuser must coerce to boolean false, not the string "false" (truthy)');
    process.env.JSS_MULTIUSER = 'true';
    const cfg2 = await loadConfig({}, null);
    assert.strictEqual(cfg2.multiuser, true);
  });
});

// Regression coverage for #331: --single-user without --idp boots a server
// that returns 404 for /.well-known/openid-configuration, which is a
// footgun. loadConfig() now implies --idp when --single-user is set,
// unless the user explicitly disables IdP via --no-idp.
describe('config — --single-user implies --idp (#331)', () => {
  // Hermetic env-var handling so JSS_IDP from the test env doesn't leak.
  const KEYS = ['JSS_IDP', 'JSS_SINGLE_USER'];
  const original = {};
  let originalWarn;
  let warnings;

  before(() => {
    for (const k of KEYS) original[k] = process.env[k];
    originalWarn = console.warn;
  });

  after(() => {
    for (const k of KEYS) {
      if (original[k] === undefined) delete process.env[k];
      else process.env[k] = original[k];
    }
    console.warn = originalWarn;
  });

  // Capture warnings so we can assert on them without polluting test output.
  beforeEach(() => {
    for (const k of KEYS) delete process.env[k];
    warnings = [];
    console.warn = (msg) => warnings.push(String(msg));
  });

  it('implies --idp when --single-user is set and --idp is not specified', async () => {
    const cfg = await loadConfig({ singleUser: true }, null);
    assert.strictEqual(cfg.idp, true,
      '--single-user should imply --idp by default');
    assert.strictEqual(warnings.length, 0,
      'no warning when implying (this is the happy path)');
  });

  it('does not imply --idp when --single-user is not set', async () => {
    const cfg = await loadConfig({}, null);
    assert.notStrictEqual(cfg.idp, true,
      '--idp should not be implied without --single-user');
  });

  it('respects explicit --idp=true with --single-user', async () => {
    const cfg = await loadConfig({ singleUser: true, idp: true }, null);
    assert.strictEqual(cfg.idp, true);
  });

  it('respects explicit --no-idp with --single-user (warns but does not flip)', async () => {
    const cfg = await loadConfig({ singleUser: true, idp: false }, null);
    assert.strictEqual(cfg.idp, false,
      'explicit --no-idp should override the implication');
    assert.ok(warnings.some(w => w.includes('--single-user') && w.includes('--idp')),
      'should warn about the footgun when --single-user + --no-idp');
  });

  it('does not warn when --single-user is unset', async () => {
    await loadConfig({ idp: false }, null);
    assert.strictEqual(warnings.length, 0,
      '--no-idp without --single-user should not trigger the warning');
  });
});
