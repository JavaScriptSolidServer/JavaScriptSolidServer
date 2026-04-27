/**
 * Config / env-var parsing tests.
 *
 * Regression coverage for the env-coercion fix in #324: only known
 * boolean keys may have their string values coerced to booleans.
 * Otherwise an env var like JSS_SINGLE_USER_PASSWORD="true" would silently
 * become a real boolean and break downstream code (bcrypt, etc.).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { loadConfig } from '../src/config.js';

describe('config — env var boolean coercion', () => {
  // Save/restore the env vars we touch so this test is hermetic.
  const KEYS = ['JSS_SINGLE_USER_PASSWORD', 'JSS_IDP', 'JSS_BASE_DOMAIN'];
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
});
