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
// unless the user explicitly disables IdP via --no-idp / JSS_IDP=false /
// idp:false in config file.
describe('config — --single-user implies --idp (#331)', () => {
  // Hermetic env-var handling so the runner's environment doesn't leak.
  // JSS_LOG_LEVEL is included because loadConfig() can emit a warning
  // for invalid log levels and we don't want that to pollute assertions
  // about the #331-specific warning.
  const KEYS = ['JSS_IDP', 'JSS_SINGLE_USER', 'JSS_IDP_ISSUER', 'JSS_LOG_LEVEL'];
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
  // We filter to the #331-specific warning so unrelated warnings (e.g. from
  // a noisy runner env) don't break the assertions.
  const isIdpFootgunWarning = (msg) =>
    msg.includes('--single-user') && msg.includes('--idp');

  beforeEach(() => {
    for (const k of KEYS) delete process.env[k];
    warnings = [];
    console.warn = (msg) => warnings.push(String(msg));
  });

  it('implies --idp when --single-user is set and --idp is not specified', async () => {
    const cfg = await loadConfig({ singleUser: true }, null);
    assert.strictEqual(cfg.idp, true,
      '--single-user should imply --idp by default');
    assert.ok(!warnings.some(isIdpFootgunWarning),
      'no #331 warning when implying (this is the happy path)');
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
    assert.ok(warnings.some(isIdpFootgunWarning),
      'should warn about the footgun when --single-user + --no-idp + no --idp-issuer');
  });

  it('respects explicit JSS_IDP=false with --single-user (warns but does not flip)', async () => {
    process.env.JSS_IDP = 'false';
    const cfg = await loadConfig({ singleUser: true }, null);
    assert.strictEqual(cfg.idp, false,
      'explicit JSS_IDP=false should override the implication');
    assert.ok(warnings.some(isIdpFootgunWarning),
      'should warn when JSS_IDP=false + --single-user + no --idp-issuer');
  });

  it('does not warn when --no-idp + --single-user but --idp-issuer is set', async () => {
    const cfg = await loadConfig({
      singleUser: true,
      idp: false,
      idpIssuer: 'https://external-issuer.example/'
    }, null);
    assert.strictEqual(cfg.idp, false);
    assert.ok(!warnings.some(isIdpFootgunWarning),
      'no footgun if an external --idp-issuer is configured');
  });

  it('does not warn when --single-user is unset', async () => {
    await loadConfig({ idp: false }, null);
    assert.ok(!warnings.some(isIdpFootgunWarning),
      '--no-idp without --single-user should not trigger the #331 warning');
  });
});
