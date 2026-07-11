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
import { loadConfig, parsePluginFlag } from '../src/config.js';

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

// #348: the user-visible default change — `jss start --single-user`
// (no name flag) must produce a config where singleUserName is null,
// so createServer() takes the root-pod path. createServer() has its
// own tests but a future refactor of loadConfig() could silently
// restore the old `'me'` default and only the server-level tests
// would catch it via behaviour, not the config layer directly.
describe('config — singleUserName default (#348)', () => {
  it('loadConfig() returns singleUserName=null when no flag/env is set', async () => {
    delete process.env.JSS_SINGLE_USER_NAME;
    const cfg = await loadConfig({}, null);
    assert.strictEqual(cfg.singleUserName, null,
      'default must be null (= root pod), not the legacy "me"');
  });

  it('loadConfig() preserves an explicit singleUserName CLI arg', async () => {
    delete process.env.JSS_SINGLE_USER_NAME;
    const cfg = await loadConfig({ singleUserName: 'alice' }, null);
    assert.strictEqual(cfg.singleUserName, 'alice');
  });

  it('loadConfig() respects JSS_SINGLE_USER_NAME from env', async () => {
    process.env.JSS_SINGLE_USER_NAME = 'me';
    try {
      const cfg = await loadConfig({}, null);
      assert.strictEqual(cfg.singleUserName, 'me',
        'env var should restore the legacy "me" pod path on demand');
    } finally {
      delete process.env.JSS_SINGLE_USER_NAME;
    }
  });
});

describe('config — parsePluginFlag (#594)', () => {
  it('parses module with prefix', () => {
    assert.deepStrictEqual(parsePluginFlag('./chat/plugin.js@/chat'),
      { module: './chat/plugin.js', prefix: '/chat' });
  });

  it('parses bare module (no prefix)', () => {
    assert.deepStrictEqual(parsePluginFlag('./chat/plugin.js'),
      { module: './chat/plugin.js' });
  });

  it('parses scoped package with prefix — scope @ is not the separator', () => {
    assert.deepStrictEqual(parsePluginFlag('@scope/pkg/plugin.js@/app'),
      { module: '@scope/pkg/plugin.js', prefix: '/app' });
  });

  it('parses bare scoped package as module only', () => {
    assert.deepStrictEqual(parsePluginFlag('@scope/pkg/plugin.js'),
      { module: '@scope/pkg/plugin.js' });
  });

  it('splits on the LAST @/ when several occur', () => {
    assert.deepStrictEqual(parsePluginFlag('pkg@/weird/path.js@/mount'),
      { module: 'pkg@/weird/path.js', prefix: '/mount' });
  });

  it('leaves a prefix without leading slash to the loader to reject', () => {
    // '@chat' has no '@/', so the whole value is the module — the import
    // fails loudly rather than mounting somewhere unexpected.
    assert.deepStrictEqual(parsePluginFlag('./p.js@chat'),
      { module: './p.js@chat' });
  });

  it('parses a missing module to module: "" for the loader to reject', () => {
    // '@/app' splits at position 0 so the loader raises its clear
    // "each entry needs a module" error instead of a confusing import failure.
    assert.deepStrictEqual(parsePluginFlag('@/app'),
      { module: '', prefix: '/app' });
  });
});
