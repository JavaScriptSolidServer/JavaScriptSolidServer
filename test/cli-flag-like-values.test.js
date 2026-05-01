/**
 * Regression tests for #103 — `bin/jss.js` must reject option values
 * that look like flags (e.g. `--single-user-name --idp`) instead of
 * silently using `--idp` as the username and breaking IdP setup.
 *
 * These spawn the CLI as a subprocess and assert exit-code + stderr.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(__dirname, '..', 'bin', 'jss.js');

function runCli(args) {
  return spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' });
}

describe('bin/jss.js — flag-like option values (#103)', () => {
  it('rejects `--single-user-name --idp` with a clear error', () => {
    const r = runCli(['start', '--single-user-name', '--idp']);
    assert.notStrictEqual(r.status, 0, 'exit code should be non-zero');
    assert.match(r.stderr, /--single-user-name value "--idp" looks like a flag/);
    assert.match(r.stderr, /Hint: did you forget to provide a value\?/);
  });

  it('rejects another option swallowing a flag (covers --idp-issuer too)', () => {
    // Commander's behaviour: it greedily consumes the next argv as the
    // value, which is the whole reason the bug exists. We use a flag
    // commander doesn't know about ("--unknown-flag") so commander
    // doesn't reroute it through its own argument-count error.
    const r = runCli(['start', '--idp-issuer', '--unknown-flag']);
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr, /--idp-issuer value "--unknown-flag" looks like a flag/);
  });

  it('rejects `--port --idp` (numeric option → NaN) with helpful error', () => {
    const r = runCli(['start', '--port', '--idp']);
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr, /--port got a non-numeric value/);
    assert.match(r.stderr, /Hint: did you forget to provide a number\?/);
  });

  it('accepts a real value and reaches normal config processing', () => {
    // --print-config exits 0 cleanly after dumping config; this proves
    // the validator doesn't false-positive on legitimate values.
    const r = runCli(['start',
      '--port', '4582',
      '--root', '/tmp/jss-103-sanity-doesnotneedtoexist',
      '--single-user-name', 'alice',
      '--print-config'
    ]);
    assert.strictEqual(r.status, 0,
      `expected clean exit, got ${r.status}; stderr: ${r.stderr}`);
    assert.match(r.stdout, /Configuration:/);
  });
});
