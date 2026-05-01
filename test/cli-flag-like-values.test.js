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
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(__dirname, '..', 'bin', 'jss.js');

// Timeout cap so the suite can never hang if the validator regresses
// and `start` actually tries to bind a port instead of exiting early.
const RUN_TIMEOUT_MS = 10_000;

function runCli(args) {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    timeout: RUN_TIMEOUT_MS,
    killSignal: 'SIGKILL'
  });
  // spawnSync sets `signal` to the kill signal when timeout fires. Treat
  // that as a hard test failure rather than letting downstream
  // assertions on stderr accidentally pass.
  assert.strictEqual(
    r.signal, null,
    `CLI did not exit within ${RUN_TIMEOUT_MS}ms — likely the preAction ` +
    `validator regressed and \`start\` is actually trying to listen. ` +
    `args: ${JSON.stringify(args)}; partial stderr: ${r.stderr}`
  );
  return r;
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
    // commander doesn't know about so commander doesn't reroute it
    // through its own argument-count error. The dummy name is
    // collision-proof — if anyone ever adds a real `--bogus-...` flag
    // matching this pattern, the duplication is the bigger problem.
    const FAKE_FLAG = '--__jss103_unlikely_cli_option__';
    const r = runCli(['start', '--idp-issuer', FAKE_FLAG]);
    assert.notStrictEqual(r.status, 0);
    assert.match(
      r.stderr,
      new RegExp(`--idp-issuer value "${FAKE_FLAG}" looks like a flag`)
    );
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
    // Use os.tmpdir() rather than a hard-coded /tmp/... so the test is
    // portable across platforms (and matches the rest of the suite).
    const tmpRoot = path.join(os.tmpdir(), 'jss-103-sanity-doesnotneedtoexist');
    const r = runCli(['start',
      '--port', '4582',
      '--root', tmpRoot,
      '--single-user-name', 'alice',
      '--print-config'
    ]);
    assert.strictEqual(r.status, 0,
      `expected clean exit, got ${r.status}; stderr: ${r.stderr}`);
    assert.match(r.stdout, /Configuration:/);
  });
});
