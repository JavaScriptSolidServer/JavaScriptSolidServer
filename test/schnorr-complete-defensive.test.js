/**
 * Regression test for #412 — handleSchnorrComplete must not hang the
 * connection (→ gateway 504) when `provider.interactionFinished` throws
 * after `reply.hijack()`. The common trigger is `SessionNotFound` from
 * oidc-provider's `#getInteraction` when the `_interaction` cookie is
 * missing (cross-browser URL paste, third-party cookies blocked, long
 * idle past the cookie TTL).
 *
 * Strategy: direct unit-test of the handler with a real account on a
 * fixture DATA_ROOT (so `findById` returns a hit) plus a stub provider
 * that throws SessionNotFound from `interactionFinished`. Captures the
 * post-hijack write to `reply.raw` and asserts a bounded 400 response
 * with the "session expired, restart login" page — instead of hanging.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import path from 'path';
import { handleSchnorrComplete } from '../src/idp/interactions.js';
import { createAccount } from '../src/idp/accounts.js';

const DATA_DIR = path.resolve('./test-data-schnorr-complete-defensive');

function makeFakeReplyAndCapture() {
  let hijacked = false;
  let status = null;
  let headers = null;
  const bodyChunks = [];
  let ended = false;
  return {
    reply: {
      hijack: () => { hijacked = true; },
      code: () => { throw new Error('reply.code called after hijack — should not happen'); },
      raw: {
        get headersSent() { return ended; },
        writeHead: (s, h) => { status = s; headers = h; },
        end: (body) => { ended = true; if (body) bodyChunks.push(body); },
      },
    },
    captured: () => ({ hijacked, status, headers, body: bodyChunks.join('') }),
  };
}

function makeFakeRequest({ uid, accountId }) {
  const logs = [];
  return {
    params: { uid },
    query: { accountId },
    raw: {},
    log: {
      info: (...args) => logs.push(['info', args]),
      warn: (...args) => logs.push(['warn', args]),
      error: (...args) => logs.push(['error', args]),
    },
    _logs: logs,
  };
}

describe('handleSchnorrComplete defensive recovery (#412)', () => {
  let originalDataRoot;
  let account;

  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    process.env.DATA_ROOT = DATA_DIR;
    await fs.remove(DATA_DIR);
    await fs.ensureDir(DATA_DIR);
    account = await createAccount({
      username: 'schnorrtest',
      email: 'schnorr@example.org',
      password: 'test12345',
      webId: 'https://example.org/schnorrtest/profile/card#me',
    });
  });

  after(async () => {
    await fs.remove(DATA_DIR);
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
  });

  it('returns 400 with a "session expired" page (not 504) when interactionFinished throws SessionNotFound', async () => {
    const sessionErr = new Error('invalid_request — interaction session id cookie not found');
    sessionErr.name = 'SessionNotFound';

    const provider = {
      Interaction: {
        find: async () => ({
          result: { login: { accountId: account.id } },
          exp: Math.floor(Date.now() / 1000) + 600,
        }),
      },
      interactionFinished: async () => { throw sessionErr; },
    };

    const { reply, captured } = makeFakeReplyAndCapture();
    const request = makeFakeRequest({ uid: 'fake-uid', accountId: account.id });

    await handleSchnorrComplete(request, reply, provider);

    const c = captured();
    assert.strictEqual(c.hijacked, true, 'must hijack before calling interactionFinished');
    assert.strictEqual(c.status, 400, 'SessionNotFound must produce 400, not a hang');
    assert.ok(c.headers && /text\/html/.test(c.headers['Content-Type']), 'response must be HTML');
    assert.ok(/Session expired/.test(c.body), 'page title should be "Session expired"');
    assert.ok(/restart the login/i.test(c.body), 'page should tell the user to restart');
  });

  it('returns 500 with a generic message (no err.message leak) when interactionFinished throws an unknown error', async () => {
    // Soft info-leak guard — mirrors handleSwitchAccount's pattern.
    // The internal error message must NOT appear in the response body.
    const internalErr = new Error('INTERNAL_DETAIL_xyz123_should_not_leak');

    const provider = {
      Interaction: {
        find: async () => ({
          result: { login: { accountId: account.id } },
          exp: Math.floor(Date.now() / 1000) + 600,
        }),
      },
      interactionFinished: async () => { throw internalErr; },
    };

    const { reply, captured } = makeFakeReplyAndCapture();
    const request = makeFakeRequest({ uid: 'fake-uid', accountId: account.id });

    await handleSchnorrComplete(request, reply, provider);

    const c = captured();
    assert.strictEqual(c.status, 500, 'unknown error must produce 500');
    assert.ok(!/INTERNAL_DETAIL_xyz123_should_not_leak/.test(c.body),
      'response body must not surface the raw err.message');
    assert.ok(/Login error/.test(c.body), 'page title should be the generic "Login error"');
  });

  it('completes successfully (no error response) when interactionFinished resolves', async () => {
    let interactionFinishedCalled = false;
    const provider = {
      Interaction: {
        find: async () => ({
          result: { login: { accountId: account.id } },
          exp: Math.floor(Date.now() / 1000) + 600,
        }),
      },
      interactionFinished: async () => { interactionFinishedCalled = true; /* oidc-provider would write to reply.raw here */ },
    };

    const { reply, captured } = makeFakeReplyAndCapture();
    const request = makeFakeRequest({ uid: 'fake-uid', accountId: account.id });

    await handleSchnorrComplete(request, reply, provider);

    const c = captured();
    assert.strictEqual(interactionFinishedCalled, true, 'interactionFinished must be called');
    assert.strictEqual(c.hijacked, true, 'reply must be hijacked');
    assert.strictEqual(c.status, null, 'no error response should be written when interactionFinished succeeds');
  });
});
