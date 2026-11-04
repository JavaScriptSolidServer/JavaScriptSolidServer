/**
 * Read a fetch Response body under a byte cap AND an abort signal.
 *
 * Pass the same AbortSignal that was handed to `fetch()` and keep its
 * timer alive until this resolves. That is what bounds a server that
 * sends headers promptly and then trickles the body (#641): a timeout
 * that is cleared as soon as `fetch()` resolves only covers the
 * connection and headers, and the body read would otherwise wait for
 * as long as the remote chooses to keep sending.
 *
 * On abort the reader is cancelled (which releases the upstream
 * socket) and the read rejects with a timeout error, never with a
 * partial body.
 *
 * @param {Response} res
 * @param {object} opts
 * @param {number} opts.maxBytes - reject once more than this many bytes arrive
 * @param {AbortSignal} [opts.signal] - the fetch's signal; abort ends the read
 * @param {string} [opts.label='response'] - noun used in error messages
 * @returns {Promise<string>} body as UTF-8 text
 */
export async function readBodyWithCap(res, { maxBytes, signal, label = 'response' }) {
  const tooLarge = () => new Error(`${label} too large (>${maxBytes} bytes)`);
  const timedOut = () => new Error(`${label} body read timed out`);

  if (signal?.aborted) throw timedOut();

  const reader = res.body?.getReader?.();
  if (!reader) {
    // Non-streaming Response (polyfills, hand-built stubs): race the
    // text read against the signal so an abort still ends the wait.
    const text = await raceAbort(res.text(), signal, timedOut);
    if (Buffer.byteLength(text, 'utf8') > maxBytes) throw tooLarge();
    return text;
  }

  // A real fetch body errors on abort by itself; cancelling here also
  // covers stream implementations that do not watch the signal.
  const onAbort = () => { reader.cancel().catch(() => { /* noop */ }); };
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    const chunks = [];
    let total = 0;
    for (;;) {
      let result;
      try {
        result = await reader.read();
      } catch (err) {
        if (signal?.aborted) throw timedOut();
        throw err;
      }
      // Check abort before honouring `done`: a cancelled reader resolves
      // `{ done: true }`, which must not pass off a partial body as complete.
      if (signal?.aborted) throw timedOut();
      const { value, done } = result;
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel(); } catch { /* noop */ }
        throw tooLarge();
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength))).toString('utf8');
  } finally {
    signal?.removeEventListener('abort', onAbort);
  }
}

function raceAbort(promise, signal, makeError) {
  if (!signal) return promise;
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(makeError());
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort));
  });
}

/**
 * Release a Response whose body will not be read (redirect hop, error
 * status, unexpected content-type, oversize, abort). Without this the
 * upstream socket stays busy until the Response is garbage-collected,
 * which on a trickling host means well past the deadline. Fire and
 * forget: cancel() on undici tears the connection down at once.
 */
export function discardBody(res) {
  if (!res?.body || res.bodyUsed) return;
  try { res.body.cancel().catch(() => { /* locked or already closed */ }); } catch { /* noop */ }
}
