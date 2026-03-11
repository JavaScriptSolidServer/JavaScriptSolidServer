/**
 * HTTP 402 Payment Required middleware
 *
 * Enables paid access to resources under /pay/* prefix.
 * Authentication via NIP-98. Balance tracking via Web Ledgers spec.
 *
 * Routes:
 *   GET  /pay/.balance  — check your balance
 *   POST /pay/.deposit  — deposit sats via TXO URI
 *   GET  /pay/*         — paid resource access (requires balance >= cost)
 *   PUT  /pay/*         — upload resources (standard auth)
 *
 * Ledger: /.well-known/webledgers/webledgers.json (webledgers.org spec)
 *
 * References:
 *   - Web Ledgers spec: https://webledgers.org/
 *   - NIP-98 HTTP Auth: https://nips.nostr.com/98
 *   - TXO URI: https://www.npmjs.com/package/txo_parser
 */

import { getNostrPubkey, pubkeyToDidNostr } from '../auth/nostr.js';
import { readLedger, writeLedger, getBalance, credit, debit } from '../webledger.js';

const DEFAULT_COST = 1; // satoshis per request

// --- Deposit verification via mempool API ---

async function verifyDeposit(txoUri, mempoolUrl) {
  const match = txoUri.match(/([0-9a-f]{64}):(\d+)/i);
  if (!match) {
    return { valid: false, amount: 0, error: 'Invalid TXO URI format (expected txid:vout)' };
  }
  const [, txid, voutStr] = match;
  const vout = parseInt(voutStr, 10);

  try {
    const resp = await fetch(`${mempoolUrl}/api/tx/${txid}`);
    if (!resp.ok) return { valid: false, amount: 0, error: 'Transaction not found' };
    const tx = await resp.json();
    const output = tx.vout?.[vout];
    if (!output) return { valid: false, amount: 0, error: `Output index ${vout} not found` };
    return { valid: true, amount: output.value };
  } catch (err) {
    return { valid: false, amount: 0, error: `Mempool API error: ${err.message}` };
  }
}

// --- Check if URL is a /pay/ route ---

export function isPayRequest(url) {
  const path = url.split('?')[0];
  return path.startsWith('/pay/') || path === '/pay';
}

// --- preHandler hook for /pay/* routes ---

/**
 * Create pay preHandler hook
 * @param {object} options
 * @param {number} options.cost - Cost per request in satoshis (default 1)
 * @param {string} options.mempoolUrl - Mempool API base URL
 * @returns {function} Fastify preHandler hook
 */
export function createPayHandler(options = {}) {
  const cost = options.cost ?? DEFAULT_COST;
  const mempoolUrl = options.mempoolUrl ?? 'https://mempool.space/testnet4';

  return async function payHandler(request, reply) {
    const url = request.url.split('?')[0];
    if (!isPayRequest(request.url)) return;

    // --- GET /pay/.balance ---
    if (url === '/pay/.balance' && request.method === 'GET') {
      const pubkey = await getNostrPubkey(request);
      if (!pubkey) {
        return reply.code(401).send({ error: 'NIP-98 authentication required' });
      }
      const didUri = pubkeyToDidNostr(pubkey);
      const ledger = await readLedger();
      return reply.send({
        did: didUri,
        balance: getBalance(ledger, didUri),
        cost,
        unit: 'sat'
      });
    }

    // --- POST /pay/.deposit ---
    if (url === '/pay/.deposit' && request.method === 'POST') {
      const pubkey = await getNostrPubkey(request);
      if (!pubkey) {
        return reply.code(401).send({ error: 'NIP-98 authentication required' });
      }

      let txoUri;
      if (Buffer.isBuffer(request.body)) {
        txoUri = request.body.toString('utf8').trim();
      } else if (typeof request.body === 'string') {
        txoUri = request.body.trim();
      } else if (request.body && typeof request.body === 'object') {
        txoUri = request.body.txo;
      }

      if (!txoUri) {
        return reply.code(400).send({ error: 'Missing TXO URI in request body' });
      }

      const result = await verifyDeposit(txoUri, mempoolUrl);
      if (!result.valid) {
        return reply.code(400).send({ error: result.error });
      }

      const didUri = pubkeyToDidNostr(pubkey);
      const ledger = await readLedger();
      const newBalance = credit(ledger, didUri, result.amount);
      await writeLedger(ledger);

      return reply.send({
        did: didUri,
        deposited: result.amount,
        balance: newBalance,
        unit: 'sat'
      });
    }

    // --- GET/HEAD /pay/* — paid resource access ---
    if (request.method === 'GET' || request.method === 'HEAD') {
      const pubkey = await getNostrPubkey(request);
      if (!pubkey) {
        return reply.code(401).send({
          error: 'NIP-98 authentication required',
          deposit: '/pay/.deposit'
        });
      }

      const didUri = pubkeyToDidNostr(pubkey);
      const ledger = await readLedger();
      const { success, balance } = debit(ledger, didUri, cost);

      if (!success) {
        return reply.code(402).send({
          error: 'Payment Required',
          balance,
          cost,
          unit: 'sat',
          deposit: '/pay/.deposit'
        });
      }

      await writeLedger(ledger);
      reply.header('X-Balance', String(balance));
      reply.header('X-Cost', String(cost));
      return; // continue to normal resource handler
    }

    // PUT/DELETE/POST — continue to normal WAC auth + resource handler
  };
}
