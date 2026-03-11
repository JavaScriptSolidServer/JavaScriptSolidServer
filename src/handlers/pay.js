/**
 * HTTP 402 Payment Required middleware
 *
 * Enables paid access to resources under /pay/* prefix.
 * Authentication via NIP-98. Balance tracking via Web Ledgers spec.
 *
 * Routes:
 *   GET  /pay/.balance  — check your balance
 *   POST /pay/.deposit  — deposit sats (TXO URI) or tokens (MRC20 state proof)
 *   GET  /pay/*         — paid resource access (requires balance >= cost)
 *   PUT  /pay/*         — upload resources (standard auth)
 *
 * Ledger: /.well-known/webledgers/webledgers.json (webledgers.org spec)
 *
 * References:
 *   - Web Ledgers spec: https://webledgers.org/
 *   - NIP-98 HTTP Auth: https://nips.nostr.com/98
 *   - TXO URI: https://www.npmjs.com/package/txo_parser
 *   - MRC20 profile: https://blocktrails.org/
 */

import { getNostrPubkey, pubkeyToDidNostr } from '../auth/nostr.js';
import { readLedger, writeLedger, getBalance, credit, debit } from '../webledger.js';
import { verifyMrc20Deposit } from '../mrc20.js';

const DEFAULT_COST = 1; // satoshis per request

// --- Deposit verification via mempool API ---

async function verifySatsDeposit(txoUri, mempoolUrl) {
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

/**
 * Parse deposit request body — returns either a sats TXO URI or MRC20 state proof
 * @param {*} body - Request body (Buffer, string, or parsed object)
 * @returns {{type: 'sats', txo: string} | {type: 'mrc20', state: object, prevState: object} | {type: 'unknown'}}
 */
function parseDepositBody(body) {
  // Buffer → string first
  if (Buffer.isBuffer(body)) {
    const str = body.toString('utf8').trim();
    // Try JSON parse
    try {
      const obj = JSON.parse(str);
      return classifyDepositObject(obj);
    } catch {
      // Not JSON — treat as TXO URI string
      return { type: 'sats', txo: str };
    }
  }

  // Already parsed object
  if (body && typeof body === 'object') {
    return classifyDepositObject(body);
  }

  // String
  if (typeof body === 'string') {
    const trimmed = body.trim();
    try {
      const obj = JSON.parse(trimmed);
      return classifyDepositObject(obj);
    } catch {
      return { type: 'sats', txo: trimmed };
    }
  }

  return { type: 'unknown' };
}

function classifyDepositObject(obj) {
  // Explicit type field
  if (obj.type === 'mrc20' && obj.state && obj.prevState) {
    return { type: 'mrc20', state: obj.state, prevState: obj.prevState };
  }
  // Auto-detect: if it has state + prevState with MRC20 profile
  if (obj.state?.profile === 'mono.mrc20.v0.1' && obj.prevState) {
    return { type: 'mrc20', state: obj.state, prevState: obj.prevState };
  }
  // Fall back to TXO URI in .txo field
  if (obj.txo) {
    return { type: 'sats', txo: obj.txo };
  }
  return { type: 'unknown' };
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
 * @param {string} options.payAddress - Pod's MRC20 address for receiving token transfers
 * @returns {function} Fastify preHandler hook
 */
export function createPayHandler(options = {}) {
  const cost = options.cost ?? DEFAULT_COST;
  const mempoolUrl = options.mempoolUrl ?? 'https://mempool.space/testnet4';
  const payAddress = options.payAddress ?? null;

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

      const deposit = parseDepositBody(request.body);

      // --- MRC20 token deposit ---
      if (deposit.type === 'mrc20') {
        if (!payAddress) {
          return reply.code(400).send({
            error: 'MRC20 deposits not configured (no payAddress set)'
          });
        }

        const result = verifyMrc20Deposit({
          state: deposit.state,
          prevState: deposit.prevState,
          toAddress: payAddress
        });

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
          ticker: result.ticker,
          balance: newBalance,
          unit: 'token'
        });
      }

      // --- Sats deposit (TXO URI) ---
      if (deposit.type === 'sats') {
        const result = await verifySatsDeposit(deposit.txo, mempoolUrl);
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

      return reply.code(400).send({
        error: 'Invalid deposit format. Send a TXO URI string or MRC20 state proof.',
        formats: {
          sats: 'POST body: "<txid>:<vout>" or {"txo": "<txid>:<vout>"}',
          mrc20: 'POST body: {"type": "mrc20", "state": {...}, "prevState": {...}}'
        }
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
