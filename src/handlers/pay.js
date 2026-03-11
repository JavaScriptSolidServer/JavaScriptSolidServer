/**
 * HTTP 402 Payment Required middleware
 *
 * Enables paid access to resources under /pay/* prefix.
 * Authentication via NIP-98. Balance tracking via Web Ledgers spec.
 *
 * Routes:
 *   GET  /pay/.info      — public endpoint: cost, token info, available routes
 *   GET  /pay/.balance   — check your balance
 *   POST /pay/.deposit   — deposit sats (TXO URI) or tokens (MRC20 state proof)
 *   POST /pay/.buy       — buy tokens with sat balance (primary market)
 *   POST /pay/.withdraw  — withdraw balance as tokens (portable MRC20 proof)
 *   GET  /pay/*          — paid resource access (requires balance >= cost)
 *   PUT  /pay/*          — upload resources (standard auth)
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
import { verifyMrc20Deposit, verifyMrc20Anchor, jcs, sha256Hex } from '../mrc20.js';
import { loadTrail, transferToken } from '../token.js';
import fs from 'fs-extra';
import path from 'path';

const DEFAULT_COST = 1; // satoshis per request

// --- Replay protection ---
const replayFile = () => path.join(process.env.DATA_ROOT || './data', '.well-known/webledgers/replay.json');

async function loadReplaySet() {
  try {
    const data = await fs.readFile(replayFile(), 'utf8');
    return new Set(JSON.parse(data));
  } catch { return new Set(); }
}

async function saveReplaySet(set) {
  await fs.ensureDir(path.dirname(replayFile()));
  await fs.writeFile(replayFile(), JSON.stringify([...set]));
}

async function checkAndRecordState(stateHash) {
  const seen = await loadReplaySet();
  if (seen.has(stateHash)) return false; // replay!
  seen.add(stateHash);
  await saveReplaySet(seen);
  return true;
}

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
    return { type: 'mrc20', state: obj.state, prevState: obj.prevState, anchor: obj.anchor };
  }
  // Auto-detect: if it has state + prevState with MRC20 profile
  if (obj.state?.profile === 'mono.mrc20.v0.1' && obj.prevState) {
    return { type: 'mrc20', state: obj.state, prevState: obj.prevState, anchor: obj.anchor };
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
  const payToken = options.payToken ?? null;
  const payRate = options.payRate ?? 1;

  return async function payHandler(request, reply) {
    const url = request.url.split('?')[0];
    if (!isPayRequest(request.url)) return;

    // --- GET /pay/.info — public, no auth ---
    if (url === '/pay/.info' && request.method === 'GET') {
      const info = {
        cost,
        unit: 'sat',
        deposit: '/pay/.deposit',
        balance: '/pay/.balance'
      };
      if (payToken) {
        const trail = await loadTrail(payToken);
        info.token = {
          ticker: payToken,
          rate: payRate,
          buy: '/pay/.buy',
          withdraw: '/pay/.withdraw'
        };
        if (trail) {
          info.token.supply = trail.latestState?.supply ?? null;
          info.token.issuer = trail.pubkeyBase ?? null;
        }
      }
      return reply.send(info);
    }

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

        // Replay protection: reject duplicate state hashes
        const stateHash = jcs(deposit.state);
        const isNew = await checkAndRecordState(stateHash);
        if (!isNew) {
          return reply.code(400).send({ error: 'Replay: this state has already been used for a deposit' });
        }

        let result;

        // Anchor verification (if anchor data provided)
        if (deposit.anchor && deposit.anchor.pubkey && deposit.anchor.stateStrings) {
          result = await verifyMrc20Anchor({
            state: deposit.state,
            prevState: deposit.prevState,
            toAddress: payAddress,
            pubkey: deposit.anchor.pubkey,
            stateStrings: deposit.anchor.stateStrings,
            mempoolUrl,
            network: deposit.anchor.network || 'testnet4'
          });
        } else {
          // Fallback: verify chain integrity only (no anchor check)
          result = verifyMrc20Deposit({
            state: deposit.state,
            prevState: deposit.prevState,
            toAddress: payAddress
          });
        }

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
          unit: 'token',
          ...(result.address ? { anchor: result.address } : {})
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

    // --- POST /pay/.buy — primary market: buy tokens with sats ---
    if (url === '/pay/.buy' && request.method === 'POST') {
      const pubkey = await getNostrPubkey(request);
      if (!pubkey) {
        return reply.code(401).send({ error: 'NIP-98 authentication required' });
      }

      if (!payToken) {
        return reply.code(400).send({ error: 'Primary market not configured (no --pay-token set)' });
      }

      // Parse buy request
      let body = request.body;
      if (Buffer.isBuffer(body)) body = JSON.parse(body.toString('utf8'));
      if (typeof body === 'string') body = JSON.parse(body);

      const ticker = body?.ticker || payToken;
      if (ticker !== payToken) {
        return reply.code(400).send({ error: `This pod only sells ${payToken}` });
      }

      // Calculate amount and cost
      let tokenAmount, satCost;
      if (body?.amount) {
        tokenAmount = Math.floor(body.amount);
        satCost = tokenAmount * payRate;
      } else if (body?.sats) {
        satCost = Math.floor(body.sats);
        tokenAmount = Math.floor(satCost / payRate);
      } else {
        return reply.code(400).send({
          error: 'Specify amount (tokens to buy) or sats (sats to spend)',
          rate: payRate,
          unit: 'sat/token'
        });
      }

      if (tokenAmount <= 0) {
        return reply.code(400).send({ error: 'Amount must be positive' });
      }

      // Check sat balance
      const didUri = pubkeyToDidNostr(pubkey);
      const ledger = await readLedger();
      const balance = getBalance(ledger, didUri);
      if (balance < satCost) {
        return reply.code(402).send({
          error: 'Insufficient sat balance',
          balance,
          cost: satCost,
          rate: payRate,
          deposit: '/pay/.deposit'
        });
      }

      // Load token trail
      const trail = await loadTrail(ticker);
      if (!trail) {
        return reply.code(500).send({ error: `Token ${ticker} not minted on this pod` });
      }

      // Transfer tokens to buyer
      let result;
      try {
        result = await transferToken({
          ticker,
          to: pubkey,
          amount: tokenAmount,
          mempoolUrl
        });
      } catch (err) {
        return reply.code(500).send({ error: `Transfer failed: ${err.message}` });
      }

      // Debit sats from buyer
      debit(ledger, didUri, satCost);
      await writeLedger(ledger);

      return reply.send({
        bought: tokenAmount,
        ticker,
        cost: satCost,
        rate: payRate,
        balance: getBalance(ledger, didUri),
        unit: 'sat',
        txid: result.txid,
        proof: {
          state: result.state,
          prevState: result.prevState,
          anchor: {
            pubkey: result.trail.pubkeyBase,
            stateStrings: result.trail.stateStrings,
            network: result.trail.network
          }
        }
      });
    }

    // --- POST /pay/.withdraw — withdraw balance as tokens ---
    if (url === '/pay/.withdraw' && request.method === 'POST') {
      const pubkey = await getNostrPubkey(request);
      if (!pubkey) {
        return reply.code(401).send({ error: 'NIP-98 authentication required' });
      }

      if (!payToken) {
        return reply.code(400).send({ error: 'Withdrawal not configured (no --pay-token set)' });
      }

      // Parse withdraw request
      let body = request.body;
      if (Buffer.isBuffer(body)) body = JSON.parse(body.toString('utf8'));
      if (typeof body === 'string') body = JSON.parse(body);

      const didUri = pubkeyToDidNostr(pubkey);
      const ledger = await readLedger();
      const balance = getBalance(ledger, didUri);

      // Calculate withdrawal amount
      let satCost, tokenAmount;
      if (body?.all) {
        satCost = balance;
        tokenAmount = Math.floor(balance / payRate);
      } else if (body?.sats) {
        satCost = Math.floor(body.sats);
        tokenAmount = Math.floor(satCost / payRate);
      } else if (body?.tokens) {
        tokenAmount = Math.floor(body.tokens);
        satCost = tokenAmount * payRate;
      } else {
        return reply.code(400).send({
          error: 'Specify tokens, sats, or all: true',
          balance,
          rate: payRate,
          unit: 'sat/token'
        });
      }

      if (tokenAmount <= 0) {
        return reply.code(400).send({ error: 'Nothing to withdraw', balance, rate: payRate });
      }

      if (balance < satCost) {
        return reply.code(402).send({
          error: 'Insufficient balance',
          balance,
          cost: satCost,
          rate: payRate
        });
      }

      // Load token trail
      const trail = await loadTrail(payToken);
      if (!trail) {
        return reply.code(500).send({ error: `Token ${payToken} not minted on this pod` });
      }

      // Transfer tokens to user
      let result;
      try {
        result = await transferToken({
          ticker: payToken,
          to: pubkey,
          amount: tokenAmount,
          mempoolUrl
        });
      } catch (err) {
        return reply.code(500).send({ error: `Transfer failed: ${err.message}` });
      }

      // Debit balance
      debit(ledger, didUri, satCost);
      await writeLedger(ledger);

      return reply.send({
        withdrawn: tokenAmount,
        ticker: payToken,
        cost: satCost,
        rate: payRate,
        balance: getBalance(ledger, didUri),
        unit: 'sat',
        txid: result.txid,
        proof: {
          state: result.state,
          prevState: result.prevState,
          anchor: {
            pubkey: result.trail.pubkeyBase,
            stateStrings: result.trail.stateStrings,
            network: result.trail.network
          }
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
