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
 *   GET  /pay/.offers    — list open sell orders (secondary market)
 *   POST /pay/.sell      — create a sell order (NIP-69 kind 38383)
 *   POST /pay/.swap      — execute a swap against a sell order
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

import crypto from 'crypto';
import { getNostrPubkey, pubkeyToDidNostr } from '../auth/nostr.js';
import { readLedger, writeLedger, getBalance, credit, creditOnce, debit } from '../webledger.js';
import { verifyMrc20Deposit, verifyMrc20Anchor, jcs, btAddress } from '../mrc20.js';
import { loadTrail, transferToken, buildTransaction, broadcastTx, p2trScript, btDeriveChainedPrivkey } from '../token.js';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import fs from 'fs-extra';
import path from 'path';

// --- Pod keypair for deposit addresses (stored outside web-accessible tree) ---
const keypairFile = () => path.join(process.env.DATA_ROOT || './data', '.private/keypair.json');

async function loadOrCreateKeypair() {
  try {
    const data = await fs.readFile(keypairFile(), 'utf8');
    return JSON.parse(data);
  } catch {
    const privkey = secp256k1.utils.randomPrivateKey();
    const pubkey = secp256k1.getPublicKey(privkey, true);
    const kp = { privkey: bytesToHex(privkey), pubkey: bytesToHex(pubkey) };
    await fs.ensureDir(path.dirname(keypairFile()));
    await fs.writeFile(keypairFile(), JSON.stringify(kp, null, 2));
    return kp;
  }
}

// --- Pod UTXO tracking (stored outside web-accessible tree) ---
const utxoFile = () => path.join(process.env.DATA_ROOT || './data', '.private/utxos.json');

async function loadUtxos() {
  try {
    const data = await fs.readFile(utxoFile(), 'utf8');
    return JSON.parse(data);
  } catch { return []; }
}

async function saveUtxos(utxos) {
  await fs.ensureDir(path.dirname(utxoFile()));
  await fs.writeFile(utxoFile(), JSON.stringify(utxos, null, 2));
}

const DEFAULT_COST = 1; // satoshis per request

// --- Chain registry for multi-chain deposits ---
const CHAIN_REGISTRY = {
  tbtc3: { explorer: 'https://mempool.space/testnet/api', unit: 'tbtc3', name: 'Bitcoin Testnet3' },
  tbtc4: { explorer: 'https://mempool.space/testnet4/api', unit: 'tbtc4', name: 'Bitcoin Testnet4' },
  btc:   { explorer: 'https://mempool.space/api', unit: 'sat', name: 'Bitcoin' },
  ltc:   { explorer: 'https://litecoinspace.org/api', unit: 'ltc', name: 'Litecoin' },
  signet:{ explorer: 'https://mempool.space/signet/api', unit: 'signet', name: 'Bitcoin Signet' },
};

/**
 * Parse chain ID from a TXO URI body string.
 * Supports: "txo:tbtc3:txid:vout", "txo:btc:txid:vout", or bare "txid:vout" (returns null).
 */
function parseTxoChain(body) {
  const str = typeof body === 'string' ? body.trim() : '';
  const match = str.match(/^txo:([a-z0-9]+):/i);
  return match ? match[1].toLowerCase() : null;
}

// --- AMM pool storage ---
const poolFile = () => path.join(process.env.DATA_ROOT || './data', '.well-known/webledgers/pool.json');

async function loadPool() {
  try {
    const data = await fs.readFile(poolFile(), 'utf8');
    return JSON.parse(data);
  } catch { return null; }
}

async function savePool(pool) {
  await fs.ensureDir(path.dirname(poolFile()));
  await fs.writeFile(poolFile(), JSON.stringify(pool, null, 2));
}

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

// --- Offers storage (secondary market) ---
const offersFile = () => path.join(process.env.DATA_ROOT || './data', '.well-known/webledgers/offers.json');

async function loadOffers() {
  try {
    const data = await fs.readFile(offersFile(), 'utf8');
    return JSON.parse(data);
  } catch { return []; }
}

async function saveOffers(offers) {
  await fs.ensureDir(path.dirname(offersFile()));
  await fs.writeFile(offersFile(), JSON.stringify(offers, null, 2));
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
  // Claim deposit: user sent sats to pod's address, claiming with txid
  if (obj.txid && obj.vout !== undefined) {
    return { type: 'claim', txid: obj.txid, vout: parseInt(obj.vout, 10), chain: obj.chain };
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

  // Parse multi-chain config: "tbtc3,tbtc4" → ['tbtc3', 'tbtc4']
  const payChains = options.payChains
    ? options.payChains.split(',').map(c => c.trim()).filter(c => CHAIN_REGISTRY[c])
    : null;

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
      if (payChains) {
        info.chains = payChains.map(id => ({ id, unit: CHAIN_REGISTRY[id].unit, name: CHAIN_REGISTRY[id].name }));
        info.pool = '/pay/.pool';
      }
      return reply.send(info);
    }

    // --- GET /pay/.address — deposit address (optional per-user tweak) ---
    if (url === '/pay/.address' && request.method === 'GET') {
      const chain = request.query?.chain || (payChains ? payChains[0] : 'tbtc4');
      if (!CHAIN_REGISTRY[chain]) {
        return reply.code(400).send({ error: `Unsupported chain: ${chain}` });
      }
      if (payChains && !payChains.includes(chain)) {
        return reply.code(400).send({ error: `Chain not enabled: ${chain}`, enabledChains: payChains });
      }
      const kp = await loadOrCreateKeypair();
      const network = chain === 'btc' ? 'mainnet' : (chain === 'tbtc3' ? 'testnet' : 'testnet4');
      const user = request.query?.user?.trim().toLowerCase() || null;
      if (user && !/^did:nostr:[0-9a-f]{64}$/.test(user)) {
        return reply.code(400).send({ error: 'Invalid user DID. Expected: did:nostr:<64-hex>' });
      }
      const states = user ? [user] : [];
      const address = btAddress(kp.pubkey, states, network);
      const response = { address, chain, pubkey: kp.pubkey };
      if (user) response.user = user;
      return reply.send(response);
    }

    // --- GET /pay/.balance ---
    if (url === '/pay/.balance' && request.method === 'GET') {
      const pubkey = await getNostrPubkey(request);
      if (!pubkey) {
        return reply.code(401).send({ error: 'NIP-98 authentication required' });
      }
      const didUri = pubkeyToDidNostr(pubkey);

      // Auto-detect deposits to user's tweaked address (Phase 3)
      if (payChains) {
        try {
          const kp = await loadOrCreateKeypair();
          const utxos = await loadUtxos();
          const ledger = await readLedger();
          let credited = 0;

          for (const chainId of payChains) {
            const chain = CHAIN_REGISTRY[chainId];
            const network = chainId === 'btc' ? 'mainnet' : (chainId === 'tbtc3' ? 'testnet' : 'testnet4');
            const userAddr = btAddress(kp.pubkey, [didUri], network);

            const resp = await fetch(`${chain.explorer}/address/${userAddr}/utxo`);
            if (!resp.ok) continue;
            const addrUtxos = await resp.json();

            for (const u of addrUtxos) {
              if (utxos.find(x => x.txid === u.txid && x.vout === u.vout)) continue;
              // New UTXO — fetch tx for scriptpubkey, then auto-credit
              let scriptpubkey = '';
              try {
                const txResp = await fetch(`${chain.explorer}/tx/${u.txid}`);
                if (txResp.ok) {
                  const txData = await txResp.json();
                  scriptpubkey = txData.vout?.[u.vout]?.scriptpubkey || '';
                }
              } catch { /* best effort */ }
              const currency = chain.unit;
              // Idempotent credit keyed on the outpoint: the balance and the
              // "already counted" marker commit together in the ledger, so a
              // crash before saveUtxos below can't double-credit on the next
              // balance poll (the scanner re-runs on every GET /pay/.balance).
              const depositKey = `${chainId}:${u.txid}:${u.vout}`;
              const { credited: didCredit } = creditOnce(ledger, depositKey, didUri, u.value, currency);
              utxos.push({ txid: u.txid, vout: u.vout, amount: u.value, scriptpubkey, chain: chainId, tweak: didUri, spent: false });
              if (didCredit) credited += u.value;
            }
          }

          if (credited > 0) {
            await writeLedger(ledger);
            await saveUtxos(utxos);
          }
        } catch { /* scan failure is non-fatal */ }
      }

      const ledger = await readLedger();
      const response = {
        did: didUri,
        balance: getBalance(ledger, didUri),
        cost,
        unit: 'sat'
      };
      // Include per-chain balances when multi-chain is enabled
      if (payChains) {
        response.balances = {};
        for (const chainId of payChains) {
          const unit = CHAIN_REGISTRY[chainId].unit;
          response.balances[unit] = getBalance(ledger, didUri, unit);
        }
      }
      return reply.send(response);
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
        // Detect chain from TXO URI prefix (e.g. "txo:tbtc3:txid:vout")
        const chainId = parseTxoChain(deposit.txo);
        let depositMempoolUrl = mempoolUrl;
        let currency = null; // null = default (simple string format)

        if (chainId && payChains && payChains.includes(chainId)) {
          const chain = CHAIN_REGISTRY[chainId];
          depositMempoolUrl = chain.explorer.replace(/\/api$/, '');
          currency = chain.unit;
        } else if (chainId && payChains) {
          return reply.code(400).send({
            error: `Chain '${chainId}' not enabled. Enabled chains: ${payChains.join(', ')}`,
          });
        }

        const result = await verifySatsDeposit(deposit.txo, depositMempoolUrl);
        if (!result.valid) {
          return reply.code(400).send({ error: result.error });
        }

        const didUri = pubkeyToDidNostr(pubkey);
        const ledger = await readLedger();
        const newBalance = credit(ledger, didUri, result.amount, currency);
        await writeLedger(ledger);

        return reply.send({
          did: didUri,
          deposited: result.amount,
          balance: newBalance,
          unit: currency || 'sat',
          ...(chainId ? { chain: chainId } : {})
        });
      }

      // --- Claim deposit: user sent sats to pod's address ---
      if (deposit.type === 'claim') {
        const kp = await loadOrCreateKeypair();
        const chainId = deposit.chain || (payChains ? payChains[0] : 'tbtc4');
        if (payChains && !payChains.includes(chainId)) {
          return reply.code(400).send({ error: `Chain '${chainId}' not enabled`, enabledChains: payChains });
        }
        const chain = CHAIN_REGISTRY[chainId];
        if (!chain) {
          return reply.code(400).send({ error: `Unknown chain: ${chainId}` });
        }

        // Derive address — try per-user tweaked address first, fall back to generic
        const network = chainId === 'btc' ? 'mainnet' : (chainId === 'tbtc3' ? 'testnet' : 'testnet4');
        const didUri = pubkeyToDidNostr(pubkey);
        const userAddress = btAddress(kp.pubkey, [didUri], network);
        const podAddress = btAddress(kp.pubkey, [], network);

        // Fetch transaction from mempool
        let txData;
        try {
          const txResp = await fetch(`${chain.explorer}/tx/${deposit.txid}`);
          if (!txResp.ok) {
            return reply.code(400).send({ error: 'Transaction not found' });
          }
          txData = await txResp.json();
        } catch (err) {
          return reply.code(502).send({ error: `Failed to verify transaction: ${err.message}` });
        }
        const output = txData.vout?.[deposit.vout];
        if (!output) {
          return reply.code(400).send({ error: `Output ${deposit.vout} not found` });
        }

        // Verify output pays our address (per-user tweaked or generic pod address)
        const outputAddr = output.scriptpubkey_address;
        const tweak = outputAddr === userAddress ? didUri : null;
        if (outputAddr !== userAddress && outputAddr !== podAddress) {
          return reply.code(400).send({ error: 'Output does not pay this pod\'s address', expected: { user: userAddress, pod: podAddress } });
        }

        const amount = output.value;
        const currency = chain.unit;

        // Replay protection + UTXO tracking
        const utxos = await loadUtxos();
        if (utxos.find(u => u.txid === deposit.txid && u.vout === deposit.vout)) {
          return reply.code(400).send({ error: 'This output has already been claimed' });
        }
        utxos.push({ txid: deposit.txid, vout: deposit.vout, amount, scriptpubkey: output.scriptpubkey, chain: chainId, tweak, spent: false });
        await saveUtxos(utxos);

        const ledger = await readLedger();
        const newBalance = credit(ledger, didUri, amount, currency);
        await writeLedger(ledger);

        return reply.send({
          did: didUri,
          deposited: amount,
          balance: newBalance,
          unit: currency,
          chain: chainId,
          txid: deposit.txid,
          address: podAddress
        });
      }

      return reply.code(400).send({
        error: 'Invalid deposit format. Send a TXO URI string, MRC20 state proof, or claim {txid, vout}.',
        formats: {
          sats: 'POST body: "<txid>:<vout>" or {"txo": "<txid>:<vout>"}',
          mrc20: 'POST body: {"type": "mrc20", "state": {...}, "prevState": {...}}',
          claim: 'POST body: {"txid": "...", "vout": 0, "chain": "tbtc4"}'
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
      try {
        if (Buffer.isBuffer(body)) body = JSON.parse(body.toString('utf8'));
        if (typeof body === 'string') body = JSON.parse(body);
      } catch {
        return reply.code(400).send({ error: 'Invalid JSON body' });
      }

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

      // Determine payment currency — chain-specific (e.g. "tbtc4") or generic "sat"
      const currency = (body?.currency && payChains && payChains.includes(body.currency))
        ? body.currency : null;

      // Check balance
      const didUri = pubkeyToDidNostr(pubkey);
      const ledger = await readLedger();
      const balance = getBalance(ledger, didUri, currency);
      if (balance < satCost) {
        return reply.code(402).send({
          error: `Insufficient ${currency || 'sat'} balance`,
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

      // Debit from buyer
      debit(ledger, didUri, satCost, currency);
      await writeLedger(ledger);

      return reply.send({
        bought: tokenAmount,
        ticker,
        cost: satCost,
        rate: payRate,
        balance: getBalance(ledger, didUri, currency),
        unit: currency || 'sat',
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
      try {
        if (Buffer.isBuffer(body)) body = JSON.parse(body.toString('utf8'));
        if (typeof body === 'string') body = JSON.parse(body);
      } catch {
        return reply.code(400).send({ error: 'Invalid JSON body' });
      }

      const didUri = pubkeyToDidNostr(pubkey);
      const ledger = await readLedger();
      if (body?.currency && (!payChains || !payChains.includes(body.currency))) {
        return reply.code(400).send({ error: `Unsupported currency: ${body.currency}`, enabledChains: payChains || [] });
      }
      const currency = body?.currency || null;
      const balance = getBalance(ledger, didUri, currency);

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
      debit(ledger, didUri, satCost, currency);
      await writeLedger(ledger);

      return reply.send({
        withdrawn: tokenAmount,
        ticker: payToken,
        cost: satCost,
        rate: payRate,
        balance: getBalance(ledger, didUri, currency),
        unit: currency || 'sat',
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

    // --- POST /pay/.withdraw-sats — withdraw sats as a TXO voucher ---
    if (url === '/pay/.withdraw-sats' && request.method === 'POST') {
      const pubkey = await getNostrPubkey(request);
      if (!pubkey) {
        return reply.code(401).send({ error: 'NIP-98 authentication required' });
      }

      let body = request.body;
      try {
        if (Buffer.isBuffer(body)) body = JSON.parse(body.toString('utf8'));
        if (typeof body === 'string') body = JSON.parse(body);
      } catch {
        return reply.code(400).send({ error: 'Invalid JSON body' });
      }

      const withdrawAmount = parseInt(body?.amount, 10);
      const chainId = body?.chain || (payChains ? payChains[0] : 'tbtc4');
      if (!withdrawAmount || withdrawAmount <= 0) {
        return reply.code(400).send({ error: 'Specify amount to withdraw' });
      }
      if (payChains && !payChains.includes(chainId)) {
        return reply.code(400).send({ error: `Chain '${chainId}' not enabled` });
      }
      const chain = CHAIN_REGISTRY[chainId];
      if (!chain) {
        return reply.code(400).send({ error: `Unknown chain: ${chainId}` });
      }
      const currency = chain.unit;

      // Check user balance
      const didUri = pubkeyToDidNostr(pubkey);
      const ledger = await readLedger();
      const balance = getBalance(ledger, didUri, currency);
      if (balance < withdrawAmount) {
        return reply.code(402).send({ error: 'Insufficient balance', balance, requested: withdrawAmount, unit: currency });
      }

      // Find unspent UTXOs for this chain
      const utxos = await loadUtxos();
      const available = utxos.filter(u => u.chain === chainId && !u.spent);
      if (available.length === 0) {
        return reply.code(400).send({ error: 'No UTXOs available for withdrawal' });
      }

      // Load pod keypair
      const kp = await loadOrCreateKeypair();

      // Select UTXOs — group by tweak so we can sign with one key
      // Prefer untweaked UTXOs first, then tweaked ones
      const fee = 300;
      const needed = withdrawAmount + fee;
      let selected = [];
      let total = 0;
      let selectedTweak = null;

      // Try untweaked first
      for (const utxo of available.filter(u => !u.tweak)) {
        selected.push(utxo);
        total += utxo.amount;
        if (total >= needed) break;
      }
      // If not enough, try tweaked (same tweak group only)
      if (total < needed) {
        const tweaked = available.filter(u => u.tweak);
        selected = [];
        total = 0;
        selectedTweak = null;
        for (const utxo of tweaked) {
          if (selectedTweak && utxo.tweak !== selectedTweak) continue;
          selected.push(utxo);
          selectedTweak = utxo.tweak;
          total += utxo.amount;
          if (total >= needed) break;
        }
      }
      if (total < needed) {
        return reply.code(400).send({ error: 'Not enough UTXO value for withdrawal + fee', available: total, needed });
      }

      // Derive signing key (tweaked if UTXOs are tweaked)
      const privkeyBytes = selectedTweak
        ? btDeriveChainedPrivkey(hexToBytes(kp.privkey), [selectedTweak])
        : hexToBytes(kp.privkey);

      // Generate a new keypair for the voucher recipient
      const voucherPrivkey = secp256k1.utils.randomPrivateKey();
      const voucherPubkey = secp256k1.getPublicKey(voucherPrivkey, true);
      const voucherXonly = voucherPubkey.slice(1);
      const voucherScript = p2trScript(voucherXonly);

      // Build outputs: voucher + change back to pod
      const outputs = [{ amount: withdrawAmount, scriptPubKey: voucherScript }];
      const change = total - withdrawAmount - fee;
      const podXonly = hexToBytes(kp.pubkey).slice(1);
      if (change > 546) {
        outputs.push({ amount: change, scriptPubKey: p2trScript(podXonly) });
      }

      // Build inputs
      const inputs = selected.map(u => ({
        txid: u.txid, vout: u.vout, amount: u.amount, scriptPubKey: hexToBytes(u.scriptpubkey)
      }));

      // Build and broadcast
      let newTxid;
      try {
        const rawTx = buildTransaction(inputs, outputs, privkeyBytes);
        newTxid = await broadcastTx(rawTx, chain.explorer.replace(/\/api$/, ''));
      } catch (err) {
        return reply.code(500).send({ error: `Broadcast failed: ${err.message}` });
      }

      // Debit user balance
      const debitResult = debit(ledger, didUri, withdrawAmount, currency);
      if (!debitResult.success) {
        return reply.code(402).send({ error: 'Balance changed during withdrawal', balance: debitResult.balance });
      }
      await writeLedger(ledger);

      // Mark UTXOs as spent, add change UTXO
      for (const u of selected) { u.spent = true; }
      if (change > 546) {
        utxos.push({ txid: newTxid, vout: 1, amount: change, scriptpubkey: '5120' + bytesToHex(podXonly), chain: chainId, spent: false });
      }
      await saveUtxos(utxos);

      // Return voucher URI
      const voucherUri = `txo:${chainId}:${newTxid}:0?amount=${withdrawAmount}&key=${bytesToHex(voucherPrivkey)}`;
      return reply.send({
        voucher: voucherUri,
        txid: newTxid,
        amount: withdrawAmount,
        unit: currency,
        balance: getBalance(ledger, didUri, currency)
      });
    }

    // --- GET /pay/.offers — list open sell orders ---
    if (url === '/pay/.offers' && request.method === 'GET') {
      const offers = await loadOffers();
      return reply.send(offers.filter(o => o.status === 'pending'));
    }

    // --- POST /pay/.sell — create a sell order ---
    if (url === '/pay/.sell' && request.method === 'POST') {
      const pubkey = await getNostrPubkey(request);
      if (!pubkey) {
        return reply.code(401).send({ error: 'NIP-98 authentication required' });
      }

      if (!payToken) {
        return reply.code(400).send({ error: 'Secondary market not configured (no --pay-token set)' });
      }

      let body = request.body;
      try {
        if (Buffer.isBuffer(body)) body = JSON.parse(body.toString('utf8'));
        if (typeof body === 'string') body = JSON.parse(body);
      } catch {
        return reply.code(400).send({ error: 'Invalid JSON body' });
      }

      const amount = Math.floor(body?.amount || 0);
      const price = Math.floor(body?.price || 0); // total sats for the lot
      if (amount <= 0 || price <= 0) {
        return reply.code(400).send({ error: 'Specify amount (tokens) and price (total sats)' });
      }

      // Verify seller has tokens on the trail
      const trail = await loadTrail(payToken);
      if (!trail) {
        return reply.code(500).send({ error: `Token ${payToken} not minted on this pod` });
      }
      const currentState = trail.states[trail.states.length - 1];
      const sellerBalance = currentState.balances[pubkey] || 0;
      if (sellerBalance < amount) {
        return reply.code(400).send({
          error: 'Insufficient token balance on trail',
          balance: sellerBalance,
          amount
        });
      }

      const offer = {
        id: crypto.randomUUID(),
        seller: pubkey,
        ticker: payToken,
        amount,
        price,
        rate: Math.round(price / amount * 100) / 100,
        status: 'pending',
        created: Date.now()
      };

      const offers = await loadOffers();
      offers.push(offer);
      await saveOffers(offers);

      return reply.send(offer);
    }

    // --- POST /pay/.swap — execute a swap against a sell order ---
    if (url === '/pay/.swap' && request.method === 'POST') {
      const pubkey = await getNostrPubkey(request);
      if (!pubkey) {
        return reply.code(401).send({ error: 'NIP-98 authentication required' });
      }

      if (!payToken) {
        return reply.code(400).send({ error: 'Secondary market not configured (no --pay-token set)' });
      }

      let body = request.body;
      try {
        if (Buffer.isBuffer(body)) body = JSON.parse(body.toString('utf8'));
        if (typeof body === 'string') body = JSON.parse(body);
      } catch {
        return reply.code(400).send({ error: 'Invalid JSON body' });
      }

      const offerId = body?.id;
      if (!offerId) {
        return reply.code(400).send({ error: 'Specify offer id' });
      }

      // Find the offer
      const offers = await loadOffers();
      const offer = offers.find(o => o.id === offerId && o.status === 'pending');
      if (!offer) {
        return reply.code(404).send({ error: 'Offer not found or already filled' });
      }

      // Can't buy your own offer
      if (offer.seller === pubkey) {
        return reply.code(400).send({ error: 'Cannot swap with your own offer' });
      }

      // Check buyer's sat balance
      const didUri = pubkeyToDidNostr(pubkey);
      const sellerDid = pubkeyToDidNostr(offer.seller);
      const ledger = await readLedger();
      const balance = getBalance(ledger, didUri);
      if (balance < offer.price) {
        return reply.code(402).send({
          error: 'Insufficient sat balance',
          balance,
          cost: offer.price,
          deposit: '/pay/.deposit'
        });
      }

      // Transfer tokens from seller to buyer on the trail
      let result;
      try {
        result = await transferToken({
          ticker: payToken,
          from: offer.seller,
          to: pubkey,
          amount: offer.amount,
          mempoolUrl
        });
      } catch (err) {
        return reply.code(500).send({ error: `Transfer failed: ${err.message}` });
      }

      // Debit buyer, credit seller
      debit(ledger, didUri, offer.price);
      credit(ledger, sellerDid, offer.price);
      await writeLedger(ledger);

      // Mark offer as filled
      offer.status = 'filled';
      offer.buyer = pubkey;
      offer.filledAt = Date.now();
      offer.txid = result.txid;
      await saveOffers(offers);

      return reply.send({
        swapped: offer.amount,
        ticker: payToken,
        cost: offer.price,
        rate: offer.rate,
        balance: getBalance(ledger, didUri),
        sellerCredited: offer.price,
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

    // --- GET /pay/.pool — AMM pool state (public) ---
    if (url === '/pay/.pool' && request.method === 'GET') {
      if (!payChains || payChains.length < 2) {
        return reply.code(400).send({ error: 'AMM not configured (requires --pay-chains with 2 chains)' });
      }
      const pool = await loadPool();
      if (!pool) {
        return reply.send({
          pair: [CHAIN_REGISTRY[payChains[0]].unit, CHAIN_REGISTRY[payChains[1]].unit],
          reserves: { [CHAIN_REGISTRY[payChains[0]].unit]: 0, [CHAIN_REGISTRY[payChains[1]].unit]: 0 },
          k: 0,
          fee: 0.003,
          totalShares: 0,
          lpShares: {}
        });
      }
      return reply.send(pool);
    }

    // --- POST /pay/.pool — AMM operations (swap, add-liquidity, remove-liquidity) ---
    if (url === '/pay/.pool' && request.method === 'POST') {
      if (!payChains || payChains.length < 2) {
        return reply.code(400).send({ error: 'AMM not configured (requires --pay-chains with 2 chains)' });
      }

      const pubkey = await getNostrPubkey(request);
      if (!pubkey) {
        return reply.code(401).send({ error: 'NIP-98 authentication required' });
      }

      let body = request.body;
      try {
        if (Buffer.isBuffer(body)) body = JSON.parse(body.toString('utf8'));
        if (typeof body === 'string') body = JSON.parse(body);
      } catch {
        return reply.code(400).send({ error: 'Invalid JSON body' });
      }

      const didUri = pubkeyToDidNostr(pubkey);
      const unitA = CHAIN_REGISTRY[payChains[0]].unit;
      const unitB = CHAIN_REGISTRY[payChains[1]].unit;
      const action = body?.action;

      // --- ADD LIQUIDITY ---
      if (action === 'add-liquidity') {
        const amountA = Math.floor(body?.[unitA] || 0);
        const amountB = Math.floor(body?.[unitB] || 0);
        if (amountA <= 0 || amountB <= 0) {
          return reply.code(400).send({ error: `Specify ${unitA} and ${unitB} amounts` });
        }

        const ledger = await readLedger();
        const balA = getBalance(ledger, didUri, unitA);
        const balB = getBalance(ledger, didUri, unitB);
        if (balA < amountA) {
          return reply.code(402).send({ error: `Insufficient ${unitA} balance`, balance: balA, required: amountA });
        }
        if (balB < amountB) {
          return reply.code(402).send({ error: `Insufficient ${unitB} balance`, balance: balB, required: amountB });
        }

        let pool = await loadPool();
        if (!pool) {
          pool = {
            pair: [unitA, unitB],
            reserves: { [unitA]: 0, [unitB]: 0 },
            k: 0,
            fee: 0.003,
            totalShares: 0,
            lpShares: {}
          };
        }

        // Calculate LP shares (initial: shares = sqrt(amountA * amountB))
        let newShares;
        if (pool.totalShares === 0) {
          newShares = Math.floor(Math.sqrt(amountA * amountB));
        } else {
          // Proportional: min(amountA/reserveA, amountB/reserveB) * totalShares
          const ratioA = amountA / pool.reserves[unitA];
          const ratioB = amountB / pool.reserves[unitB];
          newShares = Math.floor(Math.min(ratioA, ratioB) * pool.totalShares);
        }
        if (newShares <= 0) {
          return reply.code(400).send({ error: 'Amounts too small to mint LP shares' });
        }

        // Debit user balances
        debit(ledger, didUri, amountA, unitA);
        debit(ledger, didUri, amountB, unitB);
        await writeLedger(ledger);

        // Update pool
        pool.reserves[unitA] += amountA;
        pool.reserves[unitB] += amountB;
        pool.k = pool.reserves[unitA] * pool.reserves[unitB];
        pool.totalShares += newShares;
        pool.lpShares[didUri] = (pool.lpShares[didUri] || 0) + newShares;
        await savePool(pool);

        return reply.send({
          action: 'add-liquidity',
          deposited: { [unitA]: amountA, [unitB]: amountB },
          shares: newShares,
          totalShares: pool.totalShares,
          reserves: pool.reserves,
          k: pool.k
        });
      }

      // --- REMOVE LIQUIDITY ---
      if (action === 'remove-liquidity') {
        const shares = Math.floor(body?.shares || 0);
        const pool = await loadPool();
        if (!pool || pool.totalShares === 0) {
          return reply.code(400).send({ error: 'Pool has no liquidity' });
        }

        const userShares = pool.lpShares[didUri] || 0;
        const toRemove = body?.all ? userShares : shares;
        if (toRemove <= 0 || toRemove > userShares) {
          return reply.code(400).send({ error: 'Invalid shares', yours: userShares });
        }

        // Calculate proportional withdrawal
        const fraction = toRemove / pool.totalShares;
        const outA = Math.floor(pool.reserves[unitA] * fraction);
        const outB = Math.floor(pool.reserves[unitB] * fraction);

        // Credit user
        const ledger = await readLedger();
        credit(ledger, didUri, outA, unitA);
        credit(ledger, didUri, outB, unitB);
        await writeLedger(ledger);

        // Update pool
        pool.reserves[unitA] -= outA;
        pool.reserves[unitB] -= outB;
        pool.k = pool.reserves[unitA] * pool.reserves[unitB];
        pool.totalShares -= toRemove;
        pool.lpShares[didUri] -= toRemove;
        if (pool.lpShares[didUri] <= 0) delete pool.lpShares[didUri];
        await savePool(pool);

        return reply.send({
          action: 'remove-liquidity',
          withdrawn: { [unitA]: outA, [unitB]: outB },
          sharesRemoved: toRemove,
          totalShares: pool.totalShares,
          reserves: pool.reserves
        });
      }

      // --- SWAP ---
      if (action === 'swap') {
        const sellUnit = body?.sell;
        const amount = Math.floor(body?.amount || 0);
        if (!sellUnit || ![unitA, unitB].includes(sellUnit)) {
          return reply.code(400).send({ error: `Specify sell: "${unitA}" or "${unitB}"` });
        }
        if (amount <= 0) {
          return reply.code(400).send({ error: 'Amount must be positive' });
        }

        const pool = await loadPool();
        if (!pool || pool.k === 0) {
          return reply.code(400).send({ error: 'Pool has no liquidity' });
        }

        const buyUnit = sellUnit === unitA ? unitB : unitA;

        // Check user balance
        const ledger = await readLedger();
        const userBal = getBalance(ledger, didUri, sellUnit);
        if (userBal < amount) {
          return reply.code(402).send({
            error: `Insufficient ${sellUnit} balance`,
            balance: userBal,
            required: amount,
            deposit: '/pay/.deposit'
          });
        }

        // Constant product: (reserveIn + amountIn * (1-fee)) * (reserveOut - amountOut) = k
        const reserveIn = pool.reserves[sellUnit];
        const reserveOut = pool.reserves[buyUnit];
        const amountInAfterFee = amount * (1 - pool.fee);
        const amountOut = Math.floor((reserveOut * amountInAfterFee) / (reserveIn + amountInAfterFee));

        if (amountOut <= 0) {
          return reply.code(400).send({ error: 'Trade too small' });
        }

        // Slippage protection
        if (body?.minReceived && amountOut < body.minReceived) {
          return reply.code(400).send({
            error: 'Slippage exceeded',
            wouldReceive: amountOut,
            minReceived: body.minReceived
          });
        }

        // Execute: debit sellUnit, credit buyUnit
        debit(ledger, didUri, amount, sellUnit);
        credit(ledger, didUri, amountOut, buyUnit);
        await writeLedger(ledger);

        // Update pool reserves
        pool.reserves[sellUnit] += amount;
        pool.reserves[buyUnit] -= amountOut;
        pool.k = pool.reserves[unitA] * pool.reserves[unitB];
        await savePool(pool);

        const price = amount / amountOut;
        return reply.send({
          action: 'swap',
          sold: { unit: sellUnit, amount },
          bought: { unit: buyUnit, amount: amountOut },
          price: Math.round(price * 10000) / 10000,
          fee: Math.floor(amount * pool.fee),
          reserves: pool.reserves,
          balances: {
            [sellUnit]: getBalance(ledger, didUri, sellUnit),
            [buyUnit]: getBalance(ledger, didUri, buyUnit)
          }
        });
      }

      return reply.code(400).send({ error: 'Unknown action. Use: swap, add-liquidity, remove-liquidity' });
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

      // Try generic sat balance first, then fall back to chain balances
      const currency = request.headers['x-pay-currency'] || null;
      let payUnit = currency && payChains && payChains.includes(currency) ? currency : null;
      let result = debit(ledger, didUri, cost, payUnit);

      // If generic sat failed and no explicit currency, try each chain balance
      if (!result.success && !payUnit && payChains) {
        for (const chainId of payChains) {
          result = debit(ledger, didUri, cost, chainId);
          if (result.success) { payUnit = chainId; break; }
        }
      }

      if (!result.success) {
        const response = {
          error: 'Payment Required',
          balance: result.balance,
          cost,
          unit: 'sat',
          deposit: '/pay/.deposit'
        };
        if (payChains) {
          response.balances = {};
          for (const chainId of payChains) {
            response.balances[chainId] = getBalance(ledger, didUri, chainId);
          }
        }
        return reply.code(402).send(response);
      }

      await writeLedger(ledger);
      reply.header('X-Balance', String(result.balance));
      reply.header('X-Cost', String(cost));
      if (payUnit) reply.header('X-Pay-Currency', payUnit);
      return; // continue to normal resource handler
    }

    // PUT/DELETE/POST — continue to normal WAC auth + resource handler
  };
}
