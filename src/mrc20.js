/**
 * MRC20 Token Verification
 *
 * Verifies MRC20 state chain integrity and extracts transfer operations.
 * Used by the pay middleware to accept token deposits.
 *
 * MRC20 profile: mono.mrc20.v0.1
 * State chain: each state links to previous via SHA-256 of JCS-encoded state.
 *
 * References:
 *   - Blocktrails: https://blocktrails.org/
 *   - JCS (RFC 8785): JSON Canonicalization Scheme
 */

import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';

const MRC20_PROFILE = 'mono.mrc20.v0.1';
const TRANSFER_OP = 'urn:mono:op:transfer';

// --- BIP-341 key chaining constants ---
const SECP_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32M = 0x2bc830a3;

/**
 * JSON Canonicalization Scheme (RFC 8785)
 * Produces deterministic JSON — sorted keys, no whitespace.
 * @param {*} obj
 * @returns {string}
 */
export function jcs(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(v => jcs(v)).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + jcs(obj[k])).join(',') + '}';
}

/**
 * SHA-256 hex digest of a string
 * @param {string} str
 * @returns {string} Hex hash
 */
export function sha256Hex(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

/**
 * Verify state chain link: state.prev must equal SHA-256(JCS(prevState))
 * @param {object} state - Current state
 * @param {object} prevState - Previous state
 * @returns {{valid: boolean, error?: string}}
 */
export function verifyStateLink(state, prevState) {
  if (!state || !prevState) {
    return { valid: false, error: 'Missing state or prevState' };
  }

  const expectedPrev = sha256Hex(jcs(prevState));
  if (state.prev !== expectedPrev) {
    return { valid: false, error: `State chain break: expected prev ${expectedPrev}, got ${state.prev}` };
  }

  // Verify sequence number
  if (typeof state.seq === 'number' && typeof prevState.seq === 'number') {
    if (state.seq !== prevState.seq + 1) {
      return { valid: false, error: `Sequence mismatch: expected ${prevState.seq + 1}, got ${state.seq}` };
    }
  }

  return { valid: true };
}

/**
 * Validate that a state object is a valid MRC20 state
 * @param {object} state
 * @returns {{valid: boolean, error?: string}}
 */
export function validateMrc20State(state) {
  if (!state || typeof state !== 'object') {
    return { valid: false, error: 'State must be an object' };
  }
  if (state.profile !== MRC20_PROFILE) {
    return { valid: false, error: `Invalid profile: expected ${MRC20_PROFILE}, got ${state.profile}` };
  }
  if (!Array.isArray(state.ops)) {
    return { valid: false, error: 'State must have ops array' };
  }
  if (typeof state.prev !== 'string') {
    return { valid: false, error: 'State must have prev hash' };
  }
  return { valid: true };
}

/**
 * Extract transfer operations targeting a specific address
 * @param {object} state - MRC20 state
 * @param {string} toAddress - Recipient address to filter by
 * @returns {Array<{from: string, to: string, amt: number}>} Matching transfers
 */
export function extractTransfersTo(state, toAddress) {
  if (!state.ops || !Array.isArray(state.ops)) return [];
  return state.ops.filter(op =>
    op.op === TRANSFER_OP && op.to === toAddress && typeof op.amt === 'number' && op.amt > 0
  );
}

/**
 * Get total amount transferred to an address in a state
 * @param {object} state - MRC20 state
 * @param {string} toAddress - Recipient address
 * @returns {number} Total amount transferred
 */
export function totalTransferredTo(state, toAddress) {
  const transfers = extractTransfersTo(state, toAddress);
  return transfers.reduce((sum, op) => sum + op.amt, 0);
}

/**
 * Verify an MRC20 deposit: validate state chain + extract transfer amount
 * @param {object} params
 * @param {object} params.state - New state containing transfer ops
 * @param {object} params.prevState - Previous state (for chain verification)
 * @param {string} params.toAddress - Pod's address to check transfers against
 * @returns {{valid: boolean, amount: number, ticker?: string, error?: string}}
 */
export function verifyMrc20Deposit(params) {
  const { state, prevState, toAddress } = params;

  // Validate MRC20 format
  const stateCheck = validateMrc20State(state);
  if (!stateCheck.valid) return { valid: false, amount: 0, error: stateCheck.error };

  const prevCheck = validateMrc20State(prevState);
  if (!prevCheck.valid) return { valid: false, amount: 0, error: `prevState: ${prevCheck.error}` };

  // Verify state chain link
  const linkCheck = verifyStateLink(state, prevState);
  if (!linkCheck.valid) return { valid: false, amount: 0, error: linkCheck.error };

  // Extract transfers to pod
  const amount = totalTransferredTo(state, toAddress);
  if (amount <= 0) {
    return { valid: false, amount: 0, error: `No transfers to ${toAddress} found in state ops` };
  }

  return {
    valid: true,
    amount,
    ticker: state.ticker || 'UNKNOWN'
  };
}

// --- BIP-341 key chaining (blocktrails anchor verification) ---

function sha256Bytes(data) {
  const buf = data instanceof Uint8Array ? Buffer.from(data) : Buffer.from(data, 'utf8');
  return new Uint8Array(crypto.createHash('sha256').update(buf).digest());
}

function concatBytes(...arrays) {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { result.set(a, off); off += a.length; }
  return result;
}

function bytesToBigInt(bytes) {
  let r = 0n;
  for (const b of bytes) r = (r << 8n) | BigInt(b);
  return r;
}

function hexToU8(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function taggedHash(tag, ...msgs) {
  const tagHash = sha256Bytes(Buffer.from(tag, 'utf8'));
  return sha256Bytes(concatBytes(tagHash, tagHash, ...msgs));
}

function btScalar(pubkeyCompressed, state) {
  const xOnly = pubkeyCompressed.slice(1);
  const stateBytes = typeof state === 'string' ? Buffer.from(state, 'utf8') : state;
  const sh = sha256Bytes(stateBytes);
  return bytesToBigInt(taggedHash('TapTweak', xOnly, sh)) % SECP_N;
}

function btDeriveChainedPubkey(pubkeyBase, states) {
  let P = secp256k1.ProjectivePoint.fromHex(bytesToHex(pubkeyBase));
  let cur = pubkeyBase;
  for (const s of states) {
    const t = btScalar(cur, s);
    P = P.add(secp256k1.ProjectivePoint.BASE.multiply(t));
    cur = new Uint8Array(P.toRawBytes(true));
  }
  return cur;
}

// --- Bech32m encoding ---

function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0;
  const ret = [], maxv = (1 << to) - 1;
  for (const v of data) {
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) { bits -= to; ret.push((acc >> bits) & maxv); }
  }
  if (pad && bits > 0) ret.push((acc << (to - bits)) & maxv);
  return ret;
}

function hrpExpand(hrp) {
  const r = [];
  for (const c of hrp) r.push(c.charCodeAt(0) >> 5);
  r.push(0);
  for (const c of hrp) r.push(c.charCodeAt(0) & 31);
  return r;
}

function polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

function bech32mEncode(hrp, version, program) {
  const conv = convertBits(program, 8, 5, true);
  const values = [version, ...conv];
  const enc = [...hrpExpand(hrp), ...values, 0, 0, 0, 0, 0, 0];
  const mod = polymod(enc) ^ BECH32M;
  const checksum = [0, 1, 2, 3, 4, 5].map(i => (mod >> (5 * (5 - i))) & 31);
  let result = hrp + '1';
  for (const v of [...values, ...checksum]) result += BECH32_CHARSET[v];
  return result;
}

/**
 * Derive the taproot address for a state chain
 * @param {string} pubkeyHex - Issuer's compressed pubkey (66-char hex)
 * @param {string[]} states - JCS-encoded state strings
 * @param {string} [network='testnet4'] - 'testnet4' or 'mainnet'
 * @returns {string} Bech32m taproot address
 */
export function btAddress(pubkeyHex, states, network = 'testnet4') {
  const pubkeyBase = hexToU8(pubkeyHex);
  const P = btDeriveChainedPubkey(pubkeyBase, states);
  const xOnly = P.slice(1);
  const hrp = network === 'mainnet' ? 'bc' : 'tb';
  return bech32mEncode(hrp, 1, xOnly);
}

/**
 * Verify that an MRC20 state is anchored to a Bitcoin UTXO
 * @param {object} params
 * @param {object} params.state - Current state with transfer ops
 * @param {object} params.prevState - Previous state (chain verification)
 * @param {string} params.toAddress - Pod's address for transfer verification
 * @param {string} params.pubkey - Issuer's compressed pubkey (66-char hex)
 * @param {string[]} params.stateStrings - All JCS state strings (genesis to current)
 * @param {string} [params.mempoolUrl] - Mempool API base URL
 * @param {string} [params.network] - 'testnet4' or 'mainnet'
 * @returns {Promise<{valid: boolean, amount?: number, ticker?: string, address?: string, error?: string}>}
 */
export async function verifyMrc20Anchor(params) {
  const {
    state, prevState, toAddress, pubkey, stateStrings,
    mempoolUrl = 'https://mempool.space/testnet4',
    network = 'testnet4'
  } = params;

  // 1. Standard deposit verification (chain integrity + transfers)
  const depositCheck = verifyMrc20Deposit({ state, prevState, toAddress });
  if (!depositCheck.valid) return depositCheck;

  // 2. Verify stateStrings is provided and non-empty
  if (!Array.isArray(stateStrings) || stateStrings.length === 0) {
    return { valid: false, amount: 0, error: 'stateStrings required for anchor verification' };
  }

  // 3. Verify pubkey is provided
  if (!pubkey || typeof pubkey !== 'string' || pubkey.length !== 66) {
    return { valid: false, amount: 0, error: 'pubkey must be a 66-char compressed pubkey hex' };
  }

  // 4. Verify the last stateString matches the current state
  const currentJcs = jcs(state);
  const lastStateString = stateStrings[stateStrings.length - 1];
  if (currentJcs !== lastStateString) {
    return { valid: false, amount: 0, error: 'Last stateString does not match JCS(state)' };
  }

  // 5. Derive expected taproot address
  let address;
  try {
    address = btAddress(pubkey, stateStrings, network);
  } catch (err) {
    return { valid: false, amount: 0, error: `Key derivation failed: ${err.message}` };
  }

  // 6. Query mempool for UTXO at derived address
  try {
    const resp = await fetch(`${mempoolUrl}/api/address/${address}/utxo`);
    if (!resp.ok) {
      return { valid: false, amount: 0, error: `Mempool API error: ${resp.status}` };
    }
    const utxos = await resp.json();
    if (!Array.isArray(utxos) || utxos.length === 0) {
      return { valid: false, amount: 0, error: `No UTXO at derived address ${address}` };
    }
  } catch (err) {
    return { valid: false, amount: 0, error: `Mempool lookup failed: ${err.message}` };
  }

  return {
    valid: true,
    amount: depositCheck.amount,
    ticker: depositCheck.ticker,
    address
  };
}
