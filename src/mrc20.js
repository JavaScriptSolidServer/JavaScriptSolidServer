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

const MRC20_PROFILE = 'mono.mrc20.v0.1';
const TRANSFER_OP = 'urn:mono:op:transfer';

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
