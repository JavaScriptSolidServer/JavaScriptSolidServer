/**
 * Web Ledger — spec-compliant balance tracking
 *
 * Implements the Web Ledgers specification (https://webledgers.org/)
 * for mapping URIs to numerical balances. Default unit: satoshi.
 *
 * JSON-LD context: https://w3id.org/webledgers
 *
 * @module webledger
 */

import * as storage from './storage/filesystem.js';

const DEFAULT_PATH = '/.well-known/webledgers/webledgers.json';
const CONTEXT = 'https://w3id.org/webledgers';

/**
 * Create an empty spec-compliant ledger
 * @param {object} options
 * @param {string} options.name - Ledger name
 * @param {string} options.description - Ledger description
 * @param {string} options.id - Ledger URI identifier
 * @param {string} options.defaultCurrency - Default currency (default 'satoshi')
 * @returns {object} Empty WebLedger object
 */
export function createLedger(options = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    '@context': CONTEXT,
    type: 'WebLedger',
    ...(options.id && { id: options.id }),
    name: options.name ?? 'Pod Credits',
    description: options.description ?? 'Paid API balance ledger',
    defaultCurrency: options.defaultCurrency ?? 'satoshi',
    created: now,
    updated: now,
    entries: []
  };
}

/**
 * Read a webledger from storage
 * @param {string} ledgerPath - URL path to ledger file
 * @returns {Promise<object>} WebLedger object
 */
export async function readLedger(ledgerPath = DEFAULT_PATH) {
  const buf = await storage.read(ledgerPath);
  if (!buf) {
    return createLedger();
  }
  try {
    const ledger = JSON.parse(buf.toString('utf8'));
    // Migrate legacy format: add missing spec fields
    if (!ledger['@context']) ledger['@context'] = CONTEXT;
    if (!ledger.type) ledger.type = 'WebLedger';
    if (!ledger.defaultCurrency) ledger.defaultCurrency = 'satoshi';
    if (!ledger.created) ledger.created = Math.floor(Date.now() / 1000);
    if (!ledger.entries) ledger.entries = [];
    // Idempotency keys for deposits already absorbed into balances. Kept in
    // the ledger itself so crediting is crash-safe: the balance and the "this
    // deposit was counted" marker commit together in one writeLedger, instead
    // of the balance landing in one file and the spent-marker in another.
    if (!ledger.credited) ledger.credited = [];
    return ledger;
  } catch {
    return createLedger();
  }
}

/**
 * Write a webledger to storage (updates the `updated` timestamp)
 * @param {object} ledger - WebLedger object
 * @param {string} ledgerPath - URL path to ledger file
 * @returns {Promise<boolean>}
 */
export async function writeLedger(ledger, ledgerPath = DEFAULT_PATH) {
  ledger.updated = Math.floor(Date.now() / 1000);
  return storage.write(ledgerPath, JSON.stringify(ledger, null, 2));
}

/**
 * Get balance for a URI
 * @param {object} ledger - WebLedger object
 * @param {string} uri - Agent URI (e.g. did:nostr:...)
 * @param {string} [currency] - Currency code (e.g. 'tbtc3', 'tbtc4'). If omitted, reads default/simple amount.
 * @returns {number} Balance as integer
 */
export function getBalance(ledger, uri, currency) {
  const entry = ledger.entries.find(e => e.url === uri);
  if (!entry) return 0;
  // Handle array amount format
  if (Array.isArray(entry.amount)) {
    const target = currency
      ? entry.amount.find(a => a.currency === currency)
      : entry.amount.find(a => a.currency === 'satoshi' || a.currency === 'sat');
    return target ? parseInt(target.value, 10) || 0 : 0;
  }
  // Simple string format — only if no specific currency requested, or currency matches default
  if (currency) return 0;
  return parseInt(entry.amount, 10) || 0;
}

/**
 * Set balance for a URI
 * @param {object} ledger - WebLedger object
 * @param {string} uri - Agent URI
 * @param {number} amount - New balance
 * @param {string} [currency] - Currency code. If provided, uses array amount format.
 */
export function setBalance(ledger, uri, amount, currency) {
  let entry = ledger.entries.find(e => e.url === uri);
  if (!currency) {
    // Simple string format (backward compatible)
    if (entry) {
      entry.amount = String(amount);
    } else {
      ledger.entries.push({ type: 'Entry', url: uri, amount: String(amount) });
    }
    return;
  }
  // Multi-currency: use array format
  if (!entry) {
    entry = { type: 'Entry', url: uri, amount: [] };
    ledger.entries.push(entry);
  }
  // Migrate simple string to array if needed
  if (!Array.isArray(entry.amount)) {
    const oldVal = parseInt(entry.amount, 10) || 0;
    entry.amount = oldVal > 0 ? [{ currency: 'satoshi', value: String(oldVal) }] : [];
  }
  const existing = entry.amount.find(a => a.currency === currency);
  if (existing) {
    existing.value = String(amount);
  } else {
    entry.amount.push({ currency, value: String(amount) });
  }
}

/**
 * Credit (add to) a balance
 * @param {object} ledger - WebLedger object
 * @param {string} uri - Agent URI
 * @param {number} amount - Amount to add
 * @param {string} [currency] - Currency code
 * @returns {number} New balance
 */
export function credit(ledger, uri, amount, currency) {
  const current = getBalance(ledger, uri, currency);
  const newBalance = current + amount;
  setBalance(ledger, uri, newBalance, currency);
  return newBalance;
}

/**
 * Debit (subtract from) a balance
 * @param {object} ledger - WebLedger object
 * @param {string} uri - Agent URI
 * @param {number} amount - Amount to subtract
 * @param {string} [currency] - Currency code
 * @returns {{success: boolean, balance: number}} Result
 */
export function debit(ledger, uri, amount, currency) {
  const current = getBalance(ledger, uri, currency);
  if (current < amount) {
    return { success: false, balance: current };
  }
  const newBalance = current - amount;
  setBalance(ledger, uri, newBalance, currency);
  return { success: true, balance: newBalance };
}

/**
 * Idempotently credit a keyed deposit exactly once.
 *
 * The dedup key (e.g. `${chain}:${txid}:${vout}` for an on-chain UTXO) is
 * recorded in the ledger's own `credited` list, so the balance increment and
 * the "already counted" marker are committed together by a single writeLedger.
 * A crash after that single write can never re-credit the same deposit — which
 * is exactly what happened when the credit and the UTXO-spent record lived in
 * two separate files written one after another.
 *
 * @param {object} ledger - WebLedger object (must be persisted afterwards)
 * @param {string} key - Stable idempotency key for this deposit
 * @param {string} uri - Agent URI
 * @param {number} amount - Amount to add
 * @param {string} [currency] - Currency code
 * @returns {{credited: boolean, balance: number}} `credited` is false when the
 *   key was already absorbed (no change made)
 */
export function creditOnce(ledger, key, uri, amount, currency) {
  if (!ledger.credited) ledger.credited = [];
  if (ledger.credited.includes(key)) {
    return { credited: false, balance: getBalance(ledger, uri, currency) };
  }
  const balance = credit(ledger, uri, amount, currency);
  ledger.credited.push(key);
  return { credited: true, balance };
}

/**
 * List all entries with non-zero balances
 * @param {object} ledger - WebLedger object
 * @returns {Array<{url: string, amount: number}>}
 */
export function listBalances(ledger) {
  return ledger.entries
    .map(e => ({ url: e.url, amount: getBalance(ledger, e.url) }))
    .filter(e => e.amount > 0);
}

/**
 * Remove entries with zero balance
 * @param {object} ledger - WebLedger object
 */
export function compact(ledger) {
  ledger.entries = ledger.entries.filter(e => {
    const bal = getBalance(ledger, e.url);
    return bal > 0;
  });
}

// Re-export the default path for consumers
export { DEFAULT_PATH as LEDGER_PATH };
