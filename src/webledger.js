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
 * @returns {number} Balance as integer
 */
export function getBalance(ledger, uri) {
  const entry = ledger.entries.find(e => e.url === uri);
  if (!entry) return 0;
  // Handle both simple string and array amount formats
  if (Array.isArray(entry.amount)) {
    const sat = entry.amount.find(a => a.currency === 'satoshi' || a.currency === 'sat');
    return sat ? parseInt(sat.value, 10) || 0 : 0;
  }
  return parseInt(entry.amount, 10) || 0;
}

/**
 * Set balance for a URI
 * @param {object} ledger - WebLedger object
 * @param {string} uri - Agent URI
 * @param {number} amount - New balance
 */
export function setBalance(ledger, uri, amount) {
  const entry = ledger.entries.find(e => e.url === uri);
  if (entry) {
    entry.amount = String(amount);
  } else {
    ledger.entries.push({ type: 'Entry', url: uri, amount: String(amount) });
  }
}

/**
 * Credit (add to) a balance
 * @param {object} ledger - WebLedger object
 * @param {string} uri - Agent URI
 * @param {number} amount - Amount to add
 * @returns {number} New balance
 */
export function credit(ledger, uri, amount) {
  const current = getBalance(ledger, uri);
  const newBalance = current + amount;
  setBalance(ledger, uri, newBalance);
  return newBalance;
}

/**
 * Debit (subtract from) a balance
 * @param {object} ledger - WebLedger object
 * @param {string} uri - Agent URI
 * @param {number} amount - Amount to subtract
 * @returns {{success: boolean, balance: number}} Result
 */
export function debit(ledger, uri, amount) {
  const current = getBalance(ledger, uri);
  if (current < amount) {
    return { success: false, balance: current };
  }
  const newBalance = current - amount;
  setBalance(ledger, uri, newBalance);
  return { success: true, balance: newBalance };
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
