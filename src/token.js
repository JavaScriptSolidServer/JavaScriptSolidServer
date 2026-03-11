/**
 * MRC20 Token Management
 *
 * Create, manage, and transfer MRC20 tokens anchored to Bitcoin via blocktrails.
 * Uses BIP-341 key chaining to derive unique taproot addresses for each state.
 *
 * Trail state stored at: {DATA_ROOT}/.well-known/token/{ticker}.json
 *
 * References:
 *   - Blocktrails: https://blocktrails.org/
 *   - BIP-341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
 */

import crypto from 'crypto';
import fs from 'fs-extra';
import path from 'path';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { jcs, sha256Hex, btAddress } from './mrc20.js';

// --- Constants ---
const SECP_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const MRC20_PROFILE = 'mono.mrc20.v0.1';

// --- Byte helpers ---
function hexToU8(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function bytesToBigInt(bytes) {
  let r = 0n;
  for (const b of bytes) r = (r << 8n) | BigInt(b);
  return r;
}
function bigIntToBytes(n) {
  return hexToU8(n.toString(16).padStart(64, '0'));
}
function concatBytes(...arrays) {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { result.set(a, off); off += a.length; }
  return result;
}

// --- Serialization helpers ---
function writeU32LE(val) {
  const b = new Uint8Array(4);
  b[0] = val & 0xff; b[1] = (val >> 8) & 0xff; b[2] = (val >> 16) & 0xff; b[3] = (val >> 24) & 0xff;
  return b;
}
function writeU64LE(val) {
  const b = new Uint8Array(8);
  const n = BigInt(val);
  for (let i = 0; i < 8; i++) b[i] = Number((n >> BigInt(i * 8)) & 0xffn);
  return b;
}
function writeVarInt(val) {
  if (val < 0xfd) return new Uint8Array([val]);
  if (val <= 0xffff) return new Uint8Array([0xfd, val & 0xff, (val >> 8) & 0xff]);
  throw new Error('VarInt too large');
}
function reverseTxid(txidHex) {
  const bytes = hexToU8(txidHex);
  bytes.reverse();
  return bytes;
}

// --- Crypto ---
function sha256Bytes(data) {
  const buf = data instanceof Uint8Array ? Buffer.from(data) : Buffer.from(data, 'utf8');
  return new Uint8Array(crypto.createHash('sha256').update(buf).digest());
}
function taggedHash(tag, ...msgs) {
  const tagHash = sha256Bytes(Buffer.from(tag, 'utf8'));
  return sha256Bytes(concatBytes(tagHash, tagHash, ...msgs));
}

// --- BIP-341 key chaining ---
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

function btDeriveChainedPrivkey(privkeyBytes, states) {
  let d = bytesToBigInt(privkeyBytes);
  let cur = new Uint8Array(secp256k1.getPublicKey(privkeyBytes, true));
  for (const s of states) {
    const t = btScalar(cur, s);
    d = (d + t) % SECP_N;
    cur = new Uint8Array(secp256k1.ProjectivePoint.BASE.multiply(d).toRawBytes(true));
  }
  return bigIntToBytes(d);
}

function p2trScript(xonly) {
  return concatBytes(new Uint8Array([0x51, 0x20]), xonly);
}

// --- Bitcoin transaction building ---
function buildTransaction(inputs, outputs, privkeyBytes) {
  const internalXOnly = new Uint8Array(secp256k1.getPublicKey(privkeyBytes, true)).slice(1);
  const untweakedHex = '5120' + bytesToHex(internalXOnly);
  const needsTweak = bytesToHex(inputs[0].scriptPubKey) !== untweakedHex;
  let signingKey = privkeyBytes;
  if (needsTweak) {
    const tweak = taggedHash('TapTweak', internalXOnly);
    const t = bytesToBigInt(tweak);
    let d = bytesToBigInt(privkeyBytes);
    const fullPub = secp256k1.getPublicKey(privkeyBytes, false);
    if (fullPub[64] & 1) d = SECP_N - d;
    signingKey = bigIntToBytes((d + t) % SECP_N);
  }

  const version = 2, locktime = 0, sequence = 0xfffffffd;
  const serOutputs = outputs.map(o =>
    concatBytes(writeU64LE(o.amount), writeVarInt(o.scriptPubKey.length), o.scriptPubKey)
  );

  const shaPrevouts = sha256Bytes(concatBytes(...inputs.map(i =>
    concatBytes(reverseTxid(i.txid), writeU32LE(i.vout))
  )));
  const shaAmounts = sha256Bytes(concatBytes(...inputs.map(i => writeU64LE(i.amount))));
  const shaScriptPubKeys = sha256Bytes(concatBytes(...inputs.map(i =>
    concatBytes(writeVarInt(i.scriptPubKey.length), i.scriptPubKey)
  )));
  const shaSequences = sha256Bytes(concatBytes(...inputs.map(() => writeU32LE(sequence))));
  const shaOutputs = sha256Bytes(concatBytes(...serOutputs));

  const sigs = [];
  for (let i = 0; i < inputs.length; i++) {
    const sigMsg = concatBytes(
      new Uint8Array([0x00, 0x00]),
      writeU32LE(version), writeU32LE(locktime),
      shaPrevouts, shaAmounts, shaScriptPubKeys, shaSequences, shaOutputs,
      new Uint8Array([0x00]),
      writeU32LE(i)
    );
    const sighash = taggedHash('TapSighash', sigMsg);
    sigs.push(schnorr.sign(sighash, signingKey));
  }

  const parts = [
    writeU32LE(version),
    new Uint8Array([0x00, 0x01]),
    writeVarInt(inputs.length)
  ];
  for (const inp of inputs) {
    parts.push(reverseTxid(inp.txid), writeU32LE(inp.vout), new Uint8Array([0x00]), writeU32LE(sequence));
  }
  parts.push(writeVarInt(outputs.length));
  for (const so of serOutputs) parts.push(so);
  for (const sig of sigs) {
    parts.push(new Uint8Array([0x01]), writeVarInt(sig.length), sig);
  }
  parts.push(writeU32LE(locktime));
  return bytesToHex(concatBytes(...parts));
}

async function broadcastTx(rawTxHex, mempoolUrl) {
  const res = await fetch(`${mempoolUrl}/api/tx`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: rawTxHex
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Broadcast failed: ${err}`);
  }
  return res.text();
}

// --- Trail persistence ---
function trailDir() {
  return path.join(process.env.DATA_ROOT || './data', '.well-known', 'token');
}

function trailPath(ticker) {
  return path.join(trailDir(), `${ticker.toLowerCase()}.json`);
}

export async function loadTrail(ticker) {
  try {
    const data = await fs.readFile(trailPath(ticker), 'utf8');
    return JSON.parse(data);
  } catch { return null; }
}

async function saveTrail(trail) {
  await fs.ensureDir(trailDir());
  await fs.writeFile(trailPath(trail.ticker), JSON.stringify(trail, null, 2));
}

export async function listTrails() {
  try {
    const files = await fs.readdir(trailDir());
    const trails = [];
    for (const f of files) {
      if (f.endsWith('.json')) {
        const data = await fs.readFile(path.join(trailDir(), f), 'utf8');
        trails.push(JSON.parse(data));
      }
    }
    return trails;
  } catch { return []; }
}

// --- TXO URI parsing ---
export function parseTxoUri(uri) {
  // txo:btc:txid:vout?amount=N&key=hex
  const match = uri.match(/(?:txo:btc:)?([0-9a-f]{64}):(\d+)\?amount=(\d+)&key=([0-9a-f]{64})/i);
  if (!match) throw new Error('Invalid TXO URI format');
  return {
    txid: match[1],
    vout: parseInt(match[2], 10),
    amount: parseInt(match[3], 10),
    privkey: match[4]
  };
}

// --- Mint: create genesis MRC20 token ---
export async function mintToken({ ticker, name, supply, voucher, mempoolUrl = 'https://mempool.space/testnet4', network = 'testnet4' }) {
  const txo = parseTxoUri(voucher);
  const privkeyBytes = hexToU8(txo.privkey);
  const pubkeyBase = new Uint8Array(secp256k1.getPublicKey(privkeyBytes, true));
  const pubkeyBaseHex = bytesToHex(pubkeyBase);

  // Check if token already exists
  const existing = await loadTrail(ticker);
  if (existing) throw new Error(`Token ${ticker} already exists`);

  // Create genesis MRC20 state
  const genesisState = {
    profile: MRC20_PROFILE,
    prev: '0'.repeat(64),
    seq: 0,
    ticker,
    name: name || ticker,
    decimals: 0,
    supply,
    balances: { [pubkeyBaseHex]: supply },
    ops: []
  };
  const genesisJcs = jcs(genesisState);

  // Derive genesis taproot address
  const genesisP = btDeriveChainedPubkey(pubkeyBase, [genesisJcs]);
  const genesisXonly = genesisP.slice(1);
  const genesisScript = p2trScript(genesisXonly);
  const genesisAddr = btAddress(pubkeyBaseHex, [genesisJcs], network);

  // Fetch voucher scriptPubKey
  const txResp = await fetch(`${mempoolUrl}/api/tx/${txo.txid}`);
  if (!txResp.ok) throw new Error('Could not fetch voucher transaction');
  const txData = await txResp.json();
  const prevOut = txData.vout?.[txo.vout];
  if (!prevOut) throw new Error(`Voucher output ${txo.vout} not found`);
  const scriptPubKey = hexToU8(prevOut.scriptpubkey);

  // Build and broadcast genesis tx
  const fee = 300;
  const outputAmount = txo.amount - fee;
  if (outputAmount <= 546) throw new Error('Voucher too small for fee');

  const rawTx = buildTransaction(
    [{ txid: txo.txid, vout: txo.vout, amount: txo.amount, scriptPubKey }],
    [{ amount: outputAmount, scriptPubKey: genesisScript }],
    privkeyBytes
  );
  const newTxid = await broadcastTx(rawTx, mempoolUrl);

  // Save trail
  const trail = {
    ticker,
    name: name || ticker,
    supply,
    privkey: txo.privkey,
    pubkeyBase: pubkeyBaseHex,
    states: [genesisState],
    stateStrings: [genesisJcs],
    currentTxid: newTxid,
    currentVout: 0,
    currentAmount: outputAmount,
    network,
    dateCreated: new Date().toISOString()
  };
  await saveTrail(trail);

  return { trail, txid: newTxid, address: genesisAddr };
}

// --- Transfer: send tokens to an address ---
export async function transferToken({ ticker, to, amount, mempoolUrl = 'https://mempool.space/testnet4' }) {
  const trail = await loadTrail(ticker);
  if (!trail) throw new Error(`Token ${ticker} not found`);

  const privkeyBytes = hexToU8(trail.privkey);
  const pubkeyBase = hexToU8(trail.pubkeyBase);

  // Get current state
  const currentState = trail.states[trail.states.length - 1];
  const currentBalances = { ...currentState.balances };

  // Check issuer balance
  const issuerAddr = trail.pubkeyBase;
  const issuerBalance = currentBalances[issuerAddr] || 0;
  if (issuerBalance < amount) {
    throw new Error(`Insufficient balance: ${issuerBalance} < ${amount}`);
  }

  // Create transfer state
  currentBalances[issuerAddr] = issuerBalance - amount;
  currentBalances[to] = (currentBalances[to] || 0) + amount;
  // Remove zero balances
  for (const [k, v] of Object.entries(currentBalances)) {
    if (v === 0) delete currentBalances[k];
  }

  const prevJcs = trail.stateStrings[trail.stateStrings.length - 1];
  const newState = {
    profile: MRC20_PROFILE,
    prev: sha256Hex(prevJcs),
    seq: currentState.seq + 1,
    ticker: trail.ticker,
    name: trail.name,
    decimals: 0,
    supply: trail.supply,
    balances: currentBalances,
    ops: [{ op: 'urn:mono:op:transfer', from: issuerAddr, to, amt: amount }]
  };
  const newJcs = jcs(newState);

  // Derive new address
  const allStateStrings = [...trail.stateStrings, newJcs];
  const newP = btDeriveChainedPubkey(pubkeyBase, allStateStrings);
  const newXonly = newP.slice(1);
  const newScript = p2trScript(newXonly);
  const newAddr = btAddress(trail.pubkeyBase, allStateStrings, trail.network);

  // Fetch current UTXO scriptPubKey
  const txResp = await fetch(`${mempoolUrl}/api/tx/${trail.currentTxid}`);
  if (!txResp.ok) throw new Error('Could not fetch current transaction');
  const txData = await txResp.json();
  const prevOut = txData.vout?.[trail.currentVout];
  if (!prevOut) throw new Error('Current UTXO not found');
  const scriptPubKey = hexToU8(prevOut.scriptpubkey);

  // Derive chained privkey for signing
  const chainedPriv = btDeriveChainedPrivkey(privkeyBytes, trail.stateStrings);

  // Build and broadcast
  const fee = 300;
  const outputAmount = trail.currentAmount - fee;
  if (outputAmount <= 546) throw new Error('Trail UTXO too small for fee');

  const rawTx = buildTransaction(
    [{ txid: trail.currentTxid, vout: trail.currentVout, amount: trail.currentAmount, scriptPubKey }],
    [{ amount: outputAmount, scriptPubKey: newScript }],
    chainedPriv
  );
  const newTxid = await broadcastTx(rawTx, mempoolUrl);

  // Update trail
  trail.states.push(newState);
  trail.stateStrings.push(newJcs);
  trail.currentTxid = newTxid;
  trail.currentVout = 0;
  trail.currentAmount = outputAmount;
  await saveTrail(trail);

  return { trail, txid: newTxid, address: newAddr, state: newState, prevState: currentState };
}

// --- Info: show token state ---
export async function tokenInfo(ticker) {
  const trail = await loadTrail(ticker);
  if (!trail) throw new Error(`Token ${ticker} not found`);

  const currentState = trail.states[trail.states.length - 1];
  const currentAddr = btAddress(trail.pubkeyBase, trail.stateStrings, trail.network);

  return {
    ticker: trail.ticker,
    name: trail.name,
    supply: trail.supply,
    seq: currentState.seq,
    balances: currentState.balances,
    pubkeyBase: trail.pubkeyBase,
    currentTxid: trail.currentTxid,
    currentAddress: currentAddr,
    currentAmount: trail.currentAmount,
    network: trail.network,
    stateCount: trail.states.length,
    dateCreated: trail.dateCreated
  };
}
