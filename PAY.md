# PAY.md — HTTP 402 Payment System

## What This Is

JSS has a built-in payment system. Resources under `/pay/*` cost satoshis to access. Users authenticate with a Nostr key, deposit sats, and spend them on API requests. Optionally, the pod mints its own token (MRC20 on Bitcoin) that users can buy, sell, and trade.

## Architecture

```
User (Nostr keypair)
  │
  ├── POST /pay/.deposit   → credit sat balance (multi-chain: txo:tbtc3:, txo:tbtc4:, etc.)
  ├── GET  /pay/.balance   → check balance (includes per-chain balances)
  ├── GET  /pay/*          → spend 1 sat, get resource
  ├── POST /pay/.buy       → spend sats, get tokens (Bitcoin TX)
  ├── POST /pay/.withdraw  → spend balance, get tokens back
  ├── POST /pay/.sell      → list tokens for sale
  ├── POST /pay/.swap      → buy someone's sell order
  ├── GET  /pay/.pool      → AMM pool state (multi-chain)
  └── POST /pay/.pool      → AMM: swap, add-liquidity, remove-liquidity
```

All state lives in two places:
- **Webledger** — `/.well-known/webledgers/webledgers.json` — sat balances per `did:nostr:<pubkey>`
- **Token trail** — `/.well-known/token/<ticker>.json` — MRC20 state chain anchored to Bitcoin

## Authentication

Every request to `/pay/*` (except `.info` and `.offers`) requires a NIP-98 auth header:

```
Authorization: Nostr <base64-encoded-signed-event>
```

The event is kind 27235 with tags `["u", "<url>"]` and `["method", "<METHOD>"]`, signed with the user's Nostr private key. The server extracts the pubkey and maps it to `did:nostr:<pubkey>` for balance lookup.

## Endpoints

### GET /pay/.info
**Public. No auth required.**

Returns pod payment configuration.

Response:
```json
{
  "cost": 1,
  "unit": "sat",
  "deposit": "/pay/.deposit",
  "balance": "/pay/.balance",
  "token": {
    "ticker": "PODS",
    "rate": 10,
    "buy": "/pay/.buy",
    "withdraw": "/pay/.withdraw",
    "supply": 10000,
    "issuer": "025e60b6..."
  }
}
```

The `token` field is only present when `--pay-token` is configured. `rate` is sats per token.

When `--pay-chains` is configured, the response also includes:
```json
{
  "chains": [
    { "id": "tbtc3", "unit": "tbtc3", "name": "Bitcoin Testnet3" },
    { "id": "tbtc4", "unit": "tbtc4", "name": "Bitcoin Testnet4" }
  ],
  "pool": "/pay/.pool"
}
```

### GET /pay/.balance
**Requires NIP-98 auth.**

Returns the caller's sat balance.

Response:
```json
{
  "did": "did:nostr:4fa459ad...",
  "balance": 1041588,
  "cost": 1,
  "unit": "sat"
}
```

### POST /pay/.deposit
**Requires NIP-98 auth.**

Credits the caller's balance. Two deposit types:

**Sats (TXO URI):**
```
POST /pay/.deposit
Content-Type: text/plain
Body: <txid>:<vout>
```

The server calls the mempool API to verify the UTXO exists and reads its value. The sat amount is credited to the caller's webledger balance.

**MRC20 tokens (state proof):**
```json
POST /pay/.deposit
Content-Type: application/json
{
  "type": "mrc20",
  "state": { ... },
  "prevState": { ... },
  "anchor": {
    "pubkey": "<issuer-compressed-pubkey>",
    "stateStrings": ["<jcs-of-each-state>"],
    "network": "testnet4"
  }
}
```

The server verifies: state chain integrity (`state.prev == SHA256(JCS(prevState))`), transfer to the pod's `payAddress`, and optionally anchor verification (derives expected taproot address from pubkey + state chain, checks mempool for UTXO). Replay protection rejects duplicate state hashes.

### POST /pay/.buy
**Requires NIP-98 auth. Requires `--pay-token` configured.**

Buy tokens from the pod at the configured `payRate` (sats per token).

Request (pick one):
```json
{ "amount": 100 }       // buy 100 tokens
{ "sats": 1000 }        // spend 1000 sats worth
```

The server:
1. Checks caller's sat balance >= cost
2. Loads the pod's MRC20 token trail
3. Calls `transferToken()` — creates a new MRC20 state transferring tokens to the buyer's pubkey, derives a new taproot address via BIP-341 key chaining, builds and broadcasts a Bitcoin transaction
4. Debits sats from caller's webledger balance

Response includes a portable proof:
```json
{
  "bought": 100,
  "ticker": "PODS",
  "cost": 1000,
  "rate": 10,
  "balance": 1040588,
  "txid": "c3183f41...",
  "proof": {
    "state": { ... },
    "prevState": { ... },
    "anchor": {
      "pubkey": "025e60b6...",
      "stateStrings": ["<jcs>", "<jcs>"],
      "network": "testnet4"
    }
  }
}
```

The proof is independently verifiable: anyone can derive the expected taproot address from the pubkey + stateStrings and check the Bitcoin UTXO.

### POST /pay/.withdraw
**Requires NIP-98 auth. Requires `--pay-token` configured.**

Convert sat balance back to portable tokens. Same mechanism as buy.

Request (pick one):
```json
{ "tokens": 50 }        // withdraw 50 tokens
{ "sats": 500 }         // withdraw 500 sats worth
{ "all": true }         // drain entire balance
```

Response is identical to buy, with `"withdrawn"` instead of `"bought"`.

### GET /pay/.offers
**Public. No auth required.**

Returns open sell orders from the secondary market.

Response:
```json
[
  {
    "id": "uuid",
    "seller": "<pubkey>",
    "ticker": "PODS",
    "amount": 100,
    "price": 1500,
    "rate": 15,
    "status": "pending",
    "created": 1773259044534
  }
]
```

### POST /pay/.sell
**Requires NIP-98 auth. Requires `--pay-token` configured.**

Create a sell order. The seller must have tokens on the pod's MRC20 trail.

Request:
```json
{
  "amount": 100,
  "price": 1500
}
```

`amount` = tokens to sell, `price` = total sats asked. The server verifies the seller's token balance on the trail before creating the order.

### POST /pay/.swap
**Requires NIP-98 auth. Requires `--pay-token` configured.**

Execute a swap against an open sell order.

Request:
```json
{ "id": "<offer-uuid>" }
```

The server:
1. Finds the pending offer
2. Checks buyer's sat balance >= offer price
3. Transfers tokens from seller to buyer on the MRC20 trail (Bitcoin TX)
4. Debits buyer's sats, credits seller's sats on the webledger
5. Marks offer as filled

Response includes the portable proof, same as buy.

### GET /pay/*
**Requires NIP-98 auth.**

Access a paid resource. The server deducts `cost` sats from the caller's balance. If balance < cost, returns 402:

```json
{
  "error": "Payment Required",
  "balance": 0,
  "cost": 1,
  "unit": "sat",
  "deposit": "/pay/.deposit"
}
```

On success, the resource is served normally with headers:
```
X-Balance: 1040587
X-Cost: 1
```

### PUT /pay/*

Standard upload — goes through normal WAC auth, not the pay middleware. Only the pod owner can write to `/pay/`.

## Configuration

### CLI flags
```
--pay                    Enable HTTP 402 for /pay/* routes
--pay-cost <n>           Cost per request in satoshis (default: 1)
--pay-mempool-url <url>  Mempool API URL (default: testnet4)
--pay-address <addr>     Address for receiving MRC20 deposits
--pay-token <ticker>     Token ticker (enables buy/withdraw/sell/swap)
--pay-rate <n>           Sats per token for buy/withdraw (default: 1)
```

### Environment variables
```
JSS_PAY=true
JSS_PAY_COST=1
JSS_PAY_MEMPOOL_URL=https://mempool.space/testnet4
JSS_PAY_ADDRESS=tb1q...
JSS_PAY_TOKEN=PODS
JSS_PAY_RATE=10
```

## Token Management (CLI)

```bash
# Mint a new token (requires funded Bitcoin UTXO)
jss token mint --ticker PODS --supply 10000 \
  --voucher "txo:btc:<txid>:<vout>?amount=<sats>&key=<privkey-hex>"

# Transfer tokens
jss token transfer --ticker PODS --to <pubkey> --amount 100

# Show token info
jss token info PODS
```

## Data Files

| File | Contents |
|------|----------|
| `/.well-known/webledgers/webledgers.json` | Balances per DID — multi-currency array format (webledgers.org spec) |
| `/.well-known/webledgers/replay.json` | Seen MRC20 state hashes (replay protection) |
| `/.well-known/webledgers/offers.json` | Open sell orders (secondary market) |
| `/.well-known/webledgers/pool.json` | AMM pool state (reserves, LP shares, k) |
| `/.well-known/token/<ticker>.json` | MRC20 token trail (state chain, keys, UTXO) |

## Source Files

| File | Purpose |
|------|---------|
| `src/handlers/pay.js` | All `/pay/*` route handling |
| `src/webledger.js` | Balance read/write/credit/debit |
| `src/mrc20.js` | MRC20 verification, JCS, BIP-341 key chaining, bech32m |
| `src/token.js` | Token mint/transfer, Bitcoin TX building, trail persistence |
| `src/auth/nostr.js` | NIP-98 auth extraction |

## Key Concepts

**Webledger**: A JSON file mapping URIs to numerical balances, following the [webledgers.org](https://webledgers.org/) spec. The URI format is `did:nostr:<pubkey>`.

**MRC20**: A token profile on blocktrails. Each state is a JSON object with `profile`, `prev` (hash link to previous state), `seq`, `ticker`, `balances`, and `ops`. States form a hash chain.

**BIP-341 Key Chaining**: Each MRC20 state is hashed and used as a taproot tweak scalar. The scalar is added to the issuer's public key via elliptic curve addition to derive a unique P2TR address per state. This anchors the state chain to Bitcoin — anyone can verify by re-deriving the address and checking the UTXO.

**JCS (RFC 8785)**: JSON Canonicalization Scheme — sorted keys, no whitespace, deterministic serialization. Used for hashing states.

**NIP-98**: Nostr HTTP Authentication. A signed event (kind 27235) with the request URL and method in tags, base64-encoded in the Authorization header.

**NIP-69 (kind 38383)**: P2P order events for trading. Used as the convention for sell orders in the secondary market.

## Flow Examples

### Agent buys API access
```
1. Agent has a funded TXO (Bitcoin UTXO with known private key)
2. GET  /pay/.info           → learns cost=1, deposit endpoint
3. POST /pay/.deposit        → posts TXO URI, gets 1M sats credited
4. GET  /pay/data/feed.json  → costs 1 sat, returns data
5. (repeat step 4 up to 1M times)
```

### User buys and trades tokens
```
1. POST /pay/.deposit        → deposit sats
2. POST /pay/.buy            → buy 100 PODS for 1000 sats, get Bitcoin proof
3. POST /pay/.sell           → list 50 PODS for sale at 750 sats
4. (another user)
5. GET  /pay/.offers         → sees the sell order
6. POST /pay/.swap           → buys the 50 PODS, seller gets 750 sats credited
```

### Cross-chain AMM trading
```
1. Configure pod:  jss start --pay --pay-chains "tbtc3,tbtc4"
2. User A deposits: POST /pay/.deposit "txo:tbtc3:<txid>:<vout>" → gets tbtc3 balance
3. User B deposits: POST /pay/.deposit "txo:tbtc4:<txid>:<vout>" → gets tbtc4 balance
4. User A adds liquidity: POST /pay/.pool { "action": "add-liquidity", "tbtc3": 1000, "tbtc4": 5000 }
5. User B swaps: POST /pay/.pool { "action": "swap", "sell": "tbtc4", "amount": 500 }
   → receives ~90 tbtc3 (constant product formula, 0.3% fee)
6. User A removes liquidity: POST /pay/.pool { "action": "remove-liquidity", "all": true }
   → gets back proportional share of both currencies + earned fees
```

### Full exit
```
1. POST /pay/.withdraw { "all": true }  → converts entire balance to portable tokens
2. User now holds MRC20 proof, independently verifiable on Bitcoin
3. Can deposit on another pod, or trade peer-to-peer
```
