## HTTP 402 Paid Access

JSS supports two approaches to paid content:

1. **ACL Conditions** — any resource at any URL can require payment via `acl:condition` in its ACL file
2. **Pay Route** — the `/pay/*` prefix provides a full payment backend with deposits, balances, and token trading

### ACL-Based Payments (Generic)

Any resource can be payment-gated by adding a `PaymentCondition` to its ACL:

```json
{
  "@context": { "acl": "http://www.w3.org/ns/auth/acl#" },
  "@graph": [{
    "@type": "acl:Authorization",
    "acl:agentClass": { "@id": "acl:AuthenticatedAgent" },
    "acl:accessTo": { "@id": "/premium/article.jsonld" },
    "acl:mode": [{ "@id": "acl:Read" }],
    "acl:condition": {
      "@type": "PaymentCondition",
      "amount": "1000",
      "currency": "sats"
    }
  }]
}
```

When a client requests the resource:

1. Server evaluates the ACL and finds the `PaymentCondition`
2. Server checks the agent's balance in the webledger
3. If balance >= cost — deducts and serves the resource (200)
4. If balance < cost — responds with `402 Payment Required` and payment details

To fund their balance, users deposit via the `/pay/.deposit` endpoint using a TXO URI (currently testnet4 for development). The balance is tracked in the webledger at `/.well-known/webledgers/webledgers.json`.

**Design: fail-closed** — if the server encounters a condition type it doesn't support, access is denied. Unsupported conditions are never silently ignored.

#### Quick Demo

```bash
# Start JSS with payments (testnet4 by default)
jss start --pay --pay-cost 10

# Create an article and payment-gated ACL
curl -X PUT http://localhost:3000/premium/article.jsonld \
  -H "Content-Type: application/ld+json" \
  -d '{"@type": "Article", "headline": "Premium Content"}'

curl -X PUT http://localhost:3000/premium/article.jsonld.acl \
  -H "Content-Type: application/ld+json" \
  -d '{"@context":{"acl":"http://www.w3.org/ns/auth/acl#"},"@graph":[{"@type":"acl:Authorization","acl:agent":{"@id":"did:nostr:YOUR_PUBKEY"},"acl:accessTo":{"@id":"/premium/article.jsonld"},"acl:mode":[{"@id":"acl:Read"}],"acl:condition":{"@type":"PaymentCondition","amount":"10","currency":"sats"}}]}'

# Try to read → 402 Payment Required
curl -H "Authorization: Nostr <nip98-token>" http://localhost:3000/premium/article.jsonld

# Deposit testnet4 sats
curl -X POST -H "Authorization: Nostr <nip98-token>" \
  http://localhost:3000/pay/.deposit -d 'txo:tbtc4:txid:vout'

# Try again → 200 OK + article
curl -H "Authorization: Nostr <nip98-token>" http://localhost:3000/premium/article.jsonld
```

### Pay Route (Full Backend)

Monetize API endpoints with per-request satoshi payments. Resources under `/pay/*` require NIP-98 authentication and a positive balance.

```bash
jss start --pay --pay-cost 10 --pay-address your-address --pay-token PODS --pay-rate 10
```

### Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/pay/.info` | Public: cost, token info, chains, pool |
| GET | `/pay/.balance` | Check your balance (NIP-98 auth) |
| POST | `/pay/.deposit` | Deposit sats via TXO URI or MRC20 state proof |
| POST | `/pay/.buy` | Buy tokens with sat balance (requires `--pay-token`) |
| POST | `/pay/.withdraw` | Withdraw balance as portable tokens (requires `--pay-token`) |
| GET | `/pay/.offers` | List open sell orders (secondary market) |
| POST | `/pay/.sell` | Create a sell order (requires `--pay-token`) |
| POST | `/pay/.swap` | Execute a swap against a sell order |
| GET | `/pay/.pool` | AMM pool state (requires `--pay-chains`) |
| POST | `/pay/.pool` | AMM swap, add/remove liquidity |
| GET | `/pay/*` | Paid resource access (deducts balance) |

### How It Works

1. Authenticate with NIP-98 (Nostr HTTP Auth)
2. Check balance at `/pay/.balance`
3. Deposit sats by POSTing a TXO URI to `/pay/.deposit`
4. Access paid resources — each request deducts the configured cost
5. Optionally buy tokens (`/pay/.buy`) or withdraw as portable tokens (`/pay/.withdraw`)
6. Balance tracked in a [Web Ledger](https://webledgers.org/) at `/.well-known/webledgers/webledgers.json`

### Example

```bash
# Check balance
curl -H "Authorization: Nostr <base64-event>" http://localhost:3000/pay/.balance

# Deposit (post a confirmed transaction output)
curl -X POST -H "Authorization: Nostr <base64-event>" \
  http://localhost:3000/pay/.deposit \
  -d "txid:vout"

# Access paid resource
curl -H "Authorization: Nostr <base64-event>" http://localhost:3000/pay/my-resource

# Buy tokens with sat balance
curl -X POST -H "Authorization: Nostr <base64-event>" \
  -H "Content-Type: application/json" \
  http://localhost:3000/pay/.buy \
  -d '{"amount": 100}'

# Withdraw entire balance as portable tokens
curl -X POST -H "Authorization: Nostr <base64-event>" \
  -H "Content-Type: application/json" \
  http://localhost:3000/pay/.withdraw \
  -d '{"all": true}'
```

Deposit verification uses the mempool API (default: testnet4). The `X-Balance` and `X-Cost` headers are returned on successful paid requests. Buy and withdraw return portable MRC20 proofs with Bitcoin anchor data for independent verification.

### Secondary Market

Users can trade tokens peer-to-peer through the pod. Sell orders are created via `/pay/.sell` and filled via `/pay/.swap`. The pod acts as escrow — transferring tokens on the Bitcoin-anchored MRC20 trail and settling sats in the webledger.

### Multi-Chain AMM

Enable multi-chain deposits and an automated market maker:

```bash
jss start --pay --pay-chains "tbtc3,tbtc4"
```

Deposits detect the chain from the TXO URI prefix (`txo:tbtc3:txid:vout`). Each chain's balance is tracked separately. The AMM uses a constant-product formula (x × y = k) with a 0.3% fee.

```bash
# Add liquidity
curl -X POST -H "Authorization: Nostr <token>" \
  -H "Content-Type: application/json" \
  http://localhost:3000/pay/.pool \
  -d '{"action": "add-liquidity", "tbtc3": 1000, "tbtc4": 5000}'

# Swap
curl -X POST -H "Authorization: Nostr <token>" \
  -H "Content-Type: application/json" \
  http://localhost:3000/pay/.pool \
  -d '{"action": "swap", "sell": "tbtc3", "amount": 100}'

# Check pool state
curl http://localhost:3000/pay/.pool
```

Supported chains: `btc`, `tbtc3`, `tbtc4`, `ltc`, `signet`.
