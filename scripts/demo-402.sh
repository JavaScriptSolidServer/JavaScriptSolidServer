#!/bin/bash
# Demo: HTTP 402 Payment-Gated Article
# Requires: JSS running on localhost:4443 with --pay --pay-cost 10

BASE="http://localhost:4443"

echo "=== Setting up payment-gated article demo ==="

# 1. Create the premium article
echo "Creating premium article..."
curl -s -X PUT "$BASE/premium/article.jsonld" \
  -H "Content-Type: application/ld+json" \
  -d '{
    "@context": "https://schema.org",
    "@type": "Article",
    "headline": "The Future of Web Payments",
    "author": "Melvin Carvalho",
    "datePublished": "2026-03-26",
    "articleBody": "This premium article explains how HTTP 402 enables native web payments. The decentralised web finally has a business model. No Stripe. No PayPal. No app store taking 30%. Just HTTP status codes and Lightning invoices."
  }'

# 2. Create the ACL with PaymentCondition
echo "Creating payment-gated ACL..."
curl -s -X PUT "$BASE/premium/article.jsonld.acl" \
  -H "Content-Type: application/ld+json" \
  -d '{
    "@context": {
      "acl": "http://www.w3.org/ns/auth/acl#",
      "foaf": "http://xmlns.com/foaf/0.1/"
    },
    "@graph": [{
      "@id": "#paid",
      "@type": "acl:Authorization",
      "acl:agentClass": { "@id": "acl:AuthenticatedAgent" },
      "acl:accessTo": { "@id": "'$BASE'/premium/article.jsonld" },
      "acl:mode": [{ "@id": "acl:Read" }],
      "acl:condition": {
        "@type": "PaymentCondition",
        "amount": "10",
        "currency": "sats",
        "chain": "tbtc4"
      }
    }]
  }'

echo ""
echo "=== Demo ready ==="
echo ""
echo "1. Try accessing the article (should get 402):"
echo "   curl $BASE/premium/article.jsonld"
echo ""
echo "2. Deposit testnet4 sats:"
echo "   curl -X POST -H 'Authorization: Nostr <nip98-token>' $BASE/pay/.deposit -d 'txo:tbtc4:txid:vout'"
echo ""
echo "3. Try again (should get 200 + article):"
echo "   curl -H 'Authorization: Nostr <nip98-token>' $BASE/premium/article.jsonld"
