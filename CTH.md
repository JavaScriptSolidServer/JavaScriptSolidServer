# Running Solid Conformance Test Harness (CTH)

Step-by-step instructions for running the Solid Conformance Test Harness against this server.

## Prerequisites

- Node.js 18+
- Docker
- Port 4000 available

## Quick Start

```bash
# 1. Kill any existing server on port 4000
fuser -k 4000/tcp 2>/dev/null || true

# 2. Clean data directory
rm -rf data && mkdir data

# 3. Start server with IdP and content negotiation
JSS_PORT=4000 JSS_CONNEG=true JSS_IDP=true node bin/jss.js start &

# 4. Wait for server to be ready
sleep 3
curl -s http://localhost:4000/ > /dev/null && echo "Server ready"

# 5. Create test users
curl -s -X POST http://localhost:4000/.pods \
  -H "Content-Type: application/json" \
  -d '{"name": "alice", "email": "alice@example.com", "password": "alicepassword123"}'

curl -s -X POST http://localhost:4000/.pods \
  -H "Content-Type: application/json" \
  -d '{"name": "bob", "email": "bob@example.com", "password": "bobpassword123"}'

# 6. Create test container (required by CTH)
mkdir -p data/alice/cth-test

# 7. Run authentication tests
docker run --rm --network=host \
  -v /tmp/cth-test-subjects.ttl:/app/test-subjects.ttl \
  -e SOLID_IDENTITY_PROVIDER="http://localhost:4000/" \
  -e USERS_ALICE_WEBID="http://localhost:4000/alice/#me" \
  -e USERS_ALICE_USERNAME="alice@example.com" \
  -e USERS_ALICE_PASSWORD="alicepassword123" \
  -e USERS_BOB_WEBID="http://localhost:4000/bob/#me" \
  -e USERS_BOB_USERNAME="bob@example.com" \
  -e USERS_BOB_PASSWORD="bobpassword123" \
  -e SUBJECTS=/app/test-subjects.ttl \
  solidproject/conformance-test-harness:latest \
  --target="https://github.com/solid/conformance-test-harness/jss" \
  --filter="authentication"
```

## Configuration Files

### Test Subjects File (test-subjects.ttl)

Create `/tmp/cth-test-subjects.ttl`:

```turtle
@prefix solid-test: <https://github.com/solid/conformance-test-harness/vocab#> .
@prefix td: <http://www.w3.org/2006/03/test-description#> .

<https://github.com/solid/conformance-test-harness/jss>
  a solid-test:TestSubject ;
  solid-test:skip "wac-allow-public", "wac", "acp" ;
  td:maintainer <https://github.com/JavaScriptSolidServer> .
```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SOLID_IDENTITY_PROVIDER` | IdP issuer URL (with trailing slash) | `http://localhost:4000/` |
| `USERS_ALICE_WEBID` | Alice's WebID | `http://localhost:4000/alice/#me` |
| `USERS_ALICE_USERNAME` | Alice's email | `alice@example.com` |
| `USERS_ALICE_PASSWORD` | Alice's password | `alicepassword123` |
| `USERS_BOB_WEBID` | Bob's WebID | `http://localhost:4000/bob/#me` |
| `USERS_BOB_USERNAME` | Bob's email | `bob@example.com` |
| `USERS_BOB_PASSWORD` | Bob's password | `bobpassword123` |
| `SUBJECTS` | Path to test-subjects.ttl | `/app/test-subjects.ttl` |

## Running Specific Test Suites

### Authentication Tests (6 scenarios)

```bash
docker run --rm --network=host \
  --env-file cth.env \
  -v /tmp/cth-test-subjects.ttl:/app/test-subjects.ttl \
  -e SUBJECTS=/app/test-subjects.ttl \
  solidproject/conformance-test-harness:latest \
  --target="https://github.com/solid/conformance-test-harness/jss" \
  --filter="authentication"
```

**Expected result:** 6/6 scenarios passing

### All Protocol Tests

```bash
docker run --rm --network=host \
  --env-file cth.env \
  -v /tmp/cth-test-subjects.ttl:/app/test-subjects.ttl \
  -e SUBJECTS=/app/test-subjects.ttl \
  solidproject/conformance-test-harness:latest \
  --target="https://github.com/solid/conformance-test-harness/jss"
```

## Interpreting Results

### Success Output

```
scenarios:  6 | passed:  6 | failed:  0 | time: 0.6349
  MustFeatures  passed: 1, failed: 0
  MustScenarios passed: 6, failed: 0
```

### Failure Output

```
scenarios:  6 | passed:  4 | failed:  2 | time: 0.7952
Then status 401
status code was: 200, expected: 401, response time in milliseconds: 15
```

## Troubleshooting

### "Cannot get ACL url for root test container"

The test container doesn't exist. Create it:

```bash
mkdir -p data/alice/cth-test
```

### "Failed to read WebID Document" (401)

The WebID profile is not publicly readable. Check that the pod's ACL allows public read on the container itself (but not necessarily on children).

### "NullPointerException" during authentication

Usually means the IdP isn't returning proper responses. Check:
1. Server is running with `--idp` flag
2. Issuer URL has trailing slash
3. Users were created with email and password

### "DPoP htu mismatch"

URL mismatch in DPoP proof validation. Check that issuer URL doesn't have double slashes.

### Token format errors

Ensure the server returns JWT access tokens with:
- `aud: "solid"` claim
- 3-part JWT format (header.payload.signature)
- `webid` claim

## Environment File Template

Save as `cth.env`:

```bash
SOLID_IDENTITY_PROVIDER=http://localhost:4000/
USERS_ALICE_WEBID=http://localhost:4000/alice/#me
USERS_ALICE_USERNAME=alice@example.com
USERS_ALICE_PASSWORD=alicepassword123
USERS_BOB_WEBID=http://localhost:4000/bob/#me
USERS_BOB_USERNAME=bob@example.com
USERS_BOB_PASSWORD=bobpassword123
```

## Server Requirements for CTH

The server must support:

1. **Solid-OIDC Identity Provider**
   - OIDC discovery at `/.well-known/openid-configuration`
   - JWKS at `/.well-known/jwks.json`
   - Dynamic client registration at `/idp/reg`
   - Credentials endpoint at `/idp/credentials` (for programmatic login)

2. **DPoP Token Binding**
   - RS256 and ES256 algorithms
   - Proper `cnf.jkt` claim in tokens

3. **WWW-Authenticate Header**
   - 401 responses must include `WWW-Authenticate: DPoP realm="..."`

4. **Container Creation via PUT**
   - PUT to path ending with `/` creates container

5. **ACL Inheritance**
   - Children should NOT inherit public read by default
   - Only owner permissions should have `acl:default`

## Current CTH Status (v0.0.14)

| Test Suite | Status |
|------------|--------|
| Authentication | 6/6 passing |
| Protocol (other) | Not yet tested |
| WAC | Skipped |
| ACP | Skipped |
