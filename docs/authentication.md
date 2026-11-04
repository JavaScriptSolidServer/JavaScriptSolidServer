# Authentication

### Simple Tokens (Development)

Use the token returned from pod creation:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:4443/alice/private/
```

### Built-in Identity Provider (v0.0.12+)

Enable the built-in Solid-OIDC Identity Provider:

```bash
jss start --idp
```

With IdP enabled, pod creation requires email and password:

```bash
curl -X POST http://localhost:4443/.pods \
  -H "Content-Type: application/json" \
  -d '{"name": "alice", "email": "alice@example.com", "password": "secret123"}'
```

Response:
```json
{
  "name": "alice",
  "webId": "http://localhost:4443/alice/#me",
  "podUri": "http://localhost:4443/alice/",
  "idpIssuer": "http://localhost:4443",
  "loginUrl": "http://localhost:4443/idp/auth"
}
```

OIDC Discovery: `/.well-known/openid-configuration`

### Programmatic Login (CTH Compatible)

For automated testing and scripts, use the credentials endpoint:

```bash
curl -X POST http://localhost:4443/idp/credentials \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123"}'
```

Response:
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "webid": "http://localhost:4443/alice/#me"
}
```

For DPoP-bound tokens (Solid-OIDC compliant), include a DPoP proof header.

#### Refreshing a token

`/idp/credentials` tokens expire after 3600s. To keep an active session
alive without re-sending the password, slide the token forward with a
**still-valid** token:

```bash
curl -X POST http://localhost:4443/idp/refresh \
  -H "Authorization: Bearer YOUR_CURRENT_TOKEN"
```

Returns the same shape as `/idp/credentials` (a fresh `access_token`,
`expires_in: 3600`, same `webid`). Clients should refresh **proactively** —
e.g. at ~80% of the TTL — so a session lasts as long as the app is in use;
an idle hour still ends it, preserving the short-TTL security posture.

Only tokens this IdP issued can be refreshed (the token is verified against
the server's own signing keys), and only within an absolute cap measured
from the original password grant — a refresh chain maxes out at 24h by
default, so a leaked token can't be renewed forever. Override the cap with
`createServer({ refreshMaxAge: <seconds> })`. `401 invalid_grant` means the
chain has aged out and the user must sign in again.

### Passkey Authentication (v0.0.77+)

Enable passwordless login with WebAuthn/FIDO2:

```bash
jss start --idp
```

**How it works:**
1. User logs in with username/password
2. Prompted to add a passkey (Touch ID, Face ID, security key)
3. Future logins: tap "Sign in with Passkey" → biometric → done!

**Benefits:**
- Phishing-resistant (bound to domain)
- No passwords to remember or leak
- Works on mobile and desktop

Passkeys are stored per-account and work across devices via platform sync (iCloud Keychain, Google Password Manager, etc.).

### Schnorr SSO (v0.0.79+)

Sign in with your Nostr key using NIP-07 browser extensions:

```bash
jss start --idp
```

**How it works:**
1. User clicks "Sign in with Schnorr" on the login page
2. NIP-07 extension (Podkey, nos2x, Alby) signs a NIP-98 auth event
3. Server verifies BIP-340 Schnorr signature
4. User authenticated via linked did:nostr identity

**Requirements:**
- Account must have a `did:nostr:<pubkey>` WebID linked
- User needs a NIP-07 compatible browser extension

**Benefits:**
- No passwords - cryptographic authentication
- Works with existing Nostr identity
- Single sign-on across Solid and Nostr ecosystems

### Solid-OIDC (External IdP)

The server also accepts DPoP-bound access tokens from external Solid identity providers:

```bash
curl -H "Authorization: DPoP ACCESS_TOKEN" \
     -H "DPoP: DPOP_PROOF" \
     http://localhost:4443/alice/private/
```

### WebID-TLS (Client Certificates)

For backend services, CLI tools, and automated agents that need non-interactive authentication:

```bash
jss start --ssl-key key.pem --ssl-cert cert.pem --webid-tls
```

**How it works:**
1. Client presents X.509 certificate during TLS handshake
2. Certificate's `SubjectAlternativeName` contains a WebID URI
3. Server fetches the WebID profile
4. Server verifies the certificate's public key matches one in the profile

**Testing with curl:**

```bash
# Generate self-signed cert with WebID in SAN
openssl req -x509 -newkey rsa:2048 -keyout client-key.pem -out client-cert.pem -days 365 \
  -subj "/CN=Test" -addext "subjectAltName=URI:https://example.com/alice/#me" -nodes

# Make authenticated request
curl --cert client-cert.pem --key client-key.pem https://localhost:8443/alice/private/
```

**Profile requirement:** Your WebID profile must contain the certificate's public key:

```turtle
@prefix cert: <http://www.w3.org/ns/auth/cert#> .

<#me> cert:key [
    a cert:RSAPublicKey;
    cert:modulus "abc123..."^^xsd:hexBinary;
    cert:exponent 65537
] .
```

**Use cases:**
- Enterprise backend services with existing PKI
- Server-to-server communication
- CLI tools and scripts
- IoT devices with embedded certificates

