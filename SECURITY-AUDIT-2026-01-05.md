# JSS Security Audit Report

**Date:** 2026-01-05
**Auditor:** Automated QE Fleet Analysis
**Version Audited:** 0.0.71
**Previous Audit:** 2026-01-03 (v0.0.48)

---

## Executive Summary

A comprehensive multi-agent security audit of JavaScriptSolidServer (v0.0.71) was conducted using 5 specialized review agents examining authentication, path traversal, DoS resistance, WAC authorization, and dependency security.

**Overall Security Posture:** **GOOD** - Major vulnerabilities from previous audit (v0.0.48-0.0.51) have been fixed. Several medium and low severity issues remain.

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0 | - |
| High | 1 | NEW |
| Medium | 7 | Open |
| Low | 8 | Open |

**npm audit:** 0 vulnerabilities found

---

## Previous Audit Issues - Remediation Status

| Issue | Previous Severity | Status | Fixed In |
|-------|-------------------|--------|----------|
| ACL bypass (unauthenticated .acl access) | Critical | FIXED | v0.0.49 |
| JWT signature not verified | Critical | FIXED | v0.0.49 |
| SSRF in OIDC discovery | Critical | FIXED | v0.0.50 |
| SSRF in client document fetch | Critical | FIXED | v0.0.50 |
| Path traversal via `..` bypass | Critical | FIXED | v0.0.52 |
| Unauthenticated pod creation | High | FIXED | v0.0.51 |
| Default token secret | High | FIXED | v0.0.51 |
| No rate limiting | Medium | FIXED | v0.0.51 |
| WebSocket subscription spam | High | FIXED | v0.0.52 |
| JSON.parse DoS | High | PARTIALLY FIXED | v0.0.52 |

---

## New/Open Vulnerabilities

### HIGH SEVERITY

#### 1. Path Traversal in Git Handler

**Location:** `src/handlers/git.js:82-97`

**Description:** The git handler does NOT use the secure `urlToPath()` function. Instead, it extracts the repository path and passes it directly to `path.resolve()` without sanitization.

```javascript
const urlPath = decodeURIComponent(request.url.split('?')[0]);
const repoRelative = extractRepoPath(urlPath);
const repoAbs = resolve(dataRoot, repoRelative);  // No traversal check!
```

**Attack Vector:**
```
GET /../../etc/passwd/info/refs?service=git-upload-pack
```

**Impact:** Potential directory traversal outside DATA_ROOT when git endpoints are enabled.

**Mitigating Factors:**
- `findGitDir()` validates git-specific files exist, limiting exploitation
- Git support is optional

**CVSS Score:** 7.5 (High)

**Recommendation:** Use `urlToPath()` or equivalent sanitization before `path.resolve()`.

---

### MEDIUM SEVERITY

#### 2. DPoP Replay Attack Vulnerability

**Location:** `src/auth/solid-oidc.js:178-181`

```javascript
// jti: Unique identifier (we should track these to prevent replay, but skip for now)
if (!payload.jti) {
  return { thumbprint: null, error: 'DPoP proof missing jti' };
}
```

**Description:** DPoP proof `jti` (JWT ID) is required but NOT tracked. The same DPoP proof can be replayed within its 5-minute validity window (`DPOP_MAX_AGE`).

**Impact:** Token replay attacks within short window.

**CVSS Score:** 5.3 (Medium)

**Recommendation:** Implement time-bounded jti cache (5-min TTL).

---

#### 3. Agent Group Authorization Not Implemented

**Location:** `src/wac/checker.js:182`

```javascript
// TODO: Check agent groups (requires fetching and parsing group documents)
```

**Description:** ACL rules using `acl:agentGroup` are parsed (`src/wac/parser.js:152-153`) but never checked during authorization. Group-based access control silently fails.

**Impact:** Resources protected by agent groups may be incorrectly denied or allowed.

**CVSS Score:** 6.1 (Medium)

**Recommendation:** Implement group document fetching and membership checking.

---

#### 4. JSON.parse Without Size Limits (Partial)

**Locations:**
- `src/wac/parser.js:40` - ACL content parsing
- `src/auth/did-nostr.js:129,141` - DID document parsing
- `src/nostr/relay.js:242` - WebSocket message parsing
- `src/auth/token.js:105` - Token payload parsing
- `src/ap/routes/inbox.js:126` - ActivityPub inbox

**Description:** `safeJsonParse()` exists (`src/utils/url.js:242-246`) but is not used consistently.

**Impact:** DoS via large JSON payloads in unprotected parsers.

**CVSS Score:** 5.3 (Medium)

**Recommendation:** Use `safeJsonParse()` consistently across all JSON parsing.

---

#### 5. Missing Global Security Headers

**Description:** Security headers are only applied for mashlib responses, not globally:

**Present (mashlib only):**
- `X-Frame-Options: DENY`
- `Content-Security-Policy: frame-ancestors 'none'`

**Missing globally:**
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security` (for HTTPS deployments)
- `Referrer-Policy`

**CVSS Score:** 4.3 (Medium)

**Recommendation:** Add security headers via Fastify plugin for all responses.

---

#### 6. DNS Resolution Failure Allows SSRF

**Location:** `src/utils/ssrf.js:125-130`

```javascript
} catch (err) {
  // DNS resolution failed - could be a legitimate issue or attacker trying to bypass
  // For security, we'll allow it through but log a warning
  console.warn(`DNS resolution failed for ${hostname}: ${err.message}`);
}
```

**Description:** When DNS resolution fails, the request is allowed to proceed. An attacker could exploit DNS timing or failure to bypass SSRF protection.

**Impact:** Potential SSRF bypass via DNS manipulation.

**CVSS Score:** 4.9 (Medium)

**Recommendation:** Block requests on DNS resolution failure.

---

#### 7. RDF Parsing Without Triple Limits

**Locations:** `src/rdf/turtle.js:34`, `src/patch/sparql-update.js:106`

**Description:** N3.js parser is used without limits on triple count or recursion depth. Combined with 10MB body limit, a crafted Turtle file could cause CPU exhaustion.

**CVSS Score:** 5.3 (Medium)

**Recommendation:** Add triple count limit (e.g., 100,000 max).

---

#### 8. Verbose Error Messages to Clients

**Locations:**
- `src/handlers/resource.js:501-505` - Turtle parsing errors
- `src/auth/solid-oidc.js:198` - DPoP proof errors

**Description:** Internal error messages from parsing libraries are exposed to clients.

**Impact:** Information disclosure about implementation details.

**CVSS Score:** 4.3 (Medium)

---

### LOW SEVERITY

#### 9. PodName Single-Pass Sanitization

**Location:** `src/utils/url.js:69`

```javascript
let safePodName = podName.replace(/\.\./g, '');
```

Uses single-pass `..` removal unlike the iterative approach for urlPath. Mitigated by subsequent boundary check.

---

#### 10. No Global WebSocket Connection Limit

**Location:** `src/notifications/websocket.js`

Per-connection subscription limit (100) exists, but no global limit across all connections.

---

#### 11. Minimum Username Length

**Location:** `src/idp/interactions.js:370-371`

Minimum username length is 3 characters, allowing very short usernames.

---

#### 12. No Password Strength Validation

**Location:** `src/idp/interactions.js`

No minimum password length or complexity requirements enforced.

---

#### 13. TOKEN_SECRET Entropy Not Validated

**Location:** `src/auth/token.js:16-33`

Production requires TOKEN_SECRET but doesn't validate minimum entropy/length.

---

#### 14. bcrypt Rounds

**Location:** `src/idp/accounts.js:41`

Uses 10 rounds (acceptable but 12 recommended for future-proofing).

---

#### 15. CORS Reflected Origin Pattern

**Location:** `src/ldp/headers.js:93-102`

Reflects any origin with credentials. Intentional for Solid interoperability but should be documented.

---

#### 16. Console.error Information Logging

**Locations:** `src/handlers/resource.js:129,203,290`

Error messages logged to console may reveal internal details if logs are exposed.

---

## Positive Security Findings

| Control | Location | Assessment |
|---------|----------|------------|
| Path traversal protection | `src/utils/url.js:24-46` | Multi-pass `..` removal + path.resolve boundary check |
| JWT signature verification | `src/auth/token.js:125-160` | Proper jose.jwtVerify() against JWKS |
| HMAC timing-safe comparison | `src/auth/token.js:94-101` | crypto.timingSafeEqual() used |
| Production token secret enforcement | `src/auth/token.js:21-26` | process.exit(1) if not set |
| ACL Control permission for .acl files | `src/auth/middleware.js:378-389` | Stricter than spec (more secure) |
| Default deny on missing ACL | `src/wac/checker.js:30-33` | Restrictive default |
| Rate limiting | `src/server.js`, `src/idp/index.js` | Comprehensive coverage |
| SSRF protection | `src/utils/ssrf.js` | Private IP blocking, DNS rebinding protection |
| WebSocket limits | `src/notifications/websocket.js` | 100 subs/connection, 2048 char URL limit |
| Dotfile blocking | `src/server.js:235-251` | Allowlist approach |
| Body size limits | `src/server.js:84` | 10MB global, 1MB for IdP |
| bcrypt password hashing | `src/idp/accounts.js` | Proper implementation |
| DPoP proof validation | `src/auth/solid-oidc.js` | Method, URI, timestamp, ath, cnf.jkt checks |
| Nostr NIP-98 validation | `src/auth/nostr.js` | Event kind, timestamp, URL, method, signature |
| Slug validation | `src/handlers/container.js:56-69` | Strict alphanumeric + length limit |

---

## Dependency Security

**npm audit:** 0 vulnerabilities

| Package | Version | Latest | Notes |
|---------|---------|--------|-------|
| jose | 6.1.3 | 6.1.3 | Current - JWT/JWKS handling |
| bcrypt | 6.0.0 | 6.0.0 | Current - Password hashing |
| oidc-provider | 9.6.0 | 9.6.0 | Current - OIDC IdP |
| fastify | 4.29.1 | 5.6.2 | Major version behind (v5 available) |
| better-sqlite3 | 12.5.0 | 12.5.0 | Current |
| nostr-tools | 2.19.4 | 2.19.4 | Current |

**Outdated (non-security):**
- @fastify/middie: 8.3.3 -> 9.1.0
- @fastify/rate-limit: 9.1.0 -> 10.3.0
- @fastify/websocket: 8.3.1 -> 11.2.0
- fastify: 4.29.1 -> 5.6.2

---

## Recommendations

### Priority 1 (High)

1. **Fix git handler path traversal** - Use `urlToPath()` in `src/handlers/git.js`

### Priority 2 (Medium)

2. **Implement DPoP jti tracking** - Add time-bounded cache for replay prevention
3. **Implement agent group checking** - Complete TODO in `src/wac/checker.js`
4. **Use safeJsonParse consistently** - Replace raw `JSON.parse()` calls
5. **Add global security headers** - X-Content-Type-Options, HSTS
6. **Block on DNS failure** - Change SSRF to deny on DNS resolution failure

### Priority 3 (Low)

7. Add RDF triple count limits
8. Add password strength requirements
9. Validate TOKEN_SECRET entropy
10. Add global WebSocket connection limit
11. Consider Fastify v5 upgrade path

---

## Changes Since Last Audit (v0.0.51 -> v0.0.71)

20 releases since last audit, including:

- **v0.0.52** - Security hardening (path traversal fix)
- **v0.0.53** - Stricter pod creation rate limit
- **v0.0.54** - SSRF false positive fix
- **v0.0.55** - Secure cookie flag for HTTPS
- **v0.0.56-0.0.58** - Invite-only registration, quotas, did:nostr
- **v0.0.59-0.0.61** - Nostr relay, ActivityPub federation
- **v0.0.62-0.0.66** - ActivityPub fixes, Android support
- **v0.0.67-0.0.71** - UI improvements, error pages, mashlib integration

---

## Legacy Audit Files

| File | Status | Action |
|------|--------|--------|
| SECURITY-AUDIT-2026-01-03.md | Outdated (v0.0.48) | Retained for history |
| SECURITY-AUDIT-2026-01-15.md | Invalid (future date) | **REMOVED** |

---

## Conclusion

JavaScriptSolidServer v0.0.71 demonstrates strong security fundamentals with all critical vulnerabilities from previous audits remediated. The primary concern is the **HIGH severity path traversal in the git handler** which should be addressed promptly.

The codebase shows security-conscious design patterns including:
- Defense-in-depth path traversal protection
- Proper cryptographic verification
- Comprehensive rate limiting
- SSRF protection with DNS rebinding mitigation
- Secure defaults (deny on missing ACL)

**Overall Assessment:** Suitable for production use after addressing the git handler path traversal issue.

---

_Report generated: 2026-01-05_
_Audit methodology: Multi-agent QE fleet (5 specialized reviewers)_
_Next audit recommended: 2026-04-05_
