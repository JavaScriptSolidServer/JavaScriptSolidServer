/**
 * HTML templates for IdP login/consent pages
 * Minimal, functional design
 */

const styles = `
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #f5f5f5;
    margin: 0;
    padding: 40px 20px;
    min-height: 100vh;
  }
  .container {
    max-width: 400px;
    margin: 0 auto;
    background: white;
    border-radius: 12px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    padding: 40px;
  }
  h1 {
    margin: 0 0 8px 0;
    font-size: 24px;
    color: #333;
  }
  .subtitle {
    color: #666;
    margin: 0 0 30px 0;
    font-size: 14px;
  }
  .client-info {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 24px;
  }
  .client-name {
    font-weight: 600;
    color: #333;
  }
  .client-uri {
    font-size: 12px;
    color: #666;
    word-break: break-all;
  }
  label {
    display: block;
    font-size: 14px;
    font-weight: 500;
    color: #333;
    margin-bottom: 6px;
  }
  input[type="text"],
  input[type="email"],
  input[type="password"] {
    width: 100%;
    padding: 12px;
    border: 1px solid #ddd;
    border-radius: 8px;
    font-size: 16px;
    margin-bottom: 16px;
    transition: border-color 0.2s;
  }
  input:focus {
    outline: none;
    border-color: #0066cc;
  }
  .error {
    background: #fee;
    border: 1px solid #fcc;
    color: #c00;
    padding: 12px;
    border-radius: 8px;
    margin-bottom: 20px;
    font-size: 14px;
  }
  .btn {
    display: inline-block;
    padding: 12px 24px;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 500;
    cursor: pointer;
    border: none;
    text-decoration: none;
    text-align: center;
    transition: background-color 0.2s;
  }
  .btn-primary {
    background: #0066cc;
    color: white;
    width: 100%;
  }
  .btn-primary:hover {
    background: #0052a3;
  }
  .btn-secondary {
    background: #f0f0f0;
    color: #333;
    margin-top: 12px;
    width: 100%;
  }
  .btn-secondary:hover {
    background: #e0e0e0;
  }
  .btn-passkey {
    background: #1a73e8;
    color: white;
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }
  .btn-passkey:hover {
    background: #1557b0;
  }
  .btn-passkey svg {
    width: 20px;
    height: 20px;
  }
  .btn-schnorr {
    background: #7b1fa2;
    color: white;
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    margin-top: 12px;
  }
  .btn-schnorr:hover {
    background: #6a1b9a;
  }
  .btn-schnorr svg {
    width: 20px;
    height: 20px;
  }
  .divider {
    display: flex;
    align-items: center;
    margin: 20px 0;
    color: #666;
    font-size: 14px;
  }
  .divider::before,
  .divider::after {
    content: '';
    flex: 1;
    border-bottom: 1px solid #ddd;
  }
  .divider span {
    padding: 0 12px;
  }
  .scopes {
    margin: 20px 0;
  }
  .scope {
    display: flex;
    align-items: center;
    padding: 12px;
    background: #f8f9fa;
    border-radius: 8px;
    margin-bottom: 8px;
  }
  .scope-icon {
    width: 24px;
    height: 24px;
    margin-right: 12px;
    opacity: 0.6;
  }
  .scope-name {
    font-weight: 500;
  }
  .scope-desc {
    font-size: 12px;
    color: #666;
  }
  .actions {
    margin-top: 24px;
  }
  .logo {
    text-align: center;
    margin-bottom: 24px;
  }
  .logo svg {
    width: 48px;
    height: 48px;
  }
`;

const solidLogo = `
<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="45" fill="#7C4DFF" />
  <path d="M30 50 L45 65 L70 40" stroke="white" stroke-width="8" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
`;

const passkeyIcon = `
<svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
  <path d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/>
</svg>
`;

const schnorrIcon = `
<svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
  <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
</svg>
`;

const scopeDescriptions = {
  openid: 'Access your identity',
  webid: 'Access your WebID',
  profile: 'Access your name',
  email: 'Access your email address',
  offline_access: 'Stay logged in',
};

/**
 * Escape string for safe use in JavaScript
 */
function escapeJs(text) {
  if (!text) return '';
  return String(text)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/</g, '\\x3c')
    .replace(/>/g, '\\x3e')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

/**
 * Login page HTML
 */
export function loginPage(uid, clientId, error = null, passkeyEnabled = true, schnorrEnabled = true) {
  const appName = clientId || 'An application';
  const safeUid = escapeJs(uid);

  const passkeySection = passkeyEnabled ? `
    <button type="button" class="btn btn-passkey" onclick="loginWithPasskey()">
      ${passkeyIcon}
      Sign in with Passkey
    </button>
  ` : '';

  const schnorrSection = schnorrEnabled ? `
    <button type="button" class="btn btn-schnorr" onclick="loginWithSchnorr()" id="schnorrBtn">
      ${schnorrIcon}
      Sign in with Schnorr
    </button>
  ` : '';

  const ssoSection = (passkeyEnabled || schnorrEnabled) ? `
    ${passkeySection}
    ${schnorrSection}
    <div class="divider"><span>or</span></div>
  ` : '';

  const passkeyScript = passkeyEnabled ? `
  <script>
    var INTERACTION_UID = '${safeUid}';

    async function loginWithPasskey() {
      try {
        // Get authentication options
        const optionsRes = await fetch('/idp/passkey/login/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ visitorId: crypto.randomUUID() })
        });
        const options = await optionsRes.json();
        if (options.error) {
          alert('Error: ' + options.error);
          return;
        }

        // Convert base64url to ArrayBuffer
        options.challenge = base64urlToBuffer(options.challenge);
        if (options.allowCredentials) {
          options.allowCredentials = options.allowCredentials.map(c => ({
            ...c,
            id: base64urlToBuffer(c.id)
          }));
        }

        // Prompt user for passkey
        const credential = await navigator.credentials.get({ publicKey: options });

        // Send response to server
        const verifyRes = await fetch('/idp/passkey/login/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            challengeKey: options.challengeKey,
            credential: {
              id: credential.id,
              rawId: bufferToBase64url(credential.rawId),
              type: credential.type,
              response: {
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                signature: bufferToBase64url(credential.response.signature),
                userHandle: credential.response.userHandle
                  ? bufferToBase64url(credential.response.userHandle)
                  : null
              }
            }
          })
        });

        const result = await verifyRes.json();
        if (result.success) {
          // Complete the OIDC interaction - build URL safely
          const redirectUrl = '/idp/interaction/' + encodeURIComponent(INTERACTION_UID) + '/passkey-complete?accountId=' + encodeURIComponent(result.accountId);
          window.location.href = redirectUrl;
        } else {
          alert('Passkey authentication failed: ' + (result.error || 'Unknown error'));
        }
      } catch (err) {
        if (err.name === 'NotAllowedError') {
          // User cancelled - do nothing
        } else {
          console.error('Passkey error:', err);
          alert('Passkey authentication failed: ' + err.message);
        }
      }
    }

    function base64urlToBuffer(base64url) {
      const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
      const padLen = (4 - base64.length % 4) % 4;
      const padded = base64 + '='.repeat(padLen);
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    }

    function bufferToBase64url(buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary).replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/=/g, '');
    }
  </script>
  ` : '';

  const schnorrScript = schnorrEnabled ? `
  <script>
    async function loginWithSchnorr() {
      const btn = document.getElementById('schnorrBtn');

      // Check for NIP-07 extension (window.nostr)
      if (typeof window.nostr === 'undefined') {
        alert('No Schnorr signer found. Please install a NIP-07 compatible extension like Podkey, nos2x, or Alby.');
        return;
      }

      btn.disabled = true;
      btn.textContent = 'Signing...';

      try {
        // Get the current URL for the auth event
        const authUrl = window.location.origin + '/idp/interaction/${safeUid}/schnorr-login';

        // Create NIP-98 event (kind 27235)
        const event = {
          kind: 27235,
          created_at: Math.floor(Date.now() / 1000),
          tags: [
            ['u', authUrl],
            ['method', 'POST']
          ],
          content: ''
        };

        // Sign with NIP-07 extension
        const signedEvent = await window.nostr.signEvent(event);

        // Send to server
        const response = await fetch(authUrl, {
          method: 'POST',
          headers: {
            'Authorization': 'Nostr ' + btoa(JSON.stringify(signedEvent))
          }
        });

        const result = await response.json();

        if (result.success && result.redirectUrl) {
          window.location.href = result.redirectUrl;
        } else if (result.error) {
          alert('Schnorr login failed: ' + result.error);
          btn.disabled = false;
          btn.textContent = 'Sign in with Schnorr';
        } else {
          alert('Schnorr login failed: Unknown error');
          btn.disabled = false;
          btn.textContent = 'Sign in with Schnorr';
        }
      } catch (err) {
        console.error('Schnorr login error:', err);
        if (err.message && err.message.includes('User rejected')) {
          // User cancelled signing - do nothing
        } else {
          alert('Schnorr login failed: ' + err.message);
        }
        btn.disabled = false;
        btn.textContent = 'Sign in with Schnorr';
      }
    }
  </script>
  ` : '';

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In - Solid IdP</title>
  <style>${styles}</style>
</head>
<body>
  <div class="container">
    <div class="logo">${solidLogo}</div>
    <h1>Sign In</h1>
    <p class="subtitle">Sign in to your Solid Pod</p>

    <div class="client-info">
      <div class="client-name">${escapeHtml(appName)}</div>
      <div class="client-uri">is requesting access to your pod</div>
    </div>

    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}

    ${ssoSection}

    <form method="POST" action="/idp/interaction/${uid}/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autofocus placeholder="Your username">

      <label for="password">Password</label>
      <input type="password" id="password" name="password" required placeholder="Your password">

      <button type="submit" class="btn btn-primary">Sign In</button>
    </form>

    <form method="POST" action="/idp/interaction/${uid}/abort">
      <button type="submit" class="btn btn-secondary">Cancel</button>
    </form>

    <p style="text-align: center; margin-top: 24px; color: #666; font-size: 14px;">
      Don't have an account? <a href="/idp/register?uid=${uid}" style="color: #0066cc;">Register</a>
    </p>
  </div>
  ${passkeyScript}
  ${schnorrScript}
</body>
</html>
  `;
}

/**
 * Consent page HTML
 */
export function consentPage(uid, client, params, account) {
  const scopes = (params.scope || 'openid').split(' ').filter(Boolean);
  const clientName = client?.clientName || client?.client_id || 'Unknown App';
  const clientUri = client?.clientUri || client?.redirect_uris?.[0] || '';

  const scopeItems = scopes.map(scope => `
    <div class="scope">
      <div class="scope-icon">✓</div>
      <div>
        <div class="scope-name">${escapeHtml(scope)}</div>
        <div class="scope-desc">${escapeHtml(scopeDescriptions[scope] || 'Access requested')}</div>
      </div>
    </div>
  `).join('');

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize - Solid IdP</title>
  <style>${styles}</style>
</head>
<body>
  <div class="container">
    <div class="logo">${solidLogo}</div>
    <h1>Authorize Access</h1>
    <p class="subtitle">Allow this app to access your data?</p>

    <div class="client-info">
      <div class="client-name">${escapeHtml(clientName)}</div>
      ${clientUri ? `<div class="client-uri">${escapeHtml(clientUri)}</div>` : ''}
    </div>

    ${account ? `
      <div style="display: flex; align-items: center; justify-content: center; gap: 8px; flex-wrap: wrap; margin: 12px 0;">
        <span>Signed in as <strong>${escapeHtml(account.email)}</strong></span>
        <span style="color: #94a3b8;">·</span>
        <form method="POST" action="/idp/interaction/${uid}/switch" style="display: inline; margin: 0;">
          <button type="submit" style="background: none; border: 0; padding: 0; color: #2563eb; font: inherit; cursor: pointer; text-decoration: underline;">Sign in as a different user</button>
        </form>
      </div>
    ` : ''}

    <div class="scopes">
      <label>This app is requesting access to:</label>
      ${scopeItems}
    </div>

    <div class="actions">
      <form method="POST" action="/idp/interaction/${uid}/confirm">
        <button type="submit" class="btn btn-primary">Allow Access</button>
      </form>

      <form method="POST" action="/idp/interaction/${uid}/abort">
        <button type="submit" class="btn btn-secondary">Deny</button>
      </form>
    </div>
  </div>
</body>
</html>
  `;
}

/**
 * Error page HTML
 */
export function errorPage(title, message) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error - Solid IdP</title>
  <style>${styles}</style>
</head>
<body>
  <div class="container">
    <div class="logo">${solidLogo}</div>
    <h1 style="color: #c00;">${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
    <a href="/" class="btn btn-secondary">Go Home</a>
  </div>
</body>
</html>
  `;
}

/**
 * Friendly landing page for the IdP root.
 *
 * The OIDC authorization endpoint (/idp/auth) requires a client_id; opening
 * /idp manually used to drop the user into a raw OIDC error. This page is
 * the human-navigable entry point.
 *
 * In single-user mode (`ctx.singleUser`) the Create Account button is
 * suppressed — pod creation is disabled and the button would lead to a
 * 403. The sign-in note still names pilot as the example client.
 */
export function landingPage(ctx = {}) {
  const issuer = ctx.baseUri || '';
  const singleUser = !!ctx.singleUser;
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Solid Pod Server</title>
  <style>${styles}
  /* landingPage local polish (#286) */
  .container.landing { padding-top: 32px; }
  .landing-header {
    margin: -40px -40px 24px;
    padding: 32px 40px 26px;
    background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
    color: #fff;
    border-radius: 12px 12px 0 0;
    text-align: center;
  }
  .landing-header h1 { color: #fff; margin: 0 0 6px; font-size: 24px; }
  .landing-header .subtitle { color: rgba(255,255,255,.85); margin: 0; font-size: 14px; }
  .landing .signin-note {
    margin-top: 18px;
    padding: 14px 16px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    color: #475569;
    font-size: 13px;
    line-height: 1.55;
  }
  .landing .signin-note strong { color: #1e293b; }
  .landing .signin-note a { color: #4f46e5; text-decoration: none; font-weight: 500; }
  .landing .signin-note a:hover { text-decoration: underline; }
  .landing .issuer {
    margin-top: 18px;
    text-align: center;
    color: #94a3b8;
    font: 11px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace;
    word-break: break-all;
  }
  </style>
</head>
<body>
  <div class="container landing">
    <div class="landing-header">
      <h1>Solid Pod Server</h1>
      <p class="subtitle">${singleUser
        ? 'Single-user pod — sign in from any Solid app.'
        : 'Create an account, then sign in from any Solid app.'}</p>
    </div>

    ${singleUser
      ? '' /* Registration is disabled in single-user mode; suppress the dead-end button. */
      : '<a href="/idp/register" class="btn btn-primary" style="text-decoration: none;">Create Account</a>'}

    <div class="signin-note">
      <strong>${singleUser ? 'Sign in' : 'Already have an account?'}</strong> ${singleUser ? 'from' : 'Sign in from'} a Solid app — for example, <a href="https://solid-apps.github.io/pilot/" target="_blank" rel="noopener">pilot</a> is a minimal console you can open right now. Point it at this server and click Sign In. Or <a href="https://solidproject.org/apps" target="_blank" rel="noopener">browse other Solid apps</a>.
    </div>

    ${issuer ? `<div class="issuer">Issuer: ${escapeHtml(issuer.replace(/\/$/, ''))}</div>` : ''}
  </div>
</body>
</html>
  `;
}

/**
 * Registration page HTML
 */
export function registerPage(uid = null, error = null, success = null, inviteOnly = false, ctx = {}) {
  const inviteField = inviteOnly ? `
      <label for="invite">Invite Code</label>
      <input type="text" id="invite" name="invite" required
             placeholder="Enter your invite code" style="text-transform: uppercase;">
  ` : '';

  // Embed the values the live preview needs. Escape characters that are
  // unsafe in inline <script> contexts so values like "</script>" or
  // U+2028 / U+2029 line separators can't terminate the script tag or
  // confuse the parser when template-substituted.
  const previewConfig = JSON.stringify({
    baseUri: ctx.baseUri || '',
    subdomainsEnabled: !!ctx.subdomainsEnabled,
    baseDomain: ctx.baseDomain || '',
  })
    .replace(/</g, '\\u003c')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');

  // Server validates more strictly than the HTML pattern can express; mirror
  // as much as possible client-side so the browser catches obvious mistakes
  // before submit. Subdomain mode drops dot/underscore (DNS hostname rules).
  const usernamePattern = (ctx.subdomainsEnabled && ctx.baseDomain)
    ? '[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])?'
    : '(?!.*\\.\\.)[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])?';
  const usernameTitle = (ctx.subdomainsEnabled && ctx.baseDomain)
    ? 'Lowercase letters, numbers, or - (start and end alphanumeric, 3–32 chars). Subdomain mode disallows . and _.'
    : 'Lowercase letters, numbers, or . _ - (start and end alphanumeric, 3–32 chars, no consecutive dots)';

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register - Solid IdP</title>
  <style>${styles}
  /* registerPage local polish (#284) */
  .container.register { padding-top: 32px; }
  .register-header {
    margin: -40px -40px 24px;
    padding: 28px 40px 22px;
    background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
    color: #fff;
    border-radius: 12px 12px 0 0;
  }
  .register-header h1 { color: #fff; margin: 0 0 4px; font-size: 22px; }
  .register-header .subtitle { color: rgba(255,255,255,.85); margin: 0; font-size: 13px; }
  .preview {
    margin: 4px 0 18px;
    padding: 12px 14px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    font: 12px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace;
    color: #475569;
    word-break: break-all;
  }
  .preview .label { color: #64748b; font-weight: 600; margin-right: 6px; }
  .preview .placeholder { color: #94a3b8; font-style: italic; }
  </style>
</head>
<body>
  <div class="container register">
    <div class="register-header">
      <h1>Create Account</h1>
      <p class="subtitle">Register for a new Solid Pod${inviteOnly ? ' (invite required)' : ''}</p>
    </div>

    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}
    ${success ? `<div class="error" style="background: #efe; border-color: #cfc; color: #060;">${escapeHtml(success)}</div>` : ''}

    <form method="POST" action="/idp/register${uid ? `?uid=${uid}` : ''}">
      ${inviteField}

      <label for="username">Username</label>
      <input type="text" id="username" name="username" required ${!inviteOnly ? 'autofocus' : ''}
             placeholder="Choose a username" minlength="3" maxlength="32"
             pattern="${usernamePattern}"
             title="${usernameTitle}">

      <div class="preview" id="preview" aria-live="polite">
        <div><span class="label">WebID</span><span id="preview-webid" class="placeholder">choose a username to preview</span></div>
        <div style="margin-top: 4px;"><span class="label">Storage</span><span id="preview-storage" class="placeholder">—</span></div>
      </div>

      <label for="password">Password</label>
      <input type="password" id="password" name="password" required
             placeholder="Choose a password">

      <label for="confirmPassword">Confirm Password</label>
      <input type="password" id="confirmPassword" name="confirmPassword" required
             placeholder="Confirm your password">

      <button type="submit" class="btn btn-primary">Create Account</button>
    </form>

    <p style="text-align: center; margin-top: 24px; color: #666; font-size: 14px;">
      ${uid
        ? `Already have an account? <a href="/idp/interaction/${uid}" style="color: #0066cc;">Sign In</a>`
        : `<a href="/idp" style="color: #0066cc;">Back to home</a>`}
    </p>
  </div>

  <script>
  (function () {
    var cfg = ${previewConfig};
    var input = document.getElementById('username');
    var webEl = document.getElementById('preview-webid');
    var storEl = document.getElementById('preview-storage');
    if (!input || !webEl || !storEl) return;

    function render() {
      // Server rejects uppercase outright, so normalise the field as the
      // user types — keeps the preview honest and avoids a confusing
      // post-submit error.
      var normalised = (input.value || '').toLowerCase();
      if (input.value !== normalised) input.value = normalised;
      var u = normalised.trim();
      if (!u) {
        webEl.textContent = 'choose a username to preview';
        webEl.className = 'placeholder';
        storEl.textContent = '—';
        storEl.className = 'placeholder';
        return;
      }
      var pod, webid;
      if (cfg.subdomainsEnabled && cfg.baseDomain) {
        var origin = cfg.baseUri.split('://')[0] + '://';
        pod = origin + u + '.' + cfg.baseDomain + '/';
      } else {
        pod = (cfg.baseUri || (location.protocol + '//' + location.host)) + '/' + u + '/';
      }
      webid = pod + 'profile/card.jsonld#me';
      webEl.textContent = webid;
      webEl.className = '';
      storEl.textContent = pod;
      storEl.className = '';
    }
    input.addEventListener('input', render);
    render();
  })();
  </script>
</body>
</html>
  `;
}

/**
 * Passkey prompt page - shown after password login to encourage passkey setup
 */
export function passkeyPromptPage(uid, accountId) {
  const safeUid = escapeJs(uid);
  const safeAccountId = escapeJs(accountId);
  // Pre-escape the SVG for innerHTML assignment (no user data, just static SVG)
  const passkeyIconEscaped = passkeyIcon.replace(/'/g, "\\'").replace(/\n/g, '');

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Add a Passkey - Solid IdP</title>
  <style>${styles}</style>
</head>
<body>
  <div class="container">
    <div class="logo">${solidLogo}</div>
    <h1>Add a Passkey?</h1>
    <p class="subtitle">Sign in faster next time</p>

    <div class="client-info">
      <div class="client-name">Passkeys are more secure</div>
      <div class="client-uri">Use Touch ID, Face ID, or a security key instead of your password</div>
    </div>

    <button type="button" class="btn btn-passkey" onclick="registerPasskey()" id="addBtn">
      ${passkeyIcon}
      Add Passkey
    </button>

    <form method="GET" action="/idp/interaction/${escapeHtml(uid)}/passkey-skip">
      <button type="submit" class="btn btn-secondary">Skip for now</button>
    </form>
  </div>

  <script>
    var INTERACTION_UID = '${safeUid}';
    var ACCOUNT_ID = '${safeAccountId}';
    var PASSKEY_ICON = '${passkeyIconEscaped}';

    async function registerPasskey() {
      const btn = document.getElementById('addBtn');
      btn.disabled = true;
      btn.textContent = 'Setting up...';

      try {
        // Get registration options
        const optionsRes = await fetch('/idp/passkey/register/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ accountId: ACCOUNT_ID })
        });
        const options = await optionsRes.json();
        if (options.error) {
          alert('Error: ' + options.error);
          btn.disabled = false;
          btn.innerHTML = PASSKEY_ICON + ' Add Passkey';
          return;
        }

        // Save challengeKey for verification
        const challengeKey = options.challengeKey;

        // Convert base64url to ArrayBuffer
        options.challenge = base64urlToBuffer(options.challenge);
        options.user.id = base64urlToBuffer(options.user.id);
        if (options.excludeCredentials) {
          options.excludeCredentials = options.excludeCredentials.map(c => ({
            ...c,
            id: base64urlToBuffer(c.id)
          }));
        }

        // Prompt user to create passkey
        const credential = await navigator.credentials.create({ publicKey: options });

        // Send response to server
        const verifyRes = await fetch('/idp/passkey/register/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            accountId: ACCOUNT_ID,
            challengeKey: challengeKey,
            credential: {
              id: credential.id,
              rawId: bufferToBase64url(credential.rawId),
              type: credential.type,
              response: {
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                transports: credential.response.getTransports ? credential.response.getTransports() : []
              }
            },
            name: detectDeviceName()
          })
        });

        const result = await verifyRes.json();
        if (result.success) {
          // Passkey added, continue to app - build URL safely
          const redirectUrl = '/idp/interaction/' + encodeURIComponent(INTERACTION_UID) + '/passkey-complete?accountId=' + encodeURIComponent(ACCOUNT_ID);
          window.location.href = redirectUrl;
        } else {
          alert('Failed to add passkey: ' + (result.error || 'Unknown error'));
          btn.disabled = false;
          btn.innerHTML = PASSKEY_ICON + ' Add Passkey';
        }
      } catch (err) {
        if (err.name === 'NotAllowedError') {
          // User cancelled
        } else {
          console.error('Passkey error:', err);
          alert('Failed to add passkey: ' + err.message);
        }
        btn.disabled = false;
        btn.innerHTML = PASSKEY_ICON + ' Add Passkey';
      }
    }

    function detectDeviceName() {
      const ua = navigator.userAgent;
      if (/iPhone/.test(ua)) return 'iPhone';
      if (/iPad/.test(ua)) return 'iPad';
      if (/Mac/.test(ua)) return 'Mac';
      if (/Android/.test(ua)) return 'Android';
      if (/Windows/.test(ua)) return 'Windows';
      if (/Linux/.test(ua)) return 'Linux';
      return 'Security Key';
    }

    function base64urlToBuffer(base64url) {
      const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
      const padLen = (4 - base64.length % 4) % 4;
      const padded = base64 + '='.repeat(padLen);
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    }

    function bufferToBase64url(buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary).replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/=/g, '');
    }
  </script>
</body>
</html>
  `;
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
