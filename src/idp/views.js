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

const scopeDescriptions = {
  openid: 'Access your identity',
  webid: 'Access your WebID',
  profile: 'Access your name',
  email: 'Access your email address',
  offline_access: 'Stay logged in',
};

/**
 * Login page HTML
 */
export function loginPage(uid, clientId, error = null) {
  const appName = clientId || 'An application';

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

    ${account ? `<p>Signed in as <strong>${escapeHtml(account.email)}</strong></p>` : ''}

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
 * Registration page HTML
 */
export function registerPage(uid = null, error = null, success = null) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register - Solid IdP</title>
  <style>${styles}</style>
</head>
<body>
  <div class="container">
    <div class="logo">${solidLogo}</div>
    <h1>Create Account</h1>
    <p class="subtitle">Register for a new Solid Pod</p>

    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}
    ${success ? `<div class="error" style="background: #efe; border-color: #cfc; color: #060;">${escapeHtml(success)}</div>` : ''}

    <form method="POST" action="/idp/register${uid ? `?uid=${uid}` : ''}">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autofocus
             placeholder="Choose a username" pattern="[a-z0-9]+"
             title="Lowercase letters and numbers only">

      <label for="password">Password</label>
      <input type="password" id="password" name="password" required
             placeholder="Choose a password">

      <label for="confirmPassword">Confirm Password</label>
      <input type="password" id="confirmPassword" name="confirmPassword" required
             placeholder="Confirm your password">

      <button type="submit" class="btn btn-primary">Create Account</button>
    </form>

    <p style="text-align: center; margin-top: 24px; color: #666; font-size: 14px;">
      Already have an account? <a href="${uid ? `/idp/interaction/${uid}` : '/idp/auth'}" style="color: #0066cc;">Sign In</a>
    </p>
  </div>
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
