/**
 * Interaction handlers for login, consent, and registration flows
 * Handles the user-facing parts of the authentication flow
 */

import { authenticate, findById, findByWebId, createAccount, updateLastLogin, setPasskeyPromptDismissed } from './accounts.js';
import { loginPage, consentPage, errorPage, registerPage, passkeyPromptPage } from './views.js';
import * as storage from '../storage/filesystem.js';
import { createPodStructure } from '../handlers/container.js';
import { validateInvite } from './invites.js';
import { verifyNostrAuth } from '../auth/nostr.js';

// Security: Maximum body size for IdP form submissions (1MB)
const MAX_BODY_SIZE = 1024 * 1024;

/**
 * Handle GET /idp/interaction/:uid
 * Shows login or consent page based on interaction state
 */
export async function handleInteractionGet(request, reply, provider) {
  const { uid } = request.params;

  try {
    const interaction = await provider.Interaction.find(uid);
    if (!interaction) {
      return reply.code(404).type('text/html').send(errorPage('Interaction not found', 'This login session has expired. Please try again.'));
    }

    const { prompt, params, session } = interaction;

    // If we need login
    if (prompt.name === 'login') {
      return reply.type('text/html').send(loginPage(uid, params.client_id, interaction.lastError));
    }

    // If we need consent
    if (prompt.name === 'consent') {
      const client = await provider.Client.find(params.client_id);
      const account = session?.accountId ? await findById(session.accountId) : null;

      return reply.type('text/html').send(consentPage(uid, client, params, account));
    }

    // Unknown prompt
    return reply.code(400).type('text/html').send(errorPage('Unknown prompt', `Unexpected prompt: ${prompt.name}`));
  } catch (err) {
    request.log.error(err, 'Interaction error');
    return reply.code(500).type('text/html').send(errorPage('Server Error', err.message));
  }
}

/**
 * Handle POST /idp/interaction/:uid/login
 * Processes login form submission
 */
export async function handleLogin(request, reply, provider) {
  const { uid } = request.params;

  // Parse body - handle multiple formats (Buffer, string, object)
  let parsedBody = request.body || {};
  const contentType = request.headers['content-type'] || '';

  if (Buffer.isBuffer(parsedBody)) {
    // Security: check body size
    if (parsedBody.length > MAX_BODY_SIZE) {
      return reply.code(413).type('text/html').send(errorPage('Request Too Large', 'Request body exceeds maximum size.'));
    }
    const bodyStr = parsedBody.toString();
    if (contentType.includes('application/json')) {
      try {
        parsedBody = JSON.parse(bodyStr);
      } catch (e) {
        parsedBody = {};
      }
    } else {
      // Assume form-urlencoded
      const params = new URLSearchParams(bodyStr);
      parsedBody = Object.fromEntries(params.entries());
    }
  } else if (typeof parsedBody === 'string') {
    // Security: check body size
    if (parsedBody.length > MAX_BODY_SIZE) {
      return reply.code(413).type('text/html').send(errorPage('Request Too Large', 'Request body exceeds maximum size.'));
    }
    // Body might be a string for form-urlencoded
    if (contentType.includes('application/json')) {
      try {
        parsedBody = JSON.parse(parsedBody);
      } catch (e) {
        parsedBody = {};
      }
    } else {
      const params = new URLSearchParams(parsedBody);
      parsedBody = Object.fromEntries(params.entries());
    }
  }
  // If it's already an object, use as-is

  // Support username, email, or legacy 'email' field for backwards compatibility
  const identifier = parsedBody.username || parsedBody.email;
  const password = parsedBody.password;

  request.log.info({ identifier, hasPassword: !!password, bodyType: typeof request.body, keys: Object.keys(parsedBody) }, 'Login attempt');

  try {
    const interaction = await provider.Interaction.find(uid);
    if (!interaction) {
      return reply.code(404).type('text/html').send(errorPage('Session expired', 'Please try logging in again.'));
    }

    // Validate input
    if (!identifier || !password) {
      interaction.lastError = 'Username and password are required';
      await interaction.save(interaction.exp - Math.floor(Date.now() / 1000));
      return reply.redirect(`/idp/interaction/${uid}`);
    }

    // Authenticate
    const account = await authenticate(identifier, password);
    if (!account) {
      interaction.lastError = 'Invalid username or password';
      await interaction.save(interaction.exp - Math.floor(Date.now() / 1000));
      return reply.redirect(`/idp/interaction/${uid}`);
    }

    // Login successful
    request.log.info({ accountId: account.id, uid }, 'Login successful');

    // Detect if this is a browser (wants HTML/redirect) or programmatic client (wants JSON)
    const acceptHeader = request.headers.accept || '';
    const wantsBrowserRedirect = acceptHeader.includes('text/html') && !acceptHeader.includes('application/json');

    // Check if user should see passkey prompt (browser only, no passkeys, not dismissed)
    const fullAccount = await findById(account.id);
    const shouldPromptPasskey = wantsBrowserRedirect &&
      !fullAccount.passkeys?.length &&
      !fullAccount.passkeyPromptDismissed;

    if (shouldPromptPasskey) {
      // Show passkey registration prompt before completing login
      // Store the pending login in the interaction
      interaction.result = {
        passkeyPromptPending: true,
        login: { accountId: account.id, remember: true }
      };
      await interaction.save(interaction.exp - Math.floor(Date.now() / 1000));
      return reply.type('text/html').send(passkeyPromptPage(uid, account.id));
    }

    // Complete the interaction
    const result = {
      login: {
        accountId: account.id,
        remember: true,
      },
    };

    // Save the login result to the interaction
    interaction.result = result;
    await interaction.save(interaction.exp - Math.floor(Date.now() / 1000));

    // For browsers (mashlib, etc): do a proper HTTP redirect
    if (wantsBrowserRedirect) {
      reply.hijack();
      return provider.interactionFinished(request.raw, reply.raw, result, { mergeWithLastSubmission: false });
    }

    // For CTH and programmatic clients: return JSON with location
    // CTH expects a 200 response with "location" in body (CSS v3+ style)
    try {
      reply.hijack();

      // Create a mock response that captures the redirect and returns JSON
      let capturedLocation = null;
      let headersSent = false;
      const mockRes = {
        statusCode: 200,
        headersSent: false,
        setHeader: (name, value) => {
          if (name.toLowerCase() === 'location') {
            capturedLocation = value;
          }
          return mockRes;
        },
        getHeader: (name) => {
          if (name.toLowerCase() === 'location') return capturedLocation;
          return undefined;
        },
        removeHeader: () => mockRes,
        writeHead: (status, headers) => {
          if (headers) {
            if (typeof headers === 'object' && !Array.isArray(headers)) {
              for (const [key, value] of Object.entries(headers)) {
                if (key.toLowerCase() === 'location') {
                  capturedLocation = value;
                }
              }
            }
          }
          return mockRes;
        },
        write: () => mockRes,
        end: (body) => {
          if (!headersSent) {
            headersSent = true;
            const location = capturedLocation || `/idp/auth/${uid}`;
            reply.raw.writeHead(200, {
              'Content-Type': 'application/json',
              'Location': location,
            });
            reply.raw.end(JSON.stringify({ location }));
          }
        },
        finished: false,
        on: () => mockRes,
        once: () => mockRes,
        emit: () => mockRes,
      };

      await provider.interactionFinished(request.raw, mockRes, result, { mergeWithLastSubmission: false });
      return;
    } catch (err) {
      request.log.warn({ err: err.message, errName: err.name, uid }, 'interactionFinished failed, using fallback');

      // Fallback: return the redirect URL for manual following
      const redirectTo = `/idp/auth/${uid}`;
      return reply
        .code(200)
        .header('Location', redirectTo)
        .type('application/json')
        .send({ location: redirectTo });
    }
  } catch (err) {
    request.log.error(err, 'Login error');
    return reply.code(500).type('text/html').send(errorPage('Login failed', err.message));
  }
}

/**
 * Handle POST /idp/interaction/:uid/confirm
 * Processes consent confirmation
 */
export async function handleConsent(request, reply, provider) {
  const { uid } = request.params;

  try {
    const interaction = await provider.Interaction.find(uid);
    if (!interaction) {
      return reply.code(404).type('text/html').send(errorPage('Session expired', 'Please try again.'));
    }

    const { prompt, params, session } = interaction;
    if (prompt.name !== 'consent') {
      return reply.code(400).type('text/html').send(errorPage('Invalid state', 'Not in consent stage.'));
    }

    // Grant consent
    const grant = new provider.Grant({
      accountId: session.accountId,
      clientId: params.client_id,
    });

    // Grant requested scopes
    if (params.scope) {
      grant.addOIDCScope(params.scope);
    }

    // Grant resource-specific scopes if present
    if (params.resource) {
      const resources = Array.isArray(params.resource) ? params.resource : [params.resource];
      for (const resource of resources) {
        grant.addResourceScope(resource, params.scope);
      }
    }

    const grantId = await grant.save();

    const result = {
      consent: {
        grantId,
      },
    };

    // Mark reply as sent since interactionFinished will handle the response
    reply.hijack();

    // Use interactionFinished which handles the redirect directly
    return provider.interactionFinished(
      request.raw,
      reply.raw,
      result,
      { mergeWithLastSubmission: true }
    );
  } catch (err) {
    request.log.error(err, 'Consent error');
    return reply.code(500).type('text/html').send(errorPage('Consent failed', err.message));
  }
}

/**
 * Handle POST /idp/interaction/:uid/abort
 * User cancelled the flow
 */
export async function handleAbort(request, reply, provider) {
  const { uid } = request.params;

  try {
    const result = {
      error: 'access_denied',
      error_description: 'User cancelled the authorization request',
    };

    // oidc-provider is configured with /idp routes, so redirectTo will have correct path
    const redirectTo = await provider.interactionResult(
      request.raw,
      reply.raw,
      result,
      { mergeWithLastSubmission: false }
    );

    return reply.redirect(redirectTo);
  } catch (err) {
    request.log.error(err, 'Abort error');
    return reply.code(500).type('text/html').send(errorPage('Error', err.message));
  }
}

/**
 * Handle GET /idp/register
 * Shows registration page
 */
export async function handleRegisterGet(request, reply, inviteOnly = false) {
  const uid = request.query.uid || null;
  return reply.type('text/html').send(registerPage(uid, null, null, inviteOnly));
}

/**
 * Handle POST /idp/register
 * Creates account and pod
 */
export async function handleRegisterPost(request, reply, issuer, inviteOnly = false) {
  const uid = request.query.uid || null;

  // Parse body
  let parsedBody = request.body || {};
  const contentType = request.headers['content-type'] || '';

  if (Buffer.isBuffer(parsedBody)) {
    // Security: check body size
    if (parsedBody.length > MAX_BODY_SIZE) {
      return reply.code(413).type('text/html').send(registerPage(null, 'Request body exceeds maximum size.', null, inviteOnly));
    }
    const bodyStr = parsedBody.toString();
    if (contentType.includes('application/json')) {
      try {
        parsedBody = JSON.parse(bodyStr);
      } catch (e) {
        parsedBody = {};
      }
    } else {
      const params = new URLSearchParams(bodyStr);
      parsedBody = Object.fromEntries(params.entries());
    }
  } else if (typeof parsedBody === 'string') {
    // Security: check body size
    if (parsedBody.length > MAX_BODY_SIZE) {
      return reply.code(413).type('text/html').send(registerPage(null, 'Request body exceeds maximum size.', null, inviteOnly));
    }
    const params = new URLSearchParams(parsedBody);
    parsedBody = Object.fromEntries(params.entries());
  }

  const { username, password, confirmPassword, invite } = parsedBody;

  // Validate invite code if invite-only mode is enabled
  if (inviteOnly) {
    const inviteResult = await validateInvite(invite);
    if (!inviteResult.valid) {
      return reply.code(403).type('text/html').send(registerPage(uid, inviteResult.error, null, inviteOnly));
    }
  }

  // Validate input
  if (!username || !password) {
    return reply.type('text/html').send(registerPage(uid, 'Username and password are required', null, inviteOnly));
  }

  // Validate username format
  const usernameRegex = /^[a-z0-9]+$/;
  if (!usernameRegex.test(username)) {
    return reply.type('text/html').send(registerPage(uid, 'Username must contain only lowercase letters and numbers', null, inviteOnly));
  }

  if (username.length < 3) {
    return reply.type('text/html').send(registerPage(uid, 'Username must be at least 3 characters', null, inviteOnly));
  }

  // Password strength validation
  if (password.length < 8) {
    return reply.type('text/html').send(registerPage(uid, 'Password must be at least 8 characters', null, inviteOnly));
  }

  if (password !== confirmPassword) {
    return reply.type('text/html').send(registerPage(uid, 'Passwords do not match', null, inviteOnly));
  }

  try {
    // Build URLs - WebID follows standard Solid convention: /profile/card#me
    const subdomainsEnabled = request.subdomainsEnabled;
    const baseDomain = request.baseDomain;
    const baseUrl = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;

    let podUri, webId;
    if (subdomainsEnabled && baseDomain) {
      // Subdomain mode: alice.example.com/profile/card#me
      podUri = `${request.protocol}://${username}.${baseDomain}/`;
      webId = `${podUri}profile/card#me`;
    } else {
      // Path mode: example.com/alice/profile/card#me
      podUri = `${baseUrl}/${username}/`;
      webId = `${podUri}profile/card#me`;
    }

    // Check if pod already exists
    const podPath = `${username}/`;
    const podExists = await storage.exists(podPath);
    if (podExists) {
      return reply.type('text/html').send(registerPage(uid, 'Username is already taken', null, inviteOnly));
    }

    // Create pod structure
    await createPodStructure(username, webId, podUri, issuer);

    // Create account
    await createAccount({
      username,
      password,
      webId,
      podName: username,
    });

    request.log.info({ username, webId }, 'Account and pod created');

    // Redirect to login
    if (uid) {
      return reply.redirect(`/idp/interaction/${uid}`);
    } else {
      return reply.type('text/html').send(registerPage(null, null, `Account created! You can now sign in as "${username}".`, inviteOnly));
    }
  } catch (err) {
    request.log.error(err, 'Registration error');
    return reply.type('text/html').send(registerPage(uid, err.message, null, inviteOnly));
  }
}

/**
 * Handle GET /idp/interaction/:uid/passkey-complete
 * Completes OIDC interaction after passkey login or registration
 */
export async function handlePasskeyComplete(request, reply, provider) {
  const { uid } = request.params;
  const { accountId } = request.query;

  if (!accountId) {
    return reply.code(400).type('text/html').send(errorPage('Missing account', 'Account ID is required.'));
  }

  try {
    const interaction = await provider.Interaction.find(uid);
    if (!interaction) {
      return reply.code(404).type('text/html').send(errorPage('Session expired', 'Please try logging in again.'));
    }

    // If this is a post-login passkey registration flow, validate accountId matches
    // the already-authenticated user to prevent account takeover
    if (interaction.result?.passkeyPromptPending && interaction.result?.login?.accountId) {
      if (interaction.result.login.accountId !== accountId) {
        request.log.warn({ expected: interaction.result.login.accountId, provided: accountId }, 'AccountId mismatch in passkey complete');
        return reply.code(403).type('text/html').send(errorPage('Access denied', 'Account mismatch.'));
      }
    }

    const account = await findById(accountId);
    if (!account) {
      return reply.code(404).type('text/html').send(errorPage('Account not found', 'The account could not be found.'));
    }

    // Update last login
    await updateLastLogin(accountId);

    // Complete the OIDC interaction
    const result = {
      login: {
        accountId: account.id,
        remember: true,
      },
    };

    request.log.info({ accountId: account.id, uid }, 'Passkey login completed');

    reply.hijack();
    return provider.interactionFinished(request.raw, reply.raw, result, { mergeWithLastSubmission: false });
  } catch (err) {
    request.log.error(err, 'Passkey complete error');
    return reply.code(500).type('text/html').send(errorPage('Error', err.message));
  }
}

/**
 * Handle GET /idp/interaction/:uid/passkey-skip
 * User skipped passkey registration, complete login
 */
export async function handlePasskeySkip(request, reply, provider) {
  const { uid } = request.params;

  try {
    const interaction = await provider.Interaction.find(uid);
    if (!interaction) {
      return reply.code(404).type('text/html').send(errorPage('Session expired', 'Please try logging in again.'));
    }

    // Validate the interaction is in the passkey prompt state
    if (!interaction.result?.passkeyPromptPending) {
      return reply.code(400).type('text/html').send(errorPage('Invalid state', 'Not in passkey prompt flow.'));
    }

    // Get the pending login result
    const result = interaction.result;
    if (!result?.login?.accountId) {
      return reply.code(400).type('text/html').send(errorPage('Invalid state', 'No pending login found.'));
    }

    // Mark passkey prompt as dismissed so we don't nag again
    await setPasskeyPromptDismissed(result.login.accountId, true);

    request.log.info({ accountId: result.login.accountId, uid }, 'Passkey prompt skipped');

    // Complete the OIDC interaction
    reply.hijack();
    return provider.interactionFinished(request.raw, reply.raw, result, { mergeWithLastSubmission: false });
  } catch (err) {
    request.log.error(err, 'Passkey skip error');
    return reply.code(500).type('text/html').send(errorPage('Error', err.message));
  }
}

/**
 * Handle POST /idp/interaction/:uid/schnorr-login
 * Authenticates user via Schnorr signature (NIP-98)
 */
export async function handleSchnorrLogin(request, reply, provider) {
  const { uid } = request.params;

  try {
    const interaction = await provider.Interaction.find(uid);
    if (!interaction) {
      return reply.code(404).type('application/json').send({
        success: false,
        error: 'Session expired. Please try again.'
      });
    }

    // Verify the Schnorr signature
    const authResult = await verifyNostrAuth(request);

    if (authResult.error) {
      request.log.warn({ error: authResult.error }, 'Schnorr auth failed');
      return reply.code(401).type('application/json').send({
        success: false,
        error: authResult.error
      });
    }

    // authResult.webId is either a resolved WebID or did:nostr:pubkey
    const identity = authResult.webId;
    request.log.info({ identity, uid }, 'Schnorr auth verified');

    // Try to find an existing account linked to this identity
    let account = await findByWebId(identity);

    if (!account) {
      // No account linked to this did:nostr
      // For now, return error - user needs to link their did:nostr to an account
      // Future: could auto-create account or prompt for linking
      return reply.code(403).type('application/json').send({
        success: false,
        error: 'No account linked to this identity. Please register or link your Schnorr key to an existing account.'
      });
    }

    // Update last login
    await updateLastLogin(account.id);

    // Complete the OIDC interaction
    const result = {
      login: {
        accountId: account.id,
        remember: true,
      },
    };

    // Save the login result
    interaction.result = result;
    await interaction.save(interaction.exp - Math.floor(Date.now() / 1000));

    request.log.info({ accountId: account.id, identity, uid }, 'Schnorr login successful');

    // Return success with redirect URL
    // The client will follow this redirect
    const redirectUrl = `/idp/interaction/${uid}/schnorr-complete?accountId=${encodeURIComponent(account.id)}`;

    return reply.type('application/json').send({
      success: true,
      redirectUrl
    });
  } catch (err) {
    request.log.error(err, 'Schnorr login error');
    return reply.code(500).type('application/json').send({
      success: false,
      error: err.message
    });
  }
}

/**
 * Handle GET /idp/interaction/:uid/schnorr-complete
 * Completes OIDC interaction after Schnorr login
 */
export async function handleSchnorrComplete(request, reply, provider) {
  const { uid } = request.params;
  const { accountId } = request.query;

  if (!accountId) {
    return reply.code(400).type('text/html').send(errorPage('Missing account', 'Account ID is required.'));
  }

  try {
    const interaction = await provider.Interaction.find(uid);
    if (!interaction) {
      return reply.code(404).type('text/html').send(errorPage('Session expired', 'Please try logging in again.'));
    }

    // Validate accountId matches the interaction result
    if (interaction.result?.login?.accountId !== accountId) {
      request.log.warn({ expected: interaction.result?.login?.accountId, provided: accountId }, 'AccountId mismatch in schnorr complete');
      return reply.code(403).type('text/html').send(errorPage('Access denied', 'Account mismatch.'));
    }

    const account = await findById(accountId);
    if (!account) {
      return reply.code(404).type('text/html').send(errorPage('Account not found', 'The account could not be found.'));
    }

    request.log.info({ accountId: account.id, uid }, 'Schnorr login completed');

    reply.hijack();
    return provider.interactionFinished(request.raw, reply.raw, interaction.result, { mergeWithLastSubmission: false });
  } catch (err) {
    request.log.error(err, 'Schnorr complete error');
    return reply.code(500).type('text/html').send(errorPage('Error', err.message));
  }
}
