/**
 * Interaction handlers for login and consent flows
 * Handles the user-facing parts of the authentication flow
 */

import { authenticate, findById } from './accounts.js';
import { loginPage, consentPage, errorPage } from './views.js';

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
  const { email, password } = request.body || {};

  try {
    const interaction = await provider.Interaction.find(uid);
    if (!interaction) {
      return reply.code(404).type('text/html').send(errorPage('Session expired', 'Please try logging in again.'));
    }

    // Validate input
    if (!email || !password) {
      interaction.lastError = 'Email and password are required';
      await interaction.save(interaction.exp - Math.floor(Date.now() / 1000));
      return reply.redirect(`/idp/interaction/${uid}`);
    }

    // Authenticate
    const account = await authenticate(email, password);
    if (!account) {
      interaction.lastError = 'Invalid email or password';
      await interaction.save(interaction.exp - Math.floor(Date.now() / 1000));
      return reply.redirect(`/idp/interaction/${uid}`);
    }

    // Login successful - complete the interaction
    const result = {
      login: {
        accountId: account.id,
        remember: true,
      },
    };

    const redirectTo = await provider.interactionResult(
      request.raw,
      reply.raw,
      result,
      { mergeWithLastSubmission: false }
    );

    return reply.redirect(redirectTo);
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

    const redirectTo = await provider.interactionResult(
      request.raw,
      reply.raw,
      result,
      { mergeWithLastSubmission: true }
    );

    return reply.redirect(redirectTo);
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
