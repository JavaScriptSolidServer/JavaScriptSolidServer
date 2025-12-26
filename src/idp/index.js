/**
 * Identity Provider Fastify Plugin
 * Mounts oidc-provider and interaction routes
 */

import middie from '@fastify/middie';
import { createProvider } from './provider.js';
import { initializeKeys, getPublicJwks } from './keys.js';
import {
  handleInteractionGet,
  handleLogin,
  handleConsent,
  handleAbort,
} from './interactions.js';

/**
 * IdP Fastify Plugin
 * @param {FastifyInstance} fastify
 * @param {object} options
 * @param {string} options.issuer - The issuer URL
 */
export async function idpPlugin(fastify, options) {
  const { issuer } = options;

  if (!issuer) {
    throw new Error('IdP requires issuer URL');
  }

  // Initialize signing keys
  await initializeKeys();

  // Create the OIDC provider
  const provider = await createProvider(issuer);

  // Store provider reference on fastify for handlers
  fastify.decorate('oidcProvider', provider);

  // Register middleware support for oidc-provider (Koa app)
  await fastify.register(middie, {
    hook: 'preHandler',
  });

  // Mount oidc-provider on /idp path
  // oidc-provider is a Koa app, middie handles the bridge
  fastify.use('/idp', (req, res, next) => {
    // Skip our custom interaction routes
    if (req.url.startsWith('/interaction/')) {
      return next();
    }
    // Let oidc-provider handle everything else
    provider.callback()(req, res);
  });

  // /.well-known/openid-configuration
  fastify.get('/.well-known/openid-configuration', async (request, reply) => {
    // Build discovery document
    const config = {
      issuer,
      authorization_endpoint: `${issuer}/idp/auth`,
      token_endpoint: `${issuer}/idp/token`,
      userinfo_endpoint: `${issuer}/idp/me`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      registration_endpoint: `${issuer}/idp/reg`,
      introspection_endpoint: `${issuer}/idp/token/introspection`,
      revocation_endpoint: `${issuer}/idp/token/revocation`,
      end_session_endpoint: `${issuer}/idp/session/end`,
      scopes_supported: ['openid', 'webid', 'profile', 'email', 'offline_access'],
      response_types_supported: ['code'],
      response_modes_supported: ['query', 'fragment', 'form_post'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      claims_supported: ['sub', 'webid', 'name', 'email', 'email_verified'],
      code_challenge_methods_supported: ['S256'],
      dpop_signing_alg_values_supported: ['ES256', 'RS256'],
      // Solid-OIDC specific
      solid_oidc_supported: 'https://solidproject.org/TR/solid-oidc',
    };

    reply.header('Cache-Control', 'public, max-age=3600');
    return config;
  });

  // /.well-known/jwks.json
  fastify.get('/.well-known/jwks.json', async (request, reply) => {
    const jwks = await getPublicJwks();
    reply.header('Cache-Control', 'public, max-age=3600');
    return jwks;
  });

  // Interaction routes (our custom login/consent UI)
  // These bypass oidc-provider and use our handlers

  // GET interaction - show login or consent page
  fastify.get('/idp/interaction/:uid', async (request, reply) => {
    return handleInteractionGet(request, reply, provider);
  });

  // POST login
  fastify.post('/idp/interaction/:uid/login', async (request, reply) => {
    return handleLogin(request, reply, provider);
  });

  // POST consent
  fastify.post('/idp/interaction/:uid/confirm', async (request, reply) => {
    return handleConsent(request, reply, provider);
  });

  // POST abort
  fastify.post('/idp/interaction/:uid/abort', async (request, reply) => {
    return handleAbort(request, reply, provider);
  });

  fastify.log.info(`IdP initialized with issuer: ${issuer}`);
}

export default idpPlugin;
