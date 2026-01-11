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
  handleRegisterGet,
  handleRegisterPost,
  handlePasskeyComplete,
  handlePasskeySkip,
  handleSchnorrLogin,
  handleSchnorrComplete,
} from './interactions.js';
import {
  handleCredentials,
  handleCredentialsInfo,
} from './credentials.js';
import * as passkey from './passkey.js';
import { addTrustedIssuer } from '../auth/solid-oidc.js';

/**
 * IdP Fastify Plugin
 * @param {FastifyInstance} fastify
 * @param {object} options
 * @param {string} options.issuer - The issuer URL
 */
export async function idpPlugin(fastify, options) {
  const { issuer, inviteOnly = false } = options;

  if (!issuer) {
    throw new Error('IdP requires issuer URL');
  }

  // Register our own issuer as trusted (bypasses SSRF check for self-validation)
  addTrustedIssuer(issuer);

  // Initialize signing keys
  await initializeKeys();

  // Create the OIDC provider
  const provider = await createProvider(issuer);

  // Add error listener to catch internal oidc-provider errors
  provider.on('server_error', (ctx, err) => {
    fastify.log.error({
      err: err.message,
      stack: err.stack,
      path: ctx?.path,
      cause: err.cause?.message,
      error_description: err.error_description,
    }, 'oidc-provider server error');
  });
  provider.on('grant.error', (ctx, err) => {
    fastify.log.error({
      err: err.message,
      stack: err.stack?.substring(0, 800),
      cause: err.cause?.message,
      error_description: err.error_description,
    }, 'oidc-provider grant error');
  });

  // Store provider reference on fastify for handlers
  fastify.decorate('oidcProvider', provider);

  // Register middleware support for oidc-provider (Koa app)
  await fastify.register(middie);

  // Helper to forward requests to oidc-provider
  const forwardToProvider = async (request, reply) => {
    return new Promise((resolve, reject) => {
      // Get raw Node.js req/res
      const req = request.raw;
      const res = reply.raw;

      // Set CORS headers on raw response before oidc-provider handles it
      // This is needed because oidc-provider writes directly to the raw response
      const origin = request.headers.origin;
      if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Accept, Authorization, Content-Type, DPoP, If-Match, If-None-Match, Link, Slug, Origin');
        res.setHeader('Access-Control-Expose-Headers', 'Accept-Patch, Accept-Post, Allow, Content-Type, ETag, Link, Location, Updates-Via, WAC-Allow');
        res.setHeader('Access-Control-Max-Age', '86400');
      }

      // Handle OPTIONS preflight requests directly
      if (request.method === 'OPTIONS') {
        res.statusCode = 204;
        res.end();
        return resolve();
      }

      // oidc-provider is now configured with /idp routes, no stripping needed
      // Ensure parsed body is accessible to oidc-provider
      // Fastify parses body into request.body, oidc-provider looks for req.body
      if (request.body !== undefined) {
        if (Buffer.isBuffer(request.body)) {
          // Parse buffer to object if it's JSON
          const contentType = request.headers['content-type'] || '';
          if (contentType.includes('application/json')) {
            try {
              req.body = JSON.parse(request.body.toString());
            } catch (e) {
              req.body = request.body;
            }
          } else if (contentType.includes('application/x-www-form-urlencoded')) {
            // Parse form data
            const params = new URLSearchParams(request.body.toString());
            req.body = Object.fromEntries(params.entries());
          } else {
            req.body = request.body;
          }
        } else {
          req.body = request.body;
        }
      }

      // Call oidc-provider's callback
      provider.callback()(req, res);

      // Wait for response to finish
      res.on('finish', resolve);
      res.on('error', reject);
    });
  };

  // Legacy handler for /auth/:uid without prefix - redirect to /idp/auth/:uid
  // In case any old redirects or cached URLs exist
  fastify.get('/auth/:uid', async (request, reply) => {
    return reply.redirect(`/idp/auth/${request.params.uid}`);
  });

  // Catch-all route for oidc-provider paths
  // Must be registered BEFORE specific routes to be matched as fallback
  const oidcPaths = ['/idp/auth', '/idp/token', '/idp/reg', '/idp/me', '/idp/session', '/idp/session/*'];

  for (const path of oidcPaths) {
    fastify.route({
      method: ['GET', 'POST', 'DELETE', 'OPTIONS'],
      url: path,
      handler: forwardToProvider,
    });
  }

  // Also handle /idp/auth/:uid for continued authorization after login
  fastify.get('/idp/auth/:uid', forwardToProvider);

  // Token sub-paths
  fastify.route({
    method: ['GET', 'POST'],
    url: '/idp/token/introspection',
    handler: forwardToProvider,
  });

  fastify.route({
    method: ['GET', 'POST'],
    url: '/idp/token/revocation',
    handler: forwardToProvider,
  });

  // /.well-known/openid-configuration
  fastify.get('/.well-known/openid-configuration', async (request, reply) => {
    // Ensure issuer has trailing slash for CTH compatibility
    const normalizedIssuer = issuer.endsWith('/') ? issuer : issuer + '/';
    // Base URL without trailing slash for building endpoint URLs
    const baseUrl = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
    // Build discovery document
    const config = {
      issuer: normalizedIssuer,
      authorization_endpoint: `${baseUrl}/idp/auth`,
      token_endpoint: `${baseUrl}/idp/token`,
      userinfo_endpoint: `${baseUrl}/idp/me`,
      jwks_uri: `${baseUrl}/.well-known/jwks.json`,
      registration_endpoint: `${baseUrl}/idp/reg`,
      introspection_endpoint: `${baseUrl}/idp/token/introspection`,
      revocation_endpoint: `${baseUrl}/idp/token/revocation`,
      end_session_endpoint: `${baseUrl}/idp/session/end`,
      scopes_supported: ['openid', 'webid', 'profile', 'email', 'offline_access'],
      response_types_supported: ['code'],
      response_modes_supported: ['query', 'fragment', 'form_post'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256', 'ES256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      claims_supported: ['sub', 'webid', 'name', 'email', 'email_verified'],
      code_challenge_methods_supported: ['S256'],
      dpop_signing_alg_values_supported: ['ES256', 'RS256'],
      // RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification
      authorization_response_iss_parameter_supported: true,
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

  // Programmatic credentials endpoint for CTH compatibility
  // Allows obtaining tokens via email/password without browser interaction

  // GET credentials info
  fastify.get('/idp/credentials', async (request, reply) => {
    return handleCredentialsInfo(request, reply, issuer);
  });

  // POST credentials - obtain tokens (with rate limiting for brute force protection)
  fastify.post('/idp/credentials', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    return handleCredentials(request, reply, issuer);
  });

  // Interaction routes (our custom login/consent UI)
  // These bypass oidc-provider and use our handlers

  // GET interaction - show login or consent page
  fastify.get('/idp/interaction/:uid', async (request, reply) => {
    return handleInteractionGet(request, reply, provider);
  });

  // POST interaction - direct form submission (CTH compatibility)
  // This handles form submissions directly to /idp/interaction/:uid
  // Rate limited to prevent brute force attacks
  fastify.post('/idp/interaction/:uid', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    return handleLogin(request, reply, provider);
  });

  // POST login (explicit path) - rate limited
  fastify.post('/idp/interaction/:uid/login', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
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

  // Registration routes
  fastify.get('/idp/register', async (request, reply) => {
    return handleRegisterGet(request, reply, inviteOnly);
  });

  // Registration - rate limited to prevent spam accounts
  fastify.post('/idp/register', {
    config: {
      rateLimit: {
        max: 5,
        timeWindow: '1 hour',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    return handleRegisterPost(request, reply, issuer, inviteOnly);
  });

  // Passkey routes
  // Registration options - rate limited to prevent DoS
  fastify.post('/idp/passkey/register/options', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    return passkey.registrationOptions(request, reply);
  });

  // Registration verify - rate limited
  fastify.post('/idp/passkey/register/verify', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    return passkey.registrationVerify(request, reply);
  });

  // Login options - rate limited to prevent DoS
  fastify.post('/idp/passkey/login/options', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    return passkey.authenticationOptions(request, reply);
  });

  // Login verify - rate limited
  fastify.post('/idp/passkey/login/verify', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    return passkey.authenticationVerify(request, reply);
  });

  // Passkey interaction handlers
  fastify.get('/idp/interaction/:uid/passkey-complete', async (request, reply) => {
    return handlePasskeyComplete(request, reply, provider);
  });

  fastify.get('/idp/interaction/:uid/passkey-skip', async (request, reply) => {
    return handlePasskeySkip(request, reply, provider);
  });

  // Schnorr (NIP-98) interaction handlers
  fastify.post('/idp/interaction/:uid/schnorr-login', async (request, reply) => {
    return handleSchnorrLogin(request, reply, provider);
  });

  fastify.get('/idp/interaction/:uid/schnorr-complete', async (request, reply) => {
    return handleSchnorrComplete(request, reply, provider);
  });

  fastify.log.info(`IdP initialized with issuer: ${issuer}`);
}

export default idpPlugin;
