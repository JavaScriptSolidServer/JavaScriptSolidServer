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
  handleSwitchAccount,
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
  handleChangePassword,
  handleDeleteAccount,
  handleAccountDeleteForm,
  setNoCacheClickjackHeaders,
} from './credentials.js';
import { handleExportAccount } from './export.js';
import * as passkey from './passkey.js';
import { addTrustedIssuer } from '../auth/solid-oidc.js';
import { landingPage, accountDeletePage } from './views.js';

/**
 * IdP Fastify Plugin
 * @param {FastifyInstance} fastify
 * @param {object} options
 * @param {string} options.issuer - The issuer URL
 * @param {boolean} [options.inviteOnly=false] - If true, /idp/register
 *   requires a valid invite code; public registration is disabled.
 * @param {boolean} [options.singleUser=false] - Single-user mode.
 *   Disables /idp/register and /idp/account DELETE; gates the
 *   single-user branch in /idp/account/export.
 * @param {string|null} [options.singleUserName=null] - Single-user
 *   pod name. null → root pod (podDir = dataRoot); string → pod
 *   lives at <dataRoot>/<name>/. Threaded into /idp/account/export
 *   so the handler can resolve podDir + apply ROOT_POD_EXCLUDE.
 * @param {string} [options.jssVersion] - Server version, written
 *   into the export manifest for forensic / "what server made this"
 *   purposes. Defaults to 'unknown' inside the export handler.
 */
export async function idpPlugin(fastify, options) {
  const { issuer, inviteOnly = false, singleUser = false, singleUserName = null, jssVersion } = options;

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
  const oidcPaths = ['/idp/token', '/idp/reg', '/idp/me', '/idp/session', '/idp/session/*'];

  for (const path of oidcPaths) {
    fastify.route({
      method: ['GET', 'POST', 'DELETE', 'OPTIONS'],
      url: path,
      handler: forwardToProvider,
    });
  }

  // /idp/auth: guard against the human-fat-fingered case where someone opens
  // the URL directly with no `client_id`. oidc-provider would otherwise
  // return a raw `invalid_request` error page; we 302 to the friendly
  // landing instead. Real OIDC requests (with client_id) pass through.
  fastify.route({
    // HEAD is listed explicitly so the route's contract doesn't depend on
    // Fastify's auto-HEAD-from-GET (which `exposeHeadRoutes` can disable);
    // the handler below treats HEAD the same as GET for the bare-client_id
    // redirect.
    method: ['GET', 'HEAD', 'POST', 'DELETE', 'OPTIONS'],
    url: '/idp/auth',
    handler: async (request, reply) => {
      // Only catch the truly-bare case (no `client_id` param at all). An
      // explicit empty string is a malformed OIDC request — let
      // oidc-provider surface the spec error instead of redirecting.
      if (
        (request.method === 'GET' || request.method === 'HEAD') &&
        request.query?.client_id === undefined
      ) {
        return reply.redirect('/idp');
      }
      return forwardToProvider(request, reply);
    },
  });

  // Also handle /idp/auth/:uid for continued authorization after login
  fastify.get('/idp/auth/:uid', forwardToProvider);

  // Friendly landing — Create Account button + sign-in note.
  // Pairs with the /idp/auth guard above so a human visitor lands here
  // rather than on a raw OIDC error.
  fastify.get('/idp', async (request, reply) => {
    return reply.type('text/html').send(landingPage({ baseUri: issuer, singleUser }));
  });

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

  // PUT credentials - authenticated owner rotates their own password (#351)
  fastify.put('/idp/credentials', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    return handleChangePassword(request, reply);
  });

  // DELETE account - authenticated owner deletes their own account (#352).
  // Single-user mode is rejected at the handler (deletion would leave the
  // server with no IDP account until re-seed; CLI is the operator path).
  fastify.delete('/idp/account', {
    config: {
      rateLimit: {
        max: 5,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    return handleDeleteAccount(request, reply, { singleUser });
  });

  // GET account export — authenticated owner downloads their pod tree as
  // a streamed tar.gz (#353). MVP slice of the Credible Exit ladder
  // (#448). Lighter rate-limit than the destructive endpoints — this is
  // a read, but a heavy one (entire pod), so cap at 3/min to deter
  // abuse without blocking a legitimate operator pulling a backup.
  //
  // Keyed by IP, consistent with the other /idp/ endpoints. We can't
  // honestly key by WebID here: the global auth hook in src/server.js
  // skips /idp/* (so request.webId is unset at this phase) and the
  // rate-limit keyGenerator is sync, so we can't await token
  // verification inline. Per-user keying is a follow-up that needs
  // a preParsing hook resolving auth before the limiter runs.
  fastify.get('/idp/account/export', {
    config: {
      rateLimit: {
        max: 3,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    return handleExportAccount(request, reply, {
      singleUser,
      singleUserName,
      jssVersion,
    });
  });

  // GET account-delete form (#392) - human-friendly UI for #352. Public
  // unauthenticated page; auth happens at form submission via password.
  // Single-user mode returns 403 to stay consistent with /idp/register's
  // disabled-route policy and the JSON DELETE /idp/account endpoint
  // (which also 403s in single-user mode). Body is still HTML so a
  // browser visitor sees the explanation. Every response sets
  // anti-clickjacking + no-store headers — destructive-action page.
  fastify.get('/idp/account/delete', async (request, reply) => {
    setNoCacheClickjackHeaders(reply);
    if (singleUser) {
      return reply.code(403).type('text/html').send(accountDeletePage({ singleUser: true }));
    }
    return reply.type('text/html').send(accountDeletePage({ singleUser: false }));
  });

  // POST account-delete form (#392) - processes the form submission.
  // Same rate-limit as the JSON endpoint to keep the destructive-action
  // surface consistent across both paths.
  fastify.post('/idp/account/delete', {
    config: {
      rateLimit: {
        max: 5,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, async (request, reply) => {
    return handleAccountDeleteForm(request, reply, { singleUser });
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

  // POST "Sign in as a different user" (#384) — destroys the OIDC
  // session and bounces back to the login prompt while preserving the
  // in-flight authz request.
  fastify.post('/idp/interaction/:uid/switch', async (request, reply) => {
    return handleSwitchAccount(request, reply, provider);
  });

  // Registration routes (disabled in single-user mode)
  if (singleUser) {
    // Single-user mode: registration disabled
    fastify.get('/idp/register', async (request, reply) => {
      return reply.code(403).type('text/html').send(`
        <!DOCTYPE html>
        <html><head><title>Registration Disabled</title></head>
        <body style="font-family: system-ui; padding: 2rem; text-align: center;">
          <h1>Registration Disabled</h1>
          <p>This server is running in single-user mode. Registration is not available.</p>
          <p><a href="/idp/login">Login</a></p>
        </body></html>
      `);
    });
    fastify.post('/idp/register', async (request, reply) => {
      return reply.code(403).send({ error: 'Registration disabled in single-user mode' });
    });
  } else {
    fastify.get('/idp/register', async (request, reply) => {
      return handleRegisterGet(request, reply, issuer, inviteOnly);
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
  }

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
  fastify.post('/idp/interaction/:uid/schnorr-login', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute'
      }
    }
  }, async (request, reply) => {
    return handleSchnorrLogin(request, reply, provider);
  });

  fastify.get('/idp/interaction/:uid/schnorr-complete', async (request, reply) => {
    return handleSchnorrComplete(request, reply, provider);
  });

  const modeInfo = singleUser ? ' (single-user mode, registration disabled)' : inviteOnly ? ' (invite-only)' : '';
  fastify.log.info(`IdP initialized with issuer: ${issuer}${modeInfo}`);
}

export default idpPlugin;
