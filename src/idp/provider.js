/**
 * oidc-provider configuration for Solid-OIDC
 * Configures the OpenID Connect provider with DPoP support and webid claim
 */

import Provider from 'oidc-provider';
import { createAdapter } from './adapter.js';
import { getJwks, getCookieKeys } from './keys.js';
import { getAccountForProvider } from './accounts.js';

/**
 * Create and configure the OIDC provider
 * @param {string} issuer - The issuer URL (e.g., 'https://example.com')
 * @returns {Promise<Provider>} - Configured oidc-provider instance
 */
export async function createProvider(issuer) {
  const jwks = await getJwks();
  const cookieKeys = await getCookieKeys();

  const configuration = {
    // Use our filesystem adapter
    adapter: createAdapter,

    // Signing keys
    jwks,

    // Cookie configuration
    cookies: {
      keys: cookieKeys,
      // Use root path so cookies work across all endpoints
      long: {
        signed: true,
        maxAge: 14 * 24 * 60 * 60 * 1000, // 14 days
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
      },
      short: {
        signed: true,
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
      },
    },

    // Token TTLs
    ttl: {
      AccessToken: 3600,           // 1 hour
      AuthorizationCode: 600,      // 10 minutes
      IdToken: 3600,               // 1 hour
      RefreshToken: 14 * 24 * 3600, // 14 days
      Interaction: 3600,           // 1 hour
      Session: 14 * 24 * 3600,     // 14 days
      Grant: 14 * 24 * 3600,       // 14 days
    },

    // Features - configure for Solid-OIDC
    features: {
      // Disable dev interactions - we provide our own
      devInteractions: {
        enabled: false,
      },

      // DPoP is REQUIRED for Solid-OIDC
      dPoP: {
        enabled: true,
      },

      // Dynamic client registration (Solid apps need this)
      registration: {
        enabled: true,
        idFactory: () => {
          // Generate random client ID
          return `client_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
        },
        initialAccessToken: false, // Allow public registration
        policies: undefined,       // No restrictions
      },

      // Client credentials for machine-to-machine
      clientCredentials: {
        enabled: true,
      },

      // Token introspection for resource servers
      introspection: {
        enabled: true,
      },

      // Token revocation
      revocation: {
        enabled: true,
      },

      // Device flow (optional, but useful for CLI apps)
      deviceFlow: {
        enabled: false, // Keep disabled for MVP
      },

      // Allow resource parameter - always use JWT format for access tokens
      // Resource must be a valid URI, but audience can be 'solid' for Solid-OIDC
      resourceIndicators: {
        enabled: true,
        // Default to a URI resource that maps to audience 'solid'
        defaultResource: () => 'urn:solid',
        getResourceServerInfo: () => ({
          scope: 'openid webid profile email offline_access',
          accessTokenFormat: 'jwt',
          audience: 'solid', // Solid-OIDC requires this audience
        }),
        useGrantedResource: () => true,
      },

      // userinfo endpoint
      userinfo: {
        enabled: true,
      },

      // Allow backchannel logout
      backchannelLogout: {
        enabled: false,
      },

      // RP-initiated logout
      rpInitiatedLogout: {
        enabled: true,
        postLogoutSuccessSource: async (ctx) => {
          ctx.body = `
            <!DOCTYPE html>
            <html>
            <head><title>Logged Out</title></head>
            <body style="font-family: sans-serif; text-align: center; padding: 50px;">
              <h1>You have been logged out</h1>
              <p>You can close this window.</p>
            </body>
            </html>
          `;
        },
      },
    },

    // Token format - JWT for Solid-OIDC
    formats: {
      AccessToken: 'jwt',
      ClientCredentials: 'jwt',
    },

    // Scopes supported
    scopes: ['openid', 'webid', 'profile', 'email', 'offline_access'],

    // Claims configuration
    // Always include webid with openid scope for Solid-OIDC compliance
    claims: {
      openid: ['sub', 'webid'],
      webid: ['webid'],
      profile: ['name'],
      email: ['email', 'email_verified'],
    },

    // Find account by ID (for token generation)
    findAccount: async (ctx, id) => {
      return getAccountForProvider(id);
    },

    // Extra access token claims for Solid-OIDC
    extraTokenClaims: async (ctx, token) => {
      if (token.accountId) {
        const account = await getAccountForProvider(token.accountId);
        if (account) {
          const claims = await account.claims('access_token', token.scopes, {}, []);
          return {
            webid: claims.webid,
          };
        }
      }
      return {};
    },

    // Interaction URL for login/consent
    interactions: {
      url: (ctx, interaction) => {
        return `/idp/interaction/${interaction.uid}`;
      },
    },

    // Auto-approve consent by loading/creating grants automatically
    // This skips the consent prompt for all clients (appropriate for test/dev servers)
    loadExistingGrant: async (ctx) => {
      // Check if there's an existing grant for this client/account pair
      const grantId = ctx.oidc.session?.grantIdFor(ctx.oidc.client?.clientId);

      if (grantId) {
        const existingGrant = await ctx.oidc.provider.Grant.find(grantId);
        if (existingGrant) {
          return existingGrant;
        }
      }

      // Auto-approve: create a new grant with all requested scopes
      if (ctx.oidc.session?.accountId && ctx.oidc.client?.clientId) {
        const grant = new ctx.oidc.provider.Grant({
          accountId: ctx.oidc.session.accountId,
          clientId: ctx.oidc.client.clientId,
        });

        // Grant all requested OIDC scopes
        if (ctx.oidc.params?.scope) {
          grant.addOIDCScope(ctx.oidc.params.scope);
        }

        // Grant all requested resource scopes
        if (ctx.oidc.params?.resource) {
          const resources = Array.isArray(ctx.oidc.params.resource)
            ? ctx.oidc.params.resource
            : [ctx.oidc.params.resource];
          for (const resource of resources) {
            grant.addResourceScope(resource, ctx.oidc.params.scope || 'openid');
          }
        }

        await grant.save();
        return grant;
      }

      return undefined;
    },

    // Configure routes with /idp prefix so oidc-provider uses correct paths
    routes: {
      authorization: '/idp/auth',
      token: '/idp/token',
      userinfo: '/idp/me',
      jwks: '/.well-known/jwks.json',
      registration: '/idp/reg',
      introspection: '/idp/token/introspection',
      revocation: '/idp/token/revocation',
      end_session: '/idp/session/end',
    },

    // Enable refresh token rotation
    rotateRefreshToken: (ctx) => {
      return true;
    },

    // Client defaults
    clientDefaults: {
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none', // Public clients by default
      id_token_signed_response_alg: 'ES256', // ES256 is what we support
    },

    // Response modes
    responseModes: ['query', 'fragment', 'form_post'],

    // Subject types
    subjectTypes: ['public'],

    // PKCE methods - require PKCE for public clients
    pkceMethods: ['S256'],
    pkce: {
      required: () => true,
      methods: ['S256'],
    },

    // Enable RS256 for DPoP (CTH uses RS256)
    enabledJWA: {
      dPoPSigningAlgValues: ['ES256', 'RS256', 'Ed25519', 'EdDSA'],
    },

    // Enable request parameter
    requestObjects: {
      request: false,
      requestUri: false,
    },

    // Clock tolerance for token validation
    clockTolerance: 60, // 60 seconds

    // Allow CORS for browser-based clients
    // This is needed for web apps like Mashlib loaded from CDN
    clientBasedCORS: (ctx, origin, client) => {
      // Allow all origins for public clients (no client_secret)
      if (client.tokenEndpointAuthMethod === 'none') {
        return true;
      }
      // For confidential clients, allow if origin matches a registered redirect_uri
      // This is safe because the client was registered with this redirect_uri
      if (client.redirectUris && Array.isArray(client.redirectUris)) {
        for (const uri of client.redirectUris) {
          try {
            const redirectOrigin = new URL(uri).origin;
            if (redirectOrigin === origin) {
              return true;
            }
          } catch (e) {
            // Invalid URL, skip
          }
        }
      }
      // Also allow if application_type is 'web' - browser apps need CORS
      if (client.applicationType === 'web') {
        return true;
      }
      return false;
    },

    // Render errors
    renderError: async (ctx, out, error) => {
      ctx.type = 'html';
      ctx.body = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Error</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 40px; max-width: 600px; margin: 0 auto; }
            .error { background: #fee; border: 1px solid #fcc; padding: 20px; border-radius: 8px; }
            h1 { color: #c00; margin-top: 0; }
            pre { background: #f5f5f5; padding: 10px; overflow-x: auto; }
          </style>
        </head>
        <body>
          <div class="error">
            <h1>Authentication Error</h1>
            <p><strong>${out.error}</strong></p>
            <p>${out.error_description || ''}</p>
          </div>
        </body>
        </html>
      `;
    },
  };

  const provider = new Provider(issuer, configuration);

  // Allow localhost for development
  provider.proxy = true;

  return provider;
}
