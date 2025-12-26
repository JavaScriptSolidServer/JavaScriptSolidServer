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
      long: {
        signed: true,
        maxAge: 14 * 24 * 60 * 60 * 1000, // 14 days
        httpOnly: true,
        sameSite: 'lax',
      },
      short: {
        signed: true,
        httpOnly: true,
        sameSite: 'lax',
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

      // Allow resource parameter
      resourceIndicators: {
        enabled: true,
        defaultResource: () => undefined,
        getResourceServerInfo: () => ({
          scope: 'openid webid profile email offline_access',
          accessTokenFormat: 'jwt',
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
    claims: {
      openid: ['sub'],
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

    // Enable refresh token rotation
    rotateRefreshToken: (ctx) => {
      return true;
    },

    // Client defaults
    clientDefaults: {
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none', // Public clients by default
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

    // Enable request parameter
    requestObjects: {
      request: false,
      requestUri: false,
    },

    // Clock tolerance for token validation
    clockTolerance: 60, // 60 seconds

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
