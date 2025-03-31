import { createPrivateKey, createPublicKey } from 'crypto';
import * as jose from 'jose';

// In-memory user store for demo (would use a database in production)
const users = new Map();

export const handleIdentity = {
  // Return OpenID configuration
  getOpenIDConfig: async (request, reply) => {
    return {
      issuer: `https://${request.hostname}`,
      authorization_endpoint: `https://${request.hostname}/authorize`,
      token_endpoint: `https://${request.hostname}/token`,
      jwks_uri: `https://${request.hostname}/jwks`,
      registration_endpoint: `https://${request.hostname}/register`,
      scopes_supported: ['openid', 'profile', 'email'],
      response_types_supported: ['code', 'token', 'id_token'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256']
    };
  },

  // Handle user registration
  register: async (request, reply) => {
    const { username, password, email } = request.body;

    if (users.has(username)) {
      reply.code(409);
      return { error: 'Username already exists' };
    }

    // Create WebID URL
    const webId = `https://${request.hostname}/profile/${username}#me`;

    // Store user
    users.set(username, {
      username,
      password, // In production, this would be hashed
      email,
      webId,
      pods: [`https://${request.hostname}/${username}/`]
    });

    return {
      webId,
      status: 'created'
    };
  },

  // Handle login and token generation
  login: async (request, reply) => {
    const { username, password } = request.body;

    const user = users.get(username);
    if (!user || user.password !== password) {
      reply.code(401);
      return { error: 'Invalid credentials' };
    }

    // For MVP, we'll use a simple JWT token
    // In production, you would use proper OIDC flow
    const token = await new jose.SignJWT({
      sub: user.webId,
      iss: `https://${request.hostname}`,
      aud: `https://${request.hostname}`
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('1h')
      .sign(new TextEncoder().encode('secret-key-would-be-env-var'));

    return {
      id_token: token,
      token_type: 'Bearer',
      expires_in: 3600
    };
  }
};
