/**
 * Shared cookie helpers for the IdP module.
 *
 * JSS doesn't register @fastify/cookie, so we emit Set-Cookie headers
 * directly. oidc-provider sets four session cookies (_session,
 * _session.sig, _session.legacy, _session.legacy.sig); all four must
 * be expired together to fully clear the browser's session state.
 */

const SESSION_COOKIE_NAMES = [
  '_session',
  '_session.sig',
  '_session.legacy',
  '_session.legacy.sig',
];

function buildExpiredHeaders(secure) {
  const attrs = 'Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax'
    + (secure ? '; Secure' : '');
  return SESSION_COOKIE_NAMES.map((name) => `${name}=; ${attrs}`);
}

/**
 * Expire oidc-provider session cookies on a Fastify reply.
 *
 * Used by account deletion (credentials.js) and account switching
 * (interactions.js) to prevent stale session references from crashing
 * oidc-provider's consent check (#452).
 *
 * @param {object} reply - Fastify reply object
 * @param {object} [request] - Fastify request (used to detect HTTPS)
 */
export function expireSessionCookies(reply, request) {
  const secure = request?.protocol === 'https' || process.env.NODE_ENV === 'production';
  reply.header('Set-Cookie', buildExpiredHeaders(secure));
}

/**
 * Expire oidc-provider session cookies on a Koa context.
 *
 * Used by renderError in provider.js for stale-session recovery,
 * where the response object is a Koa ctx, not a Fastify reply.
 *
 * @param {object} ctx - Koa context object
 */
export function expireSessionCookiesKoa(ctx) {
  const secure = ctx.secure || process.env.NODE_ENV === 'production';
  ctx.set('Set-Cookie', buildExpiredHeaders(secure));
}
