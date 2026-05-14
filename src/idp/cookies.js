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

/**
 * Expire oidc-provider session cookies on a Fastify reply.
 *
 * Used by account deletion (credentials.js) and account switching
 * (interactions.js) to prevent stale session references from crashing
 * oidc-provider's consent check (#452).
 *
 * @param {object} reply - Fastify reply object
 */
export function expireSessionCookies(reply) {
  const expired = 'Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax';
  reply.header('Set-Cookie', SESSION_COOKIE_NAMES.map(
    (name) => `${name}=; ${expired}`,
  ));
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
  const expired = 'Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax';
  ctx.set('Set-Cookie', SESSION_COOKIE_NAMES.map(
    (name) => `${name}=; ${expired}`,
  ));
}
