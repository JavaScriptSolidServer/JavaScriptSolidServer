/**
 * Top-level Fastify error handler that logs the full stack for any 5xx.
 *
 * Without this, 500 responses carry only Fastify's default 91-byte body and
 * leave no trace in logs — production debugging has to infer the exception
 * from the response body alone (see #309 investigation for why that's bad).
 *
 * 4xx errors carry their own statusCode and don't need stack logging — they
 * are expected client errors with self-explanatory messages.
 */
export function registerErrorHandler(fastify) {
  fastify.setErrorHandler(function (err, request, reply) {
    const statusCode = err.statusCode ?? 500;
    if (statusCode >= 500) {
      request.log.error({
        err,
        method: request.method,
        url: request.url,
        hostname: request.hostname
      }, 'Unhandled 5xx error');
    }
    reply.send(err);
  });
}
