import Fastify from 'fastify';
import cors from '@fastify/cors';
import { handleIdentity } from '../identity/provider.js';
import { handleAuthorization } from '../auth/authorization.js';
import { handleStorage } from '../storage/engine.js';

export async function startServer (port) {
  const fastify = Fastify({
    logger: true,
    trustProxy: true
  });

  // Register plugins
  await fastify.register(cors, {
    origin: true
  });

  // Register routes
  // Identity routes
  fastify.get('/.well-known/openid-configuration', handleIdentity.getOpenIDConfig);
  fastify.post('/register', handleIdentity.register);
  fastify.post('/login', handleIdentity.login);

  // Storage/Pod routes
  fastify.get('/*', async (request, reply) => {
    await handleAuthorization(request, reply);
    return handleStorage.get(request, reply);
  });

  fastify.put('/*', async (request, reply) => {
    await handleAuthorization(request, reply);
    return handleStorage.put(request, reply);
  });

  fastify.delete('/*', async (request, reply) => {
    await handleAuthorization(request, reply);
    return handleStorage.delete(request, reply);
  });

  fastify.patch('/*', async (request, reply) => {
    await handleAuthorization(request, reply);
    return handleStorage.patch(request, reply);
  });

  fastify.head('/*', async (request, reply) => {
    await handleAuthorization(request, reply);
    return handleStorage.head(request, reply);
  });

  try {
    await fastify.listen({ port, host: '0.0.0.0' });
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}
