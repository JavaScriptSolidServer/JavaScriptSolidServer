import * as storage from '../storage/filesystem.js';
import { getAllHeaders, getNotFoundHeaders } from '../ldp/headers.js';
import { generateContainerJsonLd, serializeJsonLd } from '../ldp/container.js';
import { isContainer, getContentType, isRdfContentType, getEffectiveUrlPath } from '../utils/url.js';
import { parseN3Patch, applyN3Patch, validatePatch } from '../patch/n3-patch.js';
import { parseSparqlUpdate, applySparqlUpdate } from '../patch/sparql-update.js';
import {
  selectContentType,
  canAcceptInput,
  toJsonLd,
  fromJsonLd,
  getVaryHeader,
  RDF_TYPES
} from '../rdf/conneg.js';
import { emitChange } from '../notifications/events.js';
import { checkIfMatch, checkIfNoneMatchForGet, checkIfNoneMatchForWrite } from '../utils/conditional.js';
import { generateDatabrowserHtml, shouldServeMashlib } from '../mashlib/index.js';

/**
 * Get the storage path and resource URL for a request
 * In subdomain mode, storage path includes pod name, URL uses subdomain
 */
function getRequestPaths(request) {
  const urlPath = request.url.split('?')[0];
  // Storage path - includes pod name in subdomain mode
  const storagePath = getEffectiveUrlPath(request);
  // Resource URL - uses the actual request hostname (subdomain in subdomain mode)
  const resourceUrl = `${request.protocol}://${request.hostname}${urlPath}`;
  return { urlPath, storagePath, resourceUrl };
}

/**
 * Handle GET request
 */
export async function handleGet(request, reply) {
  const { urlPath, storagePath, resourceUrl } = getRequestPaths(request);
  const stats = await storage.stat(storagePath);

  if (!stats) {
    const origin = request.headers.origin;
    const connegEnabled = request.connegEnabled || false;
    const headers = getNotFoundHeaders({ resourceUrl, origin, connegEnabled });
    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.code(404).send({ error: 'Not Found' });
  }

  // Check If-None-Match for conditional GET (304 Not Modified)
  const ifNoneMatch = request.headers['if-none-match'];
  if (ifNoneMatch) {
    const check = checkIfNoneMatchForGet(ifNoneMatch, stats.etag);
    if (!check.ok && check.notModified) {
      return reply.code(304).send();
    }
  }

  const origin = request.headers.origin;

  // Handle container
  if (stats.isDirectory) {
    const connegEnabled = request.connegEnabled || false;

    // Check for index.html (serves as both profile and container representation)
    const indexPath = storagePath.endsWith('/') ? `${storagePath}index.html` : `${storagePath}/index.html`;
    const indexExists = await storage.exists(indexPath);

    if (indexExists) {
      // Serve index.html (contains JSON-LD structured data)
      const content = await storage.read(indexPath);
      const indexStats = await storage.stat(indexPath);

      // Check if RDF format requested via content negotiation
      const acceptHeader = request.headers.accept || '';
      const wantsTurtle = connegEnabled && (
        acceptHeader.includes('text/turtle') ||
        acceptHeader.includes('text/n3') ||
        acceptHeader.includes('application/n-triples')
      );

      if (wantsTurtle) {
        // Extract JSON-LD from HTML and convert to Turtle
        try {
          const htmlStr = content.toString();
          const jsonLdMatch = htmlStr.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
          if (jsonLdMatch) {
            const jsonLd = JSON.parse(jsonLdMatch[1]);
            const { content: turtleContent } = await fromJsonLd(
              jsonLd,
              'text/turtle',
              resourceUrl,
              true
            );

            const headers = getAllHeaders({
              isContainer: true,
              etag: indexStats?.etag || stats.etag,
              contentType: 'text/turtle',
              origin,
              resourceUrl,
              connegEnabled
            });

            Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
            return reply.send(turtleContent);
          }
        } catch (err) {
          // Fall through to serve HTML if conversion fails
          console.error('Failed to convert profile to Turtle:', err.message);
        }
      }

      const headers = getAllHeaders({
        isContainer: true,
        etag: indexStats?.etag || stats.etag,
        contentType: 'text/html',
        origin,
        resourceUrl,
        connegEnabled
      });

      Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
      return reply.send(content);
    }

    // No index.html, return JSON-LD container listing
    const entries = await storage.listContainer(storagePath);
    const jsonLd = generateContainerJsonLd(resourceUrl, entries || []);

    // Check if we should serve Mashlib data browser for containers
    if (shouldServeMashlib(request, request.mashlibEnabled, 'application/ld+json')) {
      const cdnVersion = request.mashlibCdn ? request.mashlibVersion : null;
      const html = generateDatabrowserHtml(resourceUrl, cdnVersion);
      const headers = getAllHeaders({
        isContainer: true,
        etag: stats.etag,
        contentType: 'text/html',
        origin,
        resourceUrl,
        connegEnabled
      });
      headers['Vary'] = 'Accept';
      headers['X-Frame-Options'] = 'DENY';
      headers['Content-Security-Policy'] = "frame-ancestors 'none'";
      headers['Cache-Control'] = 'no-store';

      Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
      return reply.type('text/html').send(html);
    }

    // Check if Turtle/N3 format is requested via content negotiation
    const acceptHeader = request.headers.accept || '';
    const wantsTurtle = connegEnabled && (
      acceptHeader.includes('text/turtle') ||
      acceptHeader.includes('text/n3') ||
      acceptHeader.includes('application/n-triples')
    );

    if (wantsTurtle) {
      // Convert container JSON-LD to Turtle
      try {
        const { content: turtleContent } = await fromJsonLd(
          jsonLd,
          'text/turtle',
          resourceUrl,
          true
        );

        const headers = getAllHeaders({
          isContainer: true,
          etag: stats.etag,
          contentType: 'text/turtle',
          origin,
          resourceUrl,
          connegEnabled
        });
        headers['Vary'] = 'Accept';

        Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
        return reply.send(turtleContent);
      } catch (err) {
        // Fall through to JSON-LD if conversion fails
        console.error('Failed to convert container to Turtle:', err.message);
      }
    }

    const headers = getAllHeaders({
      isContainer: true,
      etag: stats.etag,
      contentType: 'application/ld+json',
      origin,
      resourceUrl,
      connegEnabled
    });

    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.send(serializeJsonLd(jsonLd));
  }

  // Handle resource
  const storedContentType = getContentType(storagePath);
  const connegEnabled = request.connegEnabled || false;

  // Check if we should serve Mashlib data browser
  // Only for RDF resources when Accept: text/html is requested
  if (shouldServeMashlib(request, request.mashlibEnabled, storedContentType)) {
    // Pass CDN version if using CDN mode, null for local mode
    const cdnVersion = request.mashlibCdn ? request.mashlibVersion : null;
    const html = generateDatabrowserHtml(resourceUrl, cdnVersion);
    const headers = getAllHeaders({
      isContainer: false,
      etag: stats.etag,
      contentType: 'text/html',
      origin,
      resourceUrl,
      connegEnabled
    });
    headers['Vary'] = 'Accept';
    headers['X-Frame-Options'] = 'DENY';
    headers['Content-Security-Policy'] = "frame-ancestors 'none'";
    // Don't cache the HTML wrapper - always negotiate fresh
    headers['Cache-Control'] = 'no-store';

    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.type('text/html').send(html);
  }

  const content = await storage.read(storagePath);
  if (content === null) {
    return reply.code(500).send({ error: 'Read error' });
  }

  // Content negotiation for RDF resources (including HTML with JSON-LD data islands)
  if (connegEnabled) {
    const contentStr = content.toString();
    const acceptHeader = request.headers.accept || '';
    // Serve Turtle if: URL ends with .ttl OR Accept header requests it
    const wantsTurtle = urlPath.endsWith('.ttl') ||
                        acceptHeader.includes('text/turtle') ||
                        acceptHeader.includes('text/n3') ||
                        acceptHeader.includes('application/n-triples');

    // Check if this is HTML with JSON-LD data island
    const isHtmlWithDataIsland = contentStr.trimStart().startsWith('<!DOCTYPE') ||
                                  contentStr.trimStart().startsWith('<html');

    if (isHtmlWithDataIsland && wantsTurtle) {
      // Extract JSON-LD from HTML data island and convert to Turtle
      try {
        const jsonLdMatch = contentStr.match(/<script\s+type=["']application\/ld\+json["']\s*>([\s\S]*?)<\/script>/i);
        if (jsonLdMatch) {
          const jsonLd = JSON.parse(jsonLdMatch[1]);
          const { content: turtleContent } = await fromJsonLd(jsonLd, 'text/turtle', resourceUrl, true);

          const headers = getAllHeaders({
            isContainer: false,
            etag: stats.etag,
            contentType: 'text/turtle',
            origin,
            resourceUrl,
            connegEnabled
          });
          headers['Vary'] = getVaryHeader(connegEnabled, request.mashlibEnabled);

          Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
          return reply.send(turtleContent);
        }
      } catch (err) {
        // Fall through to serve HTML if conversion fails
        console.error('Failed to convert HTML data island to Turtle:', err.message);
      }
    } else if (isRdfContentType(storedContentType)) {
      // Plain JSON-LD file
      try {
        const jsonLd = JSON.parse(contentStr);
        // Use Turtle if URL ends with .ttl, otherwise use Accept header preference
        const targetType = wantsTurtle ? 'text/turtle' : selectContentType(acceptHeader, connegEnabled);
        const { content: outputContent, contentType: outputType } = await fromJsonLd(
          jsonLd,
          targetType,
          resourceUrl,
          connegEnabled
        );

        const headers = getAllHeaders({
          isContainer: false,
          etag: stats.etag,
          contentType: outputType,
          origin,
          resourceUrl,
          connegEnabled
        });
        headers['Vary'] = getVaryHeader(connegEnabled, request.mashlibEnabled);

        Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
        return reply.send(outputContent);
      } catch (e) {
        // If not valid JSON-LD, serve as-is
      }
    }
  }

  // Serve content as-is (no conneg or non-RDF resource)
  const headers = getAllHeaders({
    isContainer: false,
    etag: stats.etag,
    contentType: storedContentType,
    origin,
    resourceUrl,
    connegEnabled
  });
  headers['Vary'] = getVaryHeader(connegEnabled, request.mashlibEnabled);

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.send(content);
}

/**
 * Handle HEAD request
 */
export async function handleHead(request, reply) {
  const { storagePath, resourceUrl } = getRequestPaths(request);
  const stats = await storage.stat(storagePath);

  if (!stats) {
    const origin = request.headers.origin;
    const connegEnabled = request.connegEnabled || false;
    const headers = getNotFoundHeaders({ resourceUrl, origin, connegEnabled });
    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.code(404).send();
  }

  const origin = request.headers.origin;
  const contentType = stats.isDirectory ? 'application/ld+json' : getContentType(storagePath);

  const headers = getAllHeaders({
    isContainer: stats.isDirectory,
    etag: stats.etag,
    contentType,
    origin,
    resourceUrl
  });

  if (!stats.isDirectory) {
    headers['Content-Length'] = stats.size;
  }

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.code(200).send();
}

/**
 * Handle PUT request
 */
export async function handlePut(request, reply) {
  const { urlPath, storagePath, resourceUrl } = getRequestPaths(request);
  const connegEnabled = request.connegEnabled || false;

  // Handle container creation via PUT
  if (isContainer(urlPath)) {
    const stats = await storage.stat(storagePath);
    if (stats?.isDirectory) {
      // Container already exists - don't allow PUT to modify
      return reply.code(409).send({ error: 'Cannot PUT to existing container' });
    }

    // Create the container (and any intermediate containers)
    const success = await storage.createContainer(storagePath);
    if (!success) {
      return reply.code(500).send({ error: 'Failed to create container' });
    }

    const origin = request.headers.origin;
    const headers = getAllHeaders({
      isContainer: true,
      origin,
      connegEnabled
    });
    headers['Location'] = resourceUrl;
    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    emitChange(request.protocol + '://' + request.hostname, urlPath, 'created');
    return reply.code(201).send();
  }

  const contentType = request.headers['content-type'] || '';

  // Check if we can accept this input type
  if (!canAcceptInput(contentType, connegEnabled)) {
    return reply.code(415).send({
      error: 'Unsupported Media Type',
      message: connegEnabled
        ? 'Supported types: application/ld+json, text/turtle, text/n3'
        : 'Supported type: application/ld+json (enable conneg for Turtle support)'
    });
  }

  // Check if resource already exists and get current ETag
  const stats = await storage.stat(storagePath);
  const existed = stats !== null;
  const currentEtag = stats?.etag || null;

  // Check If-Match header (for safe updates)
  const ifMatch = request.headers['if-match'];
  if (ifMatch) {
    const check = checkIfMatch(ifMatch, currentEtag);
    if (!check.ok) {
      return reply.code(check.status).send({ error: check.error });
    }
  }

  // Check If-None-Match header (for create-only semantics)
  const ifNoneMatch = request.headers['if-none-match'];
  if (ifNoneMatch) {
    const check = checkIfNoneMatchForWrite(ifNoneMatch, currentEtag);
    if (!check.ok) {
      return reply.code(check.status).send({ error: check.error });
    }
  }

  // Get content from request body
  let content = request.body;

  // Handle raw body for non-JSON content types
  if (Buffer.isBuffer(content)) {
    // Already a buffer, use as-is
  } else if (typeof content === 'string') {
    content = Buffer.from(content);
  } else if (content && typeof content === 'object') {
    content = Buffer.from(JSON.stringify(content));
  } else {
    content = Buffer.from('');
  }

  // Convert Turtle/N3 to JSON-LD if conneg enabled
  const inputType = contentType.split(';')[0].trim().toLowerCase();
  if (connegEnabled && (inputType === RDF_TYPES.TURTLE || inputType === RDF_TYPES.N3)) {
    try {
      const jsonLd = await toJsonLd(content, contentType, resourceUrl, connegEnabled);
      content = Buffer.from(JSON.stringify(jsonLd, null, 2));
    } catch (e) {
      return reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid Turtle/N3 format: ' + e.message
      });
    }
  }

  const success = await storage.write(storagePath, content);
  if (!success) {
    return reply.code(500).send({ error: 'Write failed' });
  }

  const origin = request.headers.origin;
  const headers = getAllHeaders({ isContainer: false, origin, resourceUrl, connegEnabled });
  headers['Location'] = resourceUrl;
  headers['Vary'] = getVaryHeader(connegEnabled, request.mashlibEnabled);

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

  // Emit change notification for WebSocket subscribers
  if (request.notificationsEnabled) {
    emitChange(resourceUrl);
  }

  return reply.code(existed ? 204 : 201).send();
}

/**
 * Handle DELETE request
 */
export async function handleDelete(request, reply) {
  const { storagePath, resourceUrl } = getRequestPaths(request);

  // Check if resource exists and get current ETag
  const stats = await storage.stat(storagePath);
  if (!stats) {
    const origin = request.headers.origin;
    const connegEnabled = request.connegEnabled || false;
    const headers = getNotFoundHeaders({ resourceUrl, origin, connegEnabled });
    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.code(404).send({ error: 'Not Found' });
  }

  // Check If-Match header (for safe deletes)
  const ifMatch = request.headers['if-match'];
  if (ifMatch) {
    const check = checkIfMatch(ifMatch, stats.etag);
    if (!check.ok) {
      return reply.code(check.status).send({ error: check.error });
    }
  }

  const success = await storage.remove(storagePath);
  if (!success) {
    return reply.code(500).send({ error: 'Delete failed' });
  }

  const origin = request.headers.origin;
  const headers = getAllHeaders({ isContainer: false, origin, resourceUrl });
  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

  // Emit change notification for WebSocket subscribers
  if (request.notificationsEnabled) {
    emitChange(resourceUrl);
  }

  return reply.code(204).send();
}

/**
 * Handle OPTIONS request
 */
export async function handleOptions(request, reply) {
  const { urlPath, storagePath, resourceUrl } = getRequestPaths(request);
  const stats = await storage.stat(storagePath);

  const origin = request.headers.origin;
  const connegEnabled = request.connegEnabled || false;
  const headers = getAllHeaders({
    isContainer: stats?.isDirectory || isContainer(urlPath),
    origin,
    resourceUrl,
    connegEnabled
  });

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.code(204).send();
}

/**
 * Handle PATCH request
 * Supports N3 Patch format (text/n3) and SPARQL Update for updating RDF resources
 */
export async function handlePatch(request, reply) {
  const { urlPath, storagePath, resourceUrl } = getRequestPaths(request);

  // Don't allow PATCH to containers
  if (isContainer(urlPath)) {
    return reply.code(409).send({ error: 'Cannot PATCH containers' });
  }

  // Check content type
  const contentType = request.headers['content-type'] || '';
  const isN3Patch = contentType.includes('text/n3') || contentType.includes('application/n3');
  const isSparqlUpdate = contentType.includes('application/sparql-update');

  if (!isN3Patch && !isSparqlUpdate) {
    return reply.code(415).send({
      error: 'Unsupported Media Type',
      message: 'PATCH requires Content-Type: text/n3 (N3 Patch) or application/sparql-update (SPARQL Update)'
    });
  }

  // Check if resource exists - PATCH can create resources in Solid
  const stats = await storage.stat(storagePath);
  const resourceExists = !!stats;

  // Check If-Match header (for safe updates) - only if resource exists
  if (resourceExists) {
    const ifMatch = request.headers['if-match'];
    if (ifMatch) {
      const check = checkIfMatch(ifMatch, stats.etag);
      if (!check.ok) {
        return reply.code(check.status).send({ error: check.error });
      }
    }
  }

  // Read existing content or start with empty JSON-LD document
  let document;
  let htmlWrapper = null; // Track HTML wrapper for data island re-embedding

  if (resourceExists) {
    const existingContent = await storage.read(storagePath);
    if (existingContent === null) {
      return reply.code(500).send({ error: 'Read error' });
    }

    const contentStr = existingContent.toString();

    // Check if this is HTML with embedded JSON-LD data island
    if (contentStr.trimStart().startsWith('<!DOCTYPE') || contentStr.trimStart().startsWith('<html')) {
      // Extract JSON-LD from <script type="application/ld+json"> tag
      const jsonLdMatch = contentStr.match(/<script\s+type=["']application\/ld\+json["']\s*>([\s\S]*?)<\/script>/i);

      if (!jsonLdMatch) {
        return reply.code(409).send({
          error: 'Conflict',
          message: 'HTML document does not contain a JSON-LD data island'
        });
      }

      try {
        document = JSON.parse(jsonLdMatch[1]);
        // Save the HTML parts for re-embedding after patch
        const jsonLdStart = contentStr.indexOf(jsonLdMatch[0]) + jsonLdMatch[0].indexOf('>') + 1;
        const jsonLdEnd = jsonLdStart + jsonLdMatch[1].length;
        htmlWrapper = {
          before: contentStr.substring(0, jsonLdStart),
          after: contentStr.substring(jsonLdEnd)
        };
      } catch (e) {
        return reply.code(409).send({
          error: 'Conflict',
          message: 'HTML data island contains invalid JSON-LD'
        });
      }
    } else {
      // Try to parse as JSON-LD first
      try {
        document = JSON.parse(contentStr);
      } catch (e) {
        // Not JSON - might be Turtle, handle with RDF store for SPARQL Update
        if (isSparqlUpdate) {
          // Parse Turtle and apply SPARQL Update directly
          const { Parser, Writer } = await import('n3');
          const parser = new Parser({ baseIRI: resourceUrl });
          let quads;
          try {
            quads = parser.parse(contentStr);
          } catch (parseErr) {
            return reply.code(409).send({
              error: 'Conflict',
              message: 'Resource is not valid Turtle: ' + parseErr.message
            });
          }

          // Parse the SPARQL Update
          const patchContent = Buffer.isBuffer(request.body) ? request.body.toString() : request.body;
          let update;
          try {
            update = parseSparqlUpdate(patchContent, resourceUrl);
          } catch (parseErr) {
            return reply.code(400).send({
              error: 'Bad Request',
              message: 'Invalid SPARQL Update: ' + parseErr.message
            });
          }

          // Apply deletes
          for (const triple of update.deletes) {
            quads = quads.filter(q => {
              const matches = q.subject.value === triple.subject &&
                             q.predicate.value === triple.predicate &&
                             (q.object.value === (triple.object['@id'] || triple.object['@value'] || triple.object));
              return !matches;
            });
          }

          // Apply inserts
          const { DataFactory } = await import('n3');
          const { namedNode, literal } = DataFactory;
          for (const triple of update.inserts) {
            const subj = namedNode(triple.subject);
            const pred = namedNode(triple.predicate);
            let obj;
            if (triple.object['@id']) {
              obj = namedNode(triple.object['@id']);
            } else if (typeof triple.object === 'string') {
              obj = literal(triple.object);
            } else {
              obj = literal(triple.object['@value'] || triple.object);
            }
            quads.push(DataFactory.quad(subj, pred, obj));
          }

          // Serialize back to Turtle
          const writer = new Writer({ prefixes: {} });
          quads.forEach(q => writer.addQuad(q));
          let turtleOutput;
          writer.end((err, result) => { turtleOutput = result; });

          const success = await storage.write(storagePath, Buffer.from(turtleOutput));
          if (!success) {
            return reply.code(500).send({ error: 'Write failed' });
          }

          const origin = request.headers.origin;
          const headers = getAllHeaders({ isContainer: false, origin, resourceUrl });
          Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

          if (request.notificationsEnabled) {
            emitChange(resourceUrl);
          }

          return reply.code(resourceExists ? 204 : 201).send();
        }

        return reply.code(409).send({
          error: 'Conflict',
          message: 'Resource is not valid JSON-LD and cannot be patched'
        });
      }
    }
  } else {
    // Create empty JSON-LD document for new resource
    document = {
      '@context': {},
      '@graph': []
    };
  }

  // Parse the patch
  const patchContent = Buffer.isBuffer(request.body)
    ? request.body.toString()
    : request.body;

  let updatedDocument;

  if (isSparqlUpdate) {
    // Handle SPARQL Update
    let update;
    try {
      update = parseSparqlUpdate(patchContent, resourceUrl);
    } catch (e) {
      return reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid SPARQL Update: ' + e.message
      });
    }

    try {
      updatedDocument = applySparqlUpdate(document, update, resourceUrl);
    } catch (e) {
      return reply.code(409).send({
        error: 'Conflict',
        message: 'Failed to apply SPARQL Update: ' + e.message
      });
    }
  } else {
    // Handle N3 Patch
    let patch;
    try {
      patch = parseN3Patch(patchContent, resourceUrl);
    } catch (e) {
      return reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid N3 Patch format: ' + e.message
      });
    }

    try {
      updatedDocument = applyN3Patch(document, patch, resourceUrl);
    } catch (e) {
      return reply.code(409).send({
        error: 'Conflict',
        message: 'Failed to apply patch: ' + e.message
      });
    }
  }

  // Write updated document
  let updatedContent;
  if (htmlWrapper) {
    // Re-embed JSON-LD into HTML wrapper
    const jsonLdStr = JSON.stringify(updatedDocument, null, 2);
    updatedContent = htmlWrapper.before + '\n' + jsonLdStr + '\n  ' + htmlWrapper.after;
  } else {
    updatedContent = JSON.stringify(updatedDocument, null, 2);
  }
  const success = await storage.write(storagePath, Buffer.from(updatedContent));

  if (!success) {
    return reply.code(500).send({ error: 'Write failed' });
  }

  const origin = request.headers.origin;
  const headers = getAllHeaders({ isContainer: false, origin, resourceUrl });
  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

  // Emit change notification for WebSocket subscribers
  if (request.notificationsEnabled) {
    emitChange(resourceUrl);
  }

  // Return 201 Created if resource was created, 204 No Content if updated
  return reply.code(resourceExists ? 204 : 201).send();
}
