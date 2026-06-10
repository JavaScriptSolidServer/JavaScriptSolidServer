import * as storage from '../storage/filesystem.js';
import { checkQuota, updateQuotaUsage } from '../storage/quota.js';
import { getAllHeaders, getNotFoundHeaders } from '../ldp/headers.js';
import { generateContainerJsonLd, serializeJsonLd } from '../ldp/container.js';
import { isContainer, getContentType, isRdfContentType, getEffectiveUrlPath, safeJsonParse, getPodName } from '../utils/url.js';
import { parseN3Patch, applyN3Patch, validatePatch } from '../patch/n3-patch.js';
import { parseSparqlUpdate, applySparqlUpdate } from '../patch/sparql-update.js';
import {
  selectContentType,
  canAcceptInput,
  toJsonLd,
  fromJsonLd,
  RDF_TYPES,
  getVaryHeader
} from '../rdf/conneg.js';
import { emitChange } from '../notifications/events.js';
import { checkIfMatch, checkIfNoneMatchForGet, checkIfNoneMatchForWrite } from '../utils/conditional.js';
import { generateDatabrowserHtml, generateModuleDatabrowserHtml, shouldServeMashlib, DATA_ISLAND_MAX_BYTES } from '../mashlib/index.js';
import { turtleToJsonLd } from '../rdf/turtle.js';

/**
 * Live reload script - injected into HTML when --live-reload is enabled
 */
const LIVE_RELOAD_SCRIPT = `<script>(function(){var ws=new WebSocket((location.protocol==='https:'?'wss:':'ws:')+'//' +location.host+'/.notifications');ws.onopen=function(){ws.send('sub '+location.href)};ws.onmessage=function(e){if(e.data.startsWith('pub '))location.reload()};ws.onclose=function(){setTimeout(function(){location.reload()},1000)}})();</script>`;

// Cache-Control for RDF data responses: let clients keep the body but force
// revalidation via ETag on every use. This prevents stale bodies from leaking
// across auth-state changes (WAC) and closes the mashlib render-race window
// where a cached data variant was served on top-level navigation (#315).
const RDF_CACHE_CONTROL = 'private, no-cache, must-revalidate';

// Detects when the request's Accept header explicitly names a JSON
// media type. Used by the container/index.html branches of GET and HEAD
// to decide whether to surface the embedded JSON-LD data island —
// without this guard, selectContentType's `*/*` arm would divert plain
// browser requests into the RDF branch (#409). Hoisted so GET and HEAD
// can't drift apart silently.
const EXPLICIT_JSON_RE = /\b(application\/ld\+json|application\/json)\b/i;

/**
 * Inject live reload script into HTML content
 */
function injectLiveReload(content) {
  const html = content.toString();
  // Inject before </body> or at end
  if (html.includes('</body>')) {
    return Buffer.from(html.replace('</body>', LIVE_RELOAD_SCRIPT + '</body>'));
  }
  return Buffer.from(html + LIVE_RELOAD_SCRIPT);
}

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
 * Parse HTTP Range header
 * @param {string} rangeHeader - The Range header value (e.g., "bytes=0-1023")
 * @param {number} fileSize - Total file size in bytes
 * @returns {{ start: number, end: number } | null}
 */
function parseRangeHeader(rangeHeader, fileSize) {
  if (!rangeHeader || !rangeHeader.startsWith('bytes=')) {
    return null;
  }

  const range = rangeHeader.slice(6); // Remove 'bytes='

  // Multi-range requests (e.g., "0-100,200-300") are not supported
  // Per RFC 7233, ignore Range header and serve full content instead of 416
  if (range.includes(',')) {
    return null;
  }

  const parts = range.split('-');

  if (parts.length !== 2) {
    return null;
  }

  let start, end;

  if (parts[0] === '') {
    // Suffix range: bytes=-500 (last 500 bytes)
    const suffix = parseInt(parts[1], 10);
    if (isNaN(suffix) || suffix <= 0) return null;
    start = Math.max(0, fileSize - suffix);
    end = fileSize - 1;
  } else if (parts[1] === '') {
    // Open-ended range: bytes=1024- (from 1024 to end)
    start = parseInt(parts[0], 10);
    if (isNaN(start) || start < 0) return null;
    end = fileSize - 1;
  } else {
    // Normal range: bytes=0-1023
    start = parseInt(parts[0], 10);
    end = parseInt(parts[1], 10);
    if (isNaN(start) || isNaN(end) || start < 0 || end < start) return null;
  }

  // Clamp end to file size
  if (end >= fileSize) {
    end = fileSize - 1;
  }

  // Check if range is satisfiable
  if (start > end || start >= fileSize) {
    return null;
  }

  return { start, end };
}

/**
 * Compute a content-type-aware ETag. When mashlib will wrap an RDF
 * resource in HTML, the response body differs from the raw resource,
 * so the ETag must differ too — otherwise browsers confuse cached
 * JSON-LD with the HTML variant despite Vary: Accept (#456).
 */
function getMashlibEtag(request, stats, storagePath) {
  const storedType = stats.isDirectory ? 'application/ld+json' : getContentType(storagePath);
  const willServeMashlib =
    shouldServeMashlib(request, request.mashlibEnabled, storedType);
  const effectiveEtag = willServeMashlib
    ? stats.etag.replace(/"$/, '-html"')
    : stats.etag;
  return { willServeMashlib, effectiveEtag };
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

  const { willServeMashlib, effectiveEtag } = getMashlibEtag(request, stats, storagePath);

  // For non-containers, check If-None-Match early using the effective
  // ETag. For containers, defer the check until we know which branch
  // (index.html vs listing vs mashlib) will run — each uses a
  // different ETag source (#456).
  const ifNoneMatch = request.headers['if-none-match'];
  if (ifNoneMatch && !stats.isDirectory) {
    const check = checkIfNoneMatchForGet(ifNoneMatch, effectiveEtag);
    if (!check.ok && check.notModified) {
      reply.header('ETag', effectiveEtag);
      reply.header('Vary', getVaryHeader(request.connegEnabled, request.mashlibEnabled));
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

      // Deferred 304 check for index.html containers (#456)
      const indexEtag = indexStats?.etag || stats.etag;
      if (ifNoneMatch) {
        const check = checkIfNoneMatchForGet(ifNoneMatch, indexEtag);
        if (!check.ok && check.notModified) {
          reply.header('ETag', indexEtag);
          reply.header('Vary', getVaryHeader(connegEnabled, request.mashlibEnabled));
          return reply.code(304).send();
        }
      }

      // Pick the negotiated RDF type using q-aware Accept parsing. The
      // naive `acceptHeader.includes('text/turtle')` we used to do here
      // ignored q-weights — `Accept: application/ld+json, text/turtle;q=0.1`
      // would still pick Turtle even though JSON-LD was preferred (#325).
      const acceptHeader = request.headers.accept || '';
      const negotiated = connegEnabled
        ? selectContentType(acceptHeader, true)
        : null;
      const wantsTurtle = negotiated === RDF_TYPES.TURTLE
        || negotiated === RDF_TYPES.N3
        || negotiated === 'application/n-triples';
      // Only treat as JSON-LD when Accept *explicitly* asks for JSON.
      // selectContentType doesn't recognize text/html or
      // application/xhtml+xml, so for a browser Accept like
      // `text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8`
      // it walks past those unsupported types and lands on `*/*`, which
      // returns JSON-LD — diverting plain browser GETs into the RDF
      // branch and serving the embedded data island instead of the
      // index.html body. Mirrors the HEAD-handler logic below (#409).
      const explicitJson = EXPLICIT_JSON_RE.test(acceptHeader);
      const wantsJsonLd = negotiated === RDF_TYPES.JSON_LD && explicitJson;

      if (wantsTurtle || wantsJsonLd) {
        // Extract JSON-LD from HTML data island
        try {
          const htmlStr = content.toString();
          const jsonLdMatch = htmlStr.match(/<script type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/);
          if (jsonLdMatch) {
            const jsonLd = safeJsonParse(jsonLdMatch[1]);

            if (wantsTurtle) {
              // Convert to Turtle
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
              headers['Cache-Control'] = RDF_CACHE_CONTROL;

              Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
              return reply.send(turtleContent);
            } else {
              // Return JSON-LD directly
              const headers = getAllHeaders({
                isContainer: true,
                etag: indexStats?.etag || stats.etag,
                contentType: 'application/ld+json',
                origin,
                resourceUrl,
                connegEnabled
              });
              headers['Cache-Control'] = RDF_CACHE_CONTROL;

              Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
              return reply.send(JSON.stringify(jsonLd, null, 2));
            }
          }
        } catch (err) {
          // Fall through to serve HTML if conversion fails
          console.error('Failed to convert profile to RDF:', err.message);
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
      // Inject live reload script for index.html
      if (request.liveReloadEnabled) {
        reply.header('Cache-Control', 'no-store');
        reply.removeHeader('ETag');
        return reply.send(injectLiveReload(content));
      }
      return reply.send(content);
    }

    // No index.html, return JSON-LD container listing
    // Deferred 304 check for container listings (#456)
    if (ifNoneMatch) {
      const check = checkIfNoneMatchForGet(ifNoneMatch, effectiveEtag);
      if (!check.ok && check.notModified) {
        reply.header('ETag', effectiveEtag);
        reply.header('Vary', getVaryHeader(connegEnabled, request.mashlibEnabled));
        return reply.code(304).send();
      }
    }

    const entries = await storage.listContainer(storagePath);
    const jsonLd = generateContainerJsonLd(resourceUrl, entries || []);

    // Check if we should serve Mashlib data browser for containers
    if (shouldServeMashlib(request, request.mashlibEnabled, 'application/ld+json')) {
      // Phase 1 of #7: also embed the container's JSON-LD listing as a
      // data island so consumers that look for `<script
      // type="application/ld+json">` (search-engine rich-results,
      // archival crawlers, future mashlib zero-fetch path) get the data
      // without a second request. Use compact (no-whitespace) form for
      // the embed so we don't burn bytes against DATA_ISLAND_MAX_BYTES
      // on indentation that nothing will ever read.
      const embedJsonLd = JSON.stringify(jsonLd);
      const html = request.mashlibModule
        ? generateModuleDatabrowserHtml(request.mashlibModule, resourceUrl, { embedJsonLd })
        : generateDatabrowserHtml(
          resourceUrl,
          request.mashlibCdn ? request.mashlibVersion : null,
          { embedJsonLd }
        );
      const headers = getAllHeaders({
        isContainer: true,
        etag: effectiveEtag,
        contentType: 'text/html',
        origin,
        resourceUrl,
        connegEnabled,
        mashlibEnabled: request.mashlibEnabled
      });
      headers['X-Frame-Options'] = 'DENY';
      headers['Content-Security-Policy'] = "frame-ancestors 'none'";
      headers['Cache-Control'] = 'no-store';

      Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
      return reply.type('text/html').send(html);
    }

    // Pick the negotiated RDF type using q-aware Accept parsing (#325).
    const acceptHeader = request.headers.accept || '';
    const negotiated = connegEnabled
      ? selectContentType(acceptHeader, true)
      : null;
    const wantsTurtle = negotiated === RDF_TYPES.TURTLE
      || negotiated === RDF_TYPES.N3
      || negotiated === 'application/n-triples';

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
          connegEnabled,
          mashlibEnabled: request.mashlibEnabled
        });
        headers['Cache-Control'] = RDF_CACHE_CONTROL;

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
      connegEnabled,
      mashlibEnabled: request.mashlibEnabled
    });
    headers['Cache-Control'] = RDF_CACHE_CONTROL;

    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.send(serializeJsonLd(jsonLd));
  }

  // Handle resource
  const storedContentType = getContentType(storagePath);
  const connegEnabled = request.connegEnabled || false;

  // Check if we should serve Mashlib data browser
  // Only for RDF resources when Accept: text/html is requested
  if (shouldServeMashlib(request, request.mashlibEnabled, storedContentType)) {
    // #7 / #344: embed the resource as a JSON-LD data island so
    // non-mashlib consumers (search-engine rich-results, archival
    // crawlers) get the data without a second request, and so the
    // shape is uniform regardless of the URL extension.
    //
    // JSS stores all RDF as JSON-LD on disk (PUT converts Turtle/N3
    // before write — see the conneg branch in handlePut), so for
    // `.ttl` / `.n3` URLs the bytes on disk are usually already
    // JSON-LD. Try JSON parse first; only fall back to a Turtle parse
    // when that fails (covers files placed on the filesystem
    // out-of-band in their native format).
    //
    // Cap-aware short-circuit: skip the read entirely when the file
    // is already over the embed cap. The island would be dropped
    // anyway, and large RDF resources would otherwise load into
    // memory on every HTML navigation. Other formats (rdf+xml, etc.)
    // are not handled — the wrapper still loads and mashlib
    // XHR-fetches them as before.
    const islandConvertible =
      storedContentType === RDF_TYPES.JSON_LD ||
      storedContentType === RDF_TYPES.TURTLE ||
      storedContentType === RDF_TYPES.N3;
    let embedJsonLd;
    if (islandConvertible && stats.size <= DATA_ISLAND_MAX_BYTES) {
      const buf = await storage.read(storagePath);
      if (buf) {
        if (storedContentType === RDF_TYPES.JSON_LD) {
          // Pass the Buffer through. dataIsland() decodes once when
          // it needs to; we don't pre-validate or pre-decode here.
          embedJsonLd = buf;
        } else {
          // Turtle / N3 URL. JSS stores everything as JSON-LD on
          // disk (PUT converts), so try JSON parse first and pass
          // the *decoded text* through (avoids a second decode
          // inside dataIsland's String() coercion). Fall back to a
          // Turtle parse for files placed on the filesystem
          // out-of-band in their native format.
          const text = buf.toString('utf8');
          try {
            JSON.parse(text);
            embedJsonLd = text;
          } catch {
            try {
              const jsonLd = await turtleToJsonLd(text, resourceUrl);
              embedJsonLd = JSON.stringify(jsonLd);
            } catch {
              // Both parses failed → drop the island. The wrapper
              // still renders and mashlib XHR-fetches the original.
            }
          }
        }
      }
    }
    const html = request.mashlibModule
      ? generateModuleDatabrowserHtml(request.mashlibModule, resourceUrl, { embedJsonLd })
      : generateDatabrowserHtml(
        resourceUrl,
        request.mashlibCdn ? request.mashlibVersion : null,
        { embedJsonLd }
      );
    const headers = getAllHeaders({
      isContainer: false,
      etag: effectiveEtag,
      contentType: 'text/html',
      origin,
      resourceUrl,
      connegEnabled,
      mashlibEnabled: request.mashlibEnabled
    });
    headers['X-Frame-Options'] = 'DENY';
    headers['Content-Security-Policy'] = "frame-ancestors 'none'";
    // Don't cache the HTML wrapper - always negotiate fresh
    headers['Cache-Control'] = 'no-store';

    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.type('text/html').send(html);
  }

  // Handle Range requests for media files (video, audio, etc.)
  const rangeHeader = request.headers.range;
  if (rangeHeader && !isRdfContentType(storedContentType)) {
    const range = parseRangeHeader(rangeHeader, stats.size);

    if (range) {
      const { start, end } = range;
      const chunkSize = end - start + 1;

      const headers = getAllHeaders({
        isContainer: false,
        etag: stats.etag,
        contentType: storedContentType,
        origin,
        resourceUrl,
        connegEnabled
      });
      headers['Content-Range'] = `bytes ${start}-${end}/${stats.size}`;
      headers['Content-Length'] = chunkSize;

      Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

      const streamResult = storage.createReadStream(storagePath, { start, end });
      if (!streamResult) {
        return reply.code(500).send({ error: 'Stream error' });
      }

      // Handle stream errors that occur during response
      streamResult.stream.on('error', (err) => {
        console.error('Stream error during range response:', err.message);
      });

      return reply.code(206).send(streamResult.stream);
    }
    // If range is null (unsupported format or multi-range), fall through to serve full content
  }

  const content = await storage.read(storagePath);
  if (content === null) {
    return reply.code(500).send({ error: 'Read error' });
  }

  // Content negotiation for RDF resources (including HTML with JSON-LD data islands)
  if (connegEnabled) {
    const contentStr = content.toString();
    const acceptHeader = request.headers.accept || '';
    // Serve Turtle if: URL ends with .ttl OR Accept's q-weighted top
    // RDF type is Turtle/N3 (#325 — naive substring matching ignored
    // q-weights and would pick Turtle whenever it appeared in Accept).
    const negotiated = selectContentType(acceptHeader, true);
    const wantsTurtle = urlPath.endsWith('.ttl')
      || negotiated === RDF_TYPES.TURTLE
      || negotiated === RDF_TYPES.N3
      || negotiated === 'application/n-triples';

    // Check if this is HTML with JSON-LD data island
    const isHtmlWithDataIsland = contentStr.trimStart().startsWith('<!DOCTYPE') ||
                                  contentStr.trimStart().startsWith('<html');

    if (isHtmlWithDataIsland && wantsTurtle) {
      // Extract JSON-LD from HTML data island and convert to Turtle
      try {
        const jsonLdMatch = contentStr.match(/<script\s+type=["']application\/ld\+json["']\s*>([\s\S]*?)<\/script>/i);
        if (jsonLdMatch) {
          const jsonLd = safeJsonParse(jsonLdMatch[1]);
          const { content: turtleContent } = await fromJsonLd(jsonLd, 'text/turtle', resourceUrl, true);

          const headers = getAllHeaders({
            isContainer: false,
            etag: stats.etag,
            contentType: 'text/turtle',
            origin,
            resourceUrl,
            connegEnabled,
            mashlibEnabled: request.mashlibEnabled
          });
          headers['Cache-Control'] = RDF_CACHE_CONTROL;

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
        const jsonLd = safeJsonParse(contentStr);
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
          connegEnabled,
          mashlibEnabled: request.mashlibEnabled
        });
        headers['Cache-Control'] = RDF_CACHE_CONTROL;

        Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
        return reply.send(outputContent);
      } catch (e) {
        // If not valid JSON-LD, serve as-is
      }
    }
  }

  // Serve content as-is (no conneg or non-RDF resource)
  // For extensionless files (like profile/card), detect HTML by content
  let actualContentType = storedContentType;
  if (storedContentType === 'application/octet-stream') {
    const contentStr = content.toString().trimStart();
    if (contentStr.startsWith('<!DOCTYPE') || contentStr.startsWith('<html')) {
      actualContentType = 'text/html';
    }
  }

  const headers = getAllHeaders({
    isContainer: false,
    etag: stats.etag,
    contentType: actualContentType,
    origin,
    resourceUrl,
    connegEnabled,
    mashlibEnabled: request.mashlibEnabled
  });
  if (isRdfContentType(actualContentType)) {
    headers['Cache-Control'] = RDF_CACHE_CONTROL;
  }

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));

  // Inject live reload script into HTML (disable caching since content is modified)
  if (actualContentType === 'text/html' && request.liveReloadEnabled) {
    reply.header('Cache-Control', 'no-store');
    reply.removeHeader('ETag');
    return reply.send(injectLiveReload(content));
  }
  return reply.send(content);
}

// Cap on how many bytes HEAD will FULLY read to decide a content type.
// GET reads the whole file regardless (it has to send the body anyway),
// but a HEAD on a multi-GB file must not slurp it into memory just to
// report a header. Above the cap, HEAD degrades gracefully per-case
// (see negotiateHeadFileContentType) instead of reading. Bounded
// first-bytes sniffs (HEAD_SNIFF_CHUNK_BYTES via a ranged read) are
// allowed at ANY size — they cost O(1).
const HEAD_FULL_READ_MAX_BYTES = 1024 * 1024;
const HEAD_SNIFF_CHUNK_BYTES = 1024;

// Read the first `bytes` of a file via a ranged stream — O(1) cost
// regardless of file size. Used by HEAD to run GET's "does it look
// like HTML?" sniffs without reading whole files.
function readFirstBytes(storagePath, bytes) {
  return new Promise((resolve) => {
    const result = storage.createReadStream(storagePath, { start: 0, end: bytes - 1 });
    if (!result) return resolve(null);
    const chunks = [];
    result.stream.on('data', (c) => chunks.push(c));
    result.stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    result.stream.on('error', () => resolve(null));
  });
}

/**
 * Mirror handleGet's content-type decision for a FILE so HEAD emits the
 * same Content-Type a GET with the same Accept header would (#552 —
 * RFC 9110 §9.3.2: HEAD should send the same header fields as GET).
 *
 * GET's decision depends on file CONTENT in three places — the
 * HTML-data-island sniff, the JSON-parse-success gate before conneg
 * conversion, and the extensionless-file HTML sniff — so this may read
 * the file, but only when the stored type makes content relevant and
 * the file is within HEAD_FULL_READ_MAX_BYTES.
 *
 * Returns `{ contentType, converted }`. `converted: true` means GET
 * would RE-SERIALIZE the body (Turtle conversion, or JSON-LD
 * re-serialization through fromJsonLd) — its Content-Length would NOT
 * be the on-disk size, so HEAD must omit Content-Length rather than
 * claim stats.size for a body GET never sends. The extensionless HTML
 * sniff only relabels the bytes (served as-is), so it is NOT a
 * conversion.
 *
 * Large files (> HEAD_FULL_READ_MAX_BYTES) degrade per-case instead of
 * being read in full:
 *   - RDF-stored: return the negotiated type WITHOUT the parse gate
 *     (optimistic). The gate only mirrors GET's corrupt-file fallback;
 *     a corrupt >1 MiB RDF document is far rarer than a valid one, so
 *     optimism keeps parity for the common case and confines the
 *     divergence to that corner.
 *   - HTML-stored + Turtle-preferring Accept: stay at text/html
 *     (conservative) — the data island can sit anywhere in the file,
 *     so its presence can't be checked without a full read.
 *   - Extensionless: the HTML sniff only needs the first bytes, so it
 *     runs at ANY size via a bounded ranged read.
 *
 * Known residual divergences (deliberate, all need unusual documents):
 * a parseable-but-unconvertible document (GET's fromJsonLd fails after
 * JSON.parse succeeds → GET falls back to raw bytes), a corrupt
 * >1 MiB RDF file (optimistic path above), and a >1 MiB HTML file
 * carrying a data island (conservative path above).
 */
async function negotiateHeadFileContentType({ storagePath, urlPath, stats, acceptHeader, connegEnabled }) {
  const storedContentType = getContentType(storagePath);
  const fitsFullRead = stats.size <= HEAD_FULL_READ_MAX_BYTES;

  if (connegEnabled) {
    // Same negotiation as handleGet's file branch (#325 q-aware).
    const negotiated = selectContentType(acceptHeader, true);
    const wantsTurtle = urlPath.endsWith('.ttl')
      || negotiated === RDF_TYPES.TURTLE
      || negotiated === RDF_TYPES.N3
      || negotiated === 'application/n-triples';

    if (isRdfContentType(storedContentType)) {
      const targetType = wantsTurtle ? 'text/turtle' : selectContentType(acceptHeader, connegEnabled);
      if (!fitsFullRead) {
        // Optimistic large-file path — see docstring.
        return { contentType: targetType, converted: true };
      }
      const content = await storage.read(storagePath);
      if (content !== null) {
        try {
          JSON.parse(content.toString()); // GET only converts when the body parses
          return { contentType: targetType, converted: true };
        } catch { /* not valid JSON-LD → GET serves as-is; fall through */ }
      }
      return { contentType: storedContentType, converted: false };
    }

    // GET's data-island check keys off CONTENT, not the stored type —
    // an extensionless (octet-stream) HTML file with an island converts
    // too. Run it for both HTML-stored and extensionless files; the
    // extensionless case falls through to the relabel sniff below when
    // no island converts.
    const islandCandidate =
      storedContentType === 'text/html' || storedContentType === 'application/octet-stream';
    if (islandCandidate && wantsTurtle && fitsFullRead) {
      // GET converts an HTML data island to Turtle only when the island
      // exists AND its JSON parses; otherwise it serves the HTML as-is.
      const content = await storage.read(storagePath);
      if (content !== null) {
        const contentStr = content.toString();
        const trimmed = contentStr.trimStart();
        if (trimmed.startsWith('<!DOCTYPE') || trimmed.startsWith('<html')) {
          const jsonLdMatch = contentStr.match(/<script\s+type=["']application\/ld\+json["']\s*>([\s\S]*?)<\/script>/i);
          if (jsonLdMatch) {
            try {
              JSON.parse(jsonLdMatch[1]);
              return { contentType: 'text/turtle', converted: true };
            } catch { /* unparseable island → GET serves HTML; fall through */ }
          }
        }
      }
      if (storedContentType === 'text/html') {
        return { contentType: storedContentType, converted: false };
      }
      // octet-stream: fall through to the HTML relabel sniff below.
    }
  }

  // As-is path: GET sniffs extensionless files for HTML by content.
  // Only the first bytes matter, so the sniff runs at any file size
  // via a bounded ranged read. Relabel only — no conversion.
  if (storedContentType === 'application/octet-stream') {
    const head = await readFirstBytes(storagePath, HEAD_SNIFF_CHUNK_BYTES);
    if (head !== null) {
      const t = head.trimStart();
      if (t.startsWith('<!DOCTYPE') || t.startsWith('<html')) {
        return { contentType: 'text/html', converted: false };
      }
    }
  }
  return { contentType: storedContentType, converted: false };
}

/**
 * Handle HEAD request
 */
export async function handleHead(request, reply) {
  const { urlPath, storagePath, resourceUrl } = getRequestPaths(request);
  const stats = await storage.stat(storagePath);

  if (!stats) {
    const origin = request.headers.origin;
    const connegEnabled = request.connegEnabled || false;
    const headers = getNotFoundHeaders({ resourceUrl, origin, connegEnabled });
    Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
    return reply.code(404).send();
  }

  const origin = request.headers.origin;
  const connegEnabled = request.connegEnabled || false;
  let contentType;
  let headEtag = stats.etag;
  let isMashlibResponse = false;

  if (stats.isDirectory) {
    const indexPath = storagePath.endsWith('/') ? `${storagePath}index.html` : `${storagePath}/index.html`;
    const indexExists = await storage.exists(indexPath);
    const acceptHeader = request.headers.accept || '';

    if (connegEnabled) {
      // HEAD must mirror what GET would emit; otherwise client caches and
      // RDF-aware tooling key off a content-type that doesn't match the
      // body they'll see on the next GET (#325). Use q-aware Accept
      // parsing for both the index.html and listing branches.
      const negotiated = selectContentType(acceptHeader, true);
      const wantsTurtle = negotiated === RDF_TYPES.TURTLE
        || negotiated === RDF_TYPES.N3
        || negotiated === 'application/n-triples';
      const wantsJsonLd = negotiated === RDF_TYPES.JSON_LD;

      if (wantsTurtle) {
        contentType = 'text/turtle';
      } else if (wantsJsonLd) {
        const explicitJson = EXPLICIT_JSON_RE.test(acceptHeader);
        contentType = (indexExists && !explicitJson) ? 'text/html' : 'application/ld+json';
      } else {
        contentType = indexExists ? 'text/html' : 'application/ld+json';
      }
    } else if (indexExists) {
      contentType = 'text/html';
    } else {
      contentType = 'application/ld+json';
    }

    if (indexExists) {
      // Mirror GET: containers with index.html use the index file's ETag
      const indexStats = await storage.stat(indexPath);
      headEtag = indexStats?.etag || stats.etag;
    } else if (shouldServeMashlib(request, request.mashlibEnabled, 'application/ld+json')) {
      // Container listing via mashlib — suffix the ETag (#456)
      headEtag = stats.etag.replace(/"$/, '-html"');
      contentType = 'text/html';
      isMashlibResponse = true;
    }
  } else {
    const { willServeMashlib, effectiveEtag } = getMashlibEtag(request, stats, storagePath);
    headEtag = effectiveEtag;
    isMashlibResponse = willServeMashlib;
    // contentType for files is negotiated AFTER the If-None-Match check
    // below — negotiation may read the file (#552), and GET 304s files
    // before any read, so HEAD must not pay I/O a 304 will discard.
  }

  // Check If-None-Match using the final ETag (#456)
  const ifNoneMatch = request.headers['if-none-match'];
  if (ifNoneMatch) {
    const check = checkIfNoneMatchForGet(ifNoneMatch, headEtag);
    if (!check.ok && check.notModified) {
      reply.header('ETag', headEtag);
      reply.header('Vary', getVaryHeader(connegEnabled, request.mashlibEnabled));
      return reply.code(304).send();
    }
  }

  let negotiationConverted = false;
  if (!stats.isDirectory) {
    // Mirror GET's content-type for files — including the negotiated
    // Turtle/JSON-LD forms and the extensionless HTML sniff — so HEAD
    // and GET agree (#552, RFC 9110 §9.3.2).
    if (isMashlibResponse) {
      contentType = 'text/html';
    } else {
      const negotiation = await negotiateHeadFileContentType({
        storagePath,
        urlPath,
        stats,
        acceptHeader: request.headers.accept || '',
        connegEnabled,
      });
      contentType = negotiation.contentType;
      negotiationConverted = negotiation.converted;
    }
  }

  const headers = getAllHeaders({
    isContainer: stats.isDirectory,
    etag: headEtag,
    contentType,
    origin,
    resourceUrl,
    connegEnabled,
    mashlibEnabled: request.mashlibEnabled
  });

  // Mirror GET's Cache-Control for RDF responses (#552 header parity).
  // GET applies RDF_CACHE_CONTROL uniformly wherever the response
  // content type is RDF — container listings (Turtle/JSON-LD) and
  // files (converted or as-is) alike; HTML responses don't get it.
  if (isRdfContentType(contentType)) {
    headers['Cache-Control'] = RDF_CACHE_CONTROL;
  }

  // Content-Length: only set when the file size matches the response body.
  // Mashlib HTML and containers are dynamically generated, and a
  // conneg-converted body (Turtle / re-serialized JSON-LD, #552) has a
  // different length than the on-disk file — omit rather than lie.
  if (!stats.isDirectory && !isMashlibResponse && !negotiationConverted) {
    headers['Content-Length'] = stats.size;
  }

  Object.entries(headers).forEach(([k, v]) => reply.header(k, v));
  return reply.code(200).send();
}

/**
 * Handle PUT request
 */
export async function handlePut(request, reply) {
  // Read-only mode - block all writes
  if (request.config?.readOnly) {
    return reply.code(405).send({ error: 'Method Not Allowed', message: 'Server is in read-only mode' });
  }

  const { urlPath, storagePath, resourceUrl } = getRequestPaths(request);
  const connegEnabled = request.connegEnabled || false;

  // Handle container creation via PUT
  if (isContainer(urlPath)) {
    const stats = await storage.stat(storagePath);
    if (stats?.isDirectory) {
      // If container has index.html and PUT sends HTML, rewrite URL to target the
      // index document and delegate to the standard PUT pipeline. This mirrors GET
      // behavior (line 138) which serves index.html for container URLs, and reuses
      // If-Match/If-None-Match, quota checks, and notification handling.
      const indexPath = storagePath.endsWith('/') ? `${storagePath}index.html` : `${storagePath}/index.html`;
      const contentType = request.headers['content-type'] || '';
      if (contentType.includes('text/html') && await storage.exists(indexPath)) {
        const indexUrl = urlPath.endsWith('/') ? `${urlPath}index.html` : `${urlPath}/index.html`;
        // Fastify request.url is a getter, so proxy it with the rewritten path
        const proxied = Object.create(request, { url: { value: indexUrl } });
        return handlePut(proxied, reply);
      }
      // Container exists but no index routing applies - reject
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

  // ACL resources require a JSON-LD payload (application/ld+json or
  // application/json). Round-trip serialization between JSON-LD and
  // Turtle representations has limitations that can cause data loss
  // when a client PUTs Turtle and later requests Turtle.
  // Other RDF resources are unaffected. The guard fires regardless
  // of conneg setting and also when Content-Type is missing.
  const ctMain = contentType.split(';')[0].trim().toLowerCase();
  const isJsonLd = ctMain === 'application/ld+json' || ctMain === 'application/json';
  if (urlPath.endsWith('.acl') && !isJsonLd) {
    reply.header('Accept', 'application/ld+json, application/json');
    reply.header('Accept-Put', 'application/ld+json, application/json');
    return reply.code(415).send({
      error: 'Unsupported Media Type',
      message: 'ACL resources must be sent as application/ld+json or application/json.'
    });
  }

  // Check if we can accept this input type
  if (!canAcceptInput(contentType, connegEnabled)) {
    const acceptValue = connegEnabled
      ? 'application/ld+json, application/json, text/turtle, text/n3'
      : 'application/ld+json, application/json';
    reply.header('Accept', acceptValue);
    reply.header('Accept-Put', acceptValue);
    return reply.code(415).send({
      error: 'Unsupported Media Type',
      message: connegEnabled
        ? 'Supported types: application/ld+json, application/json, text/turtle, text/n3'
        : 'Supported types: application/ld+json, application/json (enable conneg for Turtle/N3 support)'
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

  // Check storage quota before writing (skip in public mode - no pod structure)
  const podName = request.config?.public ? null : getPodName(request);
  const oldSize = stats?.size || 0;
  const sizeDelta = content.length - oldSize;

  if (podName && sizeDelta > 0) {
    const { allowed, error } = await checkQuota(podName, sizeDelta, request.defaultQuota || 0);
    if (!allowed) {
      return reply.code(507).send({ error: 'Insufficient Storage', message: error });
    }
  }

  const success = await storage.write(storagePath, content);
  if (!success) {
    return reply.code(500).send({ error: 'Write failed' });
  }

  // Update quota usage after successful write
  if (podName && sizeDelta !== 0) {
    await updateQuotaUsage(podName, sizeDelta);
  }

  const origin = request.headers.origin;
  const headers = getAllHeaders({ isContainer: false, origin, resourceUrl, connegEnabled, mashlibEnabled: request.mashlibEnabled });
  headers['Location'] = resourceUrl;

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
  // Read-only mode - block all writes
  if (request.config?.readOnly) {
    return reply.code(405).send({ error: 'Method Not Allowed', message: 'Server is in read-only mode' });
  }

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

  // Get file size before deletion for quota update
  const fileSize = stats.size || 0;

  const success = await storage.remove(storagePath);
  if (!success) {
    return reply.code(500).send({ error: 'Delete failed' });
  }

  // Update quota usage (subtract deleted file size)
  const podName = getPodName(request);
  if (podName && fileSize > 0) {
    await updateQuotaUsage(podName, -fileSize);
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
  // Read-only mode - block all writes
  if (request.config?.readOnly) {
    return reply.code(405).send({ error: 'Method Not Allowed', message: 'Server is in read-only mode' });
  }

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
        document = safeJsonParse(jsonLdMatch[1]);
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
        document = safeJsonParse(contentStr);
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
