/**
 * Turtle <-> JSON-LD Conversion
 *
 * Provides bidirectional conversion between Turtle and JSON-LD formats.
 * Uses the N3.js library for parsing and serializing Turtle.
 */

import { Parser, Writer, DataFactory } from 'n3';
const { namedNode, literal, blankNode, quad } = DataFactory;

// Common prefixes for compact output
const COMMON_PREFIXES = {
  rdf: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
  rdfs: 'http://www.w3.org/2000/01/rdf-schema#',
  xsd: 'http://www.w3.org/2001/XMLSchema#',
  foaf: 'http://xmlns.com/foaf/0.1/',
  ldp: 'http://www.w3.org/ns/ldp#',
  solid: 'http://www.w3.org/ns/solid/terms#',
  acl: 'http://www.w3.org/ns/auth/acl#',
  pim: 'http://www.w3.org/ns/pim/space#',
  dc: 'http://purl.org/dc/terms/',
  schema: 'http://schema.org/',
  vcard: 'http://www.w3.org/2006/vcard/ns#'
};

/**
 * Parse Turtle to JSON-LD
 * @param {string} turtle - Turtle content
 * @param {string} baseUri - Base URI for relative references
 * @returns {Promise<object>} JSON-LD document
 */
export async function turtleToJsonLd(turtle, baseUri) {
  return new Promise((resolve, reject) => {
    const parser = new Parser({ baseIRI: baseUri });
    const quads = [];

    parser.parse(turtle, (error, quad, prefixes) => {
      if (error) {
        reject(error);
        return;
      }

      if (quad) {
        quads.push(quad);
      } else {
        // Parsing complete
        try {
          const jsonLd = quadsToJsonLd(quads, baseUri, prefixes);
          resolve(jsonLd);
        } catch (e) {
          reject(e);
        }
      }
    });
  });
}

/**
 * Convert JSON-LD to Turtle
 * @param {object} jsonLd - JSON-LD document
 * @param {string} baseUri - Base URI for the document
 * @returns {Promise<string>} Turtle content
 */
export async function jsonLdToTurtle(jsonLd, baseUri) {
  return new Promise((resolve, reject) => {
    try {
      const quads = jsonLdToQuads(jsonLd, baseUri);

      // Don't use baseIRI in writer - output absolute URIs for compatibility
      // Some Solid servers (like NSS) may not properly resolve relative URIs
      // when verifying oidcIssuer claims
      const writer = new Writer({
        prefixes: COMMON_PREFIXES
      });

      for (const q of quads) {
        writer.addQuad(q);
      }

      writer.end((error, result) => {
        if (error) {
          reject(error);
        } else {
          resolve(result);
        }
      });
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * Convert N3.js quads to JSON-LD
 */
function quadsToJsonLd(quads, baseUri, prefixes = {}) {
  if (quads.length === 0) {
    return { '@context': buildContext(prefixes) };
  }

  // Group quads by subject
  const subjects = new Map();

  for (const quad of quads) {
    const subjectKey = quad.subject.value;
    if (!subjects.has(subjectKey)) {
      subjects.set(subjectKey, {
        '@id': makeRelative(quad.subject.value, baseUri),
        _quads: []
      });
    }
    subjects.get(subjectKey)._quads.push(quad);
  }

  // Build nodes
  const nodes = [];
  for (const [subjectUri, node] of subjects) {
    const jsonNode = { '@id': node['@id'] };

    for (const quad of node._quads) {
      const predicate = quad.predicate.value;
      const predicateKey = compactUri(predicate, prefixes);

      // Handle rdf:type specially
      if (predicate === 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type') {
        const typeValue = compactUri(quad.object.value, prefixes);
        if (jsonNode['@type']) {
          if (Array.isArray(jsonNode['@type'])) {
            jsonNode['@type'].push(typeValue);
          } else {
            jsonNode['@type'] = [jsonNode['@type'], typeValue];
          }
        } else {
          jsonNode['@type'] = typeValue;
        }
        continue;
      }

      const objectValue = termToJsonLd(quad.object, baseUri, prefixes);

      if (jsonNode[predicateKey]) {
        // Multiple values - make array
        if (Array.isArray(jsonNode[predicateKey])) {
          jsonNode[predicateKey].push(objectValue);
        } else {
          jsonNode[predicateKey] = [jsonNode[predicateKey], objectValue];
        }
      } else {
        jsonNode[predicateKey] = objectValue;
      }
    }

    nodes.push(jsonNode);
  }

  // Build result - return array if multiple nodes, single object otherwise
  const context = buildContext(prefixes);

  if (nodes.length === 1) {
    return { '@context': context, ...nodes[0] };
  }

  // Multiple nodes: return as array (no @graph)
  return nodes.map((node, i) => i === 0 ? { '@context': context, ...node } : node);
}

/**
 * Convert JSON-LD to N3.js quads
 */
function jsonLdToQuads(jsonLd, baseUri) {
  const quads = [];

  // Handle array of JSON-LD objects (e.g., from multiple PATCH operations)
  const documents = Array.isArray(jsonLd) ? jsonLd : [jsonLd];

  // Merge all contexts and collect all nodes
  let mergedContext = {};
  let nodes = [];

  for (const doc of documents) {
    if (doc['@context']) {
      mergedContext = { ...mergedContext, ...doc['@context'] };
    }
    // Each document with @id is a node (no @graph needed)
    if (doc['@id']) {
      nodes.push(doc);
    }
  }

  const context = mergedContext;

  for (const node of nodes) {
    if (!node['@id']) continue;

    const subjectUri = resolveUri(node['@id'], baseUri);
    const subject = subjectUri.startsWith('_:')
      ? blankNode(subjectUri.slice(2))
      : namedNode(subjectUri);

    // Handle @type
    if (node['@type']) {
      const types = Array.isArray(node['@type']) ? node['@type'] : [node['@type']];
      for (const type of types) {
        const typeUri = expandUri(type, context);
        quads.push(quad(
          subject,
          namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
          namedNode(typeUri)
        ));
      }
    }

    // Handle other properties
    for (const [key, value] of Object.entries(node)) {
      if (key.startsWith('@')) continue;

      const predicateUri = expandUri(key, context);
      const predicate = namedNode(predicateUri);

      // Check if context specifies this property should be a URI (@type: "@id")
      const propContext = context[key];
      const isIdType = propContext && typeof propContext === 'object' && propContext['@type'] === '@id';

      const values = Array.isArray(value) ? value : [value];
      for (const v of values) {
        const object = valueToTerm(v, baseUri, context, isIdType);
        if (object) {
          quads.push(quad(subject, predicate, object));
        }
      }
    }
  }

  return quads;
}

/**
 * Convert N3.js term to JSON-LD value
 */
function termToJsonLd(term, baseUri, prefixes) {
  if (term.termType === 'NamedNode') {
    const uri = makeRelative(term.value, baseUri);
    // Check if it looks like a URI or should be @id
    if (uri.includes('://') || uri.startsWith('#') || uri.startsWith('/')) {
      return { '@id': uri };
    }
    return { '@id': uri };
  }

  if (term.termType === 'BlankNode') {
    return { '@id': '_:' + term.value };
  }

  if (term.termType === 'Literal') {
    // Check for language tag
    if (term.language) {
      return { '@value': term.value, '@language': term.language };
    }

    // Check for datatype
    const datatype = term.datatype?.value;
    if (datatype) {
      // Handle common XSD types
      if (datatype === 'http://www.w3.org/2001/XMLSchema#integer') {
        return parseInt(term.value, 10);
      }
      if (datatype === 'http://www.w3.org/2001/XMLSchema#decimal' ||
          datatype === 'http://www.w3.org/2001/XMLSchema#double' ||
          datatype === 'http://www.w3.org/2001/XMLSchema#float') {
        return parseFloat(term.value);
      }
      if (datatype === 'http://www.w3.org/2001/XMLSchema#boolean') {
        return term.value === 'true';
      }
      if (datatype === 'http://www.w3.org/2001/XMLSchema#string') {
        return term.value;
      }
      // Other typed literals
      return { '@value': term.value, '@type': compactUri(datatype, prefixes) };
    }

    return term.value;
  }

  return term.value;
}

/**
 * Convert JSON-LD value to N3.js term
 * @param {any} value - The value to convert
 * @param {string} baseUri - Base URI for resolving relative URIs
 * @param {object} context - JSON-LD context
 * @param {boolean} isIdType - Whether the property context specifies @type: "@id"
 */
function valueToTerm(value, baseUri, context, isIdType = false) {
  if (value === null || value === undefined) {
    return null;
  }

  // Plain values
  if (typeof value === 'string') {
    // If context says this should be a URI, treat it as a named node
    if (isIdType) {
      const uri = resolveUri(value, baseUri);
      return namedNode(uri);
    }
    return literal(value);
  }
  if (typeof value === 'number') {
    if (Number.isInteger(value)) {
      return literal(value.toString(), namedNode('http://www.w3.org/2001/XMLSchema#integer'));
    }
    return literal(value.toString(), namedNode('http://www.w3.org/2001/XMLSchema#decimal'));
  }
  if (typeof value === 'boolean') {
    return literal(value.toString(), namedNode('http://www.w3.org/2001/XMLSchema#boolean'));
  }

  // Object values
  if (typeof value === 'object') {
    // @id reference
    if (value['@id']) {
      const uri = resolveUri(value['@id'], baseUri);
      return uri.startsWith('_:')
        ? blankNode(uri.slice(2))
        : namedNode(uri);
    }

    // @value with @language
    if (value['@value'] && value['@language']) {
      return literal(value['@value'], value['@language']);
    }

    // @value with @type
    if (value['@value'] && value['@type']) {
      const typeUri = expandUri(value['@type'], context);
      return literal(value['@value'], namedNode(typeUri));
    }

    // Plain @value
    if (value['@value']) {
      return literal(value['@value']);
    }
  }

  return null;
}

/**
 * Make URI relative to base
 */
function makeRelative(uri, baseUri) {
  if (uri.startsWith(baseUri)) {
    const relative = uri.slice(baseUri.length);
    if (relative.startsWith('#') || relative === '') {
      return relative || '.';
    }
    return relative;
  }
  return uri;
}

/**
 * Resolve relative URI against base
 */
function resolveUri(uri, baseUri) {
  if (uri.startsWith('http://') || uri.startsWith('https://') || uri.startsWith('_:')) {
    return uri;
  }
  if (uri.startsWith('#')) {
    return baseUri + uri;
  }
  try {
    return new URL(uri, baseUri).href;
  } catch {
    return uri;
  }
}

/**
 * Expand prefixed URI using context
 */
function expandUri(uri, context) {
  if (uri.includes('://')) {
    return uri;
  }

  if (uri.includes(':')) {
    const [prefix, local] = uri.split(':', 2);
    const ns = context[prefix] || COMMON_PREFIXES[prefix];
    if (ns) {
      return ns + local;
    }
  }

  // Check if it's a term in context
  if (context[uri]) {
    const expansion = context[uri];
    if (typeof expansion === 'string') {
      return expansion;
    }
    if (expansion['@id']) {
      return expansion['@id'];
    }
  }

  return uri;
}

/**
 * Compact URI using prefixes
 */
function compactUri(uri, prefixes) {
  // Check custom prefixes first
  for (const [prefix, ns] of Object.entries(prefixes)) {
    if (uri.startsWith(ns)) {
      return prefix + ':' + uri.slice(ns.length);
    }
  }

  // Check common prefixes
  for (const [prefix, ns] of Object.entries(COMMON_PREFIXES)) {
    if (uri.startsWith(ns)) {
      return prefix + ':' + uri.slice(ns.length);
    }
  }

  return uri;
}

/**
 * Build JSON-LD @context from prefixes
 */
function buildContext(prefixes) {
  const context = { ...COMMON_PREFIXES };
  for (const [prefix, ns] of Object.entries(prefixes)) {
    if (prefix && ns) {
      context[prefix] = ns;
    }
  }
  return context;
}
