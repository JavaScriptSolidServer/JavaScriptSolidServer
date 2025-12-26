/**
 * SPARQL Update Parser
 *
 * Parses SPARQL Update syntax and applies changes to JSON-LD documents.
 * Supports:
 * - INSERT DATA { triples }
 * - DELETE DATA { triples }
 * - DELETE { pattern } INSERT { pattern } WHERE { pattern }
 *
 * Note: This is a simplified parser for common Solid use cases.
 */

import { Parser, Writer, DataFactory } from 'n3';
const { namedNode, literal, blankNode, quad } = DataFactory;

/**
 * Parse a SPARQL Update query
 * @param {string} sparql - The SPARQL Update query
 * @param {string} baseUri - Base URI for relative references
 * @returns {{ inserts: Array, deletes: Array }}
 */
export function parseSparqlUpdate(sparql, baseUri) {
  const result = {
    inserts: [],
    deletes: []
  };

  // Normalize whitespace
  const normalized = sparql.trim();

  // Extract prefixes
  const prefixes = {};
  const prefixRegex = /PREFIX\s+(\w*):?\s*<([^>]+)>/gi;
  let match;
  while ((match = prefixRegex.exec(normalized)) !== null) {
    prefixes[match[1] || ''] = match[2];
  }

  // Remove prefix declarations for parsing
  let query = normalized.replace(/PREFIX\s+\w*:?\s*<[^>]+>\s*/gi, '').trim();

  // Handle INSERT DATA
  const insertDataMatch = query.match(/INSERT\s+DATA\s*\{([^}]+)\}/is);
  if (insertDataMatch) {
    const triples = parseTriples(insertDataMatch[1], baseUri, prefixes);
    result.inserts.push(...triples);
  }

  // Handle DELETE DATA
  const deleteDataMatch = query.match(/DELETE\s+DATA\s*\{([^}]+)\}/is);
  if (deleteDataMatch) {
    const triples = parseTriples(deleteDataMatch[1], baseUri, prefixes);
    result.deletes.push(...triples);
  }

  // Handle DELETE { } INSERT { } WHERE { }
  // This is a simplified version - we treat DELETE/INSERT as data operations
  const deleteInsertMatch = query.match(/DELETE\s*\{([^}]*)\}\s*INSERT\s*\{([^}]*)\}\s*WHERE\s*\{[^}]*\}/is);
  if (deleteInsertMatch) {
    if (deleteInsertMatch[1].trim()) {
      const deleteTriples = parseTriples(deleteInsertMatch[1], baseUri, prefixes);
      result.deletes.push(...deleteTriples);
    }
    if (deleteInsertMatch[2].trim()) {
      const insertTriples = parseTriples(deleteInsertMatch[2], baseUri, prefixes);
      result.inserts.push(...insertTriples);
    }
  }

  // Handle DELETE WHERE { } (shorthand for DELETE { pattern } WHERE { pattern })
  const deleteWhereMatch = query.match(/DELETE\s+WHERE\s*\{([^}]+)\}/is);
  if (deleteWhereMatch) {
    const triples = parseTriples(deleteWhereMatch[1], baseUri, prefixes);
    result.deletes.push(...triples);
  }

  // Handle standalone INSERT { } WHERE { }
  const insertWhereMatch = query.match(/INSERT\s*\{([^}]+)\}\s*WHERE\s*\{[^}]*\}/is);
  if (insertWhereMatch && !deleteInsertMatch) {
    const triples = parseTriples(insertWhereMatch[1], baseUri, prefixes);
    result.inserts.push(...triples);
  }

  return result;
}

/**
 * Parse Turtle-like triples into an array of triple objects
 * @param {string} triplesStr - Turtle-formatted triples
 * @param {string} baseUri - Base URI
 * @param {object} prefixes - Prefix mappings
 * @returns {Array<{subject: string, predicate: string, object: any}>}
 */
function parseTriples(triplesStr, baseUri, prefixes = {}) {
  const triples = [];

  // Build prefix declarations for N3 parser
  let turtleDoc = '';
  for (const [prefix, uri] of Object.entries(prefixes)) {
    turtleDoc += `@prefix ${prefix}: <${uri}> .\n`;
  }
  turtleDoc += `@base <${baseUri}> .\n`;
  turtleDoc += triplesStr;

  try {
    const parser = new Parser({ baseIRI: baseUri });
    const quads = parser.parse(turtleDoc);

    for (const q of quads) {
      triples.push({
        subject: termToValue(q.subject, baseUri),
        predicate: termToValue(q.predicate, baseUri),
        object: termToJsonLdValue(q.object, baseUri)
      });
    }
  } catch (e) {
    // If N3 parsing fails, try simple regex parsing for basic patterns
    const simpleTriples = parseSimpleTriples(triplesStr, baseUri, prefixes);
    triples.push(...simpleTriples);
  }

  return triples;
}

/**
 * Convert N3 term to a string value
 */
function termToValue(term, baseUri) {
  if (term.termType === 'NamedNode') {
    return term.value;
  } else if (term.termType === 'BlankNode') {
    return `_:${term.value}`;
  }
  return term.value;
}

/**
 * Convert N3 term to JSON-LD value format
 */
function termToJsonLdValue(term, baseUri) {
  if (term.termType === 'NamedNode') {
    return { '@id': term.value };
  } else if (term.termType === 'BlankNode') {
    return { '@id': `_:${term.value}` };
  } else if (term.termType === 'Literal') {
    if (term.datatype && term.datatype.value !== 'http://www.w3.org/2001/XMLSchema#string') {
      return {
        '@value': term.value,
        '@type': term.datatype.value
      };
    } else if (term.language) {
      return {
        '@value': term.value,
        '@language': term.language
      };
    }
    return term.value;
  }
  return term.value;
}

/**
 * Simple regex-based triple parsing as fallback
 */
function parseSimpleTriples(triplesStr, baseUri, prefixes) {
  const triples = [];

  // Very basic pattern matching for simple cases
  // Format: <subject> <predicate> <object> .
  // or: <subject> <predicate> "literal" .
  const lines = triplesStr.split(/\.\s*/).filter(l => l.trim());

  for (const line of lines) {
    const parts = line.trim().match(/^(<[^>]+>|[\w:]+)\s+(<[^>]+>|[\w:]+)\s+(.+)$/);
    if (parts) {
      const subject = expandUri(parts[1].trim(), baseUri, prefixes);
      const predicate = expandUri(parts[2].trim(), baseUri, prefixes);
      const objectStr = parts[3].trim();

      let object;
      if (objectStr.startsWith('<') && objectStr.endsWith('>')) {
        object = { '@id': expandUri(objectStr, baseUri, prefixes) };
      } else if (objectStr.startsWith('"')) {
        // Parse literal
        const literalMatch = objectStr.match(/^"([^"]*)"(?:@(\w+)|\^\^<([^>]+)>)?/);
        if (literalMatch) {
          if (literalMatch[2]) {
            object = { '@value': literalMatch[1], '@language': literalMatch[2] };
          } else if (literalMatch[3]) {
            object = { '@value': literalMatch[1], '@type': literalMatch[3] };
          } else {
            object = literalMatch[1];
          }
        } else {
          object = objectStr.replace(/^"|"$/g, '');
        }
      } else {
        // Prefixed name
        object = { '@id': expandUri(objectStr, baseUri, prefixes) };
      }

      triples.push({ subject, predicate, object });
    }
  }

  return triples;
}

/**
 * Expand a prefixed name or relative URI
 */
function expandUri(uri, baseUri, prefixes) {
  if (uri.startsWith('<') && uri.endsWith('>')) {
    const inner = uri.slice(1, -1);
    if (inner.startsWith('http://') || inner.startsWith('https://')) {
      return inner;
    }
    // Relative URI
    return new URL(inner, baseUri).href;
  }

  // Check for prefixed name
  const colonIndex = uri.indexOf(':');
  if (colonIndex > 0) {
    const prefix = uri.substring(0, colonIndex);
    const local = uri.substring(colonIndex + 1);
    if (prefixes[prefix]) {
      return prefixes[prefix] + local;
    }
  }

  return uri;
}

/**
 * Apply SPARQL Update to a JSON-LD document
 * @param {object} document - The JSON-LD document
 * @param {{ inserts: Array, deletes: Array }} update - Parsed SPARQL Update
 * @param {string} baseUri - Base URI of the document
 * @returns {object} Updated document
 */
export function applySparqlUpdate(document, update, baseUri) {
  // Clone the document
  let doc = JSON.parse(JSON.stringify(document));

  // Ensure document is in a workable format
  if (!Array.isArray(doc)) {
    doc = [doc];
  }

  // Apply deletes
  for (const triple of update.deletes) {
    doc = deleteTriple(doc, triple, baseUri);
  }

  // Apply inserts
  for (const triple of update.inserts) {
    doc = insertTriple(doc, triple, baseUri);
  }

  // Return single object if only one node
  if (Array.isArray(doc) && doc.length === 1) {
    return doc[0];
  }

  return doc;
}

/**
 * Delete a triple from a JSON-LD document
 */
function deleteTriple(doc, triple, baseUri) {
  const subjectId = resolveSubjectId(triple.subject, baseUri);

  for (const node of doc) {
    const nodeId = node['@id'] || '';
    if (matchesSubject(nodeId, subjectId, baseUri)) {
      // Found the subject node, remove the predicate-object pair
      if (node[triple.predicate]) {
        const values = Array.isArray(node[triple.predicate])
          ? node[triple.predicate]
          : [node[triple.predicate]];

        const filtered = values.filter(v => !valuesMatch(v, triple.object));

        if (filtered.length === 0) {
          delete node[triple.predicate];
        } else if (filtered.length === 1) {
          node[triple.predicate] = filtered[0];
        } else {
          node[triple.predicate] = filtered;
        }
      }
    }
  }

  return doc;
}

/**
 * Insert a triple into a JSON-LD document
 */
function insertTriple(doc, triple, baseUri) {
  const subjectId = resolveSubjectId(triple.subject, baseUri);

  // Find existing node for subject
  let targetNode = null;
  for (const node of doc) {
    const nodeId = node['@id'] || '';
    if (matchesSubject(nodeId, subjectId, baseUri)) {
      targetNode = node;
      break;
    }
  }

  // Create new node if not found
  if (!targetNode) {
    targetNode = { '@id': subjectId };
    doc.push(targetNode);
  }

  // Add the predicate-object pair
  if (targetNode[triple.predicate]) {
    const existing = targetNode[triple.predicate];
    if (Array.isArray(existing)) {
      if (!existing.some(v => valuesMatch(v, triple.object))) {
        existing.push(triple.object);
      }
    } else {
      if (!valuesMatch(existing, triple.object)) {
        targetNode[triple.predicate] = [existing, triple.object];
      }
    }
  } else {
    targetNode[triple.predicate] = triple.object;
  }

  return doc;
}

/**
 * Resolve subject ID, handling relative URIs and hash URIs
 */
function resolveSubjectId(subject, baseUri) {
  if (subject.startsWith('#')) {
    return baseUri + subject;
  }
  if (subject.startsWith('_:')) {
    return subject;
  }
  if (!subject.includes('://')) {
    return new URL(subject, baseUri).href;
  }
  return subject;
}

/**
 * Check if a node ID matches a subject
 */
function matchesSubject(nodeId, subjectId, baseUri) {
  if (nodeId === subjectId) return true;

  // Handle hash URIs
  if (subjectId.startsWith('#') && nodeId === baseUri + subjectId) return true;
  if (nodeId.startsWith('#') && subjectId === baseUri + nodeId) return true;

  return false;
}

/**
 * Check if two JSON-LD values match
 */
function valuesMatch(a, b) {
  if (typeof a === 'string' && typeof b === 'string') {
    return a === b;
  }

  if (typeof a === 'object' && typeof b === 'object') {
    // Compare @id
    if (a['@id'] && b['@id']) {
      return a['@id'] === b['@id'];
    }

    // Compare @value
    if (a['@value'] !== undefined && b['@value'] !== undefined) {
      return a['@value'] === b['@value'] &&
             a['@type'] === b['@type'] &&
             a['@language'] === b['@language'];
    }
  }

  // Mixed string/object comparison
  if (typeof a === 'string' && typeof b === 'object' && b['@value']) {
    return a === b['@value'];
  }
  if (typeof b === 'string' && typeof a === 'object' && a['@value']) {
    return b === a['@value'];
  }

  return JSON.stringify(a) === JSON.stringify(b);
}
