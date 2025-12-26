/**
 * N3 Patch Parser and Applier
 *
 * Implements Solid's N3 Patch format for updating RDF resources.
 * https://solid.github.io/specification/protocol#n3-patch
 *
 * Supported format:
 * @prefix solid: <http://www.w3.org/ns/solid/terms#>.
 * _:patch a solid:InsertDeletePatch;
 *   solid:inserts { <subject> <predicate> "object" };
 *   solid:deletes { <subject> <predicate> "old" }.
 */

const SOLID_NS = 'http://www.w3.org/ns/solid/terms#';

/**
 * Parse an N3 Patch document
 * @param {string} patchText - The N3 patch content
 * @param {string} baseUri - Base URI for resolving relative references
 * @returns {{inserts: Array, deletes: Array, where: Array}}
 */
export function parseN3Patch(patchText, baseUri) {
  const result = {
    inserts: [],
    deletes: [],
    where: []
  };

  // Extract prefixes
  const prefixes = {};
  const prefixRegex = /@prefix\s+(\w*):?\s*<([^>]+)>\s*\./g;
  let match;
  while ((match = prefixRegex.exec(patchText)) !== null) {
    prefixes[match[1]] = match[2];
  }

  // Find solid:inserts block
  const insertsMatch = patchText.match(/solid:inserts\s*\{([^}]*)\}/s);
  if (insertsMatch) {
    result.inserts = parseTriples(insertsMatch[1], prefixes, baseUri);
  }

  // Find solid:deletes block
  const deletesMatch = patchText.match(/solid:deletes\s*\{([^}]*)\}/s);
  if (deletesMatch) {
    result.deletes = parseTriples(deletesMatch[1], prefixes, baseUri);
  }

  // Find solid:where block (for conditions - simplified support)
  const whereMatch = patchText.match(/solid:where\s*\{([^}]*)\}/s);
  if (whereMatch) {
    result.where = parseTriples(whereMatch[1], prefixes, baseUri);
  }

  return result;
}

/**
 * Parse triples from N3 block content
 */
function parseTriples(content, prefixes, baseUri) {
  const triples = [];

  // Clean up content
  content = content.trim();
  if (!content) return triples;

  // Split by '.' but be careful with strings containing '.'
  const statements = splitStatements(content);

  for (const stmt of statements) {
    const triple = parseStatement(stmt.trim(), prefixes, baseUri);
    if (triple) {
      triples.push(triple);
    }
  }

  return triples;
}

/**
 * Split content into statements (handling quoted strings)
 */
function splitStatements(content) {
  const statements = [];
  let current = '';
  let inString = false;
  let stringChar = null;

  for (let i = 0; i < content.length; i++) {
    const char = content[i];

    if (!inString && (char === '"' || char === "'")) {
      inString = true;
      stringChar = char;
      current += char;
    } else if (inString && char === stringChar && content[i - 1] !== '\\') {
      inString = false;
      stringChar = null;
      current += char;
    } else if (!inString && char === '.') {
      if (current.trim()) {
        statements.push(current);
      }
      current = '';
    } else if (!inString && char === ';') {
      // Turtle shorthand - same subject, different predicate
      if (current.trim()) {
        statements.push(current);
      }
      current = '';
    } else {
      current += char;
    }
  }

  if (current.trim()) {
    statements.push(current);
  }

  return statements;
}

/**
 * Parse a single N3 statement into a triple
 */
function parseStatement(stmt, prefixes, baseUri) {
  if (!stmt) return null;

  // Tokenize - split by whitespace but respect quotes
  const tokens = tokenize(stmt);
  if (tokens.length < 3) return null;

  const subject = resolveValue(tokens[0], prefixes, baseUri);
  const predicate = resolveValue(tokens[1], prefixes, baseUri);
  const object = resolveValue(tokens.slice(2).join(' '), prefixes, baseUri);

  return { subject, predicate, object };
}

/**
 * Tokenize a statement respecting quoted strings
 */
function tokenize(stmt) {
  const tokens = [];
  let current = '';
  let inString = false;
  let stringChar = null;

  for (let i = 0; i < stmt.length; i++) {
    const char = stmt[i];

    if (!inString && (char === '"' || char === "'")) {
      inString = true;
      stringChar = char;
      current += char;
    } else if (inString && char === stringChar && stmt[i - 1] !== '\\') {
      inString = false;
      stringChar = null;
      current += char;
    } else if (!inString && /\s/.test(char)) {
      if (current) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += char;
    }
  }

  if (current) {
    tokens.push(current);
  }

  return tokens;
}

/**
 * Resolve a value (URI, prefixed name, or literal)
 */
function resolveValue(value, prefixes, baseUri) {
  value = value.trim();

  // Full URI
  if (value.startsWith('<') && value.endsWith('>')) {
    const uri = value.slice(1, -1);
    // Resolve relative URIs
    if (!uri.includes('://') && !uri.startsWith('#')) {
      return new URL(uri, baseUri).href;
    }
    if (uri.startsWith('#')) {
      return baseUri + uri;
    }
    return uri;
  }

  // Prefixed name
  if (value.includes(':') && !value.startsWith('"')) {
    const [prefix, local] = value.split(':', 2);
    if (prefixes[prefix]) {
      return prefixes[prefix] + local;
    }
    // Common prefixes
    const commonPrefixes = {
      'solid': SOLID_NS,
      'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
      'rdfs': 'http://www.w3.org/2000/01/rdf-schema#',
      'foaf': 'http://xmlns.com/foaf/0.1/',
      'dc': 'http://purl.org/dc/terms/',
      'schema': 'http://schema.org/',
      'ldp': 'http://www.w3.org/ns/ldp#'
    };
    if (commonPrefixes[prefix]) {
      return commonPrefixes[prefix] + local;
    }
  }

  // String literal
  if (value.startsWith('"')) {
    // Handle typed literals "value"^^<type>
    const typedMatch = value.match(/^"(.*)"\^\^<([^>]+)>$/);
    if (typedMatch) {
      return { value: typedMatch[1], type: typedMatch[2] };
    }
    // Handle language tags "value"@en
    const langMatch = value.match(/^"(.*)"@(\w+)$/);
    if (langMatch) {
      return { value: langMatch[1], language: langMatch[2] };
    }
    // Plain string
    const plainMatch = value.match(/^"(.*)"$/);
    if (plainMatch) {
      return plainMatch[1];
    }
  }

  // Variable (for WHERE patterns)
  if (value.startsWith('?')) {
    return { variable: value.slice(1) };
  }

  // Blank node
  if (value.startsWith('_:')) {
    return { blankNode: value.slice(2) };
  }

  return value;
}

/**
 * Apply an N3 Patch to a JSON-LD document
 * @param {object} document - The JSON-LD document
 * @param {object} patch - Parsed patch {inserts, deletes}
 * @param {string} baseUri - Base URI of the document
 * @returns {object} Updated JSON-LD document
 */
export function applyN3Patch(document, patch, baseUri) {
  // Clone the document
  let doc = JSON.parse(JSON.stringify(document));

  // Handle @graph array or single object
  const isGraph = Array.isArray(doc['@graph']);
  let nodes = isGraph ? doc['@graph'] : [doc];

  // Apply deletes first
  for (const triple of patch.deletes) {
    nodes = deleteTriple(nodes, triple, baseUri);
  }

  // Then apply inserts
  for (const triple of patch.inserts) {
    nodes = insertTriple(nodes, triple, baseUri);
  }

  // Reconstruct document
  if (isGraph) {
    doc['@graph'] = nodes;
  } else {
    doc = nodes[0] || doc;
  }

  return doc;
}

/**
 * Delete a triple from JSON-LD nodes
 */
function deleteTriple(nodes, triple, baseUri) {
  const { subject, predicate, object } = triple;

  for (const node of nodes) {
    const nodeId = node['@id'] || '';
    const resolvedNodeId = nodeId.startsWith('#') ? baseUri + nodeId : nodeId;

    // Check if this node matches the subject
    if (resolvedNodeId === subject || nodeId === subject) {
      // Find the predicate
      for (const key of Object.keys(node)) {
        if (key.startsWith('@')) continue;

        // Check if key matches predicate (could be full URI or prefixed)
        if (key === predicate || expandPredicate(key) === predicate) {
          const values = Array.isArray(node[key]) ? node[key] : [node[key]];
          const newValues = values.filter(v => !valueMatches(v, object));

          if (newValues.length === 0) {
            delete node[key];
          } else if (newValues.length === 1) {
            node[key] = newValues[0];
          } else {
            node[key] = newValues;
          }
        }
      }
    }
  }

  return nodes;
}

/**
 * Insert a triple into JSON-LD nodes
 */
function insertTriple(nodes, triple, baseUri) {
  const { subject, predicate, object } = triple;

  // Find or create the subject node
  let subjectNode = nodes.find(n => {
    const nodeId = n['@id'] || '';
    const resolvedNodeId = nodeId.startsWith('#') ? baseUri + nodeId : nodeId;
    return resolvedNodeId === subject || nodeId === subject;
  });

  if (!subjectNode) {
    // Create new node
    subjectNode = { '@id': subject };
    nodes.push(subjectNode);
  }

  // Add the predicate-object
  const predicateKey = compactPredicate(predicate);
  const objectValue = convertToJsonLd(object);

  if (subjectNode[predicateKey]) {
    // Add to existing values
    const existing = Array.isArray(subjectNode[predicateKey])
      ? subjectNode[predicateKey]
      : [subjectNode[predicateKey]];

    // Check if value already exists
    if (!existing.some(v => valueMatches(v, object))) {
      subjectNode[predicateKey] = [...existing, objectValue];
    }
  } else {
    subjectNode[predicateKey] = objectValue;
  }

  return nodes;
}

/**
 * Check if a JSON-LD value matches an N3 object
 */
function valueMatches(jsonLdValue, n3Object) {
  // Handle null/undefined
  if (jsonLdValue === null || jsonLdValue === undefined) {
    return false;
  }

  // Number comparison - N3 numbers may come as strings
  if (typeof jsonLdValue === 'number') {
    if (typeof n3Object === 'number') {
      return jsonLdValue === n3Object;
    }
    if (typeof n3Object === 'string') {
      return jsonLdValue === parseFloat(n3Object) || jsonLdValue.toString() === n3Object;
    }
  }

  // String comparison
  if (typeof jsonLdValue === 'string' && typeof n3Object === 'string') {
    return jsonLdValue === n3Object;
  }

  // @id comparison
  if (jsonLdValue && jsonLdValue['@id']) {
    return jsonLdValue['@id'] === n3Object;
  }

  // @value comparison
  if (jsonLdValue && jsonLdValue['@value']) {
    if (typeof n3Object === 'object' && n3Object.value) {
      return jsonLdValue['@value'] === n3Object.value;
    }
    return jsonLdValue['@value'] === n3Object;
  }

  // Direct equality (for booleans, numbers parsed as numbers, etc.)
  return jsonLdValue === n3Object || String(jsonLdValue) === String(n3Object);
}

/**
 * Convert N3 object to JSON-LD value
 */
function convertToJsonLd(object) {
  if (typeof object === 'string') {
    // Check if it's a URI
    if (object.startsWith('http://') || object.startsWith('https://')) {
      return { '@id': object };
    }
    return object;
  }

  if (typeof object === 'object') {
    if (object.value && object.type) {
      return { '@value': object.value, '@type': object.type };
    }
    if (object.value && object.language) {
      return { '@value': object.value, '@language': object.language };
    }
    if (object.value) {
      return object.value;
    }
  }

  return object;
}

/**
 * Expand a potentially prefixed predicate to full URI
 */
function expandPredicate(predicate) {
  const commonPrefixes = {
    'solid': SOLID_NS,
    'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
    'rdfs': 'http://www.w3.org/2000/01/rdf-schema#',
    'foaf': 'http://xmlns.com/foaf/0.1/',
    'dc': 'http://purl.org/dc/terms/',
    'schema': 'http://schema.org/',
    'ldp': 'http://www.w3.org/ns/ldp#'
  };

  if (predicate.includes(':')) {
    const [prefix, local] = predicate.split(':', 2);
    if (commonPrefixes[prefix]) {
      return commonPrefixes[prefix] + local;
    }
  }

  return predicate;
}

/**
 * Compact a full URI predicate to prefixed form if possible
 */
function compactPredicate(predicate) {
  const prefixMap = {
    [SOLID_NS]: 'solid:',
    'http://www.w3.org/1999/02/22-rdf-syntax-ns#': 'rdf:',
    'http://www.w3.org/2000/01/rdf-schema#': 'rdfs:',
    'http://xmlns.com/foaf/0.1/': 'foaf:',
    'http://purl.org/dc/terms/': 'dc:',
    'http://schema.org/': 'schema:',
    'http://www.w3.org/ns/ldp#': 'ldp:'
  };

  for (const [uri, prefix] of Object.entries(prefixMap)) {
    if (predicate.startsWith(uri)) {
      return prefix + predicate.slice(uri.length);
    }
  }

  return predicate;
}

/**
 * Validate that a patch can be applied
 * @param {object} document - The JSON-LD document
 * @param {object} patch - Parsed patch
 * @param {string} baseUri - Base URI
 * @returns {{valid: boolean, error: string|null}}
 */
export function validatePatch(document, patch, baseUri) {
  // Check that all deletes exist in the document
  for (const triple of patch.deletes) {
    if (!tripleExists(document, triple, baseUri)) {
      return {
        valid: false,
        error: `Triple to delete not found: ${JSON.stringify(triple)}`
      };
    }
  }

  return { valid: true, error: null };
}

/**
 * Check if a triple exists in a document
 */
function tripleExists(document, triple, baseUri) {
  const nodes = document['@graph'] || [document];
  const { subject, predicate, object } = triple;

  for (const node of nodes) {
    const nodeId = node['@id'] || '';
    const resolvedNodeId = nodeId.startsWith('#') ? baseUri + nodeId : nodeId;

    if (resolvedNodeId === subject || nodeId === subject) {
      for (const key of Object.keys(node)) {
        if (key.startsWith('@')) continue;
        if (key === predicate || expandPredicate(key) === predicate) {
          const values = Array.isArray(node[key]) ? node[key] : [node[key]];
          if (values.some(v => valueMatches(v, object))) {
            return true;
          }
        }
      }
    }
  }

  return false;
}
