/**
 * Quad-based PATCH application.
 *
 * Both patch formats are parsed with N3.js and applied to the resource as a
 * set of quads, so every Turtle construct a client can write (typed and
 * language-tagged literals, prefixed names, lists, blank nodes, multi-line
 * strings) survives the round trip. The earlier hand-rolled parsers lost
 * triples whose predicates were not in a fixed prefix table (#).
 *
 * N3 Patch (https://solid.github.io/specification/protocol#n3-patch):
 *   _:p a solid:InsertDeletePatch;
 *      solid:where   { ?a ex:p ?b };     # optional; must match exactly once
 *      solid:deletes { ?a ex:p ?b };     # optional
 *      solid:inserts { ?a ex:q "new" }.  # optional
 *
 * SPARQL Update: INSERT DATA / DELETE DATA / DELETE INSERT WHERE / DELETE WHERE
 * (see ./sparql-update.js for the parsing).
 */
import { Parser, DataFactory } from 'n3';
import { parseSparqlUpdate } from './sparql-update.js';

const { namedNode, literal, blankNode, quad, defaultGraph } = DataFactory;
const SOLID = 'http://www.w3.org/ns/solid/terms#';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';

export class PatchError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

/**
 * Parse an N3 Patch document into { inserts, deletes, where } quads (default graph).
 * @param {string} text
 * @param {string} baseUri - the resource URL; relative IRIs resolve against it
 */
export function parseN3PatchQuads(text, baseUri) {
  const parser = new Parser({ format: 'text/n3', baseIRI: baseUri });
  let quads;
  try {
    quads = parser.parse(text);
  } catch (e) {
    throw new PatchError(`Invalid N3 Patch: ${e.message}`);
  }
  const top = quads.filter((q) => q.subject && q.predicate && q.object && q.graph.termType === 'DefaultGraph');
  // The patch resource: typed solid:InsertDeletePatch, or any subject with a patch property.
  const isPatchProp = (p) => [`${SOLID}inserts`, `${SOLID}deletes`, `${SOLID}where`].includes(p);
  const patchSubjects = new Set(
    top.filter((q) => (q.predicate.value === RDF_TYPE && q.object.value === `${SOLID}InsertDeletePatch`) || isPatchProp(q.predicate.value))
      .map((q) => q.subject.value),
  );
  if (!patchSubjects.size) throw new PatchError('Invalid N3 Patch: no solid:InsertDeletePatch found');
  const formula = (prop) => {
    const graphs = top.filter((q) => patchSubjects.has(q.subject.value) && q.predicate.value === `${SOLID}${prop}`).map((q) => q.object);
    return quads
      // An empty formula `{ }` comes out of N3.js as a quad with null terms: nothing to apply.
      .filter((q) => q.subject && q.predicate && q.object && graphs.some((g) => g.equals(q.graph)))
      .map((q) => quad(q.subject, q.predicate, q.object, defaultGraph()));
  };
  return { inserts: formula('inserts'), deletes: formula('deletes'), where: formula('where') };
}

/** A parsed SPARQL Update triple ({ subject, predicate, object }) as a quad. */
function tripleToQuad(t) {
  const node = (v) => (v.startsWith('_:') ? blankNode(v.slice(2)) : namedNode(v));
  let o;
  if (typeof t.object === 'string') o = literal(t.object);
  else if (t.object['@id']) o = node(t.object['@id']);
  else if (t.object['@language']) o = literal(String(t.object['@value']), t.object['@language']);
  else if (t.object['@type']) o = literal(String(t.object['@value']), namedNode(t.object['@type']));
  else o = literal(String(t.object['@value'] ?? t.object));
  return quad(node(t.subject), namedNode(t.predicate), o, defaultGraph());
}

export function parseSparqlUpdateQuads(text, baseUri) {
  let update;
  try {
    update = parseSparqlUpdate(text, baseUri);
  } catch (e) {
    throw new PatchError(`Invalid SPARQL Update: ${e.message}`);
  }
  return { inserts: update.inserts.map(tripleToQuad), deletes: update.deletes.map(tripleToQuad), where: [] };
}

export function parsePatch(text, contentType, baseUri) {
  return contentType.includes('sparql-update') ? parseSparqlUpdateQuads(text, baseUri) : parseN3PatchQuads(text, baseUri);
}

/** True when the patch only adds triples, so acl:Append is enough to apply it. */
export const isInsertOnly = (patch) => patch.deletes.length === 0 && patch.where.length === 0;

// ---------- Applying ----------

const isVar = (t) => t.termType === 'Variable';

function matchTerm(pattern, term, bindings) {
  if (!isVar(pattern)) return pattern.equals(term);
  const bound = bindings.get(pattern.value);
  if (bound) return bound.equals(term);
  bindings.set(pattern.value, term);
  return true;
}

// Every binding of the where pattern's variables against the document.
function solutions(where, quads) {
  let partial = [new Map()];
  for (const pattern of where) {
    const next = [];
    for (const bindings of partial)
      for (const q of quads) {
        const b = new Map(bindings);
        if (matchTerm(pattern.subject, q.subject, b) && matchTerm(pattern.predicate, q.predicate, b) && matchTerm(pattern.object, q.object, b)) next.push(b);
      }
    partial = next;
    if (!partial.length) break;
  }
  // Distinct solutions (the same quad can satisfy a pattern more than once).
  const seen = new Set();
  return partial.filter((b) => {
    const key = [...b].map(([k, v]) => `${k}=${v.termType}:${v.value}`).sort().join('|');
    return !seen.has(key) && seen.add(key);
  });
}

function substitute(q, bindings, blankMap) {
  const term = (t) => {
    if (isVar(t)) {
      const bound = bindings.get(t.value);
      if (!bound) throw new PatchError(`Unbound variable ?${t.value} in patch`, 409);
      return bound;
    }
    // Blank nodes from the patch are fresh: never collide with the document's own.
    if (t.termType === 'BlankNode') {
      if (!blankMap.has(t.value)) blankMap.set(t.value, blankNode(`p${blankMap.size}_${Date.now().toString(36)}`));
      return blankMap.get(t.value);
    }
    return t;
  };
  return quad(term(q.subject), term(q.predicate), term(q.object), defaultGraph());
}

/**
 * Apply a parsed patch to the document's quads. Returns the new quad list.
 * Throws PatchError(409) when the where clause does not match exactly once or a
 * triple to delete is absent (both per the Solid protocol).
 */
export function applyPatch(quads, patch) {
  let bindings = new Map();
  if (patch.where.length) {
    const found = solutions(patch.where, quads);
    if (found.length !== 1) throw new PatchError(found.length ? 'The patch where clause matches more than once' : 'The patch where clause does not match the resource', 409);
    bindings = found[0];
  }
  const blankMap = new Map();
  const deletes = patch.deletes.map((q) => substitute(q, bindings, blankMap));
  const inserts = patch.inserts.map((q) => substitute(q, bindings, blankMap));
  let result = [...quads];
  for (const d of deletes) {
    const at = result.findIndex((q) => q.equals(d));
    if (at < 0) throw new PatchError(`Triple to delete not found: ${d.subject.value} ${d.predicate.value}`, 409);
    result.splice(at, 1);
  }
  for (const i of inserts) if (!result.some((q) => q.equals(i))) result.push(i);
  return result;
}
