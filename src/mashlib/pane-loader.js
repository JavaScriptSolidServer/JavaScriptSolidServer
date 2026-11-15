// pane-loader.js — load SolidOS panes at run time, from URLs. No dependencies, no build.
//
// A dynamically loaded pane is an ES module at a URL whose default export is a SolidOS pane:
// { name, label(subject, context), render(subject, context), icon?, ... }. Nothing about the pane
// changes; only how it reaches the registry. See https://melvincarvalho.github.io/solidos-panes/#dynamic
//
// Works with released SolidOS as it is: mashlib puts the solid-panes module on the page as
// `window.panes`, and `panes.register` is all this needs.
//
//   import { loadPanes } from './pane-loader.js'
//   await loadPanes(['https://alice.example/public/panes/hello-pane.js'])
//
// or in one line, from the browser console on any SolidOS page:
//
//   import('https://…/pane-loader.js?pane=https://…/hello-pane.js')

/** Is this object usable as a SolidOS pane? The same test `register` applies, plus render. */
export function isPane (p) {
  return !!p && typeof p.name === 'string' && p.name !== '' &&
    typeof p.label === 'function' && typeof p.render === 'function'
}

/**
 * Load one pane module and register it. Never throws: a pane that cannot be loaded is skipped.
 * @param {string} url  URL of an ES module whose default export is a pane
 * @param {object} [options]
 * @param {object} [options.panes]  the solid-panes module (default: the page's `panes`)
 * @returns {Promise<{url: string, ok: boolean, name?: string, already?: boolean, reason?: string}>}
 */
export async function loadPane (url, options = {}) {
  const panes = options.panes || globalThis.panes
  if (!panes || typeof panes.register !== 'function') {
    return { url, ok: false, reason: 'no SolidOS pane registry on this page (window.panes.register)' }
  }
  let pane
  try {
    pane = (await import(url)).default
  } catch (err) {
    return { url, ok: false, reason: 'import failed: ' + (err && err.message ? err.message : err) }
  }
  if (!isPane(pane)) {
    return { url, ok: false, reason: 'default export is not a pane (needs name, label, render)' }
  }
  const existing = (panes.list || []).find(p => p.name === pane.name)
  if (existing === pane) return { url, ok: true, name: pane.name, already: true }   // same module, loaded before
  if (existing) return { url, ok: false, name: pane.name, reason: 'a different pane with this name is already registered' }
  panes.register(pane)
  return { url, ok: true, name: pane.name }
}

/**
 * Load several panes, in order, then redraw the current subject so that new panes are offered.
 * @param {string[]} urls
 * @param {object} [options]
 * @param {object} [options.panes]     the solid-panes module (default: the page's `panes`)
 * @param {boolean} [options.refresh]  redraw the current subject afterwards (default true)
 * @param {boolean} [options.show]     open the last loaded pane that applies to the current subject
 * @param {string} [options.subject]   URL of the thing on show, when it is not the page's own URL
 * @returns {Promise<Array>} one result per URL, see loadPane
 */
export async function loadPanes (urls, options = {}) {
  const results = []
  for (const url of urls) {
    const r = await loadPane(url, options)
    results.push(r)
    if (r.ok) console.info('[pane-loader] ' + (r.already ? 'already have' : 'registered') + ' "' + r.name + '" from ' + url)
    else console.warn('[pane-loader] skipped ' + url + ': ' + r.reason)
  }
  if (options.refresh !== false && results.some(r => r.ok)) refresh(results, options)
  return results
}

// Redraw the subject the data browser is showing. If `show` is set, open the newest loaded pane
// whose label accepts the subject; otherwise let SolidOS choose as usual (the new pane is a tab).
function refresh (results, options) {
  const panes = options.panes || globalThis.panes
  const $rdf = globalThis.$rdf
  if (!panes || !$rdf || typeof panes.getOutliner !== 'function' || typeof document === 'undefined') return
  try {
    const outliner = panes.getOutliner(document)
    const subject = $rdf.sym(options.subject || location.href.split('#')[0])
    let pane
    if (options.show) {
      const context = outliner.context || {}
      for (const r of results.filter(r => r.ok).reverse()) {
        const p = panes.byName(r.name)
        try { if (p && p.label(subject, context)) { pane = p; break } } catch (e) { /* a label that throws is a no */ }
      }
    }
    outliner.GotoSubject(subject, true, pane, true, undefined)
  } catch (err) {
    console.warn('[pane-loader] could not redraw the page: ' + (err && err.message ? err.message : err))
  }
}

// One-line use: import('…/pane-loader.js?pane=URL&pane=URL&show') loads those panes at once.
const self = new URL(import.meta.url)
const wanted = self.searchParams.getAll('pane')
if (wanted.length) loadPanes(wanted, { show: self.searchParams.has('show'), subject: self.searchParams.get('subject') || undefined })
