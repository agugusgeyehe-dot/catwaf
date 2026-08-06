// render/util.js — shared helpers for turning validated settings into
// Caddyfile text.
//
// Two rules everything here follows:
//
//  1. Tokens are always quoted. settings/types.js has already refused any
//     value containing a quote, brace, backtick, backslash or newline, so a
//     double-quoted token cannot escape its own directive.
//  2. Anything multi-line — HTML, PEM, a raw config blob — is written to a
//     file under the CatWAF data directory and referenced by path, never
//     inlined. That keeps the generated Caddyfile free of any construct
//     whose termination depends on user content.

const fs = require('fs')
const path = require('path')

const db = require('../db')

function q(value) {
  return `"${String(value)}"`
}

function indent(lines, level = 1) {
  const pad = '    '.repeat(level)
  return lines.map(l => (l === '' ? '' : pad + l))
}

function dur(seconds) {
  const n = Math.max(0, Math.trunc(Number(seconds) || 0))
  if (n === 0) return '0s'
  if (n % 86400 === 0) return `${n / 86400}d`
  if (n % 3600 === 0) return `${n / 3600}h`
  if (n % 60 === 0) return `${n / 60}m`
  return `${n}s`
}

function assetDir(...parts) {
  const dir = path.join(path.dirname(db.DB_PATH), 'caddy', ...parts)
  fs.mkdirSync(dir, { recursive: true, mode: 0o750 })
  return dir
}

// Writes a generated asset and returns its absolute path, or null when there
// is nothing to write. Content is compared first so an unchanged asset does
// not churn its mtime on every reload.
function writeAsset(relPath, content, { mode = 0o640 } = {}) {
  if (content == null || content === '') return null
  const parts = relPath.split('/')
  const name = parts.pop()
  const dir = assetDir(...parts)
  const full = path.join(dir, name)
  try {
    if (fs.readFileSync(full, 'utf8') === content) return full
  } catch { /* not written yet */ }
  fs.writeFileSync(full, content, { mode })
  try { fs.chmodSync(full, mode) } catch {}
  return full
}

function removeAsset(relPath) {
  try { fs.unlinkSync(path.join(assetDir(...relPath.split('/').slice(0, -1)), relPath.split('/').pop())) } catch {}
}

// Escapes a string for use inside a Caddy path/header *matcher* regexp.
function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// Caddy placeholder syntax uses {...}; a literal brace in emitted content
// would be interpreted as one. Settings validation already refuses braces in
// tokens, so this only guards generated text (robots.txt, security.txt).
function stripBraces(value) {
  return String(value).replace(/[{}]/g, '')
}

// Every matcher CatWAF emits is namespaced so it can never collide with one
// the operator wrote by hand in the same site block.
function m(name) {
  return `@catwaf_${name}`
}

// A block of directives, rendered only when it has content.
function block(header, lines, level = 0) {
  const body = lines.filter(l => l !== null && l !== undefined)
  if (!body.length) return []
  return [`${header} {`, ...indent(body, 1), '}'].map(l => '    '.repeat(level) + l)
}

module.exports = { q, indent, dur, assetDir, writeAsset, removeAsset, escapeRegex, stripBraces, m, block }
