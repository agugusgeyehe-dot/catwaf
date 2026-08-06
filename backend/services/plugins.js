// plugins.js — a data-only plugin format (idea #53).
//
// The brief for this one is explicit, and it is right: loading and running
// third-party code inside CatWAF's backend is a direct path to full
// compromise if the plugin — or the URL it came from — is ever malicious.
// So this implements the narrow version the brief asks for and stops there.
//
// A CatWAF plugin is DATA. It may declare:
//   * default values for existing settings groups (validated against the
//     same schema the API enforces),
//   * knowledge-base entries (text CatAI and the docs panel can surface),
//   * Caddy directive templates written in a constrained placeholder syntax
//     that can only interpolate settings CatWAF already holds.
//
// It may not declare code, and there is no code path that would execute it
// if it tried. `install()` refuses any manifest containing an executable
// field rather than ignoring it, so a plugin written against some future
// "real plugins" API fails loudly instead of appearing to work.

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const db = require('./db')
const settings = require('./settings')
const netGuard = require('./netGuard')
const { isSafeToken } = require('./settings/types')

const STORE_KEY = 'plugins'
const ID_RE = /^[a-z][a-z0-9-]{1,63}$/
const MAX_MANIFEST_BYTES = 256 * 1024

// Fields that would only exist on a manifest trying to execute something.
// Their presence is an error, not something to strip and carry on with.
const FORBIDDEN_FIELDS = ['code', 'script', 'main', 'require', 'exec', 'command', 'hooks', 'middleware', 'entry', 'eval']

// The only placeholders a directive template may contain. Anything else is
// rejected, so a template cannot reach outside the settings namespace.
const PLACEHOLDER_RE = /\{\{\s*settings\.([a-z_]+)\.([a-z0-9_]+)\s*\}\}/g

const VALID_CONTEXTS = ['global-http', 'per-site', 'catch-all', 'waf-global', 'waf-per-site']

function load() {
  const stored = db.getState(STORE_KEY)
  return stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {}
}

function persist(all) { db.setState(STORE_KEY, all) }

function fail(error) { return { ok: false, error } }

function validateManifest(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return fail('A plugin manifest must be a JSON object.')
  if (manifest.catwaf_plugin !== 1) return fail('Manifest is missing "catwaf_plugin": 1.')

  for (const field of FORBIDDEN_FIELDS) {
    if (Object.hasOwn(manifest, field)) {
      return fail(
        `This manifest declares "${field}". CatWAF plugins are data only — they cannot ship or reference executable code, ` +
        'and CatWAF has no mechanism that would run it. Rewrite the plugin using settings_defaults, knowledge or caddy_templates.'
      )
    }
  }

  if (!ID_RE.test(String(manifest.id || ''))) return fail('Plugin id must be lowercase letters, digits and hyphens (2-64 characters).')
  if (!isSafeToken(String(manifest.name || ''), 128)) return fail('Plugin name is missing or contains characters that are not allowed.')
  if (manifest.version !== undefined && !/^\d+\.\d+\.\d+$/.test(String(manifest.version))) return fail('Plugin version must be semver (1.2.3).')

  // settings_defaults — validated against the real schema now, so a broken
  // plugin cannot be installed and only fail later at apply time.
  const defaults = manifest.settings_defaults || {}
  if (typeof defaults !== 'object' || Array.isArray(defaults)) return fail('settings_defaults must be an object.')
  for (const [group, values] of Object.entries(defaults)) {
    if (!settings.isGroup(group)) return fail(`settings_defaults references an unknown settings group "${group}".`)
    const check = settings.validate(group, values)
    if (!check.ok) return fail(`settings_defaults.${group}: ${check.error}`)
    for (const field of Object.keys(values)) {
      if (settings.SCHEMA[group].fields[field]?.writeOnly) {
        return fail(`settings_defaults.${group}.${field} is a secret field — a plugin may not ship credentials.`)
      }
    }
  }

  // knowledge entries — plain text only.
  const knowledge = manifest.knowledge || []
  if (!Array.isArray(knowledge)) return fail('knowledge must be an array.')
  if (knowledge.length > 50) return fail('A plugin may ship at most 50 knowledge entries.')
  for (const [i, entry] of knowledge.entries()) {
    if (!entry || typeof entry !== 'object') return fail(`knowledge[${i}] must be an object.`)
    if (!isSafeToken(String(entry.title || ''), 200)) return fail(`knowledge[${i}].title is missing or invalid.`)
    if (typeof entry.body !== 'string' || entry.body.length > 20000) return fail(`knowledge[${i}].body must be text under 20000 characters.`)
    if (/<script|javascript:|on\w+\s*=/i.test(entry.body)) return fail(`knowledge[${i}].body contains markup that could execute — knowledge entries are plain text.`)
  }

  // caddy_templates — constrained placeholders only.
  const templates = manifest.caddy_templates || []
  if (!Array.isArray(templates)) return fail('caddy_templates must be an array.')
  if (templates.length > 20) return fail('A plugin may ship at most 20 Caddy templates.')
  for (const [i, tpl] of templates.entries()) {
    if (!tpl || typeof tpl !== 'object') return fail(`caddy_templates[${i}] must be an object.`)
    if (!VALID_CONTEXTS.includes(tpl.context)) return fail(`caddy_templates[${i}].context must be one of: ${VALID_CONTEXTS.join(', ')}.`)
    if (typeof tpl.template !== 'string' || tpl.template.length > 8000) return fail(`caddy_templates[${i}].template must be text under 8000 characters.`)
    const check = validateTemplateBody(tpl.template)
    if (!check.ok) return fail(`caddy_templates[${i}]: ${check.error}`)
  }

  return { ok: true }
}

function validateTemplateBody(template) {
  // Every brace pair must be either a CatWAF settings placeholder or a
  // Caddyfile block delimiter — never an arbitrary Caddy placeholder, which
  // could reach request data the plugin has no business seeing.
  const withoutPlaceholders = template.replace(PLACEHOLDER_RE, '')
  const stray = /\{\{|\}\}/.exec(withoutPlaceholders)
  if (stray) return { ok: false, error: 'Only {{settings.<group>.<field>}} placeholders are allowed.' }

  PLACEHOLDER_RE.lastIndex = 0
  let m
  while ((m = PLACEHOLDER_RE.exec(template)) !== null) {
    const [, group, field] = m
    if (!settings.isGroup(group)) return { ok: false, error: `placeholder references unknown settings group "${group}".` }
    const spec = settings.SCHEMA[group].fields[field]
    if (!spec) return { ok: false, error: `placeholder references unknown field "${group}.${field}".` }
    if (spec.writeOnly) return { ok: false, error: `placeholder references the secret field "${group}.${field}".` }
  }
  if (/`/.test(template)) return { ok: false, error: 'backticks are not allowed in a template.' }
  return { ok: true }
}

function renderTemplate(template) {
  return template.replace(PLACEHOLDER_RE, (_, group, field) => {
    const value = settings.get(group)[field]
    if (Array.isArray(value)) return value.map(v => `"${String(v).replace(/[`"'{}\\]/g, '')}"`).join(' ')
    if (typeof value === 'boolean') return value ? 'true' : 'false'
    return String(value ?? '').replace(/[`"'{}\\\r\n]/g, '')
  })
}

function fingerprint(manifest) {
  return crypto.createHash('sha256').update(JSON.stringify(manifest)).digest('hex').slice(0, 32)
}

// Optional Ed25519 signature. A plugin does not have to be signed to be
// installed locally, but an unsigned one is labelled as such everywhere it
// appears, and only signed plugins may be installed from a URL.
function verifySignature(manifest) {
  const trusted = String(process.env.CATWAF_PLUGIN_KEYS || '').split(',').map(s => s.trim()).filter(Boolean)
  if (!manifest.signature) return { signed: false, trusted: false }
  if (!trusted.length) return { signed: true, trusted: false, reason: 'No trusted plugin keys are configured (CATWAF_PLUGIN_KEYS).' }

  const { signature, ...body } = manifest
  const payload = Buffer.from(JSON.stringify(body))
  for (const keyPem of trusted) {
    try {
      const key = crypto.createPublicKey(Buffer.from(keyPem, 'base64'))
      if (crypto.verify(null, payload, key, Buffer.from(signature, 'base64'))) {
        return { signed: true, trusted: true }
      }
    } catch { /* try the next key */ }
  }
  return { signed: true, trusted: false, reason: 'The signature did not match any trusted key.' }
}

function install(manifest, { source = 'manual', requireSignature = false } = {}) {
  const check = validateManifest(manifest)
  if (!check.ok) return check

  const sig = verifySignature(manifest)
  if (requireSignature && !sig.trusted) {
    return fail(`This plugin is not signed by a trusted key${sig.reason ? ` (${sig.reason})` : ''}, and installing from a URL requires one.`)
  }

  const all = load()
  all[manifest.id] = {
    id: manifest.id,
    name: manifest.name,
    version: manifest.version || '0.0.0',
    description: String(manifest.description || '').slice(0, 500),
    author: String(manifest.author || '').slice(0, 120),
    source,
    signed: sig.signed,
    trusted: sig.trusted,
    fingerprint: fingerprint(manifest),
    installed_at: new Date().toISOString(),
    enabled: false,
    manifest,
  }
  persist(all)
  return { ok: true, plugin: summarize(all[manifest.id]) }
}

async function installFromUrl(url) {
  const { response } = await netGuard.guardedFetch(url, { timeoutMs: 15000 })
  if (!response.ok) throw new Error(`${url} returned ${response.status}`)
  const text = await response.text()
  if (text.length > MAX_MANIFEST_BYTES) throw new Error('The manifest is larger than 256 KB.')
  let manifest
  try { manifest = JSON.parse(text) } catch { throw new Error('The URL did not return valid JSON.') }
  return install(manifest, { source: url, requireSignature: true })
}

function installFromFile(filePath) {
  const st = fs.statSync(filePath)
  if (st.size > MAX_MANIFEST_BYTES) return fail('The manifest is larger than 256 KB.')
  let manifest
  try { manifest = JSON.parse(fs.readFileSync(filePath, 'utf8')) } catch { return fail('That file is not valid JSON.') }
  return install(manifest, { source: path.basename(filePath) })
}

function setEnabled(id, enabled) {
  const all = load()
  if (!all[id]) return fail('No such plugin.')
  all[id].enabled = !!enabled
  persist(all)
  return { ok: true, plugin: summarize(all[id]) }
}

function remove(id) {
  const all = load()
  if (!all[id]) return fail('No such plugin.')
  delete all[id]
  persist(all)
  return { ok: true, removed: id }
}

function summarize(entry) {
  const m = entry.manifest || {}
  return {
    id: entry.id,
    name: entry.name,
    version: entry.version,
    description: entry.description,
    author: entry.author,
    source: entry.source,
    signed: entry.signed,
    trusted: entry.trusted,
    enabled: entry.enabled,
    fingerprint: entry.fingerprint,
    installed_at: entry.installed_at,
    provides: {
      settings_groups: Object.keys(m.settings_defaults || {}),
      knowledge_entries: (m.knowledge || []).length,
      caddy_templates: (m.caddy_templates || []).map(t => t.context),
    },
  }
}

function list() {
  return Object.values(load()).map(summarize)
}

function get(id) {
  const entry = load()[id]
  return entry ? { ...summarize(entry), manifest: entry.manifest } : null
}

// What enabled plugins contribute to the generated configuration. Called by
// the renderer; returns text only, and every placeholder has already been
// checked against the settings schema at install time.
function caddyContributions(context) {
  const out = []
  for (const entry of Object.values(load())) {
    if (!entry.enabled) continue
    for (const tpl of entry.manifest.caddy_templates || []) {
      if (tpl.context !== context) continue
      out.push({ plugin: entry.id, lines: renderTemplate(tpl.template).split('\n') })
    }
  }
  return out
}

function knowledgeEntries() {
  const out = []
  for (const entry of Object.values(load())) {
    if (!entry.enabled) continue
    for (const k of entry.manifest.knowledge || []) {
      out.push({ plugin: entry.id, id: `${entry.id}:${(k.id || k.title || '').toString().slice(0, 64)}`, title: k.title, body: k.body })
    }
  }
  return out
}

function applyDefaults(id) {
  const entry = load()[id]
  if (!entry) return fail('No such plugin.')
  const applied = []
  for (const [group, values] of Object.entries(entry.manifest.settings_defaults || {})) {
    const result = settings.set(group, values)
    if (!result.ok) return fail(`${group}: ${result.error}`)
    applied.push(group)
  }
  return { ok: true, applied }
}

module.exports = {
  install, installFromUrl, installFromFile, remove, setEnabled, list, get,
  validateManifest, validateTemplateBody, renderTemplate, verifySignature,
  caddyContributions, knowledgeEntries, applyDefaults,
  FORBIDDEN_FIELDS, VALID_CONTEXTS, STORE_KEY,
}
