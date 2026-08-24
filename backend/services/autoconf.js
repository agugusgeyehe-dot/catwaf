// autoconf.js — Docker-label-driven configuration (idea #66).
//
// services/discovery/ already does the hard part: it inspects running
// containers thoroughly and works out what each one is. What it does not do
// is *act* — every run produces a suggestion for a human to confirm. That is
// the right default, and this does not change it: containers without the
// label prefix keep the existing suggest-only behaviour.
//
// What this adds is an opt-in mode where a container that explicitly asks to
// be managed (`catwaf.enable=true`) has its configuration applied
// automatically on a schedule. Auto-applying configuration has a real blast
// radius, so it is off by default, it only ever touches labelled containers,
// and it has a dry-run mode that reports what it would do without doing it.

const settings = require('./settings')
const logger = require('./logger')

const log = logger.child('autoconf')

// Labels are attacker-influenceable if someone can start a container, so
// every value goes through a parser that constrains it to its type rather
// than being trusted because it came from Docker.
const LABEL_SPEC = {
  enable: { type: 'bool' },
  port: { type: 'int', min: 1, max: 65535 },
  host: { type: 'host' },
  path: { type: 'uri' },
  protocol: { type: 'enum', values: ['http', 'https', 'grpc'] },
  paranoia: { type: 'int', min: 1, max: 4 },
  waf: { type: 'enum', values: ['on', 'detectiononly', 'off'] },
  bypass: { type: 'list', item: 'uri' },
  methods: { type: 'list', item: 'method' },
  headers: { type: 'enum', values: ['off', 'basic', 'strict'] },
  websockets: { type: 'enum', values: ['allow', 'deny'] },
}

function parseLabelValue(spec, raw) {
  const value = String(raw ?? '').trim()
  switch (spec.type) {
    case 'bool':
      if (/^(true|1|yes|on)$/i.test(value)) return true
      if (/^(false|0|no|off)$/i.test(value)) return false
      return null
    case 'int': {
      const n = Number(value)
      if (!Number.isInteger(n) || n < spec.min || n > spec.max) return null
      return n
    }
    case 'enum':
      return spec.values.includes(value.toLowerCase()) ? value.toLowerCase() : null
    case 'host':
      return /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(value) ? value.toLowerCase() : null
    case 'uri':
      return value.startsWith('/') && value.length <= 512 && !/[\s`"'{}\\]/.test(value) ? value : null
    case 'list': {
      const items = value.split(/[\s,]+/).filter(Boolean)
      const parsed = items.map(item => parseLabelValue({ type: spec.item === 'method' ? 'enum' : 'uri', values: ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'] }, item))
      return parsed.every(Boolean) ? parsed : null
    }
    default:
      return null
  }
}

function readLabels(container, prefix) {
  const labels = container?.labels || container?.Labels || {}
  const out = {}
  const rejected = []
  for (const [key, raw] of Object.entries(labels)) {
    if (!key.startsWith(`${prefix}.`)) continue
    const name = key.slice(prefix.length + 1)
    const spec = LABEL_SPEC[name]
    if (!spec) { rejected.push({ label: key, reason: 'unknown label' }); continue }
    const value = parseLabelValue(spec, raw)
    if (value === null) { rejected.push({ label: key, reason: `"${raw}" is not a valid value for ${name}` }); continue }
    out[name] = value
  }
  return { labels: out, rejected }
}

// Turns parsed labels into the settings patches they imply. Returns patches
// rather than applying them, so the same function backs both dry-run and the
// real thing.
function planFor(labelled) {
  const patches = {}
  const waf = {}

  if (labelled.paranoia) {
    waf.paranoia_level = labelled.paranoia
    waf.executing_paranoia_level = Math.max(labelled.paranoia, 2)
  }
  if (labelled.waf) {
    waf.engine = labelled.waf === 'on' ? 'On' : labelled.waf === 'detectiononly' ? 'DetectionOnly' : 'Off'
  }
  if (labelled.methods) {
    patches.access = { ...(patches.access || {}), enforce_method_allowlist: true, allowed_methods: labelled.methods.map(m => m.toUpperCase()) }
  }
  if (labelled.bypass) {
    patches.access = { ...(patches.access || {}), waf_bypass_paths: labelled.bypass }
  }
  if (labelled.headers) {
    patches.headers = { preset: labelled.headers }
  }
  if (labelled.protocol) {
    patches.proxy = { ...(patches.proxy || {}), protocol: labelled.protocol }
  }
  if (labelled.websockets) {
    patches.proxy = { ...(patches.proxy || {}), websockets: labelled.websockets }
  }
  if (labelled.host) {
    patches.sites = { primary_host: labelled.host }
  }

  return { patches, waf }
}

async function scan({ dryRun = null } = {}) {
  const cfg = settings.get('autoconf')
  if (!cfg.enabled) return { ok: true, skipped: 'disabled', changed: false }

  const effectiveDryRun = dryRun === null ? cfg.dry_run : dryRun

  let discovery
  try {
    discovery = require('./discovery')
  } catch (e) {
    return { ok: false, error: `Discovery is unavailable: ${e.message}` }
  }

  let result
  try {
    result = await discovery.discover({ quick: true })
  } catch (e) {
    return { ok: false, error: `Container discovery failed: ${e.message}` }
  }

  const containers = result?.webApps || result?.containers || []
  const managed = []
  const ignored = []
  const problems = []

  for (const container of containers) {
    const { labels, rejected } = readLabels(container, cfg.label_prefix)
    for (const r of rejected) problems.push({ container: container.name, ...r })

    if (!Object.keys(labels).length) {
      ignored.push({ container: container.name, reason: 'no CatWAF labels — discovery still suggests it, nothing is applied automatically' })
      continue
    }
    if (cfg.require_enable_label && labels.enable !== true) {
      ignored.push({ container: container.name, reason: `${cfg.label_prefix}.enable is not set to true` })
      continue
    }
    managed.push({ container: container.name, labels, plan: planFor(labels) })
  }

  if (effectiveDryRun) {
    log.info('Autoconf dry run', { managed: managed.length, ignored: ignored.length })
    return { ok: true, dryRun: true, managed, ignored, problems, changed: false }
  }

  const applied = []
  const failures = []
  for (const entry of managed) {
    for (const [group, patch] of Object.entries(entry.plan.patches)) {
      const r = settings.set(group, patch)
      if (r.ok) applied.push({ container: entry.container, group })
      else failures.push({ container: entry.container, group, error: r.error })
    }
    if (Object.keys(entry.plan.waf).length) {
      const state = require('./state')
      // Under the config lock with a fresh re-read, like every other WAF
      // writer — an autoconf scan racing the dashboard can no longer
      // overwrite a paranoia change made seconds earlier.
      state.updateWAF(w => { Object.assign(w, entry.plan.waf) }, { label: 'autoconf.waf' })
      applied.push({ container: entry.container, group: 'waf' })
    }
  }

  const changed = applied.length > 0
  if (changed) log.info('Autoconf applied container labels', { applied: applied.length, failures: failures.length })
  return { ok: true, managed: managed.length, ignored: ignored.length, applied, failures, problems, changed }
}

function describe() {
  const cfg = settings.get('autoconf')
  return {
    enabled: cfg.enabled,
    prefix: cfg.label_prefix,
    dry_run: cfg.dry_run,
    labels: Object.entries(LABEL_SPEC).map(([name, spec]) => ({
      label: `${cfg.label_prefix}.${name}`,
      type: spec.type,
      values: spec.values || null,
      range: spec.min !== undefined ? `${spec.min}-${spec.max}` : null,
    })),
    example: [
      'services:',
      '  app:',
      '    image: my-app',
      '    labels:',
      `      ${cfg.label_prefix}.enable: "true"`,
      `      ${cfg.label_prefix}.port: "3000"`,
      `      ${cfg.label_prefix}.paranoia: "2"`,
      `      ${cfg.label_prefix}.headers: "strict"`,
      `      ${cfg.label_prefix}.bypass: "/webhooks/*"`,
    ].join('\n'),
  }
}

module.exports = { scan, describe, readLabels, planFor, parseLabelValue, LABEL_SPEC }
