const state = require('./state')
const db = require('./db')
const configTx = require('./configTx')

const MODES = {
  normal: {
    label: 'Normal',
    summary: 'Standard production protection.',
    description: 'Attacks are blocked at the configured paranoia level. This is the intended steady state.',
    blocks: true,
    warning: null,
    settings: {
      engine: 'On',
      paranoia_level: 1,
      executing_paranoia_level: 2,
      inbound_anomaly_threshold: 5,
      outbound_anomaly_threshold: 4,
      sampling_percentage: 100,
      audit_log: true,
    },
  },
  lockdown: {
    label: 'Lockdown',
    summary: 'Maximum protection for an active incident.',
    description: 'Raises paranoia to 4 and tightens the anomaly threshold so borderline requests are blocked. Intended for emergencies, not steady state.',
    blocks: true,
    warning: 'Lockdown blocks aggressively and WILL produce false positives on normal traffic. Use it during an incident, then return to normal.',
    settings: {
      engine: 'On',
      paranoia_level: 4,
      executing_paranoia_level: 4,
      inbound_anomaly_threshold: 3,
      outbound_anomaly_threshold: 3,
      sampling_percentage: 100,
      audit_log: true,
      request_body_inspection: true,
    },
  },
  learning: {
    label: 'Learning',
    summary: 'Observe and record without blocking.',
    description: 'Switches Coraza to DetectionOnly at a high paranoia level. Every rule still evaluates and every match is logged, but nothing is blocked — so you can find false positives before enforcing them.',
    blocks: false,
    warning: 'LEARNING MODE DOES NOT BLOCK ANYTHING. Your site is fully exposed for as long as this mode is active. Attacks are recorded, not stopped. Use it on staging, or for a short, supervised window in production.',
    settings: {
      engine: 'DetectionOnly',
      paranoia_level: 3,
      executing_paranoia_level: 3,
      inbound_anomaly_threshold: 5,
      outbound_anomaly_threshold: 4,
      sampling_percentage: 100,
      audit_log: true,
    },
  },
  maintenance: {
    label: 'Maintenance',
    summary: 'Protection stays on; logging is reduced.',
    description: 'Keeps blocking enabled at normal strictness but reduces audit-log volume, so planned maintenance traffic does not flood the event log. Protection is NOT weakened.',
    blocks: true,
    warning: 'Maintenance mode reduces audit logging. Blocking is unchanged, but you will record less detail about what happened during the window.',
    settings: {
      engine: 'On',
      paranoia_level: 1,
      executing_paranoia_level: 2,
      inbound_anomaly_threshold: 5,
      outbound_anomaly_threshold: 4,
      sampling_percentage: 100,
      audit_log: false,
    },
  },
}

const MODE_STATE_KEY = 'operating_mode'

function listModes() {
  return Object.entries(MODES).map(([id, m]) => ({
    id,
    label: m.label,
    summary: m.summary,
    description: m.description,
    blocks: m.blocks,
    warning: m.warning,
    settings: m.settings,
  }))
}

function isValidMode(name) {
  return typeof name === 'string' && Object.prototype.hasOwnProperty.call(MODES, name)
}

function readModeRecord() {
  const rec = db.getState(MODE_STATE_KEY)
  return rec && typeof rec === 'object' ? rec : null
}

function inferModeFromState() {
  for (const [id, m] of Object.entries(MODES)) {
    const matches = Object.entries(m.settings).every(([k, v]) => state.WAF[k] === v)
    if (matches) return id
  }
  return null
}

function current() {
  const rec = readModeRecord()
  const inferred = inferModeFromState()
  const declared = rec && isValidMode(rec.mode) ? rec.mode : null

  const drifted = !!(declared && inferred !== declared)

  return {
    mode: declared || inferred || 'custom',
    declared,
    inferred,
    drifted,
    since: rec?.since || null,
    set_by: rec?.set_by || null,
    blocks: declared && MODES[declared] ? MODES[declared].blocks : state.WAF.engine === 'On',
    engine: state.WAF.engine,
    paranoia_level: state.WAF.paranoia_level,
    inbound_anomaly_threshold: state.WAF.inbound_anomaly_threshold,
    audit_log: !!state.WAF.audit_log,
    warning: declared && MODES[declared] ? MODES[declared].warning : null,
    note: drifted
      ? `WAF settings no longer match the declared "${declared}" mode — something changed them afterwards. Re-apply the mode to resynchronise.`
      : null,
  }
}

function setMode(name, { req = null, reload = true } = {}) {
  if (!isValidMode(name)) {
    return { ok: false, error: `Unknown mode "${name}". Valid modes: ${Object.keys(MODES).join(', ')}.` }
  }

  const spec = MODES[name]
  const previous = current()

  const tx = configTx.apply({
    label: `mode.set.${name}`,
    req,
    reload,
    mutate: (s) => {
      for (const [k, v] of Object.entries(spec.settings)) s.WAF[k] = v
      return { mode: name, from: previous.mode }
    },
    validate: (s) => {
      if (s.WAF.executing_paranoia_level < s.WAF.paranoia_level) {
        return { ok: false, error: 'Detection paranoia level must be >= blocking paranoia level.' }
      }
      if (!['On', 'DetectionOnly', 'Off'].includes(s.WAF.engine)) {
        return { ok: false, error: `Invalid engine mode "${s.WAF.engine}".` }
      }
      return { ok: true }
    },
  })

  if (!tx.ok) return { ok: false, ...tx, mode: previous.mode }

  db.setState(MODE_STATE_KEY, {
    mode: name,
    since: new Date().toISOString(),
    set_by: req?.user?.username || 'cli',
    previous: previous.mode,
  })

  return {
    ok: true,
    mode: name,
    previous: previous.mode,
    label: spec.label,
    blocks: spec.blocks,
    warning: spec.warning,
    description: spec.description,
    settings: spec.settings,
    reloaded: tx.reloaded,
    reloadError: tx.reloadError,
    backup: tx.backup,
  }
}

module.exports = { MODES, listModes, isValidMode, current, setMode, MODE_STATE_KEY }
