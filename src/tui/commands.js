const fs = require('fs')
const path = require('path')

const PROJECT_ROOT = path.join(__dirname, '..', '..')
const BACKEND = path.join(PROJECT_ROOT, 'backend')

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', cyan: '\x1b[36m', magenta: '\x1b[35m',
}
const useColor = process.stdout.isTTY && !process.env.NO_COLOR
const c = (s, ...codes) => useColor ? codes.join('') + s + C.reset : s

const SEV_COLOR = {
  critical: C.red, emergency: C.red, alert: C.red,
  error: C.red, high: C.red,
  warning: C.yellow, medium: C.yellow,
  notice: C.cyan, low: C.cyan, info: C.dim, debug: C.dim,
}
const sevC = (s) => s ? c(String(s), SEV_COLOR[String(s).toLowerCase()] || C.reset) : c('-', C.dim)

function out(obj, json) {
  if (json) { console.log(JSON.stringify(obj, null, 2)); return true }
  return false
}

function fail(msg) {
  console.error(`${c('✗', C.red)} ${msg}`)
  return 1
}

function heading(t) {
  console.log('\n' + c(t, C.bold, C.cyan) + '\n')
}

function kv(k, v, width = 24) {
  console.log('  ' + k.padEnd(width) + (v == null ? c('-', C.dim) : String(v)))
}

async function cmdExplain(positional, flags) {
  const events = require(path.join(BACKEND, 'services', 'events.js'))
  const id = positional[0]
  const result = events.explain(flags.last ? { last: true } : { id })

  if (!result.ok) { if (flags.json) { console.log(JSON.stringify(result, null, 2)); return 1 } return fail(result.error) }
  if (out(result, flags.json)) return 0

  const e = result.event
  heading('CatWAF event ' + e.id)
  kv('Timestamp', e.timestamp)
  kv('Action', e.action === 'block' ? c('BLOCKED', C.red) : c(String(e.action).toUpperCase(), C.green))
  kv('HTTP status', e.status)
  kv('Attack type', e.attack_type || c('unclassified', C.dim))
  kv('Severity', sevC(e.severity))
  kv('Anomaly score', e.anomaly_score != null ? `${e.anomaly_score} (threshold ${result.waf.inbound_anomaly_threshold})` : null)
  kv('Paranoia level', `${result.waf.paranoia_level} of 4`)
  kv('Matched component', result.matched_component)
  console.log('')
  kv('Method', e.method)
  kv('Request', e.uri)
  kv('Client IP', e.client_ip)
  kv('User-Agent', e.user_agent)

  console.log('\n  ' + c(`Matched rules (${result.matched_rules.length})`, C.bold))
  if (!result.matched_rules.length) console.log(c('    none recorded', C.dim))
  for (const r of result.matched_rules) {
    const desc = r.description || c('(no local description — CRS rule files not found)', C.dim)
    console.log(`    ${c(r.id, C.cyan)}  ${sevC(r.severity)}  ${r.paranoia_level ? c('PL' + r.paranoia_level, C.dim) + '  ' : ''}${desc}`)
    if (!r.enabled) console.log(c(`        disabled (${r.disabled_by})`, C.yellow))
  }

  console.log('\n  ' + c('Why CatWAF blocked it', C.bold))
  console.log('  ' + result.why.replace(/\. /g, '.\n  '))

  console.log('\n  ' + c('What you can do', C.bold))
  for (const r of result.remediation) console.log('  • ' + r)

  if (result.notes.length) {
    console.log('')
    for (const n of result.notes) console.log(c('  ' + n, C.dim))
  }
  console.log('')
  return 0
}

async function cmdSimulate(flags) {
  const sim = require(path.join(BACKEND, 'services', 'simulate.js'))

  const file = typeof flags.request === 'string' ? flags.request : null
  const url = typeof flags.url === 'string' ? flags.url : null
  if (!file && !url) return fail('Provide --url <url> or --request <file>. See `catwaf help simulate`.')

  const result = await sim.simulate({ url, file })
  if (!result.ok) { if (flags.json) { console.log(JSON.stringify(result, null, 2)); return 1 } return fail(result.error) }
  if (out(result, flags.json)) return 0

  heading('CatWAF simulation')
  console.log(c('  SIMULATION ONLY — your real upstream was never contacted.', C.magenta))
  console.log(c('  ' + result.note, C.dim))
  console.log('')
  kv('Method', result.request.method)
  kv('Target', result.request.target)
  kv('Verdict', result.blocked ? c('WOULD BE BLOCKED', C.red) : c('WOULD BE ALLOWED', C.green))
  kv('Simulated status', result.status)
  kv('Attack type', result.attack_type)
  kv('Severity', sevC(result.severity))
  kv('Anomaly score', result.anomaly_score != null ? `${result.anomaly_score} (threshold ${result.inbound_anomaly_threshold})` : null)
  kv('Paranoia level', `${result.paranoia_level} of 4`)
  kv('Engine', result.engine)
  if (result.request.redacted_headers.length) {
    kv('Redacted headers', result.request.redacted_headers.join(', '))
  }

  console.log('\n  ' + c(`Matched rules (${result.matched_rules.length})`, C.bold))
  if (!result.matched_rules.length) console.log(c('    none', C.dim))
  for (const r of result.matched_rules) {
    console.log(`    ${c(r.id, C.cyan)}  ${sevC(r.severity)}  ${r.description || c('(no local description)', C.dim)}`)
  }
  if (result.reason) console.log('\n  ' + c('Reason: ', C.bold) + result.reason)
  console.log('')
  return 0
}

async function cmdReplay(positional, flags) {
  const events = require(path.join(BACKEND, 'services', 'events.js'))
  const id = positional[0]
  if (!id) return fail('Usage: catwaf replay <event-id>')

  const result = await events.replay({ id })
  if (!result.ok) { if (flags.json) { console.log(JSON.stringify(result, null, 2)); return 1 } return fail(result.error) }
  if (out(result, flags.json)) return 0

  heading('CatWAF replay — event ' + result.event_id)
  console.log(c('  REPLAY AGAINST LOCAL SANDBOX — production was never touched.', C.magenta))
  console.log(c('  ' + result.target, C.dim))
  console.log('')

  console.log('  ' + c('Then'.padEnd(24) + 'Now', C.bold))
  const row = (label, a, b) => console.log('  ' + c(label, C.dim).padEnd(28) + String(a).padEnd(24) + String(b))
  row('blocked', result.original.action === 'block', result.current.blocked)
  row('status', result.original.status ?? '-', result.current.status ?? '-')
  row('attack type', result.original.attack_type ?? '-', result.current.attack_type ?? '-')
  row('severity', result.original.severity ?? '-', result.current.severity ?? '-')
  row('anomaly score', result.original.anomaly_score ?? '-', result.current.anomaly_score ?? '-')
  row('rules matched', result.original.rule_ids.length, result.current.rule_ids.length)

  const ch = result.changes
  if (ch.rules_no_longer_matching.length) {
    console.log('\n  ' + c('Rules that no longer match', C.yellow))
    for (const r of ch.rules_no_longer_matching) console.log(`    ${r.id}  ${r.description || ''}`)
  }
  if (ch.rules_newly_matching.length) {
    console.log('\n  ' + c('Rules that now match', C.green))
    for (const r of ch.rules_newly_matching) console.log(`    ${r.id}  ${r.description || ''}`)
  }

  const vc = result.verdict === 'regression' ? C.red : result.verdict === 'still-blocked' ? C.green : C.yellow
  console.log('\n  ' + c(result.verdict_text, vc, C.bold))
  console.log(c('\n  ' + result.note, C.dim) + '\n')
  return 0
}

async function cmdRules(positional, flags) {
  const rules = require(path.join(BACKEND, 'services', 'rules.js'))
  const configTx = require(path.join(BACKEND, 'services', 'configTx.js'))
  const sub = positional[0]

  if (!sub || sub === 'help') { return sub ? 0 : fail('Usage: catwaf rules <list|search|show|enable|disable>') }

  if (sub === 'list') {
    const enabled = flags.disabled ? false : (flags.enabled ? true : null)
    const res = rules.list({ category: typeof flags.category === 'string' ? flags.category : null, enabled, limit: Number(flags.limit) || 200 })
    if (out(res, flags.json)) return 0
    if (!res.indexAvailable) {
      console.log(c('\nNo local CRS rule files were found, so only rules seen in real traffic can be listed.', C.yellow))
      console.log(c('Set CATWAF_CRS_PATH to a CRS rules directory for full metadata.\n', C.dim))
    }
    heading(`CRS rules (${res.rules.length} of ${res.total})`)
    for (const r of res.rules) {
      const mark = r.enabled ? c('  ', C.dim) : c('✗ ', C.red)
      console.log(`  ${mark}${c(r.id.padEnd(8), C.cyan)} ${(r.category || '-').padEnd(20)} ${r.severity ? sevC(r.severity).padEnd(18) : '-'.padEnd(9)} ${(r.description || '').slice(0, 60)}`)
    }
    const st = rules.stats()
    console.log(c(`\n  ${st.disabledRules.length} individually disabled, ${st.disabledCategories.length} categories disabled\n`, C.dim))
    return 0
  }

  if (sub === 'search') {
    const q = positional.slice(1).join(' ')
    if (!q) return fail('Usage: catwaf rules search <query>')
    const res = rules.search(q, { limit: Number(flags.limit) || 40 })
    if (out(res, flags.json)) return 0
    heading(`Rules matching "${q}" (${res.rules.length} of ${res.total})`)
    if (!res.rules.length) console.log(c('  no matches\n', C.dim))
    for (const r of res.rules) {
      const mark = r.enabled ? '  ' : c('✗ ', C.red)
      console.log(`  ${mark}${c(r.id.padEnd(8), C.cyan)} ${(r.category || '-').padEnd(18)} ${(r.description || '').slice(0, 66)}`)
    }
    console.log('')
    return 0
  }

  const ruleId = positional[1]

  if (sub === 'show') {
    if (!ruleId) return fail('Usage: catwaf rules show <rule-id>')
    if (!rules.isValidRuleId(ruleId)) return fail(`"${ruleId}" is not a valid CRS rule ID (3-7 digits).`)
    const r = rules.describe(ruleId)
    if (out(r, flags.json)) return 0
    heading('CRS rule ' + r.id)
    if (!r.known) {
      console.log(c('  This rule ID is not in CatWAF\'s local index.', C.yellow))
      console.log(c('  It may still exist inside Caddy\'s embedded CRS — only local metadata is missing.\n', C.dim))
    }
    kv('Description', r.description)
    kv('Category', r.category)
    kv('Severity', r.severity ? sevC(r.severity) : null)
    kv('Paranoia level', r.paranoia_level)
    kv('Phase', r.phase)
    kv('CRS version', r.version)
    kv('Defined in', r.file)
    kv('Metadata source', r.metadata_source)
    kv('Status', r.enabled ? c('enabled', C.green) : c(`disabled (by ${r.disabled_by})`, C.red))
    if (r.targets) { console.log(''); kv('Inspects', r.targets.length > 90 ? r.targets.slice(0, 90) + '…' : r.targets) }
    if (r.tags.length) kv('Tags', r.tags.join(', '))
    console.log('')
    return 0
  }

  if (sub === 'enable' || sub === 'disable') {
    if (!ruleId) return fail(`Usage: catwaf rules ${sub} <rule-id>`)
    let validated
    try { validated = rules.validateRuleIdOrThrow(ruleId) } catch (e) { return fail(e.message) }

    const wantEnabled = sub === 'enable'
    const before = rules.describe(validated)

    const tx = configTx.apply({
      label: `rules.${sub}.${validated}`,
      mutate: () => {
        const r = rules.setRuleEnabled(validated, wantEnabled)
        if (!r.changed) throw new Error(r.reason)
        return r
      },
    })

    if (!tx.ok) {
      if (flags.json) { console.log(JSON.stringify(tx, null, 2)); return 1 }
      console.error(`${c('✗', C.red)} ${tx.error}`)
      if (tx.rolledBack) {
        console.error(c('\nCatWAF did not activate the new configuration.', C.yellow))
        console.error(c('Previous configuration has been preserved.', C.yellow))
      }
      return 1
    }

    if (out({ ok: true, rule: rules.describe(validated), reloaded: tx.reloaded }, flags.json)) return 0
    console.log(`${c('✓', C.green)} Rule ${c(validated, C.cyan)} ${wantEnabled ? 'enabled' : 'disabled'}`)
    if (before.description) console.log(c(`  ${before.description}`, C.dim))
    if (tx.backup) console.log(c(`  Backup: ${tx.backup}`, C.dim))
    console.log(tx.reloaded ? c('  Caddy reloaded — the change is live.', C.dim) : c(`  Caddy not reloaded: ${tx.reloadError || 'unknown'}`, C.yellow))
    if (!wantEnabled) console.log(c('  Disabling a rule reduces coverage. Re-enable it with `catwaf rules enable ' + validated + '`.', C.yellow))
    return 0
  }

  return fail(`Unknown subcommand "${sub}".`)
}

async function cmdAudit(flags) {
  const requestLog = require(path.join(BACKEND, 'services', 'requestLog.js'))
  const rules = require(path.join(BACKEND, 'services', 'rules.js'))

  const windowSpec = typeof flags.last === 'string' ? flags.last : '24h'
  const sinceMs = requestLog.parseWindow(windowSpec)
  if (sinceMs == null) return fail(`"${windowSpec}" is not a valid window. Use forms like 30m, 24h, 7d.`)

  const attackType = typeof flags.attack === 'string' ? flags.attack : null
  const severity = typeof flags.severity === 'string' ? flags.severity.toLowerCase() : null

  const summary = requestLog.summarize({ sinceMs, attackType, severity })
  const recent = requestLog.query({ sinceMs, attackType, severity, action: 'block', limit: Number(flags.limit) || 10 })

  const payload = {
    ...summary,
    filters: { window: windowSpec, attack_type: attackType, severity },
    recent_attacks: recent.map(r => ({
      id: r.id, timestamp: r.ts, method: r.method, uri: r.uri,
      attack_type: r.attack_type, severity: r.severity, anomaly_score: r.score,
      rule_ids: r.rule_ids, client_ip: r.ip, status: r.status,
    })),
  }

  if (out(payload, flags.json)) return 0

  heading('CatWAF audit')
  kv('Window', `${windowSpec} (since ${summary.since})`)
  if (attackType) kv('Attack filter', attackType)
  if (severity) kv('Severity filter', severity)
  console.log('')
  kv('Total requests', summary.total_requests)
  kv('Blocked', c(String(summary.blocked_requests), C.red))
  kv('Allowed', c(String(summary.allowed_requests), C.green))
  kv('Block rate', `${(summary.block_rate * 100).toFixed(1)}%`)

  if (summary.anomaly_score.scored_events) {
    kv('Anomaly score', `avg ${summary.anomaly_score.average}, max ${summary.anomaly_score.max} (${summary.anomaly_score.scored_events} scored)`)
  }

  if (summary.total_requests === 0) {
    console.log(c('\n  No events in this window. If you expected some, check `catwaf health`.\n', C.dim))
    return 0
  }

  if (summary.top_attack_types.length) {
    console.log('\n  ' + c('Top attack types', C.bold))
    for (const a of summary.top_attack_types) console.log(`    ${String(a.count).padStart(6)}  ${a.attack_type}`)
  }

  if (summary.severity_distribution.length) {
    console.log('\n  ' + c('Severity distribution', C.bold))
    for (const s of summary.severity_distribution) console.log(`    ${String(s.count).padStart(6)}  ${sevC(s.severity)}`)
  }

  if (summary.top_rules.length) {
    console.log('\n  ' + c('Top CRS rules', C.bold))
    for (const r of summary.top_rules) {
      const d = rules.describe(r.rule_id)
      console.log(`    ${String(r.count).padStart(6)}  ${c(r.rule_id.padEnd(8), C.cyan)} ${(d.description || '').slice(0, 58)}`)
    }
  }

  if (summary.top_source_ips.length) {
    console.log('\n  ' + c('Top source IPs (blocked)', C.bold))
    for (const i of summary.top_source_ips) console.log(`    ${String(i.count).padStart(6)}  ${i.ip}`)
  }

  if (payload.recent_attacks.length) {
    console.log('\n  ' + c('Recent blocked requests', C.bold))
    for (const r of payload.recent_attacks) {
      console.log(`    ${c(r.id, C.dim)}  ${r.timestamp}  ${(r.attack_type || '-').padEnd(18)} ${(r.uri || '').slice(0, 44)}`)
    }
    console.log(c('\n  Inspect one with: catwaf explain <event-id>', C.dim))
  }
  console.log('')
  return 0
}

async function cmdMode(positional, flags) {
  const modes = require(path.join(BACKEND, 'services', 'modes.js'))
  const target = positional[0]

  if (!target) {
    const cur = modes.current()
    if (out({ current: cur, available: modes.listModes() }, flags.json)) return 0
    heading('CatWAF operating mode')
    kv('Current mode', c(cur.mode, cur.blocks ? C.green : C.yellow))
    kv('Blocks attacks', cur.blocks ? c('yes', C.green) : c('NO', C.red))
    kv('Engine', cur.engine)
    kv('Paranoia level', `${cur.paranoia_level} of 4`)
    kv('Audit logging', cur.audit_log ? 'on' : c('off', C.yellow))
    if (cur.since) kv('Since', cur.since)
    if (cur.note) console.log('\n  ' + c(cur.note, C.yellow))
    if (cur.warning) console.log('\n  ' + c(cur.warning, C.yellow))
    console.log('\n  ' + c('Available modes', C.bold))
    for (const m of modes.listModes()) {
      console.log(`    ${c(m.id.padEnd(13), C.cyan)}${m.summary}`)
      if (!m.blocks) console.log(c('                 does not block', C.red))
    }
    console.log('')
    return 0
  }

  if (!modes.isValidMode(target)) {
    return fail(`Unknown mode "${target}". Valid: ${modes.listModes().map(m => m.id).join(', ')}.`)
  }

  const spec = modes.MODES[target]
  if (!spec.blocks && !flags.yes && process.stdin.isTTY) {
    console.log('\n' + c(spec.warning, C.red, C.bold))
    const readline = require('readline')
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    const answer = await new Promise(r => rl.question(`\nSwitch to ${target} mode anyway? [y/N] `, a => { rl.close(); r(a.trim()) }))
    if (!/^y(es)?$/i.test(answer)) { console.log('Cancelled — mode unchanged.'); return 0 }
  }

  const result = modes.setMode(target)
  if (!result.ok) {
    if (flags.json) { console.log(JSON.stringify(result, null, 2)); return 1 }
    console.error(`${c('✗', C.red)} ${result.error}`)
    if (result.rolledBack) {
      console.error(c('\nCatWAF did not activate the new configuration.', C.yellow))
      console.error(c('Previous configuration has been preserved.', C.yellow))
    }
    return 1
  }

  if (out(result, flags.json)) return 0
  console.log(`${c('✓', C.green)} Mode: ${c(result.previous, C.dim)} → ${c(result.mode, C.cyan, C.bold)}`)
  console.log(c(`  ${result.description}`, C.dim))
  kv('  Engine', result.settings.engine)
  kv('  Paranoia level', result.settings.paranoia_level)
  console.log(result.reloaded ? c('  Caddy reloaded — the change is live.', C.dim) : c(`  Caddy not reloaded: ${result.reloadError || 'unknown'}`, C.yellow))
  if (result.warning) console.log('\n' + c('  ' + result.warning, C.yellow, C.bold))
  console.log('')
  return 0
}

async function cmdParanoia(positional, flags) {
  const state = require(path.join(BACKEND, 'services', 'state.js'))
  const configTx = require(path.join(BACKEND, 'services', 'configTx.js'))

  const LEVELS = {
    1: { name: 'Balanced', desc: 'Blocks clear attacks with very few false positives. The right default for most sites.' },
    2: { name: 'Elevated', desc: 'Adds patterns that are usually malicious but occasionally appear in legitimate input.' },
    3: { name: 'Aggressive', desc: 'Adds aggressive heuristics. Expect to tune exclusions.' },
    4: { name: 'Maximum', desc: 'Blocks nearly anything unusual. Assume you will be writing exceptions.' },
  }

  if (!positional.length) {
    const cur = state.WAF.paranoia_level
    if (out({ paranoia_level: cur, detection_paranoia_level: state.WAF.executing_paranoia_level, levels: LEVELS }, flags.json)) return 0
    heading('CatWAF paranoia level')
    for (const [lvl, info] of Object.entries(LEVELS)) {
      const active = Number(lvl) === cur
      const marker = active ? c('▸ ', C.green) : '  '
      console.log(`  ${marker}${c('PL' + lvl, active ? C.green : C.cyan)}  ${c(info.name.padEnd(12), active ? C.bold : C.reset)}${c(info.desc, C.dim)}`)
    }
    console.log('')
    kv('Active blocking level', `PL${cur} (${LEVELS[cur]?.name || 'custom'})`)
    kv('Detection level', `PL${state.WAF.executing_paranoia_level}`)
    kv('Anomaly threshold', state.WAF.inbound_anomaly_threshold)
    console.log(c('\n  Change with: catwaf paranoia <1-4>\n', C.dim))
    return 0
  }

  const raw = positional[0]
  const level = Number(raw)
  if (!Number.isInteger(level) || level < 1 || level > 4) {
    return fail(`"${raw}" is not a valid paranoia level. Use 1, 2, 3 or 4.`)
  }

  const previous = state.WAF.paranoia_level
  if (level === previous) {
    console.log(`${c('•', C.yellow)} Already at paranoia level ${level} (${LEVELS[level].name}).`)
    return 0
  }

  if (level > previous && level >= 3 && !flags.yes && process.stdin.isTTY) {
    console.log('\n' + c(`Paranoia level ${level} (${LEVELS[level].name}) blocks aggressively and WILL cause false positives on normal traffic unless you have tuned exclusions.`, C.yellow))
    const readline = require('readline')
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    const answer = await new Promise(r => rl.question(`\nRaise paranoia to PL${level}? [y/N] `, a => { rl.close(); r(a.trim()) }))
    if (!/^y(es)?$/i.test(answer)) { console.log('Cancelled — paranoia level unchanged.'); return 0 }
  }

  const tx = configTx.apply({
    label: `paranoia.set.${level}`,
    mutate: (s) => {
      s.WAF.paranoia_level = level
      if (s.WAF.executing_paranoia_level < level) s.WAF.executing_paranoia_level = level
      return { from: previous, to: level }
    },
    validate: (s) => {
      if (s.WAF.executing_paranoia_level < s.WAF.paranoia_level) {
        return { ok: false, error: 'Detection paranoia level must be >= blocking paranoia level.' }
      }
      return { ok: true }
    },
  })

  if (!tx.ok) {
    if (flags.json) { console.log(JSON.stringify(tx, null, 2)); return 1 }
    console.error(`${c('✗', C.red)} ${tx.error}`)
    if (tx.rolledBack) {
      console.error(c('\nCatWAF did not activate the new configuration.', C.yellow))
      console.error(c('Previous configuration has been preserved.', C.yellow))
    }
    return 1
  }

  if (out({ ok: true, from: previous, to: level, reloaded: tx.reloaded }, flags.json)) return 0
  console.log(`${c('✓', C.green)} Paranoia level: PL${previous} → ${c('PL' + level, C.cyan, C.bold)} (${LEVELS[level].name})`)
  console.log(c(`  ${LEVELS[level].desc}`, C.dim))
  if (tx.backup) console.log(c(`  Backup: ${tx.backup}`, C.dim))
  console.log(tx.reloaded ? c('  Caddy reloaded — the change is live.', C.dim) : c(`  Caddy not reloaded: ${tx.reloadError || 'unknown'}`, C.yellow))
  if (level > previous) console.log(c(`\n  Watch for false positives: catwaf audit --last 1h`, C.yellow))
  console.log('')
  return 0
}

async function cmdHealth(flags) {
  const healthcheck = require(path.join(BACKEND, 'services', 'healthcheck.js'))

  const render = (r) => {
    const statusColor = r.status === 'healthy' ? C.green : r.status === 'degraded' ? C.yellow : C.red
    console.log('\n' + c('CatWAF health', C.bold, C.cyan) + '   ' + c(r.status.toUpperCase(), statusColor, C.bold))
    console.log(c('  ' + r.checked_at, C.dim) + '\n')
    for (const ch of r.checks) {
      const sym = ch.status === 'healthy' ? c('✓', C.green) : ch.status === 'degraded' ? c('!', C.yellow) : c('✗', C.red)
      console.log(`  ${sym} ${ch.name.padEnd(24)} ${c(ch.detail || '', C.dim)}`)
    }
    const problems = r.checks.filter(ch => ch.status !== 'healthy' && ch.hint)
    if (problems.length) {
      console.log('\n  ' + c('Recommendations', C.bold))
      for (const p of problems) console.log(`\n  ${p.name}\n    ${p.hint.split('\n').join('\n    ')}`)
    }
    console.log('')
  }

  if (!flags.watch) {
    const r = await healthcheck.run()
    if (out(r, flags.json)) return r.exit_code
    render(r)
    return r.exit_code
  }

  if (flags.json) return fail('--watch cannot be combined with --json.')

  const intervalSec = Math.min(Math.max(Number(flags.interval) || 5, 1), 300)
  let stopped = false
  let timer = null

  const stop = () => {
    if (stopped) return
    stopped = true
    if (timer) clearTimeout(timer)
    process.stdout.write('\x1b[?25h')
    console.log(c('\nStopped watching.\n', C.dim))
  }
  process.on('SIGINT', () => { stop(); process.exit(0) })
  process.on('SIGTERM', () => { stop(); process.exit(0) })

  process.stdout.write('\x1b[?25l')
  while (!stopped) {
    const r = await healthcheck.run()
    if (stopped) break
    process.stdout.write('\x1b[2J\x1b[H')
    render(r)
    console.log(c(`  refreshing every ${intervalSec}s — ctrl+c to stop`, C.dim))
    await new Promise(resolve => { timer = setTimeout(resolve, intervalSec * 1000) })
  }
  return 0
}

async function cmdSecurityTest(flags) {
  const st = require(path.join(BACKEND, 'services', 'securityTest.js'))
  const r = await st.run()
  if (out(r, flags.json)) return r.exit_code

  console.log('\n' + c('CATWAF SECURITY TEST', C.bold, C.cyan))
  console.log(c('─'.repeat(40), C.dim))
  const line = (label, n, color) => console.log('  ' + label.padEnd(11) + (n > 0 ? c(String(n), color, C.bold) : c('0', C.dim)))
  line('CRITICAL', r.counts.critical, C.red)
  line('HIGH', r.counts.high, C.red)
  line('MEDIUM', r.counts.medium, C.yellow)
  line('LOW', r.counts.low, C.cyan)
  console.log('')

  for (const p of r.passed) console.log(`  ${c('✓', C.green)} ${p.title}${p.detail ? c('  — ' + p.detail, C.dim) : ''}`)
  for (const f of r.findings) {
    const col = f.severity === 'critical' || f.severity === 'high' ? C.red : f.severity === 'medium' ? C.yellow : C.cyan
    console.log(`  ${c('✗', col)} ${f.title} ${c('[' + f.severity + ']', col)}`)
  }

  if (r.findings.length) {
    console.log('\n' + c('  Findings', C.bold))
    for (const f of r.findings) {
      const col = f.severity === 'critical' || f.severity === 'high' ? C.red : f.severity === 'medium' ? C.yellow : C.cyan
      console.log(`\n  ${c('[' + f.severity.toUpperCase() + ']', col, C.bold)} ${f.title}`)
      console.log(`    ${f.detail}`)
      console.log(c(`    → ${f.remediation}`, C.dim))
    }
  }

  console.log('\n' + c('  ' + r.disclaimer, C.dim) + '\n')
  return r.exit_code
}

async function cmdConfigSub(positional, flags, cmdConfigDefault) {
  const snapshots = require(path.join(BACKEND, 'services', 'snapshots.js'))
  const sub = positional[0]

  if (!sub) return cmdConfigDefault(flags)

  if (sub === 'snapshot') {
    const r = snapshots.create({ label: typeof flags.label === 'string' ? flags.label : 'manual' })
    if (out(r, flags.json)) return 0
    console.log(`${c('✓', C.green)} Snapshot ${c(r.id, C.cyan)} created (${r.label})`)
    console.log(c(`  Restore it with: catwaf config restore ${r.id}`, C.dim))
    return 0
  }

  if (sub === 'snapshots' || sub === 'list') {
    const list = snapshots.list()
    if (out({ snapshots: list }, flags.json)) return 0
    if (!list.length) {
      console.log(c('\nNo snapshots yet. Create one with: catwaf config snapshot\n', C.dim))
      return 0
    }
    heading(`Configuration snapshots (${list.length})`)
    console.log(c('  ID'.padEnd(18) + 'TIMESTAMP'.padEnd(28) + 'BY'.padEnd(12) + 'LABEL', C.bold))
    for (const s of list) {
      console.log('  ' + c(s.id.padEnd(16), C.cyan) + s.timestamp.padEnd(28) + (s.created_by || '-').padEnd(12) + (s.label || ''))
    }
    console.log('')
    return 0
  }

  const id = positional[1]

  if (sub === 'show' || sub === 'view') {
    if (!id) return fail('Usage: catwaf config show <id>')
    const r = snapshots.view(id)
    if (!r.ok) return fail(r.error)
    if (out(r, flags.json)) return 0
    heading(`Snapshot ${r.id}`)
    kv('Timestamp', r.timestamp)
    kv('Label', r.label)
    kv('Created by', r.created_by)
    console.log('\n' + JSON.stringify(r.state, null, 2) + '\n')
    return 0
  }

  if (sub === 'diff') {
    if (!id) return fail('Usage: catwaf config diff <id>')
    const r = snapshots.diff(id, { against: typeof flags.against === 'string' ? flags.against : null })
    if (!r.ok) return fail(r.error)
    if (out(r, flags.json)) return 0
    heading(`Diff — snapshot ${r.from.id} vs ${r.to.label}`)
    if (!r.changed) { console.log(c('  No differences.\n', C.green)); return 0 }
    for (const ch of r.changes) {
      const sym = ch.kind === 'added' ? c('+', C.green) : ch.kind === 'removed' ? c('-', C.red) : c('~', C.yellow)
      console.log(`  ${sym} ${c(ch.key, C.cyan)}`)
      console.log(`      ${c(String(ch.from), C.red)} → ${c(String(ch.to), C.green)}`)
    }
    console.log(c(`\n  ${r.changed} change(s)\n`, C.dim))
    return 0
  }

  if (sub === 'restore') {
    if (!id) return fail('Usage: catwaf config restore <id>')
    const preview = snapshots.diff(id)
    if (!preview.ok) return fail(preview.error)

    if (!flags.yes && process.stdin.isTTY) {
      console.log(`\nRestoring snapshot ${c(id, C.cyan)} will change ${preview.changed} setting(s).`)
      const readline = require('readline')
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
      const a = await new Promise(r => rl.question('Continue? [y/N] ', x => { rl.close(); r(x.trim()) }))
      if (!/^y(es)?$/i.test(a)) { console.log('Cancelled — nothing changed.'); return 0 }
    }

    const r = snapshots.restore(id)
    if (!r.ok) {
      if (flags.json) { console.log(JSON.stringify(r, null, 2)); return 1 }
      console.error(`${c('✗', C.red)} ${r.error}`)
      if (r.rolledBack) {
        console.error(c('\nCatWAF did not activate the restored configuration.', C.yellow))
        console.error(c('Previous configuration has been preserved.', C.yellow))
      }
      return 1
    }
    if (out(r, flags.json)) return 0
    console.log(`${c('✓', C.green)} Restored configuration from snapshot ${c(id, C.cyan)}`)
    console.log(c(`  A safety snapshot of the previous state was saved as ${r.safety_snapshot}`, C.dim))
    console.log(r.reloaded ? c('  Caddy reloaded — the change is live.', C.dim) : c(`  Caddy not reloaded: ${r.reloadError || 'unknown'}`, C.yellow))
    return 0
  }

  return fail(`Unknown config subcommand "${sub}".`)
}

async function cmdDiff(flags) {
  const snapshots = require(path.join(BACKEND, 'services', 'snapshots.js'))
  const rules = require(path.join(BACKEND, 'services', 'rules.js'))
  const modes = require(path.join(BACKEND, 'services', 'modes.js'))

  const list = snapshots.list()
  const baseline = list[0]

  const wantConfig = flags.config || (!flags.config && !flags.rules)
  const wantRules = flags.rules || (!flags.config && !flags.rules)

  const payload = { baseline: baseline ? { id: baseline.id, timestamp: baseline.timestamp, label: baseline.label } : null }

  if (!baseline) {
    if (out({ ...payload, error: 'no snapshot to compare against' }, flags.json)) return 1
    console.log(c('\nNo snapshots exist yet, so there is no known-good configuration to diff against.', C.yellow))
    console.log(c('Create one with: catwaf config snapshot\n', C.dim))
    return 1
  }

  const d = snapshots.diff(baseline.id)
  if (!d.ok) return fail(d.error)

  const RULE_KEYS = /^(disabled_rules|custom_rules|rule_exclusions|php_exclusions)/
  const configChanges = d.changes.filter(ch => !RULE_KEYS.test(ch.key))
  const ruleChanges = d.changes.filter(ch => RULE_KEYS.test(ch.key))

  const st = rules.stats()
  const cur = modes.current()

  if (wantConfig) payload.config_changes = configChanges
  if (wantRules) {
    payload.rule_changes = ruleChanges
    payload.disabled_rules = st.disabledRules
    payload.disabled_categories = st.disabledCategories
  }
  payload.mode = { current: cur.mode, drifted: cur.drifted }

  if (out(payload, flags.json)) return 0

  heading(`Changes since snapshot ${baseline.id}`)
  kv('Baseline', `${baseline.timestamp} (${baseline.label})`)
  kv('Current mode', cur.mode + (cur.drifted ? c('  (drifted from declared mode)', C.yellow) : ''))

  if (wantConfig) {
    console.log('\n  ' + c('Configuration', C.bold))
    if (!configChanges.length) console.log(c('    unchanged', C.dim))
    for (const ch of configChanges) {
      console.log(`    ${c('~', C.yellow)} ${c(ch.key, C.cyan)}: ${c(String(ch.from), C.red)} → ${c(String(ch.to), C.green)}`)
    }
  }

  if (wantRules) {
    console.log('\n  ' + c('Rules', C.bold))
    if (!ruleChanges.length) console.log(c('    unchanged', C.dim))
    for (const ch of ruleChanges) {
      console.log(`    ${c('~', C.yellow)} ${c(ch.key, C.cyan)}: ${c(String(ch.from), C.red)} → ${c(String(ch.to), C.green)}`)
    }
    if (st.disabledRules.length) console.log(c(`    currently disabled rules: ${st.disabledRules.join(', ')}`, C.dim))
    if (st.disabledCategories.length) console.log(c(`    disabled categories: ${st.disabledCategories.map(x => x.name).join(', ')}`, C.dim))
  }

  console.log(c(`\n  ${d.changed} total change(s). Secrets are never printed.\n`, C.dim))
  return 0
}

module.exports = {
  cmdExplain, cmdSimulate, cmdReplay, cmdRules, cmdAudit,
  cmdMode, cmdParanoia, cmdHealth, cmdSecurityTest, cmdConfigSub, cmdDiff,
}
