// reports.js — compiled, exportable reports over a chosen date range
// (idea #51).
//
// Site owners occasionally have to hand someone *else* evidence of what the
// WAF caught: a hosting provider, an insurer, a compliance checklist. Today
// that means screenshotting the analytics page. CSV is where most of the
// value is for the least effort, so it comes first and is complete; the
// print-friendly HTML summary is the same data with a layout.

const db = require('./db')
const state = require('./state')
const bans = require('./bans')
const { version: pkgVersion } = require('../../package.json')

const MAX_ROWS = 50000

function parseRange({ from, to } = {}) {
  const end = to ? new Date(to) : new Date()
  const start = from ? new Date(from) : new Date(end.getTime() - 7 * 86_400_000)
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    return { error: 'from and to must be valid dates (YYYY-MM-DD or an ISO timestamp).' }
  }
  if (start >= end) return { error: 'The start of the range must be before its end.' }
  if (end - start > 400 * 86_400_000) return { error: 'A report may cover at most 400 days.' }
  return { start: start.toISOString(), end: end.toISOString() }
}

function collect(range) {
  const conn = db.getDb()
  const args = [range.start, range.end]

  const totals = conn.prepare(`
    SELECT COUNT(*) AS total,
           SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS blocked,
           COUNT(DISTINCT ip) AS unique_ips
    FROM request_log WHERE ts >= ? AND ts < ?
  `).get(...args)

  return {
    range,
    generated_at: new Date().toISOString(),
    catwaf_version: pkgVersion,
    engine: state.WAF.engine,
    paranoia_level: state.WAF.paranoia_level,
    totals: {
      requests: totals.total || 0,
      blocked: totals.blocked || 0,
      unique_ips: totals.unique_ips || 0,
      block_rate: totals.total ? Math.round(((totals.blocked || 0) / totals.total) * 1000) / 10 : 0,
    },
    by_category: conn.prepare(`
      SELECT COALESCE(attack_type, 'Unclassified') AS category, COUNT(*) AS count
      FROM request_log WHERE ts >= ? AND ts < ? AND action = 'block'
      GROUP BY category ORDER BY count DESC LIMIT 50
    `).all(...args),
    by_severity: conn.prepare(`
      SELECT COALESCE(severity, 'unknown') AS severity, COUNT(*) AS count
      FROM request_log WHERE ts >= ? AND ts < ? AND action = 'block'
      GROUP BY severity ORDER BY count DESC
    `).all(...args),
    top_ips: conn.prepare(`
      SELECT ip, COUNT(*) AS count, COALESCE(country_code, '') AS country,
             MAX(ts) AS last_seen, COUNT(DISTINCT attack_type) AS categories
      FROM request_log WHERE ts >= ? AND ts < ? AND action = 'block' AND ip IS NOT NULL AND ip != ''
      GROUP BY ip ORDER BY count DESC LIMIT 50
    `).all(...args),
    by_country: conn.prepare(`
      SELECT COALESCE(country_code, 'Unknown') AS country, COUNT(*) AS count
      FROM request_log WHERE ts >= ? AND ts < ? AND action = 'block'
      GROUP BY country ORDER BY count DESC LIMIT 50
    `).all(...args),
    top_targets: conn.prepare(`
      SELECT uri, COUNT(*) AS count FROM request_log
      WHERE ts >= ? AND ts < ? AND action = 'block' AND uri IS NOT NULL
      GROUP BY uri ORDER BY count DESC LIMIT 25
    `).all(...args),
    daily: conn.prepare(`
      SELECT substr(ts, 1, 10) AS day, COUNT(*) AS requests,
             SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS blocked
      FROM request_log WHERE ts >= ? AND ts < ?
      GROUP BY day ORDER BY day ASC
    `).all(...args),
    active_bans: bans.stats(),
  }
}

// RFC 4180 quoting, plus a leading apostrophe on anything a spreadsheet
// would otherwise evaluate as a formula — an exported report is opened in
// Excel more often than not, and a URI beginning with `=` or `+` is a real
// injection vector there.
function csvCell(value) {
  const s = String(value ?? '')
  const guarded = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s
  return /[",\n\r]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded
}

function csvSection(title, columns, rows) {
  const out = [`# ${title}`, columns.map(c => csvCell(c.label)).join(',')]
  for (const row of rows) out.push(columns.map(c => csvCell(row[c.key])).join(','))
  out.push('')
  return out
}

function toCsv(report) {
  const lines = [
    '# CatWAF report',
    `# Generated,${csvCell(report.generated_at)}`,
    `# Range,${csvCell(report.range.start)},${csvCell(report.range.end)}`,
    `# CatWAF version,${csvCell(report.catwaf_version)}`,
    `# Engine,${csvCell(report.engine)},Paranoia,${csvCell(report.paranoia_level)}`,
    '',
    '# Summary',
    'Metric,Value',
    `Total requests,${report.totals.requests}`,
    `Blocked requests,${report.totals.blocked}`,
    `Unique client addresses,${report.totals.unique_ips}`,
    `Block rate (%),${report.totals.block_rate}`,
    '',
  ]
  lines.push(...csvSection('Blocked by category', [{ key: 'category', label: 'Category' }, { key: 'count', label: 'Count' }], report.by_category))
  lines.push(...csvSection('Blocked by severity', [{ key: 'severity', label: 'Severity' }, { key: 'count', label: 'Count' }], report.by_severity))
  lines.push(...csvSection('Top offending addresses', [
    { key: 'ip', label: 'Address' }, { key: 'count', label: 'Blocked' },
    { key: 'country', label: 'Country' }, { key: 'categories', label: 'Categories' }, { key: 'last_seen', label: 'Last seen' },
  ], report.top_ips))
  lines.push(...csvSection('Blocked by country', [{ key: 'country', label: 'Country' }, { key: 'count', label: 'Count' }], report.by_country))
  lines.push(...csvSection('Most targeted paths', [{ key: 'uri', label: 'Path' }, { key: 'count', label: 'Blocked' }], report.top_targets))
  lines.push(...csvSection('Daily totals', [
    { key: 'day', label: 'Day' }, { key: 'requests', label: 'Requests' }, { key: 'blocked', label: 'Blocked' },
  ], report.daily))
  return lines.join('\n')
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}

function table(title, columns, rows) {
  if (!rows.length) return `<section><h2>${escapeHtml(title)}</h2><p class="empty">Nothing recorded in this range.</p></section>`
  return `<section><h2>${escapeHtml(title)}</h2><table><thead><tr>${
    columns.map(c => `<th>${escapeHtml(c.label)}</th>`).join('')
  }</tr></thead><tbody>${
    rows.map(r => `<tr>${columns.map(c => `<td>${escapeHtml(r[c.key])}</td>`).join('')}</tr>`).join('')
  }</tbody></table></section>`
}

// Print-friendly rather than PDF: every browser can turn this into a PDF,
// and shipping a PDF engine for one report would be a large dependency for
// no additional capability.
function toHtml(report) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>CatWAF report — ${escapeHtml(report.range.start.slice(0, 10))} to ${escapeHtml(report.range.end.slice(0, 10))}</title>
<style>
  body{font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;padding:40px;color:#111;background:#fff;max-width:1000px}
  h1{font-size:22px;margin:0 0 4px} h2{font-size:15px;margin:32px 0 10px;padding-bottom:6px;border-bottom:1px solid #e3e6ec}
  .meta{color:#666;font-size:12.5px;margin-bottom:24px}
  .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:20px 0}
  .tile{border:1px solid #e3e6ec;border-radius:10px;padding:14px}
  .tile b{display:block;font-size:24px;font-weight:650;letter-spacing:-.02em}
  .tile span{color:#666;font-size:11.5px;text-transform:uppercase;letter-spacing:.05em}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;font-weight:600;color:#555;padding:7px 10px;border-bottom:2px solid #e3e6ec}
  td{padding:6px 10px;border-bottom:1px solid #f0f2f6}
  .empty{color:#888;font-size:13px}
  footer{margin-top:40px;padding-top:14px;border-top:1px solid #e3e6ec;color:#888;font-size:11.5px}
  @media print{body{padding:0} section{break-inside:avoid}}
</style></head><body>
<h1>CatWAF security report</h1>
<p class="meta">${escapeHtml(report.range.start)} &rarr; ${escapeHtml(report.range.end)} &middot;
generated ${escapeHtml(report.generated_at)} &middot; CatWAF ${escapeHtml(report.catwaf_version)} &middot;
engine ${escapeHtml(report.engine)}, paranoia level ${escapeHtml(report.paranoia_level)}</p>
<div class="tiles">
  <div class="tile"><b>${report.totals.requests.toLocaleString()}</b><span>Requests</span></div>
  <div class="tile"><b>${report.totals.blocked.toLocaleString()}</b><span>Blocked</span></div>
  <div class="tile"><b>${report.totals.block_rate}%</b><span>Block rate</span></div>
  <div class="tile"><b>${report.totals.unique_ips.toLocaleString()}</b><span>Unique addresses</span></div>
  <div class="tile"><b>${report.active_bans.total}</b><span>Active bans</span></div>
</div>
${table('Blocked by category', [{ key: 'category', label: 'Category' }, { key: 'count', label: 'Count' }], report.by_category)}
${table('Top offending addresses', [
  { key: 'ip', label: 'Address' }, { key: 'count', label: 'Blocked' },
  { key: 'country', label: 'Country' }, { key: 'last_seen', label: 'Last seen' },
], report.top_ips)}
${table('Blocked by country', [{ key: 'country', label: 'Country' }, { key: 'count', label: 'Count' }], report.by_country)}
${table('Most targeted paths', [{ key: 'uri', label: 'Path' }, { key: 'count', label: 'Blocked' }], report.top_targets)}
${table('Daily totals', [{ key: 'day', label: 'Day' }, { key: 'requests', label: 'Requests' }, { key: 'blocked', label: 'Blocked' }], report.daily)}
<footer>Generated by CatWAF. Figures come from this instance's own request log for the range above; requests older than the configured retention window (${escapeHtml(state.WAF.retention_days)} days) are not included.</footer>
</body></html>`
}

function toEventsCsv(range, { limit = MAX_ROWS } = {}) {
  const rows = db.getDb().prepare(`
    SELECT ts, ip, COALESCE(country_code,'') AS country, method, uri, status, action,
           COALESCE(attack_type,'') AS attack_type, COALESCE(severity,'') AS severity,
           COALESCE(rule_ids,'') AS rule_ids, COALESCE(score,'') AS score
    FROM request_log WHERE ts >= ? AND ts < ? ORDER BY ts DESC LIMIT ?
  `).all(range.start, range.end, Math.min(limit, MAX_ROWS))

  const columns = ['ts', 'ip', 'country', 'method', 'uri', 'status', 'action', 'attack_type', 'severity', 'rule_ids', 'score']
  return [
    columns.join(','),
    ...rows.map(r => columns.map(c => csvCell(r[c])).join(',')),
  ].join('\n')
}

function generate({ from, to, format = 'json' } = {}) {
  const range = parseRange({ from, to })
  if (range.error) return { ok: false, error: range.error }
  const report = collect(range)
  if (format === 'csv') return { ok: true, format, filename: filenameFor(range, 'csv'), body: toCsv(report), contentType: 'text/csv; charset=utf-8' }
  if (format === 'events-csv') return { ok: true, format, filename: filenameFor(range, 'events.csv'), body: toEventsCsv(range), contentType: 'text/csv; charset=utf-8' }
  if (format === 'html') return { ok: true, format, filename: filenameFor(range, 'html'), body: toHtml(report), contentType: 'text/html; charset=utf-8' }
  return { ok: true, format: 'json', report }
}

function filenameFor(range, ext) {
  return `catwaf-report-${range.start.slice(0, 10)}_${range.end.slice(0, 10)}.${ext}`
}

module.exports = { generate, collect, parseRange, toCsv, toHtml, toEventsCsv, csvCell, MAX_ROWS }
