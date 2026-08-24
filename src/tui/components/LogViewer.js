
const ansi = require('../lib/ansi')
const StatusBadge = require('./StatusBadge')

function LogViewer(entries, { limit = 20 } = {}) {
  if (!entries.length) return [ansi.color('  No entries yet.', ansi.colors.dim)]

  return entries.slice(0, limit).map(e => {
    const time = new Date(e.ts).toLocaleTimeString()
    const badge = e.severity ? StatusBadge(e.severity) : ''
    // Log fields originate from attacker-shaped HTTP traffic; strip every
    // escape/control byte so nothing can steer the operator's terminal.
    const ip = e.ip ? ansi.color(ansi.padRight(ansi.stripControl(e.ip), 16), ansi.colors.dim) : ''
    return `  ${ansi.color(time, ansi.colors.dim)}  ${badge}  ${ip}${ansi.stripControl(e.summary)}`
  })
}

module.exports = LogViewer
