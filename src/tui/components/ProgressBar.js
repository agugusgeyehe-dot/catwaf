
const ansi = require('../lib/ansi')

function ProgressBar(pct, { width = 24, showPct = true } = {}) {
  const clamped = Math.max(0, Math.min(100, pct))
  const filled = Math.round((clamped / 100) * width)
  const color = clamped >= 80 ? ansi.colors.green : clamped >= 60 ? ansi.colors.yellow : ansi.colors.red
  const bar = ansi.color('█'.repeat(filled), color) + ansi.colors.dim + '░'.repeat(width - filled) + ansi.colors.reset
  return showPct ? `${bar}  ${ansi.color(clamped + '%', color, ansi.colors.bold)}` : bar
}

module.exports = ProgressBar
