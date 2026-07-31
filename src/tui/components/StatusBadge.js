
const ansi = require('../lib/ansi')

const KIND_STYLE = {
  active:   { symbol: '●', color: ansi.colors.green },
  running:  { symbol: '●', color: ansi.colors.green },
  ok:       { symbol: '●', color: ansi.colors.green },
  inactive: { symbol: '○', color: ansi.colors.dim },
  stopped:  { symbol: '●', color: ansi.colors.red },
  down:     { symbol: '●', color: ansi.colors.red },
  degraded: { symbol: '●', color: ansi.colors.yellow },
  pass: { symbol: '✓', color: ansi.colors.green },
  warn: { symbol: '⚠', color: ansi.colors.yellow },
  fail: { symbol: '✗', color: ansi.colors.red },
  unknown: { symbol: '?', color: ansi.colors.dim },
  critical: { symbol: '●', color: ansi.colors.brightRed },
  high:     { symbol: '●', color: ansi.colors.red },
  medium:   { symbol: '●', color: ansi.colors.yellow },
  low:      { symbol: '●', color: ansi.colors.cyan },
  info:     { symbol: '●', color: ansi.colors.dim },
  blocked:  { symbol: '✗', color: ansi.colors.red },
  allowed:  { symbol: '✓', color: ansi.colors.green },
}

function StatusBadge(kind, label) {
  const style = KIND_STYLE[kind] || { symbol: '●', color: ansi.colors.dim }
  const text = label || kind.toUpperCase()
  return ansi.color(`${style.symbol} ${text}`, style.color)
}

module.exports = StatusBadge
