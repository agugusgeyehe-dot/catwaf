
const ansi = require('../lib/ansi')

function Panel(title, items, { width = 60, borderColor, labelWidth = 22 } = {}) {
  const lines = items.map(item => {
    if (Array.isArray(item)) {
      const [label, value, valueColor] = item
      const l = ansi.padRight(String(label), labelWidth)
      const v = valueColor ? ansi.color(String(value), valueColor) : String(value)
      return `${ansi.colors.dim}${l}${ansi.colors.reset} ${v}`
    }
    return String(item)
  })
  return ansi.box(lines, { title, width, borderColor })
}

module.exports = Panel
