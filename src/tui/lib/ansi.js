
const readline = require('readline')

const ESC = '\x1b['
const csi = (s) => ESC + s

const colors = {
  reset: csi('0m'),
  bold: csi('1m'),
  dim: csi('2m'),
  red: csi('31m'),
  green: csi('32m'),
  yellow: csi('33m'),
  blue: csi('34m'),
  magenta: csi('35m'),
  cyan: csi('36m'),
  white: csi('37m'),
  gray: csi('90m'),
  brightRed: csi('91m'),
  brightGreen: csi('92m'),
  brightYellow: csi('93m'),
  brightCyan: csi('96m'),
  bgRed: csi('41m'),
  bgGreen: csi('42m'),
}

const SEVERITY_COLOR = {
  critical: colors.brightRed, high: colors.red, medium: colors.yellow,
  low: colors.cyan, info: colors.dim,
  pass: colors.green, warn: colors.yellow, fail: colors.red, unknown: colors.dim,
}

function color(text, ...codes) {
  return codes.join('') + text + colors.reset
}

function clearScreen() { process.stdout.write(csi('2J') + csi('H')) }
function hideCursor() { process.stdout.write(csi('?25l')) }
function showCursor() { process.stdout.write(csi('?25h')) }
function moveTo(row, col) { process.stdout.write(csi(`${row};${col}H`)) }

function termSize() {
  return { rows: process.stdout.rows || 24, cols: process.stdout.columns || 80 }
}

function center(text, width) {
  const len = stripAnsi(text).length
  const pad = Math.max(0, Math.floor((width - len) / 2))
  return ' '.repeat(pad) + text
}

function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, '')
}

function padRight(text, width) {
  const len = stripAnsi(text).length
  return text + ' '.repeat(Math.max(0, width - len))
}

function hr(width, ch = '─') { return colors.dim + ch.repeat(width) + colors.reset }

function box(lines, { title = '', width = 60, borderColor = colors.dim } = {}) {
  const out = []
  const inner = width - 2
  const top = title
    ? `╭─ ${title} ` + '─'.repeat(Math.max(0, inner - title.length - 3)) + '╮'
    : '╭' + '─'.repeat(inner) + '╮'
  out.push(borderColor + top + colors.reset)
  for (const line of lines) {
    out.push(borderColor + '│' + colors.reset + ' ' + padRight(line, inner - 1) + borderColor + '│' + colors.reset)
  }
  out.push(borderColor + '╰' + '─'.repeat(inner) + '╯' + colors.reset)
  return out
}

function renderFrame({ header, body, footer }) {
  clearScreen()
  const { cols } = termSize()
  const lines = []
  if (header) {
    lines.push(color(padRight(' ' + header, cols), colors.bold, colors.cyan))
    lines.push(colors.dim + '─'.repeat(cols) + colors.reset)
  }
  lines.push(...body)
  if (footer) {
    lines.push('')
    lines.push(colors.dim + '─'.repeat(cols) + colors.reset)
    lines.push(colors.dim + ' ' + footer + colors.reset)
  }
  process.stdout.write(lines.join('\n'))
}

function menu({ title, items, hint = '↑↓ navigate · ↵ select · q/esc back' }) {
  return new Promise((resolve) => {
    let selected = 0
    readline.emitKeypressEvents(process.stdin)
    if (process.stdin.isTTY) process.stdin.setRawMode(true)

    const draw = () => {
      const body = items.map((item, i) => {
        const label = typeof item === 'string' ? item : item.label
        const marker = i === selected ? color('❯ ', colors.cyan, colors.bold) : '  '
        const text = i === selected ? color(label, colors.bold, colors.cyan) : label
        return marker + text
      })
      renderFrame({ header: title, body, footer: hint })
    }

    const onKey = (str, key) => {
      if (key.name === 'up') { selected = (selected - 1 + items.length) % items.length; draw() }
      else if (key.name === 'down') { selected = (selected + 1) % items.length; draw() }
      else if (key.name === 'return') { cleanup(); resolve(itemValue(items[selected], selected)) }
      else if (key.name === 'escape' || str === 'q') { cleanup(); resolve(null) }
      else if (key.ctrl && key.name === 'c') { cleanup(); process.exit(0) }
    }

    function itemValue(item, i) {
      if (typeof item === 'string') return item
      return item.value !== undefined ? item.value : i
    }

    function cleanup() {
      process.stdin.removeListener('keypress', onKey)
      if (process.stdin.isTTY) process.stdin.setRawMode(false)
    }

    process.stdin.on('keypress', onKey)
    draw()
  })
}

function prompt(question, { mask = false, defaultValue = '' } = {}) {
  process.stdin.resume()
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    const q = defaultValue ? `${question} ${colors.dim}(${defaultValue})${colors.reset}: ` : `${question}: `
    if (!mask) {
      rl.question(q, (answer) => { rl.close(); resolve(answer.trim() || defaultValue) })
      return
    }
    process.stdout.write(q)
    let input = ''
    readline.emitKeypressEvents(process.stdin)
    if (process.stdin.isTTY) process.stdin.setRawMode(true)
    const onKey = (str, key) => {
      if (key.name === 'return') {
        cleanup()
        process.stdout.write('\n')
        resolve(input || defaultValue)
      } else if (key.name === 'backspace') {
        input = input.slice(0, -1)
        redraw()
      } else if (key.ctrl && key.name === 'c') {
        cleanup(); process.exit(0)
      } else if (str && !key.ctrl) {
        input += str
        redraw()
      }
    }
    function redraw() {
      readline.cursorTo(process.stdout, q.length)
      readline.clearLine(process.stdout, 1)
      process.stdout.write('*'.repeat(input.length))
    }
    function cleanup() {
      rl.close()
      process.stdin.removeListener('keypress', onKey)
      if (process.stdin.isTTY) process.stdin.setRawMode(false)
    }
    process.stdin.on('keypress', onKey)
  })
}

function confirm(question, defaultYes = true) {
  process.stdin.resume()
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    const hint = defaultYes ? 'Y/n' : 'y/N'
    rl.question(`${question} (${hint}): `, (answer) => {
      rl.close()
      const a = answer.trim().toLowerCase()
      if (!a) return resolve(defaultYes)
      resolve(a === 'y' || a === 'yes')
    })
  })
}

function waitForKey(message) {
  process.stdin.resume()
  const shown = message || 'any key to continue…'
  return new Promise((resolve) => {
    process.stdout.write('\n' + colors.dim + shown + colors.reset)
    readline.emitKeypressEvents(process.stdin)
    if (process.stdin.isTTY) process.stdin.setRawMode(true)
    const onKey = (str, key) => {
      process.stdin.removeListener('keypress', onKey)
      if (process.stdin.isTTY) process.stdin.setRawMode(false)
      if (key.ctrl && key.name === 'c') {
        process.stdout.write('\n' + colors.yellow + 'Setup cancelled — nothing after this point was applied. Re-run `catwaf --setup` to continue.' + colors.reset + '\n')
        process.exit(1)
      }
      resolve()
    }
    process.stdin.on('keypress', onKey)
  })
}

function liveView(renderFn, { intervalMs = 2000 } = {}) {
  return new Promise((resolve) => {
    let stopped = false
    readline.emitKeypressEvents(process.stdin)
    if (process.stdin.isTTY) process.stdin.setRawMode(true)

    const tick = async () => {
      if (stopped) return
      const frame = await renderFn()
      renderFrame(frame)
    }

    const onKey = (str, key) => {
      if (key.name === 'escape' || str === 'q') { stop() }
      else if (key.ctrl && key.name === 'c') { stop(); process.exit(0) }
      else if (str === 'r' || str === 'R') { tick() }
    }
    process.stdin.on('keypress', onKey)

    const timer = setInterval(tick, intervalMs)
    tick()

    function stop() {
      if (stopped) return
      stopped = true
      clearInterval(timer)
      process.stdin.removeListener('keypress', onKey)
      if (process.stdin.isTTY) process.stdin.setRawMode(false)
      resolve()
    }
  })
}

module.exports = {
  colors, color, clearScreen, hideCursor, showCursor, moveTo, termSize,
  center, padRight, stripAnsi, box, hr, SEVERITY_COLOR, renderFrame, menu, prompt, confirm,
  waitForKey, liveView,
}
