// challenge/captcha.js — CatWAF's own generated image challenge (idea #2).
//
// The point of this tier is that it needs no third-party account and no API
// key. CatWAF Free's user is a solo site owner who has been promised
// zero-config protection; telling them to go and register with a captcha
// vendor before they can stop a scraper breaks that promise.
//
// The image is an SVG built here rather than a rasterised bitmap, so there
// is no image library to depend on. The distortions below are chosen to
// defeat naive OCR and off-the-shelf scrapers — which is the traffic this
// tier exists to stop. It is not, and does not claim to be, resistant to a
// determined attacker with a solver; the provider tier (#3) is there for
// anyone who needs that.

const crypto = require('crypto')

// No 0/O/1/I/l — an ambiguous glyph turns a solvable challenge into a
// coin-flip for a human while costing an OCR engine nothing.
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

function randomInt(max) {
  return crypto.randomInt(0, max)
}

function generateAnswer(length = 5) {
  let out = ''
  for (let i = 0; i < length; i++) out += ALPHABET[randomInt(ALPHABET.length)]
  return out
}

function noiseLines(width, height, count) {
  const lines = []
  for (let i = 0; i < count; i++) {
    const x1 = randomInt(width)
    const y1 = randomInt(height)
    const x2 = randomInt(width)
    const y2 = randomInt(height)
    const opacity = (30 + randomInt(40)) / 100
    lines.push(`<path d="M${x1} ${y1} Q${randomInt(width)} ${randomInt(height)} ${x2} ${y2}" stroke="#7c8798" stroke-width="${1 + randomInt(2)}" fill="none" opacity="${opacity}"/>`)
  }
  return lines.join('')
}

function noiseDots(width, height, count) {
  const dots = []
  for (let i = 0; i < count; i++) {
    dots.push(`<circle cx="${randomInt(width)}" cy="${randomInt(height)}" r="${1 + randomInt(2)}" fill="#8b95a5" opacity="0.5"/>`)
  }
  return dots.join('')
}

function renderSvg(answer) {
  const width = 60 + answer.length * 34
  const height = 76
  const glyphs = []

  for (const [i, char] of [...answer].entries()) {
    const x = 32 + i * 34
    const y = 50 + randomInt(10)
    const rotate = randomInt(40) - 20
    const size = 32 + randomInt(10)
    const hue = 200 + randomInt(60)
    glyphs.push(
      `<text x="${x}" y="${y}" font-family="Georgia,'Times New Roman',serif" font-size="${size}" font-weight="700" ` +
      `fill="hsl(${hue} 45% 82%)" transform="rotate(${rotate} ${x} ${y})" ` +
      `style="letter-spacing:2px">${char}</text>`
    )
  }

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="Verification characters">`,
    `<rect width="${width}" height="${height}" rx="10" fill="#141821"/>`,
    noiseDots(width, height, 40),
    glyphs.join(''),
    noiseLines(width, height, 5),
    '</svg>',
  ].join('')
}

function create(length = 5) {
  const answer = generateAnswer(Math.max(4, Math.min(8, length)))
  return { answer, svg: renderSvg(answer) }
}

// Case-insensitive and constant-time: a captcha answer is short enough that
// a timing difference is measurable, and letter case is never the point.
function matches(expected, submitted) {
  const a = Buffer.from(String(expected || '').toUpperCase())
  const b = Buffer.from(String(submitted || '').trim().toUpperCase())
  if (a.length === 0 || a.length !== b.length) return false
  return crypto.timingSafeEqual(a, b)
}

module.exports = { create, matches, generateAnswer, renderSvg, ALPHABET }
