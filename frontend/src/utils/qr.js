// A QR encoder written here rather than pulled in as a dependency, for the
// same reason backend/services/totp.js implements RFC 6238 itself: the string
// being encoded is a two-factor enrollment secret, and a transitive
// dependency is a poor place to put that trust.
//
// Scope is deliberately narrow — byte mode, error-correction level L,
// versions 1 to 10. That covers 271 characters, and an otpauth:// URI for a
// CatWAF account is around 120. Anything longer returns null and the caller
// falls back to showing the secret as text, which every authenticator app
// also accepts.
//
// It lives apart from the component it draws so test/qr.test.js can exercise
// the encoding itself — the part that is either correct or silently produces
// a code no phone will scan.

const ECC_LEVEL_L = 0b01

// [total codewords, EC codewords per block, group-1 blocks, group-1 data
// codewords, group-2 blocks, group-2 data codewords] — ECC level L.
const VERSIONS = [
  null,
  [26, 7, 1, 19, 0, 0],
  [44, 10, 1, 34, 0, 0],
  [70, 15, 1, 55, 0, 0],
  [100, 20, 1, 80, 0, 0],
  [134, 26, 1, 108, 0, 0],
  [172, 18, 2, 68, 0, 0],
  [196, 20, 2, 78, 0, 0],
  [242, 24, 2, 97, 0, 0],
  [292, 30, 2, 116, 0, 0],
  [346, 18, 2, 68, 2, 69],
]

const ALIGNMENT = [
  null, [], [6, 18], [6, 22], [6, 26], [6, 30],
  [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
]

// Bits left over after the last codeword, per version.
const REMAINDER_BITS = [0, 0, 7, 7, 7, 7, 7, 0, 0, 0, 0]

// ─── GF(256), primitive polynomial 0x11d ────────────────────────────────

const EXP = new Uint8Array(512)
const LOG = new Uint8Array(256)
{
  let x = 1
  for (let i = 0; i < 255; i++) {
    EXP[i] = x
    LOG[x] = i
    x <<= 1
    if (x & 0x100) x ^= 0x11d
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]
}

const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]])

function polyMul(a, b) {
  const out = new Array(a.length + b.length - 1).fill(0)
  for (let i = 0; i < a.length; i++) {
    for (let j = 0; j < b.length; j++) out[i + j] ^= gfMul(a[i], b[j])
  }
  return out
}

function generatorPoly(degree) {
  let poly = [1]
  for (let i = 0; i < degree; i++) poly = polyMul(poly, [1, EXP[i]])
  return poly
}

export function reedSolomon(data, ecLength) {
  const gen = generatorPoly(ecLength)
  const buf = [...data, ...new Array(ecLength).fill(0)]
  for (let i = 0; i < data.length; i++) {
    const factor = buf[i]
    if (!factor) continue
    for (let j = 0; j < gen.length; j++) buf[i + j] ^= gfMul(gen[j], factor)
  }
  return buf.slice(data.length)
}

// ─── Encoding ───────────────────────────────────────────────────────────

function pickVersion(byteLength) {
  for (let v = 1; v <= 10; v++) {
    const [, , b1, d1, b2, d2] = VERSIONS[v]
    const dataCodewords = b1 * d1 + b2 * d2
    const countBits = v <= 9 ? 8 : 16
    if (4 + countBits + byteLength * 8 <= dataCodewords * 8) return v
  }
  return 0
}

function dataCodewordsFor(bytes, version) {
  const [, , b1, d1, b2, d2] = VERSIONS[version]
  const capacity = b1 * d1 + b2 * d2
  const countBits = version <= 9 ? 8 : 16

  const bits = []
  const push = (value, length) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >> i) & 1)
  }

  push(0b0100, 4)            // byte mode
  push(bytes.length, countBits)
  for (const b of bytes) push(b, 8)

  // Terminator, then pad to a whole codeword, then the fixed pad pattern.
  const terminator = Math.min(4, capacity * 8 - bits.length)
  push(0, terminator)
  while (bits.length % 8) bits.push(0)

  const codewords = []
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j]
    codewords.push(byte)
  }
  const PAD = [0xec, 0x11]
  for (let i = 0; codewords.length < capacity; i++) codewords.push(PAD[i % 2])
  return codewords
}

function interleave(dataCodewords, version) {
  const [, ecPerBlock, b1, d1, b2, d2] = VERSIONS[version]
  const blocks = []
  let offset = 0
  for (let i = 0; i < b1; i++) { blocks.push(dataCodewords.slice(offset, offset + d1)); offset += d1 }
  for (let i = 0; i < b2; i++) { blocks.push(dataCodewords.slice(offset, offset + d2)); offset += d2 }

  const ecBlocks = blocks.map(b => reedSolomon(b, ecPerBlock))

  const out = []
  const longest = Math.max(...blocks.map(b => b.length))
  for (let i = 0; i < longest; i++) {
    for (const block of blocks) if (i < block.length) out.push(block[i])
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (const block of ecBlocks) out.push(block[i])
  }
  return out
}

// ─── Matrix ─────────────────────────────────────────────────────────────

function blankMatrix(size) {
  return Array.from({ length: size }, () => new Int8Array(size).fill(-1))
}

function placeFunctionPatterns(m, version) {
  const size = m.length

  const finder = (row, col) => {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const rr = row + r
        const cc = col + c
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue
        const inRing = (r >= 0 && r <= 6 && (c === 0 || c === 6)) || (c >= 0 && c <= 6 && (r === 0 || r === 6))
        const inCore = r >= 2 && r <= 4 && c >= 2 && c <= 4
        m[rr][cc] = inRing || inCore ? 1 : 0
      }
    }
  }
  finder(0, 0)
  finder(0, size - 7)
  finder(size - 7, 0)

  for (let i = 8; i < size - 8; i++) {
    const bit = i % 2 === 0 ? 1 : 0
    m[6][i] = bit
    m[i][6] = bit
  }

  const centres = ALIGNMENT[version]
  for (const r of centres) {
    for (const c of centres) {
      // Skip the three that would sit on a finder pattern.
      if ((r === 6 && c === 6) || (r === 6 && c === size - 7) || (r === size - 7 && c === 6)) continue
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          m[r + dr][c + dc] = Math.max(Math.abs(dr), Math.abs(dc)) !== 1 ? 1 : 0
        }
      }
    }
  }

  m[size - 8][8] = 1 // the always-dark module

  // Reserve the format-information strips so data placement skips them.
  for (let i = 0; i < 9; i++) {
    if (m[8][i] === -1) m[8][i] = 0
    if (m[i][8] === -1) m[i][8] = 0
  }
  for (let i = 0; i < 8; i++) {
    if (m[8][size - 1 - i] === -1) m[8][size - 1 - i] = 0
    if (m[size - 1 - i][8] === -1) m[size - 1 - i][8] = 0
  }

  if (version >= 7) {
    const bits = versionInfoBits(version)
    for (let i = 0; i < 18; i++) {
      const bit = (bits >> i) & 1
      m[Math.floor(i / 3)][size - 11 + (i % 3)] = bit
      m[size - 11 + (i % 3)][Math.floor(i / 3)] = bit
    }
  }
}

function versionInfoBits(version) {
  let rem = version
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1f25)
  return (version << 12) | rem
}

function formatInfoBits(mask) {
  const data = (ECC_LEVEL_L << 3) | mask
  let rem = data
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537)
  return ((data << 10) | rem) ^ 0x5412
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
]

function placeData(m, reserved, codewords, remainderBits) {
  const size = m.length
  const bits = []
  for (const cw of codewords) {
    for (let i = 7; i >= 0; i--) bits.push((cw >> i) & 1)
  }
  for (let i = 0; i < remainderBits; i++) bits.push(0)

  let index = 0
  let upward = true
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5 // the vertical timing pattern is never a data column
    for (let step = 0; step < size; step++) {
      const row = upward ? size - 1 - step : step
      for (const col of [right, right - 1]) {
        if (reserved[row][col]) continue
        m[row][col] = index < bits.length ? bits[index] : 0
        index++
      }
    }
    upward = !upward
  }
}

function applyMask(m, reserved, mask) {
  const size = m.length
  const fn = MASKS[mask]
  const out = m.map(row => Int8Array.from(row))
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!reserved[r][c] && fn(r, c)) out[r][c] ^= 1
    }
  }
  return out
}

function placeFormatInfo(m, mask) {
  const size = m.length
  const bits = formatInfoBits(mask)
  const bit = i => (bits >> i) & 1

  // First copy: up column 8 beside the top-left finder, then left along row 8.
  for (let i = 0; i <= 5; i++) m[i][8] = bit(i)
  m[7][8] = bit(6)
  m[8][8] = bit(7)
  m[8][7] = bit(8)
  for (let i = 9; i <= 14; i++) m[8][14 - i] = bit(i)

  // Second copy: up column 8 from the bottom, and right along row 8.
  for (let i = 0; i <= 7; i++) m[size - 1 - i][8] = bit(i)
  for (let i = 8; i <= 14; i++) m[8][size - 15 + i] = bit(i)

  m[size - 8][8] = 1
}

function penalty(m) {
  const size = m.length
  let score = 0

  // Rule 1 — runs of five or more identical modules in a row or column.
  for (let i = 0; i < size; i++) {
    for (const read of [(k) => m[i][k], (k) => m[k][i]]) {
      let run = 1
      for (let k = 1; k < size; k++) {
        if (read(k) === read(k - 1)) {
          run++
          if (run === 5) score += 3
          else if (run > 5) score += 1
        } else run = 1
      }
    }
  }

  // Rule 2 — 2x2 blocks of one colour.
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = m[r][c]
      if (v === m[r][c + 1] && v === m[r + 1][c] && v === m[r + 1][c + 1]) score += 3
    }
  }

  // Rule 3 — the finder-like 1:1:3:1:1 pattern with four light modules beside it.
  const A = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
  const B = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]
  for (let r = 0; r < size; r++) {
    for (let c = 0; c <= size - 11; c++) {
      let hitA = true, hitB = true, vA = true, vB = true
      for (let k = 0; k < 11; k++) {
        if (m[r][c + k] !== A[k]) hitA = false
        if (m[r][c + k] !== B[k]) hitB = false
        if (m[c + k][r] !== A[k]) vA = false
        if (m[c + k][r] !== B[k]) vB = false
      }
      if (hitA) score += 40
      if (hitB) score += 40
      if (vA) score += 40
      if (vB) score += 40
    }
  }

  // Rule 4 — deviation from an even split of dark and light.
  let dark = 0
  for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) dark += m[r][c]
  const percent = (dark * 100) / (size * size)
  score += Math.floor(Math.abs(percent - 50) / 5) * 10

  return score
}

// Returns a size x size matrix of 0/1, or null if the text does not fit.
export function encodeQR(text) {
  const bytes = new TextEncoder().encode(text)
  const version = pickVersion(bytes.length)
  if (!version) return null

  const codewords = interleave(dataCodewordsFor(bytes, version), version)
  const size = version * 4 + 17

  const base = blankMatrix(size)
  placeFunctionPatterns(base, version)
  const reserved = base.map(row => Array.from(row, v => v !== -1))

  placeData(base, reserved, codewords, REMAINDER_BITS[version])

  let best = null
  let bestScore = Infinity
  for (let mask = 0; mask < 8; mask++) {
    const candidate = applyMask(base, reserved, mask)
    placeFormatInfo(candidate, mask)
    const score = penalty(candidate)
    if (score < bestScore) { bestScore = score; best = candidate }
  }

  return best.map(row => Array.from(row))
}

// Exposed so test/qr.test.js can take a finished matrix apart again — read
// the format information back, undo the mask, walk the same zigzag, and check
// the Reed-Solomon syndromes. A QR code that is subtly wrong still looks
// exactly like a QR code, so "it renders" is not evidence of anything.
export const INTERNALS = {
  VERSIONS, ALIGNMENT, REMAINDER_BITS, MASKS,
  formatInfoBits, versionInfoBits, generatorPoly, gfMul, EXP, LOG,
  blankMatrix, placeFunctionPatterns, pickVersion, dataCodewordsFor, interleave,
}
