#!/usr/bin/env node

// Verifies frontend/src/utils/qr.js by taking its own output apart again.
//
// A QR code that is subtly wrong still looks exactly like a QR code — the
// only honest test is to decode it. This file rebuilds the function-pattern
// map independently of the encoder's data placement, reads the format
// information back out of the finished matrix, undoes the mask, walks the
// zigzag, checks every Reed-Solomon block's syndromes are zero, and compares
// the recovered bytes with what went in.

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }

;(async () => {
  const qr = await import('../frontend/src/utils/qr.js')
  const { encodeQR, reedSolomon, INTERNALS } = qr
  const { VERSIONS, ALIGNMENT, REMAINDER_BITS, MASKS, blankMatrix, placeFunctionPatterns, gfMul, EXP } = INTERNALS

  // ── decoder ───────────────────────────────────────────────────────────

  function readFormatInfo(m) {
    const size = m.length
    const bit = []
    for (let i = 0; i <= 5; i++) bit[i] = m[i][8]
    bit[6] = m[7][8]
    bit[7] = m[8][8]
    bit[8] = m[8][7]
    for (let i = 9; i <= 14; i++) bit[i] = m[8][14 - i]

    const mirrored = []
    for (let i = 0; i <= 7; i++) mirrored[i] = m[size - 1 - i][8]
    for (let i = 8; i <= 14; i++) mirrored[i] = m[8][size - 15 + i]

    let raw = 0
    for (let i = 0; i < 15; i++) raw |= bit[i] << i
    let raw2 = 0
    for (let i = 0; i < 15; i++) raw2 |= mirrored[i] << i

    const unmasked = raw ^ 0x5412
    // BCH(15,5) check: the whole 15-bit word must divide by 0x537.
    let rem = unmasked
    for (let i = 4; i >= 0; i--) if ((rem >> (i + 10)) & 1) rem ^= 0x537 << i
    return {
      bothCopiesAgree: raw === raw2,
      bchValid: rem === 0,
      // The 15-bit word is (data << 10) | bch, and data is (ecc << 3) | mask.
      ecc: (unmasked >> 13) & 0b11,
      mask: (unmasked >> 10) & 0b111,
    }
  }

  function readCodewords(m, version, mask) {
    const size = m.length
    const skeleton = blankMatrix(size)
    placeFunctionPatterns(skeleton, version)
    const reserved = skeleton.map(row => Array.from(row, v => v !== -1))

    const fn = MASKS[mask]
    const bits = []
    let upward = true
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5
      for (let step = 0; step < size; step++) {
        const row = upward ? size - 1 - step : step
        for (const col of [right, right - 1]) {
          if (reserved[row][col]) continue
          bits.push(m[row][col] ^ (fn(row, col) ? 1 : 0))
        }
      }
      upward = !upward
    }

    const total = VERSIONS[version][0]
    const codewords = []
    for (let i = 0; i < total; i++) {
      let byte = 0
      for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i * 8 + j]
      codewords.push(byte)
    }
    return { codewords, trailingBits: bits.length - total * 8 }
  }

  function deinterleave(codewords, version) {
    const [, ecPerBlock, b1, d1, b2, d2] = VERSIONS[version]
    const sizes = [...Array(b1).fill(d1), ...Array(b2).fill(d2)]
    const blocks = sizes.map(() => [])
    const dataTotal = sizes.reduce((a, b) => a + b, 0)

    let idx = 0
    const longest = Math.max(...sizes)
    for (let i = 0; i < longest; i++) {
      for (let b = 0; b < blocks.length; b++) {
        if (i < sizes[b]) blocks[b].push(codewords[idx++])
      }
    }
    const ecBlocks = blocks.map(() => [])
    let p = dataTotal
    for (let i = 0; i < ecPerBlock; i++) {
      for (let b = 0; b < blocks.length; b++) ecBlocks[b][i] = codewords[p++]
    }
    return { blocks, ecBlocks, ecPerBlock }
  }

  // Every syndrome of an uncorrupted RS codeword is zero.
  function syndromesZero(block, ec, ecLen) {
    const poly = [...block, ...ec]
    for (let i = 0; i < ecLen; i++) {
      let acc = 0
      for (const coeff of poly) acc = gfMul(acc, EXP[i]) ^ coeff
      if (acc !== 0) return false
    }
    return true
  }

  function readPayload(blocks, version) {
    const data = blocks.flat()
    const bits = []
    for (const cw of data) for (let i = 7; i >= 0; i--) bits.push((cw >> i) & 1)
    let at = 0
    const take = n => { let v = 0; for (let i = 0; i < n; i++) v = (v << 1) | bits[at++]; return v }

    const mode = take(4)
    const count = take(version <= 9 ? 8 : 16)
    const bytes = []
    for (let i = 0; i < count; i++) bytes.push(take(8))
    return { mode, count, text: Buffer.from(bytes).toString('utf8') }
  }

  function roundTrip(text) {
    const m = encodeQR(text)
    if (!m) return { fitted: false }
    const version = (m.length - 17) / 4
    const fmt = readFormatInfo(m)
    const { codewords, trailingBits } = readCodewords(m, version, fmt.mask)
    const { blocks, ecBlocks, ecPerBlock } = deinterleave(codewords, version)
    const rsOk = blocks.every((b, i) => syndromesZero(b, ecBlocks[i], ecPerBlock))
    const payload = readPayload(blocks, version)
    return { fitted: true, m, version, fmt, rsOk, payload, trailingBits }
  }

  // ── tests ─────────────────────────────────────────────────────────────

  section('Galois field and Reed-Solomon')

  {
    const { LOG } = INTERNALS
    let expLogOk = true
    for (let x = 1; x < 256; x++) if (EXP[LOG[x]] !== x) expLogOk = false
    check('GF(256) exp and log are inverses across the whole field', expLogOk)

    // Multiplication must agree with the carry-less definition it replaces.
    const slowMul = (a, b) => {
      let r = 0
      while (b) { if (b & 1) r ^= a; b >>= 1; a <<= 1; if (a & 0x100) a ^= 0x11d }
      return r
    }
    let mulOk = true
    for (let a = 0; a < 256; a += 7) for (let b = 0; b < 256; b += 5) {
      if (gfMul(a, b) !== slowMul(a, b)) mulOk = false
    }
    check('GF(256) multiplication matches the polynomial definition', mulOk)
  }

  {
    // A codeword built from its own EC bytes must have zero syndromes.
    const data = Array.from({ length: 19 }, (_, i) => (i * 37 + 11) & 0xff)
    const ec = reedSolomon(data, 7)
    check('generated EC codewords produce zero syndromes', syndromesZero(data, ec, 7), { ec })
    check('EC block has the requested length', ec.length === 7, ec.length)

    // A single corrupted byte must break at least one syndrome — otherwise
    // the check above would be vacuous.
    const broken = [...data]; broken[3] ^= 0x5a
    check('a corrupted codeword fails the syndrome check', !syndromesZero(broken, ec, 7))
  }

  section('structure of a rendered code')

  {
    const uri = 'otpauth://totp/CatWAF:admin?secret=JBSWY3DPEHPK3PXP&issuer=CatWAF&algorithm=SHA1&digits=6&period=30'
    const r = roundTrip(uri)
    check('a CatWAF otpauth URI fits', r.fitted)
    const { m, version } = r
    const size = m.length

    check('matrix size matches its version', size === version * 4 + 17, { size, version })
    check('every module is 0 or 1', m.every(row => row.every(v => v === 0 || v === 1)))

    // Finder patterns: dark ring, light ring, dark 3x3 core.
    const finderOk = (r0, c0) => {
      for (let r = 0; r < 7; r++) {
        for (let c = 0; c < 7; c++) {
          const ring = r === 0 || r === 6 || c === 0 || c === 6
          const core = r >= 2 && r <= 4 && c >= 2 && c <= 4
          if (m[r0 + r][c0 + c] !== (ring || core ? 1 : 0)) return false
        }
      }
      return true
    }
    check('three finder patterns are correct',
      finderOk(0, 0) && finderOk(0, size - 7) && finderOk(size - 7, 0))

    let separatorsOk = true
    for (let i = 0; i < 8; i++) {
      if (m[7][i] !== 0 || m[i][7] !== 0) separatorsOk = false
      if (m[7][size - 1 - i] !== 0 || m[i][size - 8] !== 0) separatorsOk = false
      if (m[size - 8][i] !== 0 || m[size - 1 - i][7] !== 0) separatorsOk = false
    }
    check('finder separators are light', separatorsOk)

    let timingOk = true
    for (let i = 8; i < size - 8; i++) {
      if (m[6][i] !== (i % 2 === 0 ? 1 : 0)) timingOk = false
      if (m[i][6] !== (i % 2 === 0 ? 1 : 0)) timingOk = false
    }
    check('timing patterns alternate', timingOk)

    check('the always-dark module is dark', m[size - 8][8] === 1)

    let alignOk = true
    for (const rc of ALIGNMENT[version]) {
      for (const cc of ALIGNMENT[version]) {
        if ((rc === 6 && cc === 6) || (rc === 6 && cc === size - 7) || (rc === size - 7 && cc === 6)) continue
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) {
            const want = Math.max(Math.abs(dr), Math.abs(dc)) !== 1 ? 1 : 0
            if (m[rc + dr][cc + dc] !== want) alignOk = false
          }
        }
      }
    }
    check('alignment patterns are correct', alignOk, { version, centres: ALIGNMENT[version] })

    check('format information passes its BCH check', r.fmt.bchValid, r.fmt)
    check('both format-information copies agree', r.fmt.bothCopiesAgree, r.fmt)
    check('format information records error-correction level L', r.fmt.ecc === 0b01, r.fmt.ecc)
    check('the recorded mask is one of the eight', r.fmt.mask >= 0 && r.fmt.mask <= 7, r.fmt.mask)
    check('trailing remainder bits match the version', r.trailingBits === REMAINDER_BITS[version], {
      got: r.trailingBits, want: REMAINDER_BITS[version],
    })
  }

  section('round trip')

  const SAMPLES = [
    'a',
    'CatWAF',
    'otpauth://totp/CatWAF:admin?secret=JBSWY3DPEHPK3PXP&issuer=CatWAF&algorithm=SHA1&digits=6&period=30',
    'otpauth://totp/CatWAF:a-very-long-administrator-account-name?secret=MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U&issuer=CatWAF&algorithm=SHA1&digits=6&period=30',
    'x'.repeat(17),   // exactly fills version 1
    'x'.repeat(18),   // forces version 2
    'x'.repeat(106),  // exactly fills version 5
    'x'.repeat(271),  // exactly fills version 10, the largest supported
    'héllo — ünicode ✓',
  ]

  for (const sample of SAMPLES) {
    const label = sample.length > 40 ? `${sample.slice(0, 34)}… (${sample.length})` : sample
    const r = roundTrip(sample)
    if (!r.fitted) { check(`encodes "${label}"`, false, 'did not fit'); continue }
    check(`"${label}" → v${r.version}, RS blocks intact`, r.rsOk)
    check(`"${label}" decodes back to itself`, r.payload.text === sample, {
      got: r.payload.text.slice(0, 60), mode: r.payload.mode,
    })
  }

  section('capacity boundaries')

  check('version steps up exactly at the documented limits', (() => {
    const limits = [17, 32, 53, 78, 106, 134, 154, 192, 230, 271]
    for (let v = 1; v <= 10; v++) {
      const atLimit = encodeQR('x'.repeat(limits[v - 1]))
      if (!atLimit || (atLimit.length - 17) / 4 !== v) return false
      if (v < 10) {
        const overLimit = encodeQR('x'.repeat(limits[v - 1] + 1))
        if (!overLimit || (overLimit.length - 17) / 4 !== v + 1) return false
      }
    }
    return true
  })())

  check('text beyond version 10 is refused rather than truncated', encodeQR('x'.repeat(272)) === null)

  section('determinism')

  {
    const a = encodeQR('CatWAF two-factor')
    const b = encodeQR('CatWAF two-factor')
    check('the same input always produces the same matrix', JSON.stringify(a) === JSON.stringify(b))
  }

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
})().catch(e => {
  console.error('\nqr test harness error:', e)
  process.exit(1)
})
