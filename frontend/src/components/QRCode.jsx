import { useMemo } from 'react'
import { encodeQR } from '../utils/qr.js'

// Draws the matrix produced by utils/qr.js. Rendering it as one SVG path of
// unit squares keeps it crisp at any size and avoids a canvas, so it prints
// and scales cleanly.
//
// The colours are fixed black-on-white rather than themed: a QR code read by
// a phone camera needs real contrast, and a dark-theme code on a dark card is
// the classic way to produce something that looks right and does not scan.

export default function QRCode({ text, size = 208, quiet = 4, title = 'QR code' }) {
  const matrix = useMemo(() => {
    try { return encodeQR(text) } catch { return null }
  }, [text])

  if (!matrix) return null

  const dim = matrix.length + quiet * 2
  const path = []
  for (let r = 0; r < matrix.length; r++) {
    for (let c = 0; c < matrix.length; c++) {
      if (matrix[r][c]) path.push(`M${c + quiet} ${r + quiet}h1v1h-1z`)
    }
  }

  return (
    <svg
      width={size} height={size} viewBox={`0 0 ${dim} ${dim}`}
      role="img" aria-label={title}
      shapeRendering="crispEdges"
      style={{ borderRadius: 8, display: 'block', background: '#ffffff' }}
    >
      <rect width={dim} height={dim} fill="#ffffff" />
      <path d={path.join('')} fill="#000000" />
    </svg>
  )
}
