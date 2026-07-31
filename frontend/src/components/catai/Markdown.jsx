
function escapeText(s) { return s }

function renderInline(text, keyPrefix) {
  const nodes = []
  const re = /`([^`]+)`|\*\*([^*]+)\*\*/g
  let m
  let last = 0
  let idx = 0
  while ((m = re.exec(text))) {
    if (m.index > last) nodes.push(<span key={`${keyPrefix}-t${idx++}`}>{escapeText(text.slice(last, m.index))}</span>)
    if (m[1] !== undefined) {
      nodes.push(<code key={`${keyPrefix}-c${idx++}`} className="catai-inline-code">{m[1]}</code>)
    } else {
      nodes.push(<strong key={`${keyPrefix}-b${idx++}`}>{m[2]}</strong>)
    }
    last = re.lastIndex
  }
  if (last < text.length) nodes.push(<span key={`${keyPrefix}-t${idx++}`}>{escapeText(text.slice(last))}</span>)
  return nodes
}

export function Markdown({ text }) {
  if (!text) return null
  const lines = String(text).split('\n')
  const blocks = []
  let i = 0
  let key = 0

  while (i < lines.length) {
    const line = lines[i]

    if (/^```/.test(line.trim())) {
      const buf = []
      i++
      while (i < lines.length && !/^```/.test(lines[i].trim())) { buf.push(lines[i]); i++ }
      i++
      blocks.push(<pre key={key++} className="catai-code-block"><code>{buf.join('\n')}</code></pre>)
      continue
    }

    if (/^\s*[-*]\s+/.test(line)) {
      const items = []
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*]\s+/, ''))
        i++
      }
      blocks.push(
        <ul key={key++} className="catai-list">
          {items.map((it, n) => <li key={n}>{renderInline(it, `li${key}-${n}`)}</li>)}
        </ul>,
      )
      continue
    }

    if (!line.trim()) { i++; continue }

    const buf = [line]
    i++
    while (i < lines.length && lines[i].trim() && !/^\s*[-*]\s+/.test(lines[i]) && !/^```/.test(lines[i].trim())) {
      buf.push(lines[i]); i++
    }
    const para = buf.join(' ')
    blocks.push(<p key={key++} className="catai-paragraph">{renderInline(para, `p${key}`)}</p>)
  }

  return <div className="catai-markdown">{blocks}</div>
}
