
import { useEffect, useRef, useState } from 'react'

const ICON = '/assets/logo/catwaf-icon-256.png'

const STATE_CLASS = {
  idle: 'catai-mascot-idle',
  thinking: 'catai-mascot-thinking',
  talking: 'catai-mascot-talking',
  acted: 'catai-mascot-acted',
  error: 'catai-mascot-error',
}

export function Mascot({ state = 'idle', size = 40 }) {
  return (
    <div className={`catai-mascot ${STATE_CLASS[state] || STATE_CLASS.idle}`} style={{ width: size, height: size }}>
      <img src={ICON} alt="CatAI" width={size} height={size} draggable={false} />
    </div>
  )
}

export function ActivityTrail({ entries, done }) {
  const [collapsed, setCollapsed] = useState(false)
  const timerRef = useRef(null)

  useEffect(() => {
    if (done && entries.length) {
      timerRef.current = setTimeout(() => setCollapsed(true), 900)
      return () => clearTimeout(timerRef.current)
    }
    setCollapsed(false)
  }, [done, entries.length])

  if (!entries.length || collapsed) return null

  return (
    <div className="catai-trail">
      {entries.map((e, i) => (
        <div key={i} className="catai-trail-item" style={{ animationDelay: `${i * 30}ms` }}>
          <span className="catai-trail-dot" />{e}
        </div>
      ))}
    </div>
  )
}
