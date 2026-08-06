import { useCallback, useEffect, useRef, useState } from 'react'
import { Check, X, Info } from 'lucide-react'

export function Toggle({ on, onChange, disabled }) {
  return (
    <button
      type="button" role="switch" aria-checked={on} disabled={disabled}
      onClick={(e) => { e.stopPropagation(); if (!disabled) onChange(!on) }}
      className={`toggle-track ${on ? 'on' : 'off'} ${disabled ? 'opacity-40 cursor-not-allowed' : ''}`}
      style={{ flexShrink: 0 }}
    >
      <span className="toggle-thumb" />
    </button>
  )
}

export function Badge({ children, color = 'blue' }) {
  return <span className={`badge badge-${color}`}>{children}</span>
}

export function Card({ children, className = '', hover = false, delay = 0 }) {
  return (
    <div
      className={`card ${hover ? 'card-glow' : ''} ${className}`}
      style={delay ? { animationDelay: `${delay}ms` } : undefined}
    >
      {children}
    </div>
  )
}

function motionScale() {
  if (typeof window === 'undefined') return 1
  const mode = document.documentElement.dataset.motion
  if (mode === 'off') return 0
  if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches && !mode) return 0
  return { reduced: 0.6, minimal: 0.3, full: 1 }[mode] ?? 1
}

export function AnimatedNumber({ value, duration = 800, prefix = '', suffix = '' }) {
  const ref = useRef(null)
  const rafRef = useRef(null)

  const target = typeof value === 'number'
    ? value
    : parseFloat(String(value).replace(/[^0-9.-]/g, '')) || 0
  const isFloat = !Number.isInteger(target)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const format = n => prefix + (isFloat ? n.toFixed(2) : Math.round(n)).toLocaleString() + suffix

    const scale = motionScale()
    if (scale === 0 || duration <= 0) { el.textContent = format(target); return }

    const total = duration * scale
    const start = performance.now()
    const from = 0

    const step = now => {
      const progress = Math.min((now - start) / total, 1)
      const eased = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress)
      el.textContent = format(from + (target - from) * eased)
      if (progress < 1) rafRef.current = requestAnimationFrame(step)
    }
    rafRef.current = requestAnimationFrame(step)
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current) }
  }, [target, isFloat, duration, prefix, suffix])

  return <span className="count-up" ref={ref}>{prefix}{(isFloat ? target.toFixed(2) : target).toLocaleString()}{suffix}</span>
}

export function StatCard({ label, value, sub, icon: Icon, color = 'accent', delta, deltaPositive, animate = true }) {
  const deltaIsGood = deltaPositive ? delta >= 0 : delta < 0
  return (
    <div className={`card card-glow stat-card ${color} animate-card-in`}>
      <div className="flex items-start justify-between mb-4">
        <span className="text-xs text-cat-sub font-medium uppercase tracking-wide">{label}</span>
        {Icon && <span className={`stat-icon ${color}`}><Icon size={16} /></span>}
      </div>
      <div className="stat-number">
        {animate && typeof value === 'number'
          ? <AnimatedNumber value={value} />
          : value}
      </div>
      <div className="flex items-center gap-2 mt-1.5 min-h-[16px]">
        {sub && <span className="text-xs text-cat-sub">{sub}</span>}
        {delta !== undefined && (
          <span className={`text-[11px] font-medium ${deltaIsGood ? 'text-cat-green' : 'text-cat-red'}`}>
            {delta >= 0 ? '↑' : '↓'} {Math.abs(delta)}%
          </span>
        )}
      </div>
    </div>
  )
}

export function SectionTitle({ children }) {
  return <div className="section-title">{children}</div>
}

export function Divider() {
  return <div className="divider" />
}

export function Skeleton({ className = '', h = 'h-8' }) {
  return <div className={`shimmer rounded-lg ${h} ${className}`} />
}

export function EmptyState({ icon: Icon, title, desc, action }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center animate-fade-in">
      {Icon && <Icon size={32} className="text-cat-sub mb-3 opacity-40 animate-float" aria-hidden="true" />}
      <div className="text-sm font-medium text-cat-text mb-1">{title}</div>
      {desc && <div className="text-xs text-cat-sub max-w-xs">{desc}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function Input({ label, ...props }) {
  return (
    <div className="flex flex-col gap-1.5">
      {label && <label className="text-xs text-cat-sub font-medium">{label}</label>}
      <input className="input" {...props} />
    </div>
  )
}

export function Select({ label, children, ...props }) {
  return (
    <div className="flex flex-col gap-1.5">
      {label && <label className="text-xs text-cat-sub font-medium">{label}</label>}
      <select className="input select" {...props}>{children}</select>
    </div>
  )
}

export function ActionBar({ children }) {
  return (
    <div className="flex items-center gap-2 pt-4 border-t border-cat-border mt-4 animate-fade-in">
      {children}
    </div>
  )
}

export function StatusPill({ mode }) {
  if (mode === 'On') return <span className="badge badge-green"><span className="dot-green mr-1.5" />Blocking</span>
  if (mode === 'DetectionOnly') return <span className="badge badge-orange"><span style={{ display:'inline-block',width:6,height:6,borderRadius:'50%',background:'#f59e0b',marginRight:6 }} />Detection Only</span>
  return <span className="badge badge-muted">Off</span>
}

const TOAST_DWELL_MS = 4500
const TOAST_EXIT_MS = 220

export function Toast({ message, type = 'success', onClose }) {
  const [leaving, setLeaving] = useState(false)
  const [paused, setPaused] = useState(false)
  const timers = useRef([])
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  const colors = {
    success: 'border-green-500/30 text-green-400',
    error:   'border-red-500/30 text-red-400',
    info:    'border-blue-500/30 text-blue-400',
  }
  const Icon = { success: Check, error: X, info: Info }[type] || Info

  const close = useCallback(() => {
    setLeaving(true)
    timers.current.push(setTimeout(() => onCloseRef.current?.(), TOAST_EXIT_MS))
  }, [])

  useEffect(() => {
    if (paused) return
    const t = setTimeout(close, TOAST_DWELL_MS)
    timers.current.push(t)
    return () => clearTimeout(t)
  }, [paused, close])

  useEffect(() => () => { timers.current.forEach(clearTimeout) }, [])

  return (
    <div
      role={type === 'error' ? 'alert' : 'status'}
      aria-live={type === 'error' ? 'assertive' : 'polite'}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocusCapture={() => setPaused(true)}
      onBlurCapture={() => setPaused(false)}
      className={`fixed bottom-6 right-6 z-50 flex items-center gap-3 bg-cat-card border ${colors[type]} px-4 py-3 rounded-xl text-sm shadow-2xl ${leaving ? 'toast-exit' : 'toast-enter'}`}
      style={{ backdropFilter: 'blur(12px)' }}
    >
      <Icon size={15} className="opacity-80 flex-shrink-0" aria-hidden="true" />
      <span>{message}</span>
      <button onClick={close} className="text-cat-sub hover:text-cat-text ml-2 transition-colors" aria-label="Dismiss notification">
        <X size={13} />
      </button>
    </div>
  )
}

export function ProgressBar({ value = 0, max = 100, color = 'var(--cat-accent)', label }) {
  const safeMax = max > 0 ? max : 100
  const pct = Math.min(100, Math.max(0, (value / safeMax) * 100))
  return (
    <div
      className="progress-bar"
      role="progressbar"
      aria-valuenow={Math.round(value)}
      aria-valuemin={0}
      aria-valuemax={safeMax}
      aria-label={label}
    >
      <div className="progress-bar-fill" style={{ width: `${pct}%`, background: color }} />
    </div>
  )
}

export function Spinner({ size = 16, label = 'Loading' }) {
  return (
    <svg className="spin" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-label={label}>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" strokeOpacity="0.25" />
      <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  )
}
