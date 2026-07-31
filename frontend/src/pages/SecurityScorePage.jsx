import React, { useEffect, useState } from 'react'
import {
  ShieldCheck, AlertTriangle, XCircle, CheckCircle2, HelpCircle,
  RefreshCw, ChevronDown, ChevronRight,
} from 'lucide-react'
import { Card, SectionTitle, Badge, Skeleton, EmptyState } from '../components/ui.jsx'
import { api } from '../utils/api.js'

const STATUS_META = {
  pass:    { icon: CheckCircle2,  color: 'text-cat-green',  badge: 'green',  label: 'Pass' },
  warn:    { icon: AlertTriangle, color: 'text-cat-orange', badge: 'orange', label: 'Warning' },
  fail:    { icon: XCircle,       color: 'text-cat-red',    badge: 'red',    label: 'Fail' },
  unknown: { icon: HelpCircle,    color: 'text-cat-sub',    badge: 'muted',  label: 'Unknown' },
}

function gradeColor(grade) {
  if (grade === 'A') return 'text-cat-green'
  if (grade === 'B') return 'text-cat-accent'
  if (grade === 'C') return 'text-cat-orange'
  return 'text-cat-red'
}

function ScoreRing({ score, grade }) {
  const r = 54
  const circumference = 2 * Math.PI * r
  const offset = circumference * (1 - score / 100)
  const ringColor = score >= 90 ? '#22d3a0' : score >= 75 ? 'var(--cat-accent)' : score >= 60 ? '#f59e0b' : '#f25c5c'
  return (
    <div className="relative w-36 h-36 flex-shrink-0">
      <svg width="144" height="144" viewBox="0 0 144 144" className="-rotate-90">
        <circle cx="72" cy="72" r={r} fill="none" stroke="var(--cat-muted)" strokeWidth="10" />
        <circle
          cx="72" cy="72" r={r} fill="none" stroke={ringColor} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.16,1,0.3,1)' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-3xl font-bold text-cat-text leading-none">{score}</div>
        <div className={`text-sm font-semibold mt-1 ${gradeColor(grade)}`}>Grade {grade}</div>
      </div>
    </div>
  )
}

function CheckRow({ check }) {
  const meta = STATUS_META[check.status]
  const Icon = meta.icon
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-cat-muted/40 last:border-b-0">
      <Icon size={16} className={`${meta.color} mt-0.5 flex-shrink-0`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium text-cat-text">{check.label}</span>
          <Badge color={meta.badge}>{meta.label}</Badge>
        </div>
        <div className="text-xs text-cat-sub mt-0.5">{check.detail}</div>
      </div>
    </div>
  )
}

function CategorySection({ category, checks, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen)
  const passCount = checks.filter(c => c.status === 'pass').length
  return (
    <Card className="animate-slide-up">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between text-left"
      >
        <div className="flex items-center gap-2">
          {open ? <ChevronDown size={16} className="text-cat-sub" /> : <ChevronRight size={16} className="text-cat-sub" />}
          <span className="text-sm font-semibold text-cat-text">{category}</span>
        </div>
        <span className="text-xs text-cat-sub">{passCount}/{checks.length} passing</span>
      </button>
      {open && <div className="mt-2">{checks.map(c => <CheckRow key={c.id} check={c} />)}</div>}
    </Card>
  )
}

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 }
const SEVERITY_BADGE = { high: 'red', medium: 'orange', low: 'muted' }

export default function SecurityScorePage() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [refreshing, setRefreshing] = useState(false)

  function load() {
    setRefreshing(true)
    return api.get('/security/score')
      .then(d => { setData(d); setError(null) })
      .catch(() => setError('Could not load the security score — is the backend running?'))
      .finally(() => setRefreshing(false))
  }

  useEffect(() => { load() }, [])

  if (error) {
    return (
      <div className="p-6 page-enter">
        <EmptyState icon={AlertTriangle} title="Couldn't load security score" desc={error} />
      </div>
    )
  }

  if (!data) {
    return (
      <div className="p-6 space-y-4 page-enter">
        <Skeleton className="h-40" />
        <Skeleton className="h-64" />
        <Skeleton className="h-64" />
      </div>
    )
  }

  const recommendations = [...data.recommendations].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])

  return (
    <div className="p-6 space-y-5 page-enter">
      <Card className="animate-card-in flex items-center gap-6 flex-wrap">
        <ScoreRing score={data.score} grade={data.grade} />
        <div className="flex-1 min-w-[220px]">
          <SectionTitle>Overall Security Score</SectionTitle>
          <p className="text-xs text-cat-sub mt-1 max-w-md">
            Computed live from CatWAF's actual configuration — not a demo number.
            Checks CatWAF genuinely can't verify yet (like origin TLS without a
            Cloudflare connection) are shown as <span className="text-cat-sub font-medium">Unknown</span>, not
            guessed.
          </p>
          <div className="flex items-center gap-4 mt-3 text-xs">
            <span className="flex items-center gap-1.5 text-cat-green"><CheckCircle2 size={13} /> {data.passing} passing</span>
            <span className="flex items-center gap-1.5 text-cat-orange"><AlertTriangle size={13} /> {data.warnings} to review</span>
            {data.critical_failures > 0 && (
              <span className="flex items-center gap-1.5 text-cat-red"><XCircle size={13} /> {data.critical_failures} critical</span>
            )}
          </div>
        </div>
        <button
          onClick={load}
          disabled={refreshing}
          className="btn-ghost flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg self-start"
        >
          <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} /> Recheck
        </button>
      </Card>

      {recommendations.length > 0 && (
        <Card className="animate-slide-up">
          <SectionTitle>Recommendations</SectionTitle>
          <div className="mt-2 space-y-2">
            {recommendations.map(r => (
              <div key={r.id} className="flex items-start gap-3 py-1.5">
                <Badge color={SEVERITY_BADGE[r.severity]}>{r.severity}</Badge>
                <div className="text-sm text-cat-text flex-1">
                  <span className="font-medium">{r.label}:</span>{' '}
                  <span className="text-cat-sub">{r.recommendation}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      <div className="space-y-3">
        {Object.entries(data.by_category).map(([category, checks], i) => (
          <CategorySection key={category} category={category} checks={checks} defaultOpen={i < 2} />
        ))}
      </div>

      <div className="text-[11px] text-cat-sub text-center pt-1">
        Last computed {new Date(data.computed_at).toLocaleString()}
      </div>
    </div>
  )
}
