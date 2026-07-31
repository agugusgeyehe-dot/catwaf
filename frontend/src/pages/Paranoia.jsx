import React, { useEffect, useState } from 'react'
import { AlertTriangle, Shield, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react'
import { Card, SectionTitle, Toggle, ActionBar, Toast } from '../components/ui.jsx'
import { api } from '../utils/api.js'

const PL_INFO = [
  {
    level: 1,
    label: 'Baseline',
    icon: ShieldCheck,
    color: 'cat-green',
    hex: '#22d3a0',
    desc: 'Minimal false positives. Suitable for most PHP applications running in production. Covers the most common and critical attack categories.',
    rules: 185,
    fp_risk: 'Very Low',
    use_for: 'Production PHP apps, WordPress, Laravel, Joomla where uptime matters most.',
    what_enabled: ['SQL Injection basics', 'XSS basics', 'LFI detection', 'Protocol enforcement', 'Scanner detection'],
  },
  {
    level: 2,
    label: 'Increased',
    icon: Shield,
    color: 'cat-accent',
    hex: '#4f8ef7',
    desc: 'Additional rules active on top of PL1. Detects more attack variants at the cost of occasional false positives for complex PHP input.',
    rules: 243,
    fp_risk: 'Low–Medium',
    use_for: 'Internal apps, staging environments, APIs with controlled clients.',
    what_enabled: ['Advanced SQLi payloads', 'Obfuscated XSS', 'PHP-specific injection', 'HTTP smuggling variants', 'More RCE patterns'],
  },
  {
    level: 3,
    label: 'Strict',
    icon: ShieldAlert,
    color: 'cat-orange',
    hex: '#f59e0b',
    desc: 'Aggressive rule set for specialized attacks. Likely to block certain legitimate PHP form submissions. Requires rule exclusions for apps using complex inputs.',
    rules: 318,
    fp_risk: 'Medium–High',
    use_for: 'High-value targets, fintech, login gateways. Expect tuning work.',
    what_enabled: ['Deep SQL detection', 'Unicode XSS bypasses', 'Advanced shell injection', 'Complex path traversal', 'Java/Node attack patterns'],
  },
  {
    level: 4,
    label: 'Maximum',
    icon: ShieldX,
    color: 'cat-red',
    hex: '#f25c5c',
    desc: 'Near-complete attack coverage. Will almost certainly break PHP applications without heavy exclusion tuning. Use in conjunction with Detection-Only mode first.',
    rules: 369,
    fp_risk: 'Very High',
    use_for: 'Critical infrastructure, admin portals. Weeks of tuning expected.',
    what_enabled: ['All above patterns', 'Aggressive header inspection', 'Base64 and encoding tricks', 'Multi-vector combinations', 'Every CRS rule active'],
  },
]

export default function ParanoiaPage() {
  const [data, setData] = useState(null)
  const [blockingPL, setBlockingPL] = useState(1)
  const [executingPL, setExecutingPL] = useState(2)
  const [saving, setSaving] = useState(false)
  const [toast, setToast] = useState(null)

  useEffect(() => {
    api.get('/waf/paranoia').then(d => {
      setData(d)
      setBlockingPL(d.blocking_paranoia_level)
      setExecutingPL(d.executing_paranoia_level)
    })
  }, [])

  const save = async () => {
    setSaving(true)
    try {
      await api.post('/waf/paranoia', { level: blockingPL, executing_level: executingPL })
      setToast({ message: `Paranoia level set to PL${blockingPL}`, type: 'success' })
    } catch (e) {
      setToast({ message: e.message, type: 'error' })
    } finally {
      setSaving(false)
    }
  }

  const fpColors = { 'Very Low': 'badge-green', 'Low–Medium': 'badge-blue', 'Medium–High': 'badge-orange', 'Very High': 'badge-red' }
  const activeInfo = PL_INFO[blockingPL - 1]

  return (
    <div className="p-6 space-y-5 page-enter">
      {toast && <Toast {...toast} onClose={() => setToast(null)} />}

      <div className="card animate-slide-up">
        <SectionTitle>Blocking Paranoia Level</SectionTitle>
        <div className="flex items-center gap-4 mb-4">
          <span className="text-5xl font-bold" style={{ color: activeInfo.hex }}>PL{blockingPL}</span>
          <div>
            <div className="text-sm font-semibold text-cat-text">{activeInfo.label}</div>
            <div className="text-xs text-cat-sub mt-0.5">{activeInfo.rules} rules active</div>
          </div>
        </div>

        <input
          type="range" min="1" max="4" value={blockingPL}
          onChange={e => setBlockingPL(+e.target.value)}
          className="pl-slider w-full mb-4"
        />

        <div className="flex justify-between text-[10px] text-cat-sub mb-6">
          {PL_INFO.map(p => (
            <span key={p.level} className={blockingPL === p.level ? 'text-cat-text font-semibold' : ''}>
              PL{p.level} — {p.label}
            </span>
          ))}
        </div>

        <div className="text-sm text-cat-sub">{activeInfo.desc}</div>

        <div className="mt-4 grid grid-cols-2 gap-4">
          <div>
            <div className="text-xs text-cat-sub mb-1">False Positive Risk</div>
            <span className={fpColors[activeInfo.fp_risk]}>{activeInfo.fp_risk}</span>
          </div>
          <div>
            <div className="text-xs text-cat-sub mb-1">Best For</div>
            <div className="text-xs text-cat-text">{activeInfo.use_for}</div>
          </div>
        </div>

        <div className="mt-5 pt-4 border-t border-cat-border">
          <div className="flex items-center justify-between mb-2">
            <div>
              <div className="text-sm font-medium text-cat-text">Executing Paranoia Level</div>
              <div className="text-xs text-cat-sub mt-0.5">
                Run rules from a higher PL in log-only mode without blocking. PL{executingPL} active.
              </div>
            </div>
            <span className="badge-purple">PL{executingPL}</span>
          </div>
          <input
            type="range" min={blockingPL} max="4" value={executingPL}
            onChange={e => setExecutingPL(+e.target.value)}
            className="pl-slider w-full"
          />
          <div className="flex justify-between text-[10px] text-cat-sub mt-1">
            <span>= Blocking PL (PL{blockingPL})</span>
            <span>PL4 (max)</span>
          </div>
        </div>

        <ActionBar>
          <button className="btn-primary btn" onClick={save} disabled={saving}>
            {saving ? 'Saving…' : 'Apply Paranoia Levels'}
          </button>
          <span className="text-xs text-cat-sub">Requires WAF config reload to take effect.</span>
        </ActionBar>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {PL_INFO.map(p => {
          const Icon = p.icon
          const active = blockingPL === p.level
          return (
            <button
              key={p.level}
              onClick={() => { setBlockingPL(p.level); if (executingPL < p.level) setExecutingPL(p.level) }}
              className={`card text-left transition-all duration-200 hover:border-cat-accent/40 ${active ? 'border-cat-accent/60' : ''}`}
              style={active ? { boxShadow: `0 0 20px ${p.hex}18` } : {}}
            >
              <div className="flex items-center justify-between mb-3">
                <Icon size={18} style={{ color: p.hex }} />
                <span className="font-mono text-xs text-cat-sub">PL{p.level}</span>
              </div>
              <div className="text-sm font-semibold text-cat-text mb-1">{p.label}</div>
              <div className="text-xs text-cat-sub mb-3">{p.rules} rules</div>
              <div className="space-y-1">
                {p.what_enabled.slice(0, 3).map(w => (
                  <div key={w} className="text-[10px] text-cat-sub flex items-center gap-1.5">
                    <span className="w-1 h-1 rounded-full" style={{ background: p.hex }} />
                    {w}
                  </div>
                ))}
              </div>
              {active && (
                <div className="mt-3 pt-2 border-t border-cat-border">
                  <span className="badge-blue text-[10px]">Active</span>
                </div>
              )}
            </button>
          )
        })}
      </div>

      <div className="card bg-cat-accent/5 border-cat-accent/20 animate-slide-up">
        <div className="flex gap-3">
          <AlertTriangle size={16} className="text-cat-orange mt-0.5 shrink-0" />
          <div className="text-xs text-cat-sub leading-relaxed">
            <strong className="text-cat-text">Paranoia Level ≠ Anomaly Threshold.</strong> The PL controls <em>how many rules are active</em>.
            The anomaly threshold controls <em>how high a score triggers a block</em>.
            At PL3–PL4, you almost certainly need to add rule exclusions for PHP apps using rich text editors,
            file uploads, JSON APIs, or admin panels. Configure exclusions under Rules → Rule Exclusions.
          </div>
        </div>
      </div>
    </div>
  )
}
