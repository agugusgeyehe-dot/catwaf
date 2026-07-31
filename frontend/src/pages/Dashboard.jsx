import React, { useEffect, useState, useCallback, lazy, Suspense } from 'react'
import { Shield, Activity, AlertTriangle, Zap, TrendingUp, Ban, Clock, ShieldCheck, ShieldAlert, ShieldX, MapPin } from 'lucide-react'
import { StatCard, SectionTitle, Skeleton, EmptyState } from '../components/ui.jsx'
import { api } from '../utils/api.js'
import { usePreferences } from '../utils/preferences.jsx'

const TrafficAreaChart = lazy(() => import('../components/DashboardCharts.jsx').then(m => ({ default: m.TrafficAreaChart })))
const AttackTypesPie   = lazy(() => import('../components/DashboardCharts.jsx').then(m => ({ default: m.AttackTypesPie })))

const ChartFallback = () => <div className="shimmer" style={{ height: 180, borderRadius: 8 }} />

const REFRESH_MS = 15000

const PROTECTION_META = {
  healthy:   { label: 'Protected', color: '#22d3a0', icon: ShieldCheck },
  degraded:  { label: 'At Risk',   color: '#f59e0b', icon: ShieldAlert },
  unhealthy: { label: 'Degraded',  color: '#f25c5c', icon: ShieldX },
  unknown:   { label: 'Checking…', color: '#7c8db0', icon: Shield },
}

export default function Dashboard() {
  const { prefs } = usePreferences()
  const [stats, setStats] = useState(null)
  const [chart, setChart] = useState([])
  const [attacks, setAttacks] = useState([])
  const [live, setLive] = useState([])
  const [topIps, setTopIps] = useState([])
  const [health, setHealth] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback((signal) => {
    setLoading(true)
    api.get('/waf/health').then(h => { if (!signal?.aborted) setHealth(h) }).catch(() => { if (!signal?.aborted) setHealth(null) })
    return Promise.all([
      api.get('/stats'),
      api.get('/traffic/chart'),
      api.get('/traffic/attacks'),
      api.get('/traffic/live'),
      api.get('/traffic/top-ips'),
    ]).then(([s, c, a, l, ips]) => {
      if (signal?.aborted) return
      setStats(s); setChart(c); setAttacks(a); setLive(l.slice(0, 8)); setTopIps(ips)
      setError(null)
    }).catch(e => { if (!signal?.aborted) setError(e.message || 'Failed to load dashboard data') })
      .finally(() => { if (!signal?.aborted) setLoading(false) })
  }, [])

  useEffect(() => {
    const ac = new AbortController()
    load(ac.signal)
    let timer
    const tick = () => { if (document.visibilityState === 'visible') load(ac.signal) }
    const start = () => { clearInterval(timer); timer = setInterval(tick, REFRESH_MS) }
    const onVisibility = () => {
      if (document.visibilityState === 'visible') { load(ac.signal); start() }
      else clearInterval(timer)
    }
    start()
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      ac.abort()
      clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [load])

  if (error && !stats) {
    return (
      <div className="p-6">
        <EmptyState icon={AlertTriangle} title="Could not load the dashboard" desc={error} />
      </div>
    )
  }

  if (!stats) return (
    <div className="p-6 grid grid-cols-2 lg:grid-cols-4 gap-4 animate-fade-in" aria-busy="true" aria-label="Loading dashboard">
      {Array(8).fill(0).map((_, i) => <Skeleton key={i} className="h-24" />)}
    </div>
  )

  const plColor = { 1: 'text-cat-green', 2: 'text-cat-accent', 3: 'text-cat-orange', 4: 'text-cat-red' }
  const prot = PROTECTION_META[health?.status] || PROTECTION_META.unknown
  const ProtIcon = prot.icon

  return (
    <div className="p-6 space-y-5 page-enter">
      <div className="card animate-slide-up" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{
          width: 42, height: 42, borderRadius: 12, flexShrink: 0,
          background: `color-mix(in srgb, ${prot.color} 16%, transparent)`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <ProtIcon size={22} color={prot.color} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--cat-text)' }}>{prot.label}</div>
          <div style={{ fontSize: 11.5, color: 'var(--cat-sub)', marginTop: 1 }}>
            {health ? `${health.counts.healthy}/${health.checks.length} components healthy` : 'Checking system health…'}
          </div>
        </div>
        <div className="hide-mobile" style={{ display: 'flex', gap: 6 }}>
          {(health?.checks || []).slice(0, 5).map(c => (
            <span key={c.name} title={`${c.name}: ${c.detail}`} style={{
              width: 7, height: 7, borderRadius: '50%',
              background: c.status === 'healthy' ? '#22d3a0' : c.status === 'degraded' ? '#f59e0b' : '#f25c5c',
            }} />
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Requests" value={stats.total_requests} icon={Activity} color="accent" sub="Last 24 hours" />
        <StatCard label="Blocked" value={stats.blocked_requests} icon={Ban} color="red" sub="Last 24 hours" />
        <StatCard label="Active Rules" value={stats.active_rules} icon={Shield} color="purple"
          sub={stats.crs_version ? `CRS v${stats.crs_version}` : 'OWASP CRS'} />
        <StatCard label="Requests / min" value={stats.requests_per_min} icon={Zap} color="green" sub="Updating live" />
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Avg Anomaly Score" value={stats.avg_anomaly_score ?? '—'} icon={TrendingUp} color="orange" />
        <StatCard label="False Positives Today" value={stats.false_positives_today} icon={AlertTriangle} color="orange" />
        <StatCard label="Blocked IPs" value={stats.blocked_ips} icon={Ban} color="red" />
        <StatCard label="Uptime" value={`${stats.uptime_hours}h`} icon={Clock} color="green" />
      </div>

      <div className="card flex items-center justify-between animate-slide-up">
        <div className="flex items-center gap-4">
          <div className="text-3xl font-bold text-cat-text">PL{stats.paranoia_level}</div>
          <div>
            <div className="text-sm font-medium text-cat-text">Paranoia Level</div>
            <div className="text-xs text-cat-sub mt-0.5">
              {['Minimal false positives', 'Increased detection', 'Strict — requires tuning', 'Maximum strictness'][stats.paranoia_level - 1]}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-6 text-center">
          {[1,2,3,4].map(l => {
            const current = l === stats.paranoia_level
            return (
              <div
                key={l}
                className={`text-center ${current ? plColor[l] : 'text-cat-sub'}`}
                style={{ opacity: current ? 1 : 0.35, transition: 'opacity var(--dur-2) ease' }}
                aria-current={current ? 'true' : undefined}
              >
                <div className="text-lg font-semibold">PL{l}</div>
                <div className="text-[10px]">
                  {['Low','Med','High','Max'][l-1]}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 card animate-slide-up">
          <SectionTitle>Traffic — Last 24 hours</SectionTitle>
          {chart.every(c => c.total === 0) ? (
            <EmptyState icon={Activity} title="No traffic yet" desc="Once requests start flowing through CatWAF, they'll show up here." />
          ) : (
            <Suspense fallback={<ChartFallback />}>
              <TrafficAreaChart data={chart} />
            </Suspense>
          )}
        </div>

        {prefs.dashboardAttackTypes === 'on' && (
          <div className="card animate-slide-up">
            <SectionTitle>Attack Types</SectionTitle>
            {attacks.every(a => a.count === 0) ? (
              <EmptyState icon={Shield} title="No attacks detected" desc="CatWAF hasn't blocked any categorized attacks yet." />
            ) : (
              <>
                <Suspense fallback={<ChartFallback />}>
                  <AttackTypesPie data={attacks} />
                </Suspense>
                <div className="space-y-1.5 mt-2">
                  {attacks.filter(a => a.count > 0).slice(0, 4).map(a => (
                    <div key={a.type} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full" style={{ background: a.color }} />
                        <span className="text-cat-sub">{a.type}</span>
                      </div>
                      <span className="text-cat-text font-medium">{a.count}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {(prefs.dashboardRecentRequests === 'on' || prefs.dashboardTopTargets === 'on') && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {prefs.dashboardRecentRequests === 'on' && (
            <div className={`card animate-slide-up ${prefs.dashboardTopTargets === 'on' ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
              <SectionTitle>Recent Requests</SectionTitle>
              {live.length === 0 ? (
                <EmptyState icon={Activity} title="No requests logged yet" desc="Recent traffic will appear here as it's processed." />
              ) : (
                <div className="mobile-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th><th>IP</th><th>Method</th><th>URI</th>
                      <th>Score</th><th>Action</th><th>Attack</th>
                    </tr>
                  </thead>
                  <tbody>
                    {live.map(tx => (
                      <tr key={tx.id}>
                        <td className="text-cat-sub mono">{new Date(tx.timestamp).toLocaleTimeString()}</td>
                        <td className="mono text-cat-text">{tx.ip}{tx.country ? ` (${tx.country})` : ''}</td>
                        <td><span className="badge badge-blue">{tx.method}</span></td>
                        <td className="mono text-cat-sub max-w-[160px] truncate" title={tx.uri}>{tx.uri}</td>
                        <td>
                          <span className={`mono font-medium ${tx.score > 10 ? 'text-cat-red' : tx.score > 4 ? 'text-cat-orange' : 'text-cat-green'}`}>
                            {tx.score ?? '—'}
                          </span>
                        </td>
                        <td>
                          <span className={`badge ${tx.action === 'block' ? 'badge-red' : 'badge-green'}`}>
                            {tx.action}
                          </span>
                        </td>
                        <td className="text-xs text-cat-sub">{tx.attack_type || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                </div>
              )}
            </div>
          )}

          {prefs.dashboardTopTargets === 'on' && (
            <div className={`card animate-slide-up ${prefs.dashboardRecentRequests === 'on' ? '' : 'lg:col-span-3'}`}>
              <SectionTitle>Top Targeted IPs</SectionTitle>
              {topIps.length === 0 ? (
                <EmptyState icon={MapPin} title="No blocked IPs yet" desc="Top attacking source IPs will appear here." />
              ) : (
                <div className="space-y-2">
                  {topIps.slice(0, 8).map(ip => (
                    <div key={ip.ip} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="mono text-cat-text truncate" title={ip.city ? `${ip.ip} — ${ip.city}` : ip.ip}>{ip.ip}</span>
                        {ip.country && <span className="badge badge-muted" style={{ flexShrink: 0 }}>{ip.country}</span>}
                      </div>
                      <span className="text-cat-sub font-medium flex-shrink-0">{ip.blocked}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
