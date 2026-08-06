import { useEffect, useState } from 'react'
import { api } from '../utils/api.js'
import SettingsForm from '../components/SettingsForm.jsx'
import { Toast, Badge } from '../components/ui.jsx'
import { GroupsPage, PageHeader, useToast, Caveat } from '../components/pageKit.jsx'
import {
  ShieldAlert, Lock, FileCode, Server, Network, KeyRound,
  AlertTriangle, CheckCircle, Package,
} from 'lucide-react'

export function AccessControlPage() {
  return (
    <GroupsPage
      icon={ShieldAlert} color="orange"
      title="Access control"
      subtitle="Host matching, method allowlist, deny behaviour and protocol limits"
      groups={['access', 'basic_auth', 'connections']}
    >
      <Caveat tone="info" title="Two settings here close problems CatWAF's own docs describe">
        <p>
          <strong>Reject unknown Host/SNI</strong> is the mechanical fix for the origin-exposure problem — until now CatWAF could
          explain the risk but had no switch to close it. <strong>Paths exempt from WAF inspection</strong> is the safe answer to a
          webhook or upload endpoint that a CRS rule keeps flagging, instead of weakening protection sitewide.
        </p>
      </Caveat>
    </GroupsPage>
  )
}

export function HeadersPage() {
  const [preview, setPreview] = useState({ robots: null, security: null })
  useEffect(() => {
    api.get('/wellknown/robots.txt').then(r => setPreview(p => ({ ...p, robots: r }))).catch(() => {})
    api.get('/wellknown/security.txt').then(r => setPreview(p => ({ ...p, security: r }))).catch(() => {})
  }, [])

  return (
    <GroupsPage
      icon={FileCode} color="purple"
      title="Content &amp; headers"
      subtitle="Response headers, CORS, cookies, compression, caching and generated files"
      groups={['headers', 'cors', 'cookies', 'compression', 'client_cache', 'html_injection', 'robots', 'security_txt', 'error_pages', 'redirects']}
    >
      {(preview.robots || preview.security) && (
        <div className="card">
          <div className="section-title">Generated files</div>
          <p className="text-xs text-cat-sub mb-3">Exactly what visitors and crawlers receive — generated from the settings below, not a sample.</p>
          {preview.robots && (
            <div className="mb-3">
              <div className="text-[11px] text-cat-sub uppercase tracking-wide mb-1">/robots.txt</div>
              <pre style={{ margin: 0, padding: 10, fontSize: 11, background: 'var(--cat-bg)', border: '1px solid var(--cat-border)', borderRadius: 8, maxHeight: 200, overflow: 'auto' }}>{preview.robots}</pre>
            </div>
          )}
          {preview.security && (
            <div>
              <div className="text-[11px] text-cat-sub uppercase tracking-wide mb-1">/.well-known/security.txt</div>
              {preview.security.errors?.length > 0 && (
                <div className="text-[11px] mb-1.5" style={{ color: '#fbbf24' }}>
                  {preview.security.errors.map((e, i) => <div key={i}>{e}</div>)}
                </div>
              )}
              <pre style={{ margin: 0, padding: 10, fontSize: 11, background: 'var(--cat-bg)', border: '1px solid var(--cat-border)', borderRadius: 8, maxHeight: 200, overflow: 'auto' }}>
                {preview.security.body || 'Not being served.'}
              </pre>
            </div>
          )}
        </div>
      )}
    </GroupsPage>
  )
}

export function TlsPage() {
  const [status, setStatus] = useState(null)
  const [check, setCheck] = useState(null)
  const [cert, setCert] = useState('')
  const [key, setKey] = useState('')
  const { toast, show, hide } = useToast()

  useEffect(() => { api.get('/tls/status').then(setStatus).catch(() => {}) }, [])

  const validate = async () => {
    try { setCheck(await api.post('/tls/validate', { certificate: cert, key: key || undefined })) }
    catch (e) { show(e.message, 'error') }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader icon={Lock} color="green" title="TLS &amp; certificates" subtitle="Certificate source, ACME behaviour, protocol strictness and client certificates" />

      {status?.advice?.length > 0 && (
        <div className="card">
          <div className="section-title">Before you apply</div>
          {status.advice.map((a, i) => (
            <div key={i} className="text-[11.5px] mb-1.5" style={{ color: a.level === 'error' ? '#f87171' : a.level === 'warn' ? '#fbbf24' : 'var(--cat-sub)' }}>
              {a.level === 'error' ? <AlertTriangle size={11} style={{ display: 'inline', verticalAlign: -1, marginRight: 5 }} /> : null}
              {a.message}
            </div>
          ))}
        </div>
      )}

      {status?.acme_storage?.certificates?.length > 0 && (
        <div className="card">
          <div className="section-title">Certificates Caddy currently holds</div>
          {status.acme_storage.certificates.map((c, i) => (
            <div key={i} className="flex items-center justify-between" style={{ padding: '7px 0', borderBottom: '1px solid var(--cat-border)' }}>
              <div>
                <div className="text-xs text-cat-text">{(c.hosts || []).join(', ') || c.file}</div>
                <div className="text-[10.5px] text-cat-sub">{c.issuer}</div>
              </div>
              <Badge color={c.days_remaining <= 14 ? 'red' : c.days_remaining <= 30 ? 'orange' : 'green'}>
                {c.days_remaining}d left
              </Badge>
            </div>
          ))}
        </div>
      )}

      <SettingsForm group="tls" onSaved={() => { show('Applied'); api.get('/tls/status').then(setStatus).catch(() => {}) }} onError={m => show(m, 'error')} />
      <SettingsForm group="mtls" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />

      <div className="card">
        <div className="section-title">Check a certificate before uploading it</div>
        <p className="text-xs text-cat-sub mb-3">
          A mismatched certificate and key does not fail at apply time — it fails when a visitor tries to connect. Paste both here first.
        </p>
        <textarea className="input" rows={4} placeholder="-----BEGIN CERTIFICATE-----" style={{ fontFamily: 'monospace', fontSize: 11 }} value={cert} onChange={e => setCert(e.target.value)} />
        <textarea className="input" rows={4} placeholder="-----BEGIN PRIVATE KEY----- (optional — checks the pair matches)" style={{ fontFamily: 'monospace', fontSize: 11, marginTop: 8 }} value={key} onChange={e => setKey(e.target.value)} />
        <button className="btn btn-sm btn-ghost" style={{ marginTop: 8 }} onClick={validate} disabled={!cert.trim()}>Check</button>
        {check && (
          <div style={{ marginTop: 10, padding: 10, borderRadius: 8, background: 'var(--cat-bg)', border: `1px solid ${check.ok ? 'rgba(74,222,128,.3)' : 'rgba(248,113,113,.3)'}` }}>
            {check.ok ? (
              <div className="text-xs space-y-1">
                <div style={{ color: '#4ade80', display: 'flex', gap: 6, alignItems: 'center' }}><CheckCircle size={13} /> Valid</div>
                <div className="text-cat-sub">Subject: {check.subject}</div>
                <div className="text-cat-sub">Hosts: {(check.hosts || []).join(', ') || '—'}</div>
                <div className="text-cat-sub">Expires: {String(check.valid_to).slice(0, 10)} ({check.days_remaining} days)</div>
                {(check.warnings || []).map((w, i) => <div key={i} style={{ color: '#fbbf24' }}>{w}</div>)}
              </div>
            ) : (
              <div className="text-xs" style={{ color: '#f87171' }}>{check.error}</div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export function ProxyPage() {
  return (
    <GroupsPage
      icon={Server} color="blue"
      title="Reverse proxy &amp; origin"
      subtitle="What sits behind the WAF, and how CatWAF talks to it"
      groups={['origin', 'proxy']}
    >
      <Caveat tone="info" title="CatWAF does not have to proxy anything">
        <p>
          Setting the origin type to <strong>static folder</strong> or <strong>PHP-FPM</strong> means CatWAF serves the site itself,
          with the WAF layer unchanged — no separate nginx or Apache just to give CatWAF something to sit in front of.
        </p>
      </Caveat>
    </GroupsPage>
  )
}

export function NetworkPage() {
  return (
    <GroupsPage
      icon={Network} color="blue"
      title="Network"
      subtitle="Client address resolution, PROXY protocol and the protected site's hostnames"
      groups={['real_ip', 'sites']}
    >
      <Caveat tone="info" title="Every IP-based feature depends on this page">
        <p>
          Rate limiting, the IP/ASN/rDNS lists, geo blocking, behavioural banning and the challenge gate are only ever as accurate
          as the address CatWAF reads. Behind Cloudflare, a load balancer or another reverse proxy, that address is the proxy's
          unless it is configured here.
        </p>
      </Caveat>
    </GroupsPage>
  )
}

export function AdvancedConfigPage() {
  const [plugins, setPlugins] = useState(null)
  const [manifest, setManifest] = useState('')
  const { toast, show, hide } = useToast()

  const load = () => api.get('/plugins').then(setPlugins).catch(() => {})
  useEffect(() => { load() }, [])

  const install = async () => {
    try {
      await api.post('/plugins', JSON.parse(manifest))
      setManifest(''); load(); show('Plugin installed')
    } catch (e) { show(e.message, 'error') }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader icon={KeyRound} color="orange" title="Advanced" subtitle="Raw configuration, plugins and container-driven configuration" />

      <Caveat tone="danger" title="Unmanaged configuration">
        <p>
          Anything entered under raw configuration bypasses CatWAF's guardrails around <em>what</em> is being set. The
          validate-before-apply safety net still applies — a bad snippet fails exactly the way a bad structured setting does, and
          the previous configuration is kept — but CatWAF cannot tell you whether a directive is a good idea.
        </p>
      </Caveat>

      <SettingsForm group="raw_config" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />
      <SettingsForm group="autoconf" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />

      <div className="card">
        <div className="section-title">Plugins</div>
        {plugins?.policy && (
          <p className="text-[11.5px] text-cat-sub mb-3 leading-relaxed">{plugins.policy.note}</p>
        )}
        {plugins?.plugins?.length ? (
          <div className="space-y-2 mb-3">
            {plugins.plugins.map(p => (
              <div key={p.id} className="flex items-center justify-between" style={{ padding: 9, borderRadius: 8, border: '1px solid var(--cat-border)' }}>
                <div>
                  <div className="text-xs text-cat-text font-medium">
                    {p.name} <span className="text-cat-sub">{p.version}</span>
                    {!p.trusted && <Badge color="orange">unsigned</Badge>}
                  </div>
                  <div className="text-[10.5px] text-cat-sub mt-0.5">
                    {p.provides.settings_groups.length} settings group(s), {p.provides.knowledge_entries} knowledge entr(ies), {p.provides.caddy_templates.length} template(s)
                  </div>
                </div>
                <div className="flex gap-2">
                  <button className="btn btn-sm btn-ghost" onClick={async () => { await api.post(`/plugins/${p.id}/enabled`, { enabled: !p.enabled }); load() }}>
                    {p.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button className="btn btn-sm btn-ghost" onClick={async () => { await api.delete(`/plugins/${p.id}`); load() }}>Remove</button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-cat-sub mb-3">No plugins installed.</p>
        )}
        <textarea className="input" rows={5} placeholder='{"catwaf_plugin": 1, "id": "my-plugin", "name": "My plugin", "settings_defaults": {...}}'
          style={{ fontFamily: 'monospace', fontSize: 11 }} value={manifest} onChange={e => setManifest(e.target.value)} />
        <button className="btn btn-sm btn-ghost" style={{ marginTop: 8 }} onClick={install} disabled={!manifest.trim()}>
          <Package size={13} /> Install manifest
        </button>
      </div>
    </div>
  )
}
