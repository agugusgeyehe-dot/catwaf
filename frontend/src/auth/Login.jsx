import { useEffect, useRef, useState } from 'react'
import { Shield, LogIn, ShieldCheck, Activity, Lock, Zap, KeyRound, ArrowLeft } from 'lucide-react'
import { useAuth } from './AuthContext.jsx'
import { Spinner } from '../components/ui.jsx'

const FEATURES = [
  { icon: ShieldCheck, title: 'OWASP Core Rule Set', desc: 'Coraza engine, four paranoia levels' },
  { icon: Activity,    title: 'Real request data', desc: 'Every number comes from your traffic, never a demo feed' },
  { icon: Lock,        title: 'Hardened by default', desc: 'Sensitive-file blocking, geo and IP controls' },
  { icon: Zap,         title: 'Caddy integration', desc: 'Writes real Coraza directives and reloads on every change' },
]

export default function Login() {
  const { login } = useAuth()
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [code, setCode] = useState('')
  const [stage, setStage] = useState('credentials')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const codeRef = useRef(null)

  useEffect(() => { if (stage === 'totp') codeRef.current?.focus() }, [stage])

  const submit = async (e) => {
    e.preventDefault(); setErr(''); setBusy(true)
    try {
      await login(u, p, stage === 'totp' ? code.trim() : undefined)
    } catch (e) {
      // The password was right and the account has a second factor — that is
      // a step forward, not a failure, so the form advances rather than
      // showing an error the operator cannot act on.
      if (e.code === 'TOTP_REQUIRED') {
        setStage('totp')
        setErr('')
      } else {
        setErr(e.message)
        if (e.code === 'TOTP_INVALID') setCode('')
        // Anything else means the credentials themselves were rejected, so
        // go back rather than leaving a code box that can never succeed.
        else if (stage === 'totp') { setStage('credentials'); setCode('') }
      }
    } finally { setBusy(false) }
  }

  const backToCredentials = () => {
    setStage('credentials'); setCode(''); setErr('')
  }

  return (
    <div style={{ position: 'fixed', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--cat-bg)', padding: 24, overflowY: 'auto' }}>
      <div className="login-grid animate-fade-in" style={{ margin: 'auto' }}>

        <div className="login-pitch" style={{
          flexDirection: 'column', justifyContent: 'space-between',
          padding: 36, borderRadius: 18, border: '1px solid var(--cat-border)',
          background: 'linear-gradient(160deg, color-mix(in srgb, var(--cat-accent) 16%, var(--cat-card)), var(--cat-card) 60%)',
          animation: 'cardIn 0.6s cubic-bezier(0.16,1,0.3,1) both',
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 28 }}>
              <div className="animate-logo" style={{ width: 48, height: 48, borderRadius: 14, background: 'color-mix(in srgb, var(--cat-accent) 24%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
                <img src="/catwaf-icon-256.png" alt="CatWAF" style={{ width: 34, height: 34, objectFit: 'contain' }} />
              </div>
              <div>
                <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--cat-text)', letterSpacing: '-0.01em' }}>CatWAF</div>
                <div style={{ fontSize: 12, color: 'var(--cat-sub)' }}>Web Application Firewall</div>
              </div>
            </div>
            <h1 style={{ fontSize: 26, fontWeight: 700, lineHeight: 1.25, color: 'var(--cat-text)', letterSpacing: '-0.02em', margin: '0 0 10px', animation: 'slideUp 0.5s 0.15s cubic-bezier(0.16,1,0.3,1) both' }}>
              Stop attacks before<br />they reach your app.
            </h1>
            <p style={{ fontSize: 13, color: 'var(--cat-sub)', lineHeight: 1.7, maxWidth: 320, margin: 0, animation: 'slideUp 0.5s 0.25s cubic-bezier(0.16,1,0.3,1) both' }}>
              A clean control panel for Coraza + OWASP CRS — tune your rules, see what's being blocked, and lock things down without being a security engineer.
            </p>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 32 }}>
            {FEATURES.map(({ icon: Icon, title, desc }, i) => (
              <div key={title} style={{ display: 'flex', gap: 12, alignItems: 'flex-start', animation: `slideUp 0.4s ${0.3 + i * 0.07}s cubic-bezier(0.16,1,0.3,1) both` }}>
                <span className="stat-icon accent" style={{ marginTop: 1, flexShrink: 0 }}><Icon size={15} /></span>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--cat-text)' }}>{title}</div>
                  <div style={{ fontSize: 12, color: 'var(--cat-sub)', lineHeight: 1.5 }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <form onSubmit={submit} className="card" style={{ padding: 32, borderRadius: 18, alignSelf: 'center', animation: 'cardIn 0.6s 0.1s cubic-bezier(0.16,1,0.3,1) both' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
            <div className="animate-logo" style={{ width: 42, height: 42, borderRadius: 12, background: 'color-mix(in srgb, var(--cat-accent) 20%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
              <img src="/catwaf-icon-256.png" alt="CatWAF" style={{ width: 30, height: 30, objectFit: 'contain' }} />
            </div>
            <div>
              <div style={{ fontSize: 17, fontWeight: 700, color: 'var(--cat-text)', letterSpacing: '-0.01em' }}>
                {stage === 'totp' ? 'Two-factor code' : 'Welcome back'}
              </div>
              <div style={{ fontSize: 12, color: 'var(--cat-sub)' }}>
                {stage === 'totp' ? `Signed in as ${u}` : 'Sign in to your control panel'}
              </div>
            </div>
          </div>

          {stage === 'totp' ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <label className="text-xs text-cat-sub" style={{ fontWeight: 500, display: 'block', marginBottom: 6 }}>
                  Code from your authenticator app
                </label>
                <input
                  ref={codeRef}
                  className="input"
                  value={code}
                  onChange={e => setCode(e.target.value)}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="000000"
                  style={{ fontFamily: 'monospace', fontSize: 18, letterSpacing: '0.28em', textAlign: 'center' }}
                />
              </div>
              <div className="text-xs text-cat-sub" style={{ lineHeight: 1.6 }}>
                Lost the authenticator? Enter one of your recovery codes instead — each works once.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <label className="text-xs text-cat-sub" style={{ fontWeight: 500, display: 'block', marginBottom: 6 }}>Username</label>
                <input className="input" autoFocus value={u} onChange={e => setU(e.target.value)} />
              </div>
              <div>
                <label className="text-xs text-cat-sub" style={{ fontWeight: 500, display: 'block', marginBottom: 6 }}>Password</label>
                <input className="input" type="password" value={p} onChange={e => setP(e.target.value)} />
              </div>
            </div>
          )}

          {err && (
            <div className="badge-red animate-slide-up" style={{ marginTop: 14, width: '100%', justifyContent: 'flex-start', padding: '9px 12px', borderRadius: 8, display: 'flex' }}>
              {err}
            </div>
          )}

          <button className="btn btn-primary" disabled={busy || (stage === 'totp' && !code.trim())} style={{ width: '100%', marginTop: 18, padding: '11px 14px', justifyContent: 'center', gap: 8 }}>
            {busy
              ? <><Spinner size={14} /> {stage === 'totp' ? 'Verifying…' : 'Signing in…'}</>
              : stage === 'totp' ? <><KeyRound size={15} /> Verify</> : <><LogIn size={15} /> Sign in</>}
          </button>

          <div style={{ marginTop: 18, paddingTop: 16, borderTop: '1px solid var(--cat-border)' }}>
            {stage === 'totp' ? (
              <button type="button" className="btn btn-ghost btn-sm" onClick={backToCredentials} style={{ gap: 6 }}>
                <ArrowLeft size={13} /> Use a different account
              </button>
            ) : (
              <div className="text-xs text-cat-sub" style={{ display: 'flex', alignItems: 'center', gap: 6, lineHeight: 1.6 }}>
                <Shield size={12} />
                No account yet? Run <code>catwaf --setup</code> on the server.
              </div>
            )}
          </div>
        </form>
      </div>
    </div>
  )
}
