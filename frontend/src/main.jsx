import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.jsx'
import { AuthProvider, useAuth } from './auth/AuthContext.jsx'
import Login from './auth/Login.jsx'
import { Spinner } from './components/ui.jsx'
import { PreferencesProvider } from './utils/preferences.jsx'
import './index.css'

function BootScreen() {
  return (
    <div className="animate-fade-in" style={{ position: 'fixed', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 14, background: 'var(--cat-bg)' }}>
      <div className="animate-logo" style={{ width: 48, height: 48, borderRadius: 14, background: 'color-mix(in srgb, var(--cat-accent) 24%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
        <img src="/assets/logo/catwaf-icon-256.png" alt="CatWAF" style={{ width: 34, height: 34, objectFit: 'contain' }} />
      </div>
      <Spinner size={16} />
    </div>
  )
}

// Shown when CatWAF's dashboard is loaded but its API cannot be reached. The
// operator has a session; the backend is not answering. Sending them to the
// login form here would be wrong twice over — it suggests they were signed
// out, and every attempt to sign back in would fail for the same reason.
function ApiDownScreen({ detail, onRetry }) {
  return (
    <div style={{ position: 'fixed', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--cat-bg)', padding: 24 }}>
      <div className="card" style={{ maxWidth: 460, padding: 30, borderRadius: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
          <div style={{ width: 40, height: 40, borderRadius: 12, background: 'color-mix(in srgb, var(--cat-accent) 20%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
            <img src="/assets/logo/catwaf-icon-256.png" alt="" style={{ width: 28, height: 28, objectFit: 'contain' }} />
          </div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--cat-text)' }}>CatWAF API is unavailable</div>
        </div>
        <p style={{ fontSize: 13, color: 'var(--cat-sub)', lineHeight: 1.65, margin: '0 0 8px' }}>{detail}</p>
        <p style={{ fontSize: 13, color: 'var(--cat-sub)', lineHeight: 1.65, margin: '0 0 18px' }}>
          You are still signed in. This is CatWAF's own control API — it is separate from the
          WAF itself, so traffic to your protected sites is unaffected by this screen.
        </p>
        <div style={{ fontSize: 12, color: 'var(--cat-sub)', fontFamily: 'monospace', background: 'var(--cat-surface)', border: '1px solid var(--cat-border)', borderRadius: 8, padding: '10px 12px', marginBottom: 16 }}>
          catwaf status<br />catwaf start
        </div>
        <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }} onClick={onRetry}>
          Try again
        </button>
      </div>
    </div>
  )
}

function Gate() {
  const { user, ready, apiDown, refresh } = useAuth()
  if (!ready) return <BootScreen />
  if (apiDown && !user) return <ApiDownScreen detail={apiDown} onRetry={refresh} />
  if (!user || user.username === 'guest') return <Login />
  return <App />
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <PreferencesProvider>
      <BrowserRouter>
        <AuthProvider>
          <Gate />
        </AuthProvider>
      </BrowserRouter>
    </PreferencesProvider>
  </React.StrictMode>
)
