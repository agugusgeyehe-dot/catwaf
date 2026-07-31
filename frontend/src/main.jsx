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
        <img src="/catwaf-icon-256.png" alt="CatWAF" style={{ width: 34, height: 34, objectFit: 'contain' }} />
      </div>
      <Spinner size={16} />
    </div>
  )
}

function Gate() {
  const { user, ready } = useAuth()
  if (!ready) return <BootScreen />
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
