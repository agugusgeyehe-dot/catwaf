import React, { createContext, useContext, useEffect, useState } from 'react'
import { api, setSession, clearSession, hasToken } from '../utils/api.js'

const Ctx = createContext(null)
export const useAuth = () => useContext(Ctx)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [ready, setReady] = useState(false)

  const refresh = () => {
    if (!hasToken()) { setUser(null); setReady(true); return Promise.resolve() }
    return api.get('/auth/me').then(d => setUser(d.user)).catch(() => setUser(null)).finally(() => setReady(true))
  }

  useEffect(() => {
    refresh()
    const h = () => refresh()
    window.addEventListener('catwaf-auth-changed', h)
    return () => window.removeEventListener('catwaf-auth-changed', h)
  }, [])

  async function login(username, password) {
    const r = await api.post('/auth/login', { username, password })
    setSession(r)
    setUser(r.user)
    window.dispatchEvent(new Event('catwaf-auth-changed'))
  }
  function logout() {
    clearSession()
    setUser(null)
    window.dispatchEvent(new Event('catwaf-auth-changed'))
  }

  return <Ctx.Provider value={{ user, ready, login, logout, isAdmin: user?.role === 'admin' }}>{children}</Ctx.Provider>
}
