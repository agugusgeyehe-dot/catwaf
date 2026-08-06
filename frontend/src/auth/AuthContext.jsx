import { createContext, useContext, useEffect, useState } from 'react'
import { api, setSession, clearSession, hasToken, API_UNREACHABLE } from '../utils/api.js'

const Ctx = createContext(null)
export const useAuth = () => useContext(Ctx)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [ready, setReady] = useState(false)
  // Set when CatWAF's API cannot be reached at all. This is deliberately not
  // the same as "signed out": the dashboard shows why it is empty instead of
  // pretending the operator's session ended.
  const [apiDown, setApiDown] = useState(null)

  // Establishes who is signed in by asking the server.
  //
  // The rule this function exists to get right: only the *server* can end a
  // session. Previously every failure landed in one `.catch(() => setUser(null))`,
  // so a request that never reached CatWAF — backend restarting, laptop asleep,
  // a refused response — logged the operator out. Combined with the
  // `catwaf-auth-changed` event that login itself dispatches, that produced the
  // login loop: sign in successfully, the follow-up /auth/me fails to connect,
  // the session is discarded, back to the login screen.
  const refresh = async () => {
    if (!hasToken()) {
      setUser(null)
      setApiDown(null)
      setReady(true)
      return
    }
    try {
      const d = await api.get('/auth/me')
      setUser(d.user)
      setApiDown(null)
    } catch (e) {
      if (e.code === API_UNREACHABLE) {
        // Keep the token and whoever we already believed was signed in. When
        // the backend comes back, the next refresh resolves it for real.
        setApiDown(e.message)
      } else if (e.status === 401 || e.status === 403) {
        // The server actually rejected the token.
        clearSession()
        setUser(null)
        setApiDown(null)
      } else {
        // A 5xx or anything else: CatWAF answered but is unwell. Do not
        // discard the session over it.
        setApiDown(e.message)
      }
    } finally {
      setReady(true)
    }
  }

  useEffect(() => {
    refresh()
    const h = () => refresh()
    window.addEventListener('catwaf-auth-changed', h)
    return () => window.removeEventListener('catwaf-auth-changed', h)
  }, [])

  // `totp` is only sent once the server has asked for it. Sending it blind
  // would tell an attacker whether an account has a second factor before the
  // password is checked.
  async function login(username, password, totp) {
    const r = await api.post('/auth/login', totp ? { username, password, totp } : { username, password })
    setSession(r)
    setUser(r.user)
    setApiDown(null)
    setReady(true)
    // Note: no `catwaf-auth-changed` here. The login response already carries
    // the authoritative user, and dispatching would trigger a refresh() that
    // can only confirm what we just learned — or, if it fails to connect,
    // undo it.
    return r
  }

  // Closing the session server-side is the point of logging out: without it
  // the JWT stays valid for its full lifetime and the session record stays
  // open. Local state is cleared either way, because a logout must never be
  // blocked by an unreachable server.
  async function logout() {
    try { await api.post('/auth/logout') } catch { /* clear locally regardless */ }
    clearSession()
    setUser(null)
    setApiDown(null)
    window.dispatchEvent(new Event('catwaf-auth-changed'))
  }

  return (
    <Ctx.Provider value={{ user, ready, apiDown, login, logout, refresh, isAdmin: user?.role === 'admin' }}>
      {children}
    </Ctx.Provider>
  )
}
