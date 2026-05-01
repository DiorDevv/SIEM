import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react'
import { login as apiLogin, getMe, totpLogin } from '../api'

const AuthContext = createContext(null)

const IDLE_WARN_MS  = 25 * 60 * 1000  // 25 daqiqa — ogohlantirish
const IDLE_LIMIT_MS = 30 * 60 * 1000  // 30 daqiqa — chiqish

export function AuthProvider({ children }) {
  const [user, setUser]           = useState(null)
  const [loading, setLoading]     = useState(true)
  const [idleWarn, setIdleWarn]   = useState(false)
  const warnTimer  = useRef(null)
  const logoutTimer = useRef(null)

  const resetIdleTimers = useCallback(() => {
    clearTimeout(warnTimer.current)
    clearTimeout(logoutTimer.current)
    setIdleWarn(false)
    warnTimer.current   = setTimeout(() => setIdleWarn(true),  IDLE_WARN_MS)
    logoutTimer.current = setTimeout(() => doLogout(),         IDLE_LIMIT_MS)
  }, [])

  const doLogout = useCallback(() => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    setUser(null)
    setIdleWarn(false)
    clearTimeout(warnTimer.current)
    clearTimeout(logoutTimer.current)
  }, [])

  const loadUser = useCallback(async () => {
    const token = localStorage.getItem('access_token')
    if (!token) { setLoading(false); return }
    try {
      const resp = await getMe()
      setUser(resp.data)
    } catch {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadUser() }, [loadUser])

  // Idle tracking — faqat user tizimga kirgan bo'lsa
  useEffect(() => {
    if (!user) return
    const events = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart']
    const handler = () => resetIdleTimers()
    events.forEach((e) => window.addEventListener(e, handler, { passive: true }))
    resetIdleTimers()
    return () => {
      events.forEach((e) => window.removeEventListener(e, handler))
      clearTimeout(warnTimer.current)
      clearTimeout(logoutTimer.current)
    }
  }, [user, resetIdleTimers])

  const _storeTokens = (access_token, refresh_token, userData) => {
    localStorage.setItem('access_token', access_token)
    localStorage.setItem('refresh_token', refresh_token)
    setUser(userData)
  }

  const login = async (username, password) => {
    const resp = await apiLogin(username, password)
    const data = resp.data
    if (data.requires_2fa) return { requires_2fa: true, temp_token: data.temp_token }
    _storeTokens(data.access_token, data.refresh_token, data.user)
    return data.user
  }

  const verifyTotp = async (temp_token, code) => {
    const resp = await totpLogin(temp_token, code)
    const { access_token, refresh_token, user: userData } = resp.data
    _storeTokens(access_token, refresh_token, userData)
    return userData
  }

  const logout = () => doLogout()

  const refreshUser = async () => {
    try { const resp = await getMe(); setUser(resp.data) } catch {}
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, verifyTotp, logout, refreshUser }}>
      {children}

      {/* Session timeout warning modal */}
      {idleWarn && user && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center"
          style={{ background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(12px)' }}>
          <div className="rounded-2xl p-8 text-center max-w-sm w-full mx-4"
            style={{ background: 'var(--bg-card)', border: '1px solid rgba(245,158,11,0.4)', boxShadow: '0 25px 80px rgba(0,0,0,0.7)' }}>
            <div className="text-5xl mb-4">⏱️</div>
            <h2 className="text-xl font-black text-white mb-2">Sessiya muddati tugayapti</h2>
            <p className="text-sm mb-6" style={{ color: 'var(--text-muted)' }}>
              5 daqiqa faoliyatsizlik sababli tizimdan chiqarilasiz. Davom etish uchun tugmani bosing.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => { resetIdleTimers() }}
                className="flex-1 py-3 rounded-xl font-bold text-sm"
                style={{ background: 'rgba(16,185,129,0.15)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.3)' }}>
                ✓ Davom etish
              </button>
              <button
                onClick={() => doLogout()}
                className="flex-1 py-3 rounded-xl font-bold text-sm"
                style={{ background: 'rgba(239,68,68,0.12)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.25)' }}>
                Chiqish
              </button>
            </div>
          </div>
        </div>
      )}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
