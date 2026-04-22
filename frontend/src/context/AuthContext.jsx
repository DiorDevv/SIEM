import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { login as apiLogin, getMe, totpLogin } from '../api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  const loadUser = useCallback(async () => {
    const token = localStorage.getItem('access_token')
    if (!token) {
      setLoading(false)
      return
    }
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

  useEffect(() => {
    loadUser()
  }, [loadUser])

  const _storeTokens = (access_token, refresh_token, userData) => {
    localStorage.setItem('access_token', access_token)
    localStorage.setItem('refresh_token', refresh_token)
    setUser(userData)
  }

  const login = async (username, password) => {
    const resp = await apiLogin(username, password)
    const data = resp.data
    if (data.requires_2fa) {
      // Return flag so Login.jsx can show the TOTP step
      return { requires_2fa: true, temp_token: data.temp_token }
    }
    _storeTokens(data.access_token, data.refresh_token, data.user)
    return data.user
  }

  const verifyTotp = async (temp_token, code) => {
    const resp = await totpLogin(temp_token, code)
    const { access_token, refresh_token, user: userData } = resp.data
    _storeTokens(access_token, refresh_token, userData)
    return userData
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    setUser(null)
  }

  const refreshUser = async () => {
    try {
      const resp = await getMe()
      setUser(resp.data)
    } catch {}
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, verifyTotp, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
