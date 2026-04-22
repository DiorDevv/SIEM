import React, { useState, useEffect, useCallback } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { LanguageProvider, useLang } from './context/LanguageContext'
import { ThemeProvider } from './context/ThemeContext'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Agents from './pages/Agents'
import Alerts from './pages/Alerts'
import Logs from './pages/Logs'
import Rules from './pages/Rules'
import Settings from './pages/Settings'
import ActiveResponse from './pages/ActiveResponse'
import Vulnerabilities from './pages/Vulnerabilities'
import SCA from './pages/SCA'
import AuditLog from './pages/AuditLog'
import Sidebar from './components/Sidebar'
import Navbar from './components/Navbar'

const WS_URL = (import.meta.env.VITE_WS_URL || 'ws://localhost:8000') + '/ws/live'

function ProtectedLayout({ children }) {
  const { user } = useAuth()
  const { t } = useLang()
  const [wsConnected, setWsConnected] = useState(false)
  const [toasts, setToasts] = useState([])
  const [unackCount, setUnackCount] = useState(0)
  const [sidebarOpen, setSidebarOpen] = useState(true)

  const addToast = useCallback((message, type = 'info') => {
    const id = Date.now()
    setToasts((prev) => [...prev.slice(-4), { id, message, type }])
    setTimeout(() => setToasts((prev) => prev.filter((x) => x.id !== id)), 5000)
  }, [])

  useEffect(() => {
    if (!user) return
    let ws, reconnectTimer

    const connect = () => {
      ws = new WebSocket(WS_URL)
      ws.onopen = () => {
        setWsConnected(true)
        const ping = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send('ping')
        }, 25000)
        ws._ping = ping
      }
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          if (msg.type === 'new_alert') {
            addToast(`${t('ws.newAlert')}: ${msg.data?.title} [${msg.data?.severity}]`, 'alert')
            if (msg.data?.status === 'open') setUnackCount((c) => c + 1)
          } else if (msg.type === 'agent_offline') {
            addToast(`${t('ws.agentOffline')}: ${msg.data?.hostname}`, 'warning')
          } else if (msg.type === 'critical_log') {
            addToast(`${t('ws.criticalLog')}: ${msg.data?.message?.slice(0, 80)}`, 'critical')
          }
        } catch {}
      }
      ws.onclose = () => {
        setWsConnected(false)
        if (ws._ping) clearInterval(ws._ping)
        reconnectTimer = setTimeout(connect, 3000)
      }
      ws.onerror = () => ws.close()
    }

    connect()
    return () => {
      clearTimeout(reconnectTimer)
      if (ws) { ws.onclose = null; ws.close() }
    }
  }, [user, addToast, t])

  if (!user) return <Navigate to="/login" replace />

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: 'var(--bg-primary)' }}>
      <Sidebar open={sidebarOpen} onToggle={() => setSidebarOpen(!sidebarOpen)} />
      <div className="flex flex-col flex-1 overflow-hidden">
        <Navbar
          wsConnected={wsConnected}
          unackCount={unackCount}
          onMenuToggle={() => setSidebarOpen(!sidebarOpen)}
        />
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>

      {/* Toast notifications */}
      <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2">
        {toasts.map((toast) => {
          const styles = {
            alert:    { bg: 'rgba(239,68,68,0.95)',  icon: '🚨' },
            critical: { bg: 'rgba(239,68,68,0.95)',  icon: '🔴' },
            warning:  { bg: 'rgba(245,158,11,0.95)', icon: '⚠️' },
            info:     { bg: 'rgba(22,29,46,0.97)',   icon: '🔔' },
          }
          const s = styles[toast.type] || styles.info
          return (
            <div
              key={toast.id}
              className="flex items-start gap-2 px-4 py-3 rounded-xl text-sm font-medium animate-fade-in"
              style={{
                background: s.bg,
                border: '1px solid rgba(255,255,255,0.1)',
                color: '#fff',
                boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
                maxWidth: 340,
              }}
            >
              <span className="flex-shrink-0">{s.icon}</span>
              <span>{toast.message}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function AppRoutes() {
  const { loading } = useAuth()
  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen" style={{ background: 'var(--bg-primary)' }}>
        <div
          className="w-12 h-12 rounded-full border-2 border-t-transparent animate-spin"
          style={{ borderColor: 'rgba(59,130,246,0.3)', borderTopColor: '#3b82f6' }}
        />
      </div>
    )
  }
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/"        element={<ProtectedLayout><Dashboard /></ProtectedLayout>} />
      <Route path="/agents"  element={<ProtectedLayout><Agents /></ProtectedLayout>} />
      <Route path="/alerts"  element={<ProtectedLayout><Alerts /></ProtectedLayout>} />
      <Route path="/logs"    element={<ProtectedLayout><Logs /></ProtectedLayout>} />
      <Route path="/rules"           element={<ProtectedLayout><Rules /></ProtectedLayout>} />
      <Route path="/active-response"  element={<ProtectedLayout><ActiveResponse /></ProtectedLayout>} />
      <Route path="/vulnerabilities" element={<ProtectedLayout><Vulnerabilities /></ProtectedLayout>} />
      <Route path="/sca"             element={<ProtectedLayout><SCA /></ProtectedLayout>} />
      <Route path="/audit-log"        element={<ProtectedLayout><AuditLog /></ProtectedLayout>} />
      <Route path="/settings"        element={<ProtectedLayout><Settings /></ProtectedLayout>} />
      <Route path="*"        element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <LanguageProvider>
          <AuthProvider>
            <AppRoutes />
          </AuthProvider>
        </LanguageProvider>
      </ThemeProvider>
    </BrowserRouter>
  )
}
