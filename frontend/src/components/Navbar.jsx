import React, { useState, useRef, useEffect } from 'react'
import { useLang } from '../context/LanguageContext'
import { useTheme } from '../context/ThemeContext'

const TYPE_STYLE = {
  alert:    { bg: 'rgba(239,68,68,0.15)',  color: '#fca5a5', icon: '🚨', dot: '#ef4444' },
  critical: { bg: 'rgba(239,68,68,0.12)',  color: '#fca5a5', icon: '🔴', dot: '#ef4444' },
  warning:  { bg: 'rgba(245,158,11,0.12)', color: '#fcd34d', icon: '⚠️', dot: '#f59e0b' },
  info:     { bg: 'rgba(59,130,246,0.10)', color: '#93c5fd', icon: '🔔', dot: '#3b82f6' },
}

export default function Navbar({ wsConnected, unackCount, onMenuToggle, notifications = [], onClearAll, onDismiss }) {
  const { lang, toggle, t } = useLang()
  const { theme, toggle: toggleTheme, isDark } = useTheme()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  const unread = notifications.filter((n) => !n.read).length

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  return (
    <header
      className="flex items-center justify-between px-6 flex-shrink-0"
      style={{
        height: '64px',
        background: 'var(--bg-secondary)',
        borderBottom: '1px solid var(--border-color)',
        position: 'sticky',
        top: 0,
        zIndex: 10,
      }}
    >
      <button
        onClick={onMenuToggle}
        className="p-2 rounded-lg transition-colors"
        style={{ color: 'var(--text-secondary)' }}
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <line x1="3" y1="6" x2="21" y2="6"/>
          <line x1="3" y1="12" x2="21" y2="12"/>
          <line x1="3" y1="18" x2="21" y2="18"/>
        </svg>
      </button>

      <div className="flex items-center gap-3">
        {unackCount > 0 && (
          <div
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold animate-fade-in"
            style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.3)' }}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse-glow inline-block" />
            {unackCount} {t('alerts.filterOpen').toLowerCase()}
          </div>
        )}

        {/* WebSocket status */}
        <div
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium"
          style={
            wsConnected
              ? { background: 'rgba(16,185,129,0.12)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.2)' }
              : { background: 'rgba(107,114,128,0.12)', color: '#9ca3af', border: '1px solid rgba(107,114,128,0.2)' }
          }
        >
          <span style={{
            width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
            background: wsConnected ? '#10b981' : '#6b7280',
            animation: wsConnected ? 'pulse-glow 1.5s infinite' : 'none',
          }} />
          {wsConnected ? t('ws.connected') : t('ws.disconnected')}
        </div>

        {/* Notification bell */}
        <div ref={ref} style={{ position: 'relative' }}>
          <button
            onClick={() => setOpen(!open)}
            style={{
              position: 'relative',
              width: 36, height: 36,
              borderRadius: 10,
              border: `1px solid ${open ? 'rgba(99,102,241,0.4)' : 'var(--border-color)'}`,
              background: open ? 'rgba(99,102,241,0.12)' : 'var(--bg-card)',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              transition: 'all 0.2s',
            }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
              <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
            </svg>
            {unread > 0 && (
              <span style={{
                position: 'absolute', top: -4, right: -4,
                minWidth: 16, height: 16,
                borderRadius: 8,
                background: '#ef4444',
                color: '#fff',
                fontSize: 10,
                fontWeight: 700,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                padding: '0 3px',
                border: '2px solid var(--bg-secondary)',
              }}>
                {unread > 9 ? '9+' : unread}
              </span>
            )}
          </button>

          {/* Dropdown */}
          {open && (
            <div style={{
              position: 'absolute', top: 44, right: 0,
              width: 340,
              borderRadius: 14,
              background: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
              zIndex: 100,
              overflow: 'hidden',
            }}>
              {/* Header */}
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '12px 16px',
                borderBottom: '1px solid var(--border-color)',
                background: 'var(--bg-secondary)',
              }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                  Bildirishnomalar {unread > 0 && <span style={{ color: '#ef4444' }}>({unread})</span>}
                </span>
                {notifications.length > 0 && (
                  <button
                    onClick={() => { onClearAll?.(); setOpen(false) }}
                    style={{ fontSize: 11, color: 'var(--text-muted)', cursor: 'pointer', border: 'none', background: 'none' }}
                  >
                    Hammasini tozalash
                  </button>
                )}
              </div>

              {/* List */}
              <div style={{ maxHeight: 360, overflowY: 'auto' }}>
                {notifications.length === 0 ? (
                  <div style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                    Bildirishnomalar yo'q
                  </div>
                ) : (
                  notifications.slice().reverse().map((n) => {
                    const s = TYPE_STYLE[n.type] || TYPE_STYLE.info
                    return (
                      <div key={n.id} style={{
                        display: 'flex', alignItems: 'flex-start', gap: 10,
                        padding: '10px 16px',
                        borderBottom: '1px solid var(--border-color)',
                        background: n.read ? 'transparent' : `${s.bg}`,
                        transition: 'background 0.2s',
                      }}>
                        <span style={{ fontSize: 16, flexShrink: 0, marginTop: 1 }}>{s.icon}</span>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <p style={{
                            fontSize: 12, color: 'var(--text-primary)',
                            margin: 0, lineHeight: 1.4,
                            overflow: 'hidden', textOverflow: 'ellipsis',
                            display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
                          }}>
                            {n.message}
                          </p>
                          <p style={{ fontSize: 10, color: 'var(--text-muted)', margin: '3px 0 0' }}>
                            {new Date(n.time).toLocaleTimeString()}
                          </p>
                        </div>
                        <button
                          onClick={() => onDismiss?.(n.id)}
                          style={{ color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer', fontSize: 14, flexShrink: 0 }}
                        >×</button>
                      </div>
                    )
                  })
                )}
              </div>
            </div>
          )}
        </div>

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          aria-label="Toggle theme"
          style={{
            position: 'relative', width: 52, height: 28, borderRadius: 14,
            border: '1px solid var(--border-light)',
            background: isDark ? 'linear-gradient(135deg, #1e2a42, #111827)' : 'linear-gradient(135deg, #bfdbfe, #ddd6fe)',
            cursor: 'pointer', flexShrink: 0, padding: 0,
            transition: 'background 0.3s ease, border-color 0.3s ease',
          }}
        >
          <span style={{ position: 'absolute', left: 6, top: '50%', transform: 'translateY(-50%)', fontSize: 11, opacity: isDark ? 0.4 : 0, transition: 'opacity 0.25s' }}>🌙</span>
          <span style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)', fontSize: 11, opacity: isDark ? 0 : 0.9, transition: 'opacity 0.25s' }}>☀️</span>
          <span style={{
            position: 'absolute', top: 3, left: isDark ? 3 : 25, width: 20, height: 20,
            borderRadius: '50%',
            background: isDark ? '#3b82f6' : '#f59e0b',
            boxShadow: isDark ? '0 0 8px rgba(59,130,246,0.6)' : '0 0 8px rgba(245,158,11,0.6)',
            transition: 'left 0.25s cubic-bezier(.4,0,.2,1), background 0.25s, box-shadow 0.25s',
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10,
          }}>
            {isDark ? '🌙' : '☀️'}
          </span>
        </button>

        {/* Language toggle */}
        <button
          onClick={toggle}
          className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold transition-all"
          style={{
            background: 'linear-gradient(135deg, rgba(59,130,246,0.15), rgba(139,92,246,0.15))',
            color: isDark ? '#a5b4fc' : '#4f46e5',
            border: '1px solid rgba(99,102,241,0.3)',
          }}
        >
          <span>{lang === 'en' ? '🇺🇸' : '🇺🇿'}</span>
          <span>{lang.toUpperCase()}</span>
        </button>
      </div>
    </header>
  )
}
