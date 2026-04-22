import React from 'react'
import { useLang } from '../context/LanguageContext'
import { useTheme } from '../context/ThemeContext'

export default function Navbar({ wsConnected, unackCount, onMenuToggle }) {
  const { lang, toggle, t } = useLang()
  const { theme, toggle: toggleTheme, isDark } = useTheme()

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

        <div
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium"
          style={
            wsConnected
              ? { background: 'rgba(16,185,129,0.12)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.2)' }
              : { background: 'rgba(107,114,128,0.12)', color: '#9ca3af', border: '1px solid rgba(107,114,128,0.2)' }
          }
        >
          <span
            style={{
              width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
              background: wsConnected ? '#10b981' : '#6b7280',
              animation: wsConnected ? 'pulse-glow 1.5s infinite' : 'none',
            }}
          />
          {wsConnected ? t('ws.connected') : t('ws.disconnected')}
        </div>

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          aria-label="Toggle theme"
          style={{
            position: 'relative',
            width: 52,
            height: 28,
            borderRadius: 14,
            border: '1px solid var(--border-light)',
            background: isDark
              ? 'linear-gradient(135deg, #1e2a42, #111827)'
              : 'linear-gradient(135deg, #bfdbfe, #ddd6fe)',
            cursor: 'pointer',
            flexShrink: 0,
            padding: 0,
            transition: 'background 0.3s ease, border-color 0.3s ease',
          }}
        >
          {/* track icons */}
          <span style={{
            position: 'absolute', left: 6, top: '50%', transform: 'translateY(-50%)',
            fontSize: 11, opacity: isDark ? 0.4 : 0, transition: 'opacity 0.25s',
          }}>🌙</span>
          <span style={{
            position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)',
            fontSize: 11, opacity: isDark ? 0 : 0.9, transition: 'opacity 0.25s',
          }}>☀️</span>
          {/* thumb */}
          <span style={{
            position: 'absolute',
            top: 3,
            left: isDark ? 3 : 25,
            width: 20,
            height: 20,
            borderRadius: '50%',
            background: isDark ? '#3b82f6' : '#f59e0b',
            boxShadow: isDark ? '0 0 8px rgba(59,130,246,0.6)' : '0 0 8px rgba(245,158,11,0.6)',
            transition: 'left 0.25s cubic-bezier(.4,0,.2,1), background 0.25s, box-shadow 0.25s',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 10,
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
