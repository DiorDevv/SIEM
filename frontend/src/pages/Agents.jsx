import React, { useState, useEffect, useCallback } from 'react'
import { getAgents, deleteAgent, getLogs, getAlerts } from '../api'
import { useLang } from '../context/LanguageContext'
import DeployModal from '../components/DeployModal'

function AgentAvatar({ hostname, online }) {
  return (
    <div className="w-10 h-10 rounded-xl flex items-center justify-center text-sm font-black flex-shrink-0 relative"
      style={{
        background: online ? 'rgba(16,185,129,0.15)' : 'rgba(107,114,128,0.15)',
        border: `1px solid ${online ? 'rgba(16,185,129,0.3)' : 'rgba(107,114,128,0.2)'}`,
        color: online ? '#6ee7b7' : '#9ca3af',
      }}>
      {hostname?.[0]?.toUpperCase() || '?'}
      <span className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2"
        style={{
          background: online ? '#10b981' : '#6b7280',
          borderColor: 'var(--bg-card)',
          boxShadow: online ? '0 0 6px #10b98180' : 'none',
        }} />
    </div>
  )
}

function OsBadge({ os }) {
  const s = (os || '').toLowerCase()
  const isMac  = s.includes('darwin') || s.includes('mac')
  const isWin  = s.includes('windows') || s.includes('win')
  const icon   = isMac ? '🍎' : isWin ? '🪟' : '🐧'
  const color  = isMac ? '#a78bfa' : isWin ? '#3b82f6' : '#f97316'
  const bg     = isMac ? 'rgba(167,139,250,0.12)' : isWin ? 'rgba(59,130,246,0.12)' : 'rgba(249,115,22,0.12)'
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-0.5 rounded"
      style={{ background: bg, color, border: `1px solid ${color}30` }}>
      {icon} {os || '—'}
    </span>
  )
}

/* ── Agent detail modal ──────────────────────────────────── */
function AgentModal({ agent, onClose }) {
  const { t } = useLang()
  const [recentLogs, setRecentLogs] = useState([])
  const [recentAlerts, setRecentAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const online = agent.status === 'online'

  useEffect(() => {
    const fetch = async () => {
      try {
        const [lr, ar] = await Promise.all([
          getLogs({ agent_id: agent.agent_id, size: 5 }),
          getAlerts({ agent_id: agent.agent_id, size: 5 }),
        ])
        setRecentLogs(lr.data.logs || [])
        setRecentAlerts(ar.data.alerts || [])
      } catch {}
      setLoading(false)
    }
    fetch()
  }, [agent.agent_id])

  const SEV_COLOR = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#3b82f6' }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in"
      style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(8px)' }}
      onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="w-full max-w-2xl rounded-2xl overflow-hidden animate-slide-down"
        style={{ background: 'var(--bg-card)', maxHeight: '90vh', overflowY: 'auto',
          border: `1px solid ${online ? 'rgba(16,185,129,0.3)' : 'var(--border-light)'}`,
          boxShadow: `0 25px 60px rgba(0,0,0,0.7)` }}>

        {/* header */}
        <div className="relative px-6 py-5 overflow-hidden"
          style={{ background: `linear-gradient(135deg, var(--bg-secondary), ${online ? 'rgba(16,185,129,0.05)' : 'var(--bg-secondary)'})`,
            borderBottom: '1px solid var(--border-color)' }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 rounded-2xl flex items-center justify-center text-lg font-black"
                style={{ background: online ? 'rgba(16,185,129,0.15)' : 'rgba(107,114,128,0.15)',
                  border: `1px solid ${online ? 'rgba(16,185,129,0.3)' : 'rgba(107,114,128,0.2)'}`,
                  color: online ? '#6ee7b7' : '#9ca3af', fontSize: 22 }}>
                {agent.hostname?.[0]?.toUpperCase()}
              </div>
              <div>
                <h2 className="font-black text-white text-lg">{agent.hostname}</h2>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="font-mono text-sm" style={{ color: '#93c5fd' }}>{agent.ip_address}</span>
                  <span className="text-xs px-2 py-0.5 rounded-full font-bold"
                    style={{ background: online ? 'rgba(16,185,129,0.15)' : 'rgba(107,114,128,0.15)',
                      color: online ? '#6ee7b7' : '#9ca3af' }}>
                    {online ? '● ' + t('agents.online') : '○ ' + t('agents.offline')}
                  </span>
                </div>
              </div>
            </div>
            <button onClick={onClose} className="w-8 h-8 rounded-xl flex items-center justify-center text-lg"
              style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)' }}>×</button>
          </div>
        </div>

        <div className="p-6 space-y-5">
          {/* info grid */}
          <div className="grid grid-cols-2 gap-2.5">
            {[
              ['Agent ID',            agent.agent_id?.slice(0, 20) + '…'],
              [t('agents.ipAddress'), agent.ip_address],
              [t('agents.os'),        agent.os || '—'],
              ['OS Version',          agent.os_version || '—'],
              [t('agents.version'),   agent.agent_version || '—'],
              [t('agents.lastSeen'),  agent.last_seen ? new Date(agent.last_seen).toLocaleString() : '—'],
              ['Registered',          agent.registered_at ? new Date(agent.registered_at).toLocaleString() : '—'],
              ['Tags',                agent.tags || '—'],
            ].map(([k, v]) => (
              <div key={k} className="rounded-xl p-3" style={{ background: 'var(--bg-secondary)' }}>
                <div className="text-xs mb-1 font-medium" style={{ color: 'var(--text-muted)' }}>{k}</div>
                <div className="text-sm font-medium text-white truncate">{v}</div>
              </div>
            ))}
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-10">
              <div className="w-8 h-8 border-2 rounded-full animate-spin"
                style={{ borderColor: 'rgba(59,130,246,0.2)', borderTopColor: '#3b82f6' }} />
            </div>
          ) : (
            <>
              {/* Recent alerts */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                    Recent Alerts
                  </h3>
                  <span className="text-xs px-2 py-0.5 rounded-full"
                    style={{ background: 'rgba(239,68,68,0.1)', color: '#fca5a5' }}>
                    {recentAlerts.length}
                  </span>
                </div>
                {recentAlerts.length === 0 ? (
                  <div className="text-center py-6 rounded-xl text-xs" style={{ color: 'var(--text-muted)', background: 'var(--bg-secondary)' }}>
                    No recent alerts
                  </div>
                ) : (
                  <div className="space-y-2">
                    {recentAlerts.map((a) => {
                      const col = SEV_COLOR[a.severity] || '#3b82f6'
                      return (
                        <div key={a.id} className="flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm"
                          style={{ background: 'var(--bg-secondary)', borderLeft: `3px solid ${col}` }}>
                          <span className="text-xs font-black flex-shrink-0" style={{ color: col, minWidth: 52 }}>
                            {a.severity}
                          </span>
                          <span className="text-white truncate text-xs">{a.title}</span>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>

              {/* Recent logs */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                    Recent Logs
                  </h3>
                </div>
                <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
                  {recentLogs.length === 0 ? (
                    <div className="text-center py-5 text-xs" style={{ color: 'var(--text-muted)' }}>No recent logs</div>
                  ) : recentLogs.map((l, i) => {
                    const lvlColors = { CRITICAL: '#ef4444', ERROR: '#f87171', WARNING: '#fcd34d', INFO: '#93c5fd', DEBUG: '#9ca3af' }
                    return (
                      <div key={i} className="flex items-start gap-3 px-4 py-2 font-mono text-xs"
                        style={{ borderBottom: i < recentLogs.length - 1 ? '1px solid var(--border-color)' : 'none',
                          background: i % 2 === 0 ? 'var(--bg-secondary)' : 'transparent' }}>
                        <span className="flex-shrink-0" style={{ color: 'var(--text-muted)', minWidth: 68 }}>
                          {l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : '—'}
                        </span>
                        <span className="flex-shrink-0 font-bold" style={{ color: lvlColors[l.level] || '#93c5fd', minWidth: 44 }}>
                          [{l.level || 'INFO'}]
                        </span>
                        <span className="text-white truncate">{l.message}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════ */
export default function Agents() {
  const { t } = useLang()
  const [agents, setAgents]         = useState([])
  const [loading, setLoading]       = useState(true)
  const [search, setSearch]         = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [selected, setSelected]     = useState(null)
  const [confirmDel, setConfirmDel] = useState(null)
  const [viewMode, setViewMode]     = useState('table') // 'table' | 'grid'
  const [deployOpen, setDeployOpen] = useState(false)

  const fetchAgents = useCallback(async () => {
    setLoading(true)
    try {
      const resp = await getAgents({ status: statusFilter || undefined })
      setAgents(resp.data)
    } catch {}
    setLoading(false)
  }, [statusFilter])

  useEffect(() => { fetchAgents() }, [fetchAgents])

  const handleDelete = async (agent) => {
    try {
      await deleteAgent(agent.agent_id)
      setAgents((prev) => prev.filter((a) => a.agent_id !== agent.agent_id))
    } catch {}
    setConfirmDel(null)
  }

  const filtered = agents.filter((a) =>
    !search || a.hostname?.toLowerCase().includes(search.toLowerCase()) || a.ip_address?.includes(search)
  )
  const online  = agents.filter((a) => a.status === 'online').length
  const offline = agents.filter((a) => a.status !== 'online').length
  const health  = agents.length ? Math.round((online / agents.length) * 100) : 0

  return (
    <div className="space-y-5 animate-fade-in">

      {/* ── Banner ── */}
      <div className="page-header-banner relative rounded-2xl overflow-hidden p-6"
        style={{ background: 'linear-gradient(135deg, #0f172a, #0a1f14, #0f172a)',
          border: '1px solid rgba(16,185,129,0.2)' }}>
        <div className="absolute top-0 right-0 w-64 h-64 pointer-events-none"
          style={{ background: 'radial-gradient(circle, rgba(16,185,129,0.07) 0%, transparent 70%)',
            transform: 'translate(20%,-20%)' }} />
        <div className="relative flex items-center justify-between flex-wrap gap-4">
          <div>
            <h2 className="text-2xl font-black text-white mb-1">{t('agents.title')}</h2>
            <p className="text-sm" style={{ color: 'rgba(148,163,184,0.7)' }}>{t('agents.subtitle')}</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs"
              style={{ background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.2)' }}>
              <span className="live-dot" />
              <span style={{ color: '#6ee7b7' }}>{online} online</span>
            </div>
            <button onClick={() => setDeployOpen(true)}
              className="flex items-center gap-2 py-2 px-3 rounded-xl text-xs font-bold transition-all"
              style={{ background: 'rgba(16,185,129,0.15)', color: '#6ee7b7',
                border: '1px solid rgba(16,185,129,0.3)' }}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="13" height="13">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="16"/>
                <line x1="8" y1="12" x2="16" y2="12"/>
              </svg>
              {t('agents.deployAgent')}
            </button>
            <button onClick={fetchAgents} className="btn-ghost py-2 px-3 text-xs flex items-center gap-1.5">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/>
              </svg>
              {t('common.refresh')}
            </button>
            <div className="flex rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
              {[['table', '☰'], ['grid', '⊞']].map(([mode, icon]) => (
                <button key={mode} onClick={() => setViewMode(mode)}
                  className="px-3 py-2 text-sm transition-all"
                  style={{ background: viewMode === mode ? 'var(--accent)' : 'transparent',
                    color: viewMode === mode ? '#fff' : 'var(--text-muted)' }}>
                  {icon}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── Stats ── */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: t('agents.totalAgents'), value: agents.length, color: '#3b82f6', icon: '🖥️',
            sub: `${health}% ${t('agents.online')}` },
          { label: t('agents.onlineCount'),  value: online,   color: '#10b981', icon: '✅',
            sub: 'Active now' },
          { label: t('agents.offlineCount'), value: offline,  color: '#6b7280', icon: '💤',
            sub: 'Inactive' },
        ].map(({ label, value, color, icon, sub }) => (
          <div key={label} className="rounded-2xl p-5"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xl">{icon}</span>
              <span className="text-xs px-2 py-0.5 rounded-full font-medium"
                style={{ background: `${color}15`, color }}>
                {sub}
              </span>
            </div>
            <div className="text-3xl font-black mb-0.5" style={{ color }}>{value}</div>
            <div className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</div>
          </div>
        ))}
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-wrap gap-3 rounded-2xl p-4"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        <div className="relative flex-1 min-w-48">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" width="14" height="14"
            viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
            style={{ color: 'var(--text-muted)' }}>
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input type="text" placeholder={`${t('common.search')} hostname / IP...`}
            value={search} onChange={(e) => setSearch(e.target.value)}
            className="w-full" style={{ paddingLeft: 36 }} />
        </div>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} style={{ minWidth: 130 }}>
          <option value="">{t('alerts.filterAll')}</option>
          <option value="online">{t('agents.online')}</option>
          <option value="offline">{t('agents.offline')}</option>
        </select>
      </div>

      {/* ── Content: table or grid ── */}
      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-10 h-10 border-2 rounded-full animate-spin"
            style={{ borderColor: 'rgba(59,130,246,0.2)', borderTopColor: '#3b82f6' }} />
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 gap-4" style={{ color: 'var(--text-muted)' }}>
          <div className="w-20 h-20 rounded-2xl flex items-center justify-center"
            style={{ background: 'var(--bg-card)' }}>
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="opacity-30">
              <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/>
            </svg>
          </div>
          <p className="text-sm font-medium">{t('agents.noAgents')}</p>
        </div>
      ) : viewMode === 'grid' ? (
        /* Grid view */
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map((agent) => {
            const isOnline = agent.status === 'online'
            const lastSeen = agent.last_seen
              ? (() => {
                  const diff = Date.now() - new Date(agent.last_seen)
                  const mins = Math.floor(diff / 60000)
                  if (mins < 1) return 'Just now'
                  if (mins < 60) return `${mins}m ago`
                  return `${Math.floor(mins / 60)}h ago`
                })()
              : '—'
            return (
              <div key={agent.agent_id}
                className="rounded-2xl p-5 cursor-pointer transition-all group"
                style={{ background: 'var(--bg-card)', border: `1px solid ${isOnline ? 'rgba(16,185,129,0.2)' : 'var(--border-color)'}` }}
                onClick={() => setSelected(agent)}
                onMouseEnter={(e) => e.currentTarget.style.borderColor = isOnline ? 'rgba(16,185,129,0.4)' : 'var(--border-light)'}
                onMouseLeave={(e) => e.currentTarget.style.borderColor = isOnline ? 'rgba(16,185,129,0.2)' : 'var(--border-color)'}>
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <AgentAvatar hostname={agent.hostname} online={isOnline} />
                    <div>
                      <div className="font-bold text-white text-sm">{agent.hostname}</div>
                      <div className="font-mono text-xs mt-0.5" style={{ color: '#93c5fd' }}>{agent.ip_address}</div>
                    </div>
                  </div>
                  <button onClick={(e) => { e.stopPropagation(); setConfirmDel(agent) }}
                    className="opacity-0 group-hover:opacity-100 w-7 h-7 rounded-lg flex items-center justify-center transition-all"
                    style={{ background: 'rgba(239,68,68,0.1)', color: '#fca5a5' }}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/>
                    </svg>
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="rounded-lg p-2" style={{ background: 'var(--bg-secondary)' }}>
                    <div style={{ color: 'var(--text-muted)' }}>{t('agents.os')}</div>
                    <div className="mt-0.5"><OsBadge os={agent.os} /></div>
                  </div>
                  <div className="rounded-lg p-2" style={{ background: 'var(--bg-secondary)' }}>
                    <div style={{ color: 'var(--text-muted)' }}>{t('agents.version')}</div>
                    <div className="font-medium text-white mt-0.5">{agent.agent_version || '—'}</div>
                  </div>
                </div>
                <div className="flex items-center justify-between mt-3 pt-3"
                  style={{ borderTop: '1px solid var(--border-color)' }}>
                  <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    {t('agents.lastSeen')}: {lastSeen}
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      ) : (
        /* Table view */
        <div className="rounded-2xl overflow-hidden"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
                {[t('agents.hostname'), t('agents.ipAddress'), t('agents.os'),
                  t('agents.version'), t('agents.status'), t('agents.lastSeen'), ''].map((h) => (
                  <th key={h} className="text-left px-5 py-3.5 text-xs font-bold uppercase tracking-wider"
                    style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((agent) => {
                const isOnline = agent.status === 'online'
                return (
                  <tr key={agent.agent_id} className="cursor-pointer transition-all"
                    style={{ borderBottom: '1px solid var(--border-color)' }}
                    onClick={() => setSelected(agent)}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-secondary)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}>
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-3">
                        <AgentAvatar hostname={agent.hostname} online={isOnline} />
                        <span className="font-semibold text-white">{agent.hostname}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3.5 font-mono text-xs" style={{ color: '#93c5fd' }}>{agent.ip_address}</td>
                    <td className="px-5 py-3.5"><OsBadge os={agent.os} /></td>
                    <td className="px-5 py-3.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{agent.agent_version || '—'}</td>
                    <td className="px-5 py-3.5">
                      <span className="inline-flex items-center gap-1.5 text-xs font-bold px-2.5 py-1 rounded-full"
                        style={{
                          background: isOnline ? 'rgba(16,185,129,0.12)' : 'rgba(107,114,128,0.12)',
                          color: isOnline ? '#6ee7b7' : '#9ca3af',
                        }}>
                        <span className="w-1.5 h-1.5 rounded-full" style={{
                          background: isOnline ? '#10b981' : '#6b7280',
                          boxShadow: isOnline ? '0 0 5px #10b981' : 'none',
                        }} />
                        {isOnline ? t('agents.online') : t('agents.offline')}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                      {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : '—'}
                    </td>
                    <td className="px-5 py-3.5" onClick={(e) => e.stopPropagation()}>
                      <button onClick={() => setConfirmDel(agent)}
                        className="text-xs px-2.5 py-1.5 rounded-lg transition-colors"
                        style={{ background: 'rgba(239,68,68,0.08)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.15)' }}>
                        {t('common.delete')}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {deployOpen && <DeployModal onClose={() => setDeployOpen(false)} />}
      {selected && <AgentModal agent={selected} onClose={() => setSelected(null)} />}

      {/* ── Delete confirm ── */}
      {confirmDel && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in"
          style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(8px)' }}>
          <div className="w-full max-w-sm rounded-2xl p-6 animate-slide-down"
            style={{ background: 'var(--bg-card)', border: '1px solid rgba(239,68,68,0.3)',
              boxShadow: '0 25px 60px rgba(0,0,0,0.7)' }}>
            <div className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4"
              style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)' }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2">
                <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/>
                <path d="M10 11v6"/><path d="M14 11v6"/>
              </svg>
            </div>
            <h3 className="font-black text-white text-center mb-1">{t('common.delete')} Agent</h3>
            <p className="text-sm text-center mb-6" style={{ color: 'var(--text-secondary)' }}>
              <span className="text-white font-semibold">"{confirmDel.hostname}"</span> — are you sure?
            </p>
            <div className="flex gap-3">
              <button onClick={() => handleDelete(confirmDel)}
                className="flex-1 py-2.5 rounded-xl font-bold text-sm transition-all"
                style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.3)' }}>
                {t('common.delete')}
              </button>
              <button onClick={() => setConfirmDel(null)}
                className="flex-1 btn-ghost py-2.5 text-sm">{t('common.cancel')}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
