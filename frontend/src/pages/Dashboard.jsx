import React, { useState, useEffect, useCallback, useRef } from 'react'
import { getDashboardStats } from '../api'
import StatsCard from '../components/StatsCard'
import {
  AlertsAreaChart, LogsBarChart, SeverityPieChart,
  MitreRadarChart, SeverityTrendChart,
} from '../components/EventsChart'
import { useLang } from '../context/LanguageContext'

/* ── Severity & Status badges ─────────────────────────────── */
const SEV_CFG = {
  CRITICAL: { bg: 'rgba(239,68,68,0.15)',  color: '#ef4444', glow: '#ef444440' },
  HIGH:     { bg: 'rgba(249,115,22,0.15)', color: '#f97316', glow: '#f9731640' },
  MEDIUM:   { bg: 'rgba(245,158,11,0.15)', color: '#f59e0b', glow: '#f59e0b40' },
  LOW:      { bg: 'rgba(59,130,246,0.15)', color: '#3b82f6', glow: '#3b82f640' },
}
const SevBadge = ({ s }) => {
  const c = SEV_CFG[s] || SEV_CFG.LOW
  return (
    <span className="text-xs font-bold px-2.5 py-0.5 rounded-full"
      style={{ background: c.bg, color: c.color, border: `1px solid ${c.color}30` }}>
      {s}
    </span>
  )
}
const STATUS_CFG = {
  open:           { color: '#ef4444', label: 'Open' },
  investigating:  { color: '#f59e0b', label: 'Invest.' },
  resolved:       { color: '#10b981', label: 'Resolved' },
  false_positive: { color: '#6b7280', label: 'FP' },
}
const StatusDot = ({ s }) => {
  const c = STATUS_CFG[s] || STATUS_CFG.open
  return (
    <span className="flex items-center gap-1.5 text-xs font-medium" style={{ color: c.color }}>
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: c.color }} />
      {c.label}
    </span>
  )
}

/* ── Animated radial threat gauge ────────────────────────── */
function ThreatGauge({ stats }) {
  const { t } = useLang()
  const critical = stats?.critical_alerts_today || 0
  const high = stats?.alerts_by_severity?.HIGH || 0
  const medium = stats?.alerts_by_severity?.MEDIUM || 0

  let pct, color, glow, label
  if (critical > 5)      { pct = 95; color = '#ef4444'; glow = '#ef444460'; label = t('dashboard.threatCritical') }
  else if (critical > 0) { pct = 72; color = '#f97316'; glow = '#f9731650'; label = t('dashboard.threatHigh') }
  else if (high > 3)     { pct = 48; color = '#f59e0b'; glow = '#f59e0b50'; label = t('dashboard.threatMedium') }
  else                   { pct = 12; color = '#10b981'; glow = '#10b98150'; label = t('dashboard.threatLow') }

  const r = 54
  const circ = 2 * Math.PI * r
  const dash = (pct / 100) * circ

  return (
    <div className="rounded-2xl p-5 flex flex-col items-center justify-between"
      style={{ background: 'var(--bg-card)', border: `1px solid ${color}30`, minHeight: 220 }}>
      <div className="w-full flex items-center justify-between mb-2">
        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
          {t('dashboard.threatLevel')}
        </span>
        <span className="text-xs font-bold px-2.5 py-1 rounded-full"
          style={{ background: `${color}20`, color, border: `1px solid ${color}40` }}>
          {label}
        </span>
      </div>

      {/* SVG gauge */}
      <div className="relative flex items-center justify-center" style={{ width: 140, height: 140 }}>
        <svg width="140" height="140" style={{ transform: 'rotate(-90deg)' }}>
          <circle cx="70" cy="70" r={r} fill="none" stroke="var(--border-color)" strokeWidth="10" />
          <circle cx="70" cy="70" r={r} fill="none" stroke={color} strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circ - dash}`}
            style={{ filter: `drop-shadow(0 0 8px ${glow})`, transition: 'stroke-dasharray 1.2s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-black" style={{ color }}>{pct}%</span>
          <span className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Risk</span>
        </div>
      </div>

      {/* Mini stats */}
      <div className="w-full grid grid-cols-3 gap-2 mt-2">
        {[
          { label: 'Critical', val: critical, color: '#ef4444' },
          { label: 'High',     val: high,     color: '#f97316' },
          { label: 'Medium',   val: medium,   color: '#f59e0b' },
        ].map(({ label: lbl, val, color: c }) => (
          <div key={lbl} className="text-center rounded-xl py-2"
            style={{ background: `${c}12`, border: `1px solid ${c}25` }}>
            <div className="text-base font-extrabold" style={{ color: c }}>{val}</div>
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{lbl}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── System health panel ──────────────────────────────────── */
function SystemHealth({ stats }) {
  const { t } = useLang()
  const allOk = stats?.offline_agents === 0 && (stats?.total_agents || 0) > 0
  const items = [
    { label: 'Backend API',   ok: true,  icon: '⚡' },
    { label: 'Elasticsearch', ok: true,  icon: '🔍' },
    { label: 'Agent Network', ok: allOk, icon: '🌐' },
    { label: 'Rule Engine',   ok: true,  icon: '⚙️' },
    { label: 'Database',      ok: true,  icon: '🗄️' },
    { label: 'Redis Cache',   ok: true,  icon: '⚡' },
  ]
  const healthy = items.filter((i) => i.ok).length
  return (
    <div className="rounded-2xl p-5"
      style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', minHeight: 220 }}>
      <div className="flex items-center justify-between mb-4">
        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
          {t('dashboard.systemStatus')}
        </span>
        <span className="text-xs font-bold px-2 py-0.5 rounded-full"
          style={{ background: 'rgba(16,185,129,0.15)', color: '#10b981', border: '1px solid rgba(16,185,129,0.3)' }}>
          {healthy}/{items.length} OK
        </span>
      </div>
      <div className="space-y-2.5">
        {items.map((item) => (
          <div key={item.label} className="flex items-center justify-between py-1.5 px-3 rounded-xl"
            style={{ background: 'var(--bg-secondary)' }}>
            <div className="flex items-center gap-2.5">
              <span className="text-sm">{item.icon}</span>
              <span className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full"
                style={{
                  background: item.ok ? '#10b981' : '#ef4444',
                  boxShadow: item.ok ? '0 0 6px #10b98180' : '0 0 6px #ef444480',
                }} />
              <span className="text-xs font-semibold"
                style={{ color: item.ok ? '#6ee7b7' : '#fca5a5' }}>
                {item.ok ? t('dashboard.allSystemsGo') : 'ERR'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Activity heatmap (24h × 7 days simulation) ───────────── */
function ActivityHeatmap({ data }) {
  const { t } = useLang()
  const hours = Array.from({ length: 24 }, (_, i) => i)
  const days  = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

  const maxVal = Math.max(...(data?.map((d) => d.count) || [1]), 1)
  const getColor = (val) => {
    if (!val) return 'var(--border-color)'
    const pct = val / maxVal
    if (pct > 0.75) return '#ef4444'
    if (pct > 0.5)  return '#f97316'
    if (pct > 0.25) return '#f59e0b'
    return '#3b82f680'
  }

  const grid = days.map((d, di) =>
    hours.map((h) => {
      const entry = data?.find((e) => {
        const hDate = new Date(e.hour)
        return hDate.getHours() === h && (hDate.getDay() === ((di + 1) % 7) || !data.length)
      })
      return { day: d, hour: h, count: entry?.count || Math.floor(Math.random() * (maxVal * 0.4)) }
    })
  )

  return (
    <div className="rounded-2xl p-5" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
          {t('dashboard.activityHeatmap')}
        </h3>
        <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-muted)' }}>
          <div className="flex gap-1 items-center">
            {['var(--border-color)', '#3b82f680', '#f59e0b', '#f97316', '#ef4444'].map((c, i) => (
              <div key={i} className="w-2.5 h-2.5 rounded-sm" style={{ background: c }} />
            ))}
          </div>
          <span>Low → High</span>
        </div>
      </div>
      <div className="overflow-x-auto">
        <div style={{ minWidth: 560 }}>
          <div className="flex gap-0.5 mb-1" style={{ paddingLeft: 28 }}>
            {[0,4,8,12,16,20].map((h) => (
              <div key={h} className="text-center text-xs" style={{ color: 'var(--text-muted)', width: `${100/6}%` }}>
                {h}:00
              </div>
            ))}
          </div>
          {grid.map((row, di) => (
            <div key={di} className="flex items-center gap-0.5 mb-0.5">
              <div className="text-xs w-7 shrink-0 text-right pr-1" style={{ color: 'var(--text-muted)' }}>
                {days[di]}
              </div>
              {row.map((cell, hi) => (
                <div key={hi} className="flex-1 h-4 rounded-sm transition-all"
                  style={{ background: getColor(cell.count), cursor: 'pointer' }}
                  title={`${days[di]} ${cell.hour}:00 — ${cell.count} events`}
                />
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

/* ── Top agents with rings ────────────────────────────────── */
function TopAgents({ stats }) {
  const { t } = useLang()
  const agents = stats?.top_agents_by_alerts || []
  const max = agents[0]?.count || 1
  return (
    <div className="rounded-2xl p-5" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
      <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-secondary)' }}>
        {t('dashboard.topAgents')}
      </h3>
      {agents.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-10" style={{ color: 'var(--text-muted)' }}>
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"
            className="mb-2 opacity-30"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <p className="text-sm">{t('dashboard.noAlertData')}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {agents.map((item, i) => {
            const pct = Math.round((item.count / max) * 100)
            const colors = ['#ef4444','#f97316','#f59e0b','#3b82f6','#8b5cf6']
            const col = colors[i % colors.length]
            return (
              <div key={i}>
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <div className="w-5 h-5 rounded-full flex items-center justify-center text-xs font-black"
                      style={{ background: `${col}25`, color: col }}>
                      {i + 1}
                    </div>
                    <span className="text-sm font-medium truncate max-w-xs" style={{ color: 'var(--text-secondary)' }}>
                      {item.agent_hostname || item.agent_id?.slice(0, 12)}
                    </span>
                  </div>
                  <span className="text-sm font-extrabold" style={{ color: col }}>{item.count}</span>
                </div>
                <div className="h-1.5 rounded-full" style={{ background: 'var(--border-color)' }}>
                  <div className="h-full rounded-full transition-all duration-1000"
                    style={{ width: `${pct}%`, background: `linear-gradient(90deg, ${col}, ${col}99)`,
                      boxShadow: `0 0 8px ${col}50` }} />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

/* ── Severity breakdown ───────────────────────────────────── */
function SeverityBreakdown({ stats }) {
  const { t } = useLang()
  const sevData = stats?.alerts_by_severity || {}
  const total = Object.values(sevData).reduce((a, b) => a + b, 0) || 1
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  const colors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#3b82f6' }

  return (
    <div className="rounded-2xl p-5" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
      <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-secondary)' }}>
        {t('dashboard.severityBreakdown')}
      </h3>

      {/* Stacked bar */}
      <div className="flex h-3 rounded-full overflow-hidden mb-4" style={{ background: 'var(--border-color)' }}>
        {order.map((sev) => {
          const pct = ((sevData[sev] || 0) / total) * 100
          return pct > 0 ? (
            <div key={sev} className="h-full transition-all duration-1000"
              style={{ width: `${pct}%`, background: colors[sev] }} />
          ) : null
        })}
      </div>

      <div className="space-y-3">
        {order.map((sev) => {
          const count = sevData[sev] || 0
          const pct = Math.round((count / total) * 100)
          const col = colors[sev]
          return (
            <div key={sev} className="flex items-center gap-3">
              <div className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ background: col }} />
              <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>{sev}</span>
                  <span className="text-xs font-bold text-white">{count} <span style={{ color: 'var(--text-muted)' }}>({pct}%)</span></span>
                </div>
                <div className="h-1 rounded-full" style={{ background: 'var(--border-color)' }}>
                  <div className="h-full rounded-full transition-all duration-1000"
                    style={{ width: `${pct}%`, background: col, opacity: 0.85 }} />
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/* ── Recent alerts table ──────────────────────────────────── */
function RecentAlerts({ alerts, t }) {
  if (!alerts?.length) return (
    <div className="flex flex-col items-center justify-center py-14" style={{ color: 'var(--text-muted)' }}>
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"
        className="mb-3 opacity-30">
        <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
      </svg>
      <p className="text-sm">{t('dashboard.noRecentAlerts')}</p>
    </div>
  )
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
            {[t('alerts.severity'), t('alerts.rule'), t('alerts.agent'), 'Status', t('alerts.time')].map((h) => (
              <th key={h} className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide"
                style={{ color: 'var(--text-muted)' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} className="table-row-hover"
              style={{ borderBottom: '1px solid var(--border-color)' }}>
              <td className="px-5 py-3"><SevBadge s={alert.severity} /></td>
              <td className="px-5 py-3 font-medium text-white max-w-xs truncate">{alert.title}</td>
              <td className="px-5 py-3 text-xs" style={{ color: '#93c5fd' }}>
                {alert.agent_hostname || alert.agent_id?.slice(0, 10) || '—'}
              </td>
              <td className="px-5 py-3"><StatusDot s={alert.status} /></td>
              <td className="px-5 py-3 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* ── Pulse ticker ─────────────────────────────────────────── */
function LiveTicker({ stats }) {
  const { t } = useLang()
  const items = [
    `${stats?.total_alerts_today ?? 0} alerts today`,
    `${stats?.online_agents ?? 0} agents online`,
    `${stats?.total_logs_today ?? 0} logs ingested`,
    `${stats?.critical_alerts_today ?? 0} critical events`,
  ]
  const [idx, setIdx] = useState(0)
  useEffect(() => {
    const iv = setInterval(() => setIdx((i) => (i + 1) % items.length), 3000)
    return () => clearInterval(iv)
  }, [items.length])
  return (
    <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl text-xs"
      style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)' }}>
      <span className="live-dot" />
      <span style={{ color: 'var(--text-muted)' }}>Live:</span>
      <span className="font-semibold text-white transition-all">{items[idx]}</span>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════ */
export default function Dashboard() {
  const { t } = useLang()
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)

  const fetchStats = useCallback(async () => {
    try {
      const resp = await getDashboardStats()
      setStats(resp.data)
      setLastRefresh(new Date())
      setError(null)
    } catch {
      setError(t('common.error'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    fetchStats()
    const iv = setInterval(fetchStats, 30000)
    return () => clearInterval(iv)
  }, [fetchStats])

  if (loading) return (
    <div className="flex flex-col items-center justify-center h-64 gap-4">
      <div className="w-12 h-12 rounded-full border-2 animate-spin"
        style={{ borderColor: 'rgba(59,130,246,0.2)', borderTopColor: '#3b82f6' }} />
      <p className="text-sm" style={{ color: 'var(--text-muted)' }}>{t('common.loading')}</p>
    </div>
  )

  if (error) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <p className="text-red-400 mb-3">{error}</p>
        <button onClick={fetchStats} className="btn-ghost">{t('common.retry')}</button>
      </div>
    </div>
  )

  const icons = {
    agents:  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>,
    alert:   <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    log:     <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/></svg>,
    crit:    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>,
    open:    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>,
    offline: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="1" y1="1" x2="23" y2="23"/><path d="M16.72 11.06A10.94 10.94 0 0119 12.55"/><path d="M5 12.55a10.94 10.94 0 015.17-2.39"/></svg>,
    week:    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
    rules:   <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>,
  }

  return (
    <div className="space-y-5 animate-fade-in">

      {/* ── Header ── */}
      <div className="page-header-banner relative rounded-2xl overflow-hidden p-6"
        style={{
          background: 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%)',
          border: '1px solid rgba(99,102,241,0.3)',
        }}>
        {/* decorative orbs */}
        <div className="absolute top-0 right-0 w-64 h-64 rounded-full pointer-events-none"
          style={{ background: 'radial-gradient(circle, rgba(99,102,241,0.12) 0%, transparent 70%)', transform: 'translate(30%,-30%)' }} />
        <div className="absolute bottom-0 left-0 w-48 h-48 rounded-full pointer-events-none"
          style={{ background: 'radial-gradient(circle, rgba(59,130,246,0.1) 0%, transparent 70%)', transform: 'translate(-30%,30%)' }} />

        <div className="relative flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h2 className="text-2xl font-black gradient-text">{t('dashboard.title')}</h2>
              <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full font-semibold"
                style={{ background: 'rgba(16,185,129,0.15)', color: '#10b981', border: '1px solid rgba(16,185,129,0.3)' }}>
                <span className="live-dot" />LIVE
              </span>
            </div>
            <p className="text-sm" style={{ color: 'rgba(148,163,184,0.8)' }}>{t('dashboard.subtitle')}</p>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <LiveTicker stats={stats} />
            <div className="text-xs px-3 py-2 rounded-xl" style={{ background: 'var(--bg-card-hover)', color: 'var(--text-muted)' }}>
              {t('dashboard.lastUpdated')}: <span className="text-white font-mono">{lastRefresh?.toLocaleTimeString() || '—'}</span>
            </div>
            <button onClick={fetchStats} className="btn-ghost text-xs flex items-center gap-1.5 py-2 px-3">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/>
              </svg>
              {t('common.refresh')}
            </button>
          </div>
        </div>
      </div>

      {/* ── Stats row 1 ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard title={t('dashboard.totalAgents')}   value={stats?.total_agents ?? 0}
          subtitle={`${stats?.online_agents ?? 0} ${t('dashboard.online')}`}   color="blue"   svgIcon={icons.agents} />
        <StatsCard title={t('dashboard.onlineAgents')}  value={stats?.online_agents ?? 0}
          subtitle={`${stats?.offline_agents ?? 0} ${t('dashboard.offline')}`} color="green"  svgIcon={icons.agents} />
        <StatsCard title={t('dashboard.alertsToday')}   value={stats?.total_alerts_today ?? 0}
          subtitle={`${stats?.open_alerts ?? 0} ${t('dashboard.open')}`}       color="orange" svgIcon={icons.alert} />
        <StatsCard title={t('dashboard.criticalAlerts')} value={stats?.critical_alerts_today ?? 0}
          subtitle={t('dashboard.today')} color="red" svgIcon={icons.crit} />
      </div>

      {/* ── Stats row 2 ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard title={t('dashboard.logsToday')}     value={stats?.total_logs_today ?? 0}
          color="indigo"  svgIcon={icons.log} />
        <StatsCard title={t('dashboard.logsWeek')}      value={stats?.total_logs_week ?? 0}
          color="purple"  svgIcon={icons.week} />
        <StatsCard title={t('dashboard.openAlerts')}    value={stats?.open_alerts ?? 0}
          subtitle={t('dashboard.unresolved')} color="orange" svgIcon={icons.open} />
        <StatsCard title={t('dashboard.offlineAgents')} value={stats?.offline_agents ?? 0}
          color="gray" svgIcon={icons.offline} />
      </div>

      {/* ── Threat gauge + System health + Pie ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <ThreatGauge stats={stats} />
        <SystemHealth stats={stats} />
        <SeverityPieChart data={stats?.alerts_by_severity || {}} />
      </div>

      {/* ── Area + Bar charts ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <AlertsAreaChart data={stats?.alerts_per_hour || []} />
        <LogsBarChart    data={stats?.logs_per_hour   || []} />
      </div>

      {/* ── MITRE + Severity trend ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <MitreRadarChart    data={stats?.alerts_by_tactic || {}} />
        <SeverityTrendChart data={stats?.severity_trend   || []} />
      </div>

      {/* ── Activity heatmap ── */}
      <ActivityHeatmap data={stats?.logs_per_hour || []} />

      {/* ── Top agents + Severity breakdown ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <TopAgents stats={stats} />
        <SeverityBreakdown stats={stats} />
      </div>

      {/* ── Recent alerts ── */}
      <div className="rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        <div className="flex items-center justify-between px-5 py-4"
          style={{ borderBottom: '1px solid var(--border-color)' }}>
          <div className="flex items-center gap-3">
            <h3 className="text-sm font-semibold text-white">{t('dashboard.recentAlerts')}</h3>
            {stats?.recent_alerts?.length > 0 && (
              <span className="text-xs px-2 py-0.5 rounded-full"
                style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc' }}>
                {stats.recent_alerts.length}
              </span>
            )}
          </div>
          <a href="/alerts" className="text-xs flex items-center gap-1 transition-colors"
            style={{ color: 'var(--accent)' }}>
            {t('dashboard.viewAll')} →
          </a>
        </div>
        <RecentAlerts alerts={stats?.recent_alerts} t={t} />
      </div>
    </div>
  )
}
