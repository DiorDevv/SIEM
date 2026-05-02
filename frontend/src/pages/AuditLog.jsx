import React, { useState, useEffect, useCallback } from 'react'
import { getAuditLogs, getAuditActions, exportAuditCSV } from '../api'
import { useLang } from '../context/LanguageContext'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'

const ACTION_COLORS = {
  login:               '#10b981',
  logout:              '#6b7280',
  create_rule:         '#6366f1',
  update_rule:         '#3b82f6',
  delete_rule:         '#ef4444',
  create_user:         '#6366f1',
  update_user:         '#3b82f6',
  delete_user:         '#ef4444',
  reset_user_password: '#f59e0b',
  acknowledge_alert:   '#f59e0b',
  resolve_alert:       '#10b981',
  close_alert:         '#8b5cf6',
  delete_alert:        '#ef4444',
  false_positive:      '#64748b',
  update_config:       '#0ea5e9',
  create_ar_policy:    '#6366f1',
  delete_ar_policy:    '#ef4444',
}

function ActionBadge({ action }) {
  const color = ACTION_COLORS[action] || '#6b7280'
  return (
    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold"
      style={{ background: `${color}18`, color }}>
      {action.replace(/_/g, ' ')}
    </span>
  )
}

function StatusDot({ status }) {
  const color = status === 'failed' ? '#ef4444' : '#10b981'
  return (
    <span className="flex items-center gap-1.5 text-xs font-semibold" style={{ color }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
      {status}
    </span>
  )
}

function MiniStatCard({ label, value, color = '#818cf8', sub }) {
  return (
    <div className="rounded-xl p-4 flex flex-col gap-1"
      style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
      <span className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{label}</span>
      <span className="text-2xl font-black" style={{ color }}>{value ?? '—'}</span>
      {sub && <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{sub}</span>}
    </div>
  )
}

function ExpandedDetails({ details, action, resource_type, resource_name, resource_id }) {
  if (!details && !resource_name && !resource_id) return null
  return (
    <tr style={{ background: 'rgba(99,102,241,0.04)' }}>
      <td colSpan={6} className="px-4 py-3">
        <div className="flex flex-wrap gap-6 text-xs">
          {resource_type && (
            <div>
              <span className="font-bold uppercase tracking-wider mr-2" style={{ color: 'var(--text-muted)' }}>Resource</span>
              <span className="text-white">{resource_type}</span>
              {resource_name && <span className="ml-1 text-white font-semibold">"{resource_name}"</span>}
              {resource_id && !resource_name && <span className="ml-1 font-mono" style={{ color: 'var(--text-muted)' }}>#{resource_id}</span>}
            </div>
          )}
          {details && (
            <div className="flex-1">
              <span className="font-bold uppercase tracking-wider mr-2" style={{ color: 'var(--text-muted)' }}>Details</span>
              <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                {typeof details === 'object'
                  ? Object.entries(details).map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join('  |  ')
                  : String(details)}
              </span>
            </div>
          )}
        </div>
      </td>
    </tr>
  )
}

export default function AuditLog() {
  const { t } = useLang()
  const [logs, setLogs]         = useState([])
  const [total, setTotal]       = useState(0)
  const [loading, setLoading]   = useState(true)
  const [actions, setActions]   = useState([])
  const [stats, setStats]       = useState(null)
  const [expanded, setExpanded] = useState(null)
  const [page, setPage]         = useState(1)
  const SIZE = 50

  const [filters, setFilters] = useState({
    username: '', action: '', resource_type: '', status: '', days: 7,
  })

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, size: SIZE, days: filters.days }
      if (filters.username)      params.username      = filters.username
      if (filters.action)        params.action        = filters.action
      if (filters.resource_type) params.resource_type = filters.resource_type
      if (filters.status)        params.status        = filters.status
      const r = await getAuditLogs(params)
      setLogs(r.data.logs)
      setTotal(r.data.total)
    } catch {}
    setLoading(false)
  }, [page, filters])

  const loadStats = useCallback(async () => {
    try {
      const token = localStorage.getItem('access_token')
      if (!token) return
      const r = await fetch(`/api/audit/stats?days=${filters.days}`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (r.ok) setStats(await r.json())
    } catch {}
  }, [filters.days])

  useEffect(() => { load() }, [load])
  useEffect(() => { loadStats() }, [loadStats])
  useEffect(() => {
    getAuditActions().then(r => setActions(r.data)).catch(() => {})
  }, [])

  const handleExport = async () => {
    try {
      const r = await exportAuditCSV({ days: filters.days })
      const url = URL.createObjectURL(new Blob([r.data]))
      const a = document.createElement('a')
      a.href = url; a.download = 'audit_log.csv'; a.click()
      URL.revokeObjectURL(url)
    } catch {}
  }

  const totalPages = Math.max(1, Math.ceil(total / SIZE))
  const failRate = stats?.total > 0 ? Math.round((stats.failed / stats.total) * 100) : 0

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div className="relative rounded-2xl overflow-hidden p-6"
        style={{ background: 'linear-gradient(135deg,#0f172a,#1a1f35,#0f172a)',
          border: '1px solid rgba(99,102,241,0.2)' }}>
        <div className="absolute top-0 right-0 w-64 h-64 pointer-events-none"
          style={{ background: 'radial-gradient(circle,rgba(99,102,241,0.08) 0%,transparent 70%)',
            transform: 'translate(25%,-25%)' }} />
        <div className="relative">
          <h1 className="text-2xl font-black text-white">{t('audit.title')}</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>{t('audit.subtitle')}</p>
        </div>
      </div>

      {/* Stats cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <MiniStatCard label="Total Events" value={stats.total?.toLocaleString()} color="#818cf8"
            sub={`last ${filters.days} days`} />
          <MiniStatCard label="Failed Actions" value={stats.failed} color={stats.failed > 0 ? '#ef4444' : '#10b981'}
            sub={`${failRate}% failure rate`} />
          <MiniStatCard label="Unique Users" value={stats.unique_users} color="#0ea5e9"
            sub="distinct actors" />
          <MiniStatCard label="Top Action"
            value={stats.top_actions?.[0]?.action?.replace(/_/g, ' ') || '—'}
            color="#f59e0b"
            sub={`${stats.top_actions?.[0]?.count || 0} times`} />
        </div>
      )}

      {/* Charts row */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Hourly trend */}
          <div className="rounded-2xl p-5"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            <h3 className="text-sm font-bold text-white mb-4">Events — Last 24 Hours</h3>
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={stats.hourly_trend || []} barCategoryGap="20%">
                <XAxis dataKey="hour" tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
                  axisLine={false} tickLine={false} interval={5} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 8 }}
                  labelStyle={{ color: '#fff' }} itemStyle={{ color: '#a5b4fc' }} />
                <Bar dataKey="count" fill="#6366f1" radius={[3,3,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Top users */}
          <div className="rounded-2xl p-5"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            <h3 className="text-sm font-bold text-white mb-4">Top Users by Activity</h3>
            <div className="space-y-2">
              {(stats.top_users || []).slice(0, 6).map((u, i) => {
                const max = stats.top_users[0]?.count || 1
                const pct = Math.round((u.count / max) * 100)
                return (
                  <div key={i} className="flex items-center gap-3">
                    <span className="text-xs font-mono w-20 truncate text-white">{u.username}</span>
                    <div className="flex-1 h-4 rounded-full overflow-hidden" style={{ background: 'var(--bg-secondary)' }}>
                      <div className="h-full rounded-full transition-all"
                        style={{ width: `${pct}%`, background: 'linear-gradient(90deg,#6366f1,#818cf8)' }} />
                    </div>
                    <span className="text-xs font-bold w-8 text-right" style={{ color: '#818cf8' }}>{u.count}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {/* Top actions */}
      {stats?.top_actions?.length > 0 && (
        <div className="rounded-2xl p-5 flex flex-wrap gap-3"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          <span className="text-xs font-bold uppercase tracking-wider w-full" style={{ color: 'var(--text-muted)' }}>
            Top Actions (last {filters.days}d)
          </span>
          {stats.top_actions.map((a, i) => {
            const color = ACTION_COLORS[a.action] || '#6b7280'
            return (
              <div key={i} className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold"
                style={{ background: `${color}12`, border: `1px solid ${color}25`, color }}>
                {a.action.replace(/_/g, ' ')}
                <span className="ml-1 px-1.5 py-0.5 rounded-full text-xs font-black"
                  style={{ background: `${color}20` }}>{a.count}</span>
              </div>
            )
          })}
        </div>
      )}

      {/* Filters */}
      <div className="rounded-2xl p-4 flex flex-wrap gap-3 items-end"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        <div>
          <label className="block text-xs font-bold mb-1 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            {t('audit.userFilter')}
          </label>
          <input value={filters.username} placeholder="username..."
            onChange={e => { setFilters(p => ({ ...p, username: e.target.value })); setPage(1) }}
            className="w-36" />
        </div>
        <div>
          <label className="block text-xs font-bold mb-1 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            {t('audit.actionFilter')}
          </label>
          <select value={filters.action}
            onChange={e => { setFilters(p => ({ ...p, action: e.target.value })); setPage(1) }}
            className="w-44">
            <option value="">All Actions</option>
            {actions.map(a => <option key={a} value={a}>{a.replace(/_/g, ' ')}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-bold mb-1 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            {t('audit.resourceFilter')}
          </label>
          <select value={filters.resource_type}
            onChange={e => { setFilters(p => ({ ...p, resource_type: e.target.value })); setPage(1) }}
            className="w-32">
            <option value="">All</option>
            {['user', 'rule', 'alert', 'agent', 'ar_policy', 'system'].map(r =>
              <option key={r} value={r}>{r}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-bold mb-1 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            Status
          </label>
          <select value={filters.status}
            onChange={e => { setFilters(p => ({ ...p, status: e.target.value })); setPage(1) }}
            className="w-28">
            <option value="">All</option>
            <option value="success">Success</option>
            <option value="failed">Failed</option>
          </select>
        </div>
        <div>
          <label className="block text-xs font-bold mb-1 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            {t('audit.daysFilter')}
          </label>
          <select value={filters.days}
            onChange={e => { setFilters(p => ({ ...p, days: Number(e.target.value) })); setPage(1) }}
            className="w-28">
            {[1, 3, 7, 14, 30, 90].map(d => <option key={d} value={d}>{d}d</option>)}
          </select>
        </div>
        <button onClick={load}
          className="px-4 py-2 rounded-xl text-sm font-bold h-9"
          style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)' }}>
          {t('common.refresh')}
        </button>
        <button onClick={handleExport}
          className="px-4 py-2 rounded-xl text-sm font-bold h-9"
          style={{ background: 'rgba(16,185,129,0.12)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.25)' }}>
          {t('common.export')} CSV
        </button>
        <span className="ml-auto text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>
          {total.toLocaleString()} {t('audit.records')}
        </span>
      </div>

      {/* Table */}
      <div className="rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        {loading ? (
          <div className="flex items-center gap-3 p-8" style={{ color: 'var(--text-muted)' }}>
            <div className="w-5 h-5 border-2 rounded-full animate-spin"
              style={{ borderColor: 'rgba(99,102,241,0.2)', borderTopColor: '#818cf8' }} />
            <span className="text-sm">{t('common.loading')}</span>
          </div>
        ) : logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3">
            <span className="text-3xl">📋</span>
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>{t('common.noData')}</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
                  {[t('audit.colTime'), t('audit.colUser'), t('audit.colAction'),
                    t('audit.colResource'), 'Status', t('audit.colIP')].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-bold uppercase tracking-wider"
                      style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {logs.map(log => {
                  const isExpanded = expanded === log.id
                  return (
                    <React.Fragment key={log.id}>
                      <tr
                        onClick={() => setExpanded(isExpanded ? null : log.id)}
                        style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'pointer' }}
                        className="hover:bg-white/5 transition-colors">
                        <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="px-4 py-3 font-semibold text-white">{log.username || '—'}</td>
                        <td className="px-4 py-3"><ActionBadge action={log.action} /></td>
                        <td className="px-4 py-3">
                          {log.resource_type && (
                            <div className="flex items-center gap-1.5">
                              <span className="text-xs px-1.5 py-0.5 rounded"
                                style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)' }}>
                                {log.resource_type}
                              </span>
                              <span className="text-xs font-medium text-white truncate max-w-32">
                                {log.resource_name || log.resource_id || ''}
                              </span>
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3"><StatusDot status={log.status} /></td>
                        <td className="px-4 py-3 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                          {log.ip_address || '—'}
                        </td>
                      </tr>
                      {isExpanded && (
                        <ExpandedDetails
                          details={log.details}
                          action={log.action}
                          resource_type={log.resource_type}
                          resource_name={log.resource_name}
                          resource_id={log.resource_id}
                        />
                      )}
                    </React.Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            {t('common.page')} {page} {t('common.of')} {totalPages}
          </span>
          <div className="flex gap-2">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold disabled:opacity-40"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>
              {t('common.prev')}
            </button>
            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold disabled:opacity-40"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>
              {t('common.next')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
