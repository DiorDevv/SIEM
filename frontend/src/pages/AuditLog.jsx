import React, { useState, useEffect, useCallback } from 'react'
import { getAuditLogs, getAuditActions, exportAuditCSV } from '../api'
import { useLang } from '../context/LanguageContext'

const ACTION_COLORS = {
  login:                { bg: 'rgba(16,185,129,0.12)', color: '#6ee7b7' },
  create_rule:          { bg: 'rgba(99,102,241,0.12)', color: '#a5b4fc' },
  update_rule:          { bg: 'rgba(59,130,246,0.12)', color: '#60a5fa' },
  delete_rule:          { bg: 'rgba(239,68,68,0.12)',  color: '#f87171' },
  create_user:          { bg: 'rgba(99,102,241,0.12)', color: '#a5b4fc' },
  update_user:          { bg: 'rgba(59,130,246,0.12)', color: '#60a5fa' },
  delete_user:          { bg: 'rgba(239,68,68,0.12)',  color: '#f87171' },
  reset_user_password:  { bg: 'rgba(245,158,11,0.12)', color: '#fcd34d' },
  acknowledge_alert:    { bg: 'rgba(245,158,11,0.12)', color: '#fcd34d' },
  resolve_alert:        { bg: 'rgba(16,185,129,0.12)', color: '#6ee7b7' },
  delete_alert:         { bg: 'rgba(239,68,68,0.12)',  color: '#f87171' },
}

function ActionBadge({ action }) {
  const c = ACTION_COLORS[action] || { bg: 'rgba(107,114,128,0.12)', color: '#9ca3af' }
  return (
    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold"
      style={{ background: c.bg, color: c.color }}>
      {action.replace(/_/g, ' ')}
    </span>
  )
}

export default function AuditLog() {
  const { t } = useLang()
  const [logs, setLogs]         = useState([])
  const [total, setTotal]       = useState(0)
  const [loading, setLoading]   = useState(true)
  const [actions, setActions]   = useState([])
  const [page, setPage]         = useState(1)
  const SIZE = 50

  const [filters, setFilters] = useState({
    username: '', action: '', resource_type: '', days: 7,
  })

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, size: SIZE, days: filters.days }
      if (filters.username)      params.username      = filters.username
      if (filters.action)        params.action        = filters.action
      if (filters.resource_type) params.resource_type = filters.resource_type
      const r = await getAuditLogs(params)
      setLogs(r.data.logs)
      setTotal(r.data.total)
    } catch {}
    setLoading(false)
  }, [page, filters])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    getAuditActions().then((r) => setActions(r.data)).catch(() => {})
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

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div className="page-header-banner relative rounded-2xl overflow-hidden p-6"
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

      {/* Filters */}
      <div className="rounded-2xl p-4 flex flex-wrap gap-3 items-end"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        <div>
          <label className="block text-xs font-bold mb-1 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            {t('audit.userFilter')}
          </label>
          <input value={filters.username} placeholder="username..."
            onChange={(e) => { setFilters(p => ({ ...p, username: e.target.value })); setPage(1) }}
            className="w-36" />
        </div>
        <div>
          <label className="block text-xs font-bold mb-1 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            {t('audit.actionFilter')}
          </label>
          <select value={filters.action}
            onChange={(e) => { setFilters(p => ({ ...p, action: e.target.value })); setPage(1) }}
            className="w-44">
            <option value="">{t('common.filter')} — All</option>
            {actions.map((a) => <option key={a} value={a}>{a.replace(/_/g, ' ')}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-bold mb-1 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            {t('audit.resourceFilter')}
          </label>
          <select value={filters.resource_type}
            onChange={(e) => { setFilters(p => ({ ...p, resource_type: e.target.value })); setPage(1) }}
            className="w-32">
            <option value="">All</option>
            {['user','rule','alert','agent'].map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-bold mb-1 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            {t('audit.daysFilter')}
          </label>
          <select value={filters.days}
            onChange={(e) => { setFilters(p => ({ ...p, days: Number(e.target.value) })); setPage(1) }}
            className="w-28">
            {[1,3,7,14,30,90].map((d) => <option key={d} value={d}>{d}d</option>)}
          </select>
        </div>
        <button onClick={load} className="px-4 py-2 rounded-xl text-sm font-bold h-9"
          style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)' }}>
          {t('common.refresh')}
        </button>
        <button onClick={handleExport} className="px-4 py-2 rounded-xl text-sm font-bold h-9"
          style={{ background: 'rgba(16,185,129,0.12)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.25)' }}>
          {t('common.export')} CSV
        </button>
        <span className="ml-auto text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>
          {total} {t('audit.records')}
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
                    t('audit.colResource'), t('audit.colDetails'), t('audit.colIP')].map((h) => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-bold uppercase tracking-wider"
                      style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}
                    className="hover:bg-white/5 transition-colors">
                    <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 font-semibold text-white">{log.username || '—'}</td>
                    <td className="px-4 py-3"><ActionBadge action={log.action} /></td>
                    <td className="px-4 py-3">
                      {log.resource_type && (
                        <div>
                          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{log.resource_type} </span>
                          <span className="text-xs font-medium text-white">{log.resource_name || log.resource_id}</span>
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs max-w-xs truncate" style={{ color: 'var(--text-secondary)' }}>
                      {log.details ? JSON.stringify(log.details) : '—'}
                    </td>
                    <td className="px-4 py-3 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                      {log.ip_address || '—'}
                    </td>
                  </tr>
                ))}
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
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold disabled:opacity-40"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>
              {t('common.prev')}
            </button>
            <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages}
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
