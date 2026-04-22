import React, { useState, useEffect, useCallback } from 'react'
import { getAlerts, updateAlertStatus, exportAlertsCSV, exportAlertsJSON } from '../api'
import { useLang } from '../context/LanguageContext'

const SEV = {
  CRITICAL: { bg: 'rgba(239,68,68,0.15)',  border: 'rgba(239,68,68,0.4)',  color: '#ef4444', glow: '#ef444430' },
  HIGH:     { bg: 'rgba(249,115,22,0.15)', border: 'rgba(249,115,22,0.4)', color: '#f97316', glow: '#f9731630' },
  MEDIUM:   { bg: 'rgba(245,158,11,0.15)', border: 'rgba(245,158,11,0.4)', color: '#f59e0b', glow: '#f59e0b30' },
  LOW:      { bg: 'rgba(59,130,246,0.15)', border: 'rgba(59,130,246,0.4)', color: '#3b82f6', glow: '#3b82f630' },
}
const STATUS = {
  open:           { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',  label: 'Open' },
  investigating:  { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)', label: 'Investing.' },
  resolved:       { color: '#10b981', bg: 'rgba(16,185,129,0.1)', label: 'Resolved' },
  false_positive: { color: '#6b7280', bg: 'rgba(107,114,128,0.1)',label: 'FP' },
}

function SevBadge({ s }) {
  const c = SEV[s] || SEV.LOW
  return (
    <span className="text-xs font-black px-2.5 py-0.5 rounded-full tracking-wide"
      style={{ background: c.bg, color: c.color, border: `1px solid ${c.border}` }}>{s}</span>
  )
}
function StatusBadge({ s }) {
  const { t } = useLang()
  const c = STATUS[s] || STATUS.open
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-0.5 rounded-full"
      style={{ background: c.bg, color: c.color }}>
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: c.color }} />
      {t(`status.${s}`) || c.label}
    </span>
  )
}

/* ── Alert detail modal ─────────────────────────────────────── */
function AlertModal({ alert, onClose, onStatus }) {
  const { t } = useLang()
  if (!alert) return null
  const sev = SEV[alert.severity] || SEV.LOW
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in"
      style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(8px)' }}
      onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="w-full max-w-2xl rounded-2xl overflow-hidden animate-slide-down"
        style={{ background: 'var(--bg-card)', border: `1px solid ${sev.border}`, maxHeight: '90vh', overflowY: 'auto',
          boxShadow: `0 25px 60px rgba(0,0,0,0.7), 0 0 40px ${sev.glow}` }}>

        {/* header */}
        <div className="relative px-6 py-5 overflow-hidden"
          style={{ background: `linear-gradient(135deg, ${sev.bg}, var(--bg-secondary))`,
            borderBottom: `1px solid ${sev.border}` }}>
          <div className="absolute inset-0 opacity-30"
            style={{ background: `radial-gradient(circle at top right, ${sev.color}20, transparent 60%)` }} />
          <div className="relative flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                style={{ background: sev.bg, border: `1px solid ${sev.border}` }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={sev.color} strokeWidth="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                  <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
              </div>
              <div>
                <div className="flex items-center gap-2 mb-0.5">
                  <SevBadge s={alert.severity} />
                  <StatusBadge s={alert.status} />
                </div>
                <h3 className="font-bold text-white text-sm leading-tight">{alert.title}</h3>
              </div>
            </div>
            <button onClick={onClose} className="w-8 h-8 flex items-center justify-center rounded-xl text-lg transition-colors"
              style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)' }}>×</button>
          </div>
        </div>

        <div className="p-6 space-y-4">
          {/* info grid */}
          <div className="grid grid-cols-2 gap-2.5">
            {[
              [t('alerts.agent'),     alert.agent_hostname || alert.agent_id?.slice(0,16)],
              [t('alerts.rule'),      alert.rule_name || '—'],
              [t('alerts.srcIp'),     alert.src_ip || '—'],
              ['Level',               alert.level ?? '—'],
              ['MITRE Tactic',        alert.mitre_tactic || '—'],
              ['MITRE Technique',     alert.mitre_technique || '—'],
              [t('alerts.time'),      alert.created_at ? new Date(alert.created_at).toLocaleString() : '—'],
              ['Rule ID',             alert.rule_id ? `#${alert.rule_id}` : '—'],
            ].map(([k, v]) => (
              <div key={k} className="rounded-xl p-3" style={{ background: 'var(--bg-secondary)' }}>
                <div className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>{k}</div>
                <div className="text-sm font-medium text-white truncate">{v}</div>
              </div>
            ))}
          </div>

          {alert.description && (
            <div className="rounded-xl p-4" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
              <div className="text-xs font-semibold mb-2 uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                {t('alerts.description')}
              </div>
              <p className="text-sm text-white leading-relaxed">{alert.description}</p>
            </div>
          )}

          {alert.mitre_tactic && (
            <div className="rounded-xl p-4" style={{ background: 'rgba(139,92,246,0.07)', border: '1px solid rgba(139,92,246,0.25)' }}>
              <div className="flex items-center gap-2 mb-3">
                <div className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                <div className="text-xs font-bold uppercase tracking-wider" style={{ color: '#a78bfa' }}>MITRE ATT&CK</div>
              </div>
              <div className="flex flex-wrap gap-2">
                <span className="text-xs px-3 py-1.5 rounded-full font-semibold"
                  style={{ background: 'rgba(139,92,246,0.2)', color: '#c4b5fd', border: '1px solid rgba(139,92,246,0.3)' }}>
                  {alert.mitre_tactic}
                </span>
                {alert.mitre_technique && (
                  <span className="text-xs px-3 py-1.5 rounded-full font-mono"
                    style={{ background: 'rgba(99,102,241,0.2)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)' }}>
                    {alert.mitre_technique}
                  </span>
                )}
              </div>
            </div>
          )}

          {alert.raw_log && (
            <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
              <div className="px-4 py-2.5 text-xs font-bold uppercase tracking-wider flex items-center gap-2"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', borderBottom: '1px solid var(--border-color)' }}>
                <span className="w-1.5 h-1.5 rounded-full bg-green-400" />{t('alerts.rawLog')}
              </div>
              <pre className="p-4 text-xs overflow-x-auto leading-relaxed"
                style={{ background: '#060c17', color: '#86efac', fontFamily: 'monospace', maxHeight: 160 }}>
                {alert.raw_log}
              </pre>
            </div>
          )}

          <div className="flex gap-3 pt-2">
            {alert.status !== 'resolved' && (
              <button onClick={() => { onStatus(alert.id, 'resolved'); onClose() }}
                className="flex-1 py-2.5 rounded-xl text-sm font-bold transition-all"
                style={{ background: 'rgba(16,185,129,0.15)', color: '#6ee7b7',
                  border: '1px solid rgba(16,185,129,0.3)' }}>
                ✓ {t('alerts.markResolved')}
              </button>
            )}
            {alert.status === 'open' && (
              <button onClick={() => { onStatus(alert.id, 'investigating'); onClose() }}
                className="flex-1 py-2.5 rounded-xl text-sm font-semibold transition-all"
                style={{ background: 'rgba(245,158,11,0.1)', color: '#fcd34d',
                  border: '1px solid rgba(245,158,11,0.3)' }}>
                🔍 {t('alerts.markInvestigating')}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════ */
export default function Alerts() {
  const { t } = useLang()
  const [alerts, setAlerts]           = useState([])
  const [total, setTotal]             = useState(0)
  const [loading, setLoading]         = useState(true)
  const [page, setPage]               = useState(1)
  const [search, setSearch]           = useState('')
  const [sevFilter, setSevFilter]     = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('all')
  const [selected, setSelected]       = useState(null)
  const SIZE = 20

  const fetchAlerts = useCallback(async () => {
    setLoading(true)
    try {
      const params = {
        page, size: SIZE,
        ...(sevFilter !== 'ALL' && { severity: sevFilter }),
        ...(statusFilter !== 'all' && { status: statusFilter }),
        ...(search && { keyword: search }),
      }
      const resp = await getAlerts(params)
      setAlerts(resp.data.alerts || [])
      setTotal(resp.data.total || 0)
    } catch {}
    finally { setLoading(false) }
  }, [page, sevFilter, statusFilter, search])

  useEffect(() => { setPage(1) }, [sevFilter, statusFilter, search])
  useEffect(() => { fetchAlerts() }, [fetchAlerts])

  const handleStatus = async (id, status) => {
    try {
      await updateAlertStatus(id, status)
      setAlerts((prev) => prev.map((a) => a.id === id ? { ...a, status } : a))
      if (selected?.id === id) setSelected((p) => ({ ...p, status }))
    } catch {}
  }

  const handleExportCSV = async () => {
    try {
      const params = { days: 30, ...(sevFilter !== 'ALL' && { severity: sevFilter }), ...(statusFilter !== 'ALL' && { status: statusFilter }) }
      const resp = await exportAlertsCSV(params)
      const url = URL.createObjectURL(new Blob([resp.data], { type: 'text/csv' }))
      const a = document.createElement('a'); a.href = url; a.download = `alerts_${Date.now()}.csv`; a.click()
      URL.revokeObjectURL(url)
    } catch {}
  }

  const handleExportJSON = async () => {
    try {
      const params = { days: 30, ...(sevFilter !== 'ALL' && { severity: sevFilter }), ...(statusFilter !== 'ALL' && { status: statusFilter }) }
      const resp = await exportAlertsJSON(params)
      const url = URL.createObjectURL(new Blob([resp.data], { type: 'application/json' }))
      const a = document.createElement('a'); a.href = url; a.download = `alerts_${Date.now()}.json`; a.click()
      URL.revokeObjectURL(url)
    } catch {}
  }

  const pages = Math.ceil(total / SIZE) || 1
  const sevCounts = alerts.reduce((acc, a) => ({ ...acc, [a.severity]: (acc[a.severity] || 0) + 1 }),
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 })

  return (
    <div className="space-y-5 animate-fade-in">

      {/* ── Banner ── */}
      <div className="page-header-banner relative rounded-2xl overflow-hidden p-6"
        style={{ background: 'linear-gradient(135deg, #0f172a 0%, #1c0a0a 60%, #0f172a 100%)',
          border: '1px solid rgba(239,68,68,0.2)' }}>
        <div className="absolute top-0 right-0 w-72 h-72 rounded-full pointer-events-none"
          style={{ background: 'radial-gradient(circle, rgba(239,68,68,0.08) 0%, transparent 70%)',
            transform: 'translate(30%,-30%)' }} />
        <div className="relative flex items-center justify-between flex-wrap gap-4">
          <div>
            <h2 className="text-2xl font-black text-white mb-1">{t('alerts.title')}</h2>
            <p className="text-sm" style={{ color: 'rgba(148,163,184,0.7)' }}>{t('alerts.subtitle')}</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="px-4 py-2 rounded-xl text-sm font-bold"
              style={{ background: 'rgba(239,68,68,0.1)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.2)' }}>
              {total} {t('alerts.total')}
            </div>
            <button onClick={fetchAlerts} className="btn-ghost py-2 px-3 text-xs flex items-center gap-1.5">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/>
              </svg>
              {t('common.refresh')}
            </button>
            <button onClick={handleExportCSV} className="btn-ghost py-2 px-3 text-xs flex items-center gap-1.5">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              CSV
            </button>
            <button onClick={handleExportJSON} className="btn-ghost py-2 px-3 text-xs flex items-center gap-1.5">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              JSON
            </button>
          </div>
        </div>
      </div>

      {/* ── Severity filter cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => {
          const c = SEV[s]
          const active = sevFilter === s
          const icons = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' }
          return (
            <button key={s} onClick={() => setSevFilter(active ? 'ALL' : s)}
              className="rounded-2xl p-5 text-left transition-all group"
              style={{
                background: active ? c.bg : 'var(--bg-card)',
                border: `1px solid ${active ? c.color : 'var(--border-color)'}`,
                boxShadow: active ? `0 0 24px ${c.glow}` : 'none',
                transform: active ? 'translateY(-2px)' : 'none',
              }}>
              <div className="flex items-center justify-between mb-3">
                <span className="text-lg">{icons[s]}</span>
                {active && <span className="text-xs px-2 py-0.5 rounded-full font-bold"
                  style={{ background: c.bg, color: c.color }}>✓</span>}
              </div>
              <div className="text-3xl font-black mb-1 transition-all"
                style={{ color: c.color, textShadow: active ? `0 0 20px ${c.color}` : 'none' }}>
                {sevCounts[s]}
              </div>
              <div className="text-xs font-semibold uppercase tracking-wider"
                style={{ color: active ? c.color : 'var(--text-muted)' }}>
                {t(`severity.${s}`)}
              </div>
            </button>
          )
        })}
      </div>

      {/* ── Search + status tabs ── */}
      <div className="flex flex-wrap items-center gap-3 rounded-2xl p-4"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        <div className="relative flex-1 min-w-52">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" width="14" height="14"
            viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
            style={{ color: 'var(--text-muted)' }}>
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input type="text" value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder={t('alerts.searchPlaceholder')} className="w-full" style={{ paddingLeft: 36 }} />
        </div>

        <div className="flex rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
          {[
            { key: 'all',          label: t('alerts.filterAll'),          dot: null },
            { key: 'open',         label: t('alerts.filterOpen'),         dot: '#ef4444' },
            { key: 'investigating',label: t('alerts.filterInvestigating'), dot: '#f59e0b' },
            { key: 'resolved',     label: t('alerts.filterResolved'),     dot: '#10b981' },
          ].map(({ key, label, dot }) => (
            <button key={key} onClick={() => setStatusFilter(key)}
              className="px-3.5 py-2 text-xs font-semibold transition-all flex items-center gap-1.5 whitespace-nowrap"
              style={{
                background: statusFilter === key ? 'var(--accent)' : 'transparent',
                color: statusFilter === key ? '#fff' : 'var(--text-secondary)',
              }}>
              {dot && <span className="w-1.5 h-1.5 rounded-full" style={{ background: dot }} />}
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Alerts table ── */}
      <div className="rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
                {[t('alerts.severity'), t('alerts.rule'), t('alerts.agent'),
                  t('alerts.srcIp'), 'MITRE', t('alerts.status'), t('alerts.time'), ''].map((h) => (
                  <th key={h} className="text-left px-4 py-3.5 text-xs font-bold uppercase tracking-wider whitespace-nowrap"
                    style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border-color)' }}>
                    {[60, 140, 90, 80, 100, 70, 90, 30].map((w, j) => (
                      <td key={j} className="px-4 py-4">
                        <div className="skeleton h-4 rounded" style={{ width: w }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : alerts.length === 0 ? (
                <tr><td colSpan={8} className="py-20">
                  <div className="flex flex-col items-center gap-3" style={{ color: 'var(--text-muted)' }}>
                    <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
                      style={{ background: 'var(--bg-secondary)' }}>
                      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="opacity-40">
                        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                      </svg>
                    </div>
                    <p className="text-sm font-medium">{t('alerts.noAlerts')}</p>
                  </div>
                </td></tr>
              ) : alerts.map((alert) => {
                const sev = SEV[alert.severity] || SEV.LOW
                return (
                  <tr key={alert.id}
                    className="group cursor-pointer transition-all"
                    style={{ borderBottom: '1px solid var(--border-color)' }}
                    onClick={() => setSelected(alert)}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-secondary)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}>
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2">
                        <div className="w-0.5 h-8 rounded-full flex-shrink-0" style={{ background: sev.color }} />
                        <SevBadge s={alert.severity} />
                      </div>
                    </td>
                    <td className="px-4 py-3.5 font-semibold text-white" style={{ maxWidth: 200 }}>
                      <div className="truncate">{alert.title}</div>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-lg flex items-center justify-center text-xs font-bold"
                          style={{ background: 'rgba(59,130,246,0.15)', color: '#93c5fd' }}>
                          {(alert.agent_hostname || '?')[0]?.toUpperCase()}
                        </div>
                        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                          {alert.agent_hostname || alert.agent_id?.slice(0, 8)}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3.5 font-mono text-xs" style={{ color: alert.src_ip ? '#93c5fd' : 'var(--text-muted)' }}>
                      {alert.src_ip || '—'}
                    </td>
                    <td className="px-4 py-3.5">
                      {alert.mitre_tactic ? (
                        <span className="text-xs px-2 py-0.5 rounded-full font-medium"
                          style={{ background: 'rgba(139,92,246,0.15)', color: '#c4b5fd', border: '1px solid rgba(139,92,246,0.2)' }}>
                          {alert.mitre_tactic}
                        </span>
                      ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                    </td>
                    <td className="px-4 py-3.5"><StatusBadge s={alert.status} /></td>
                    <td className="px-4 py-3.5 text-xs font-mono whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                      {alert.created_at ? new Date(alert.created_at).toLocaleString() : '—'}
                    </td>
                    <td className="px-4 py-3.5" onClick={(e) => e.stopPropagation()}>
                      {alert.status !== 'resolved' && (
                        <button onClick={() => handleStatus(alert.id, 'resolved')}
                          className="w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold transition-all"
                          style={{ background: 'rgba(16,185,129,0.1)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.2)' }}
                          title="Resolve">✓</button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {pages > 1 && (
          <div className="flex items-center justify-between px-5 py-3.5"
            style={{ borderTop: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
              {t('common.page')} <span className="text-white font-semibold">{page}</span> {t('common.of')} {pages}
            </span>
            <div className="flex gap-2">
              <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
                className="btn-ghost py-1.5 px-3.5 text-xs disabled:opacity-30">{t('common.prev')}</button>
              <button onClick={() => setPage((p) => Math.min(pages, p + 1))} disabled={page === pages}
                className="btn-ghost py-1.5 px-3.5 text-xs disabled:opacity-30">{t('common.next')}</button>
            </div>
          </div>
        )}
      </div>

      {selected && <AlertModal alert={selected} onClose={() => setSelected(null)} onStatus={handleStatus} />}
    </div>
  )
}
