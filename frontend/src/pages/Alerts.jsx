import React, { useState, useEffect, useCallback, useRef } from 'react'
import {
  getAlerts, updateAlertStatus, assignAlert,
  addAlertNote, getAlertNotes, bulkAlertAction,
  deleteAlert, exportAlertsCSV, exportAlertsJSON,
} from '../api'
import { useLang } from '../context/LanguageContext'

/* ── Design tokens ─────────────────────────────────────────────────────────── */
const SEV = {
  CRITICAL: { bg: 'rgba(239,68,68,0.15)',  border: 'rgba(239,68,68,0.4)',  color: '#ef4444', glow: '#ef444430' },
  HIGH:     { bg: 'rgba(249,115,22,0.15)', border: 'rgba(249,115,22,0.4)', color: '#f97316', glow: '#f9731630' },
  MEDIUM:   { bg: 'rgba(245,158,11,0.15)', border: 'rgba(245,158,11,0.4)', color: '#f59e0b', glow: '#f59e0b30' },
  LOW:      { bg: 'rgba(59,130,246,0.15)', border: 'rgba(59,130,246,0.4)', color: '#3b82f6', glow: '#3b82f630' },
}
const STATUS = {
  open:          { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',    label: 'Open' },
  investigating: { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)',   label: 'Investigating' },
  acknowledged:  { color: '#3b82f6', bg: 'rgba(59,130,246,0.1)',   label: 'Acknowledged' },
  resolved:      { color: '#10b981', bg: 'rgba(16,185,129,0.1)',   label: 'Resolved' },
  false_positive:{ color: '#6b7280', bg: 'rgba(107,114,128,0.1)', label: 'False Positive' },
  closed:        { color: '#475569', bg: 'rgba(71,85,105,0.1)',    label: 'Closed' },
}

/* ── Micro components ──────────────────────────────────────────────────────── */
function SevBadge({ s }) {
  const c = SEV[s] || SEV.LOW
  return (
    <span className="text-xs font-black px-2.5 py-0.5 rounded-full tracking-wide"
      style={{ background: c.bg, color: c.color, border: `1px solid ${c.border}` }}>{s}</span>
  )
}
function StatusBadge({ s }) {
  const c = STATUS[s] || STATUS.open
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-0.5 rounded-full"
      style={{ background: c.bg, color: c.color }}>
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: c.color }} />
      {c.label}
    </span>
  )
}
function EventCountBadge({ n }) {
  if (!n || n <= 1) return null
  return (
    <span className="inline-flex items-center text-xs font-black px-1.5 py-0 rounded-md ml-1.5"
      style={{ background: 'rgba(239,68,68,0.2)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.3)' }}>
      ×{n}
    </span>
  )
}
function SlaChip({ minutes }) {
  if (minutes == null) return null
  const h   = Math.floor(minutes / 60)
  const m   = minutes % 60
  const txt = h > 0 ? `${h}h ${m}m` : `${m}m`
  const color = minutes > 240 ? '#ef4444' : minutes > 60 ? '#f59e0b' : '#10b981'
  return (
    <span className="text-xs font-mono px-1.5 py-0 rounded" style={{ color, background: `${color}18` }}>
      {txt}
    </span>
  )
}

/* ── Timeline / notes panel ────────────────────────────────────────────────── */
function NotesPanel({ alertId }) {
  const [notes, setNotes] = useState([])
  const [body, setBody]   = useState('')
  const [busy, setBusy]   = useState(false)
  const endRef = useRef(null)

  useEffect(() => {
    getAlertNotes(alertId).then(r => setNotes(r.data.notes || [])).catch(() => {})
  }, [alertId])

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [notes])

  const submit = async () => {
    if (!body.trim()) return
    setBusy(true)
    try {
      const r = await addAlertNote(alertId, body.trim())
      setNotes(p => [...p, r.data])
      setBody('')
    } catch {}
    setBusy(false)
  }

  const fmt = (ts) => ts ? new Date(ts).toLocaleString() : ''

  return (
    <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
      <div className="px-4 py-2.5 text-xs font-bold uppercase tracking-wider flex items-center gap-2"
        style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
        <span className="w-1.5 h-1.5 rounded-full bg-blue-400" /> Analyst Timeline
      </div>
      <div className="p-3 space-y-2 max-h-48 overflow-y-auto" style={{ background: 'var(--bg-card)' }}>
        {notes.length === 0
          ? <p className="text-xs text-center py-4" style={{ color: 'var(--text-muted)' }}>No notes yet</p>
          : notes.map(n => (
            <div key={n.id} className="rounded-lg p-2.5" style={{ background: 'var(--bg-secondary)' }}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold" style={{ color: '#93c5fd' }}>{n.author}</span>
                <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{fmt(n.created_at)}</span>
              </div>
              <p className="text-xs text-white leading-relaxed">{n.body}</p>
            </div>
          ))
        }
        <div ref={endRef} />
      </div>
      <div className="p-3 flex gap-2" style={{ borderTop: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
        <textarea
          value={body} onChange={e => setBody(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !e.shiftKey && (e.preventDefault(), submit())}
          placeholder="Add note… (Enter to submit)"
          rows={2}
          className="flex-1 text-xs rounded-lg px-3 py-2 resize-none"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
        />
        <button onClick={submit} disabled={busy || !body.trim()}
          className="px-3 py-1 rounded-lg text-xs font-bold disabled:opacity-40 transition-all self-end"
          style={{ background: 'rgba(59,130,246,0.2)', color: '#93c5fd', border: '1px solid rgba(59,130,246,0.3)' }}>
          Add
        </button>
      </div>
    </div>
  )
}

/* ── Alert detail modal ─────────────────────────────────────────────────────── */
function AlertModal({ alert, onClose, onStatus, currentUserId }) {
  if (!alert) return null
  const sev = SEV[alert.severity] || SEV.LOW

  const transitionButtons = [
    { from: ['open'],                           to: 'investigating',  label: '🔍 Investigate',    cls: 'amber'  },
    { from: ['open', 'investigating'],          to: 'acknowledged',   label: '✓ Acknowledge',     cls: 'blue'   },
    { from: ['open','investigating','acknowledged'], to: 'resolved',  label: '✓ Resolve',         cls: 'green'  },
    { from: ['open','investigating','acknowledged','resolved'], to: 'false_positive', label: '✗ False Positive', cls: 'gray' },
    { from: ['open','investigating','acknowledged'], to: 'closed',    label: '✕ Close',            cls: 'slate'  },
    { from: ['resolved','false_positive','closed'],  to: 'open',     label: '↩ Re-open',          cls: 'red'    },
  ]
  const colors = {
    amber: ['rgba(245,158,11,0.15)', '#fcd34d', 'rgba(245,158,11,0.3)'],
    blue:  ['rgba(59,130,246,0.15)', '#93c5fd', 'rgba(59,130,246,0.3)'],
    green: ['rgba(16,185,129,0.15)', '#6ee7b7', 'rgba(16,185,129,0.3)'],
    gray:  ['rgba(107,114,128,0.15)','#9ca3af', 'rgba(107,114,128,0.3)'],
    slate: ['rgba(71,85,105,0.15)',  '#94a3b8', 'rgba(71,85,105,0.3)'],
    red:   ['rgba(239,68,68,0.15)',  '#fca5a5', 'rgba(239,68,68,0.3)'],
  }

  const fmt = (ts) => ts ? new Date(ts).toLocaleString() : '—'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(8px)' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="w-full max-w-2xl rounded-2xl overflow-hidden"
        style={{
          background: 'var(--bg-card)',
          border: `1px solid ${sev.border}`,
          maxHeight: '92vh', overflowY: 'auto',
          boxShadow: `0 25px 60px rgba(0,0,0,0.7), 0 0 40px ${sev.glow}`,
        }}>

        {/* header */}
        <div className="relative px-6 py-5"
          style={{ background: `linear-gradient(135deg,${sev.bg},var(--bg-secondary))`, borderBottom: `1px solid ${sev.border}` }}>
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-3 min-w-0">
              <div className="w-10 h-10 flex-shrink-0 rounded-xl flex items-center justify-center mt-0.5"
                style={{ background: sev.bg, border: `1px solid ${sev.border}` }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={sev.color} strokeWidth="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                  <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <SevBadge s={alert.severity} />
                  <StatusBadge s={alert.status} />
                  {alert.event_count > 1 && (
                    <span className="text-xs font-black px-2 py-0.5 rounded-full"
                      style={{ background: 'rgba(239,68,68,0.2)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.35)' }}>
                      ×{alert.event_count} events
                    </span>
                  )}
                  {alert.sla_minutes != null && (
                    <span className="text-xs font-mono opacity-70 ml-1">
                      <SlaChip minutes={alert.sla_minutes} />
                    </span>
                  )}
                </div>
                <h3 className="font-bold text-white text-sm leading-tight">{alert.title}</h3>
                {alert.assigned_to_name && (
                  <p className="text-xs mt-0.5" style={{ color: '#93c5fd' }}>
                    Assigned to {alert.assigned_to_name}
                  </p>
                )}
              </div>
            </div>
            <button onClick={onClose}
              className="w-8 h-8 flex-shrink-0 flex items-center justify-center rounded-xl text-lg"
              style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)' }}>×</button>
          </div>
        </div>

        <div className="p-6 space-y-4">
          {/* info grid */}
          <div className="grid grid-cols-2 gap-2.5">
            {[
              ['Agent',           alert.agent_hostname || alert.agent_id?.slice(0,16)],
              ['Rule',            alert.rule_name || '—'],
              ['Source IP',       alert.src_ip || '—'],
              ['Level',           alert.level ?? '—'],
              ['Category',        alert.category || '—'],
              ['First Seen',      fmt(alert.first_seen_at)],
              ['Last Seen',       fmt(alert.last_seen_at)],
              ['MITRE',           alert.mitre_tactic ? `${alert.mitre_tactic} · ${alert.mitre_technique || ''}` : '—'],
            ].map(([k, v]) => (
              <div key={k} className="rounded-xl p-3" style={{ background: 'var(--bg-secondary)' }}>
                <div className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>{k}</div>
                <div className="text-sm font-medium text-white truncate" title={String(v)}>{v}</div>
              </div>
            ))}
          </div>

          {/* description */}
          {alert.description && (
            <div className="rounded-xl p-4" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
              <div className="text-xs font-semibold mb-2 uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Description</div>
              <p className="text-sm text-white leading-relaxed">{alert.description}</p>
            </div>
          )}

          {/* MITRE */}
          {alert.mitre_tactic && (
            <div className="rounded-xl p-4" style={{ background: 'rgba(139,92,246,0.07)', border: '1px solid rgba(139,92,246,0.25)' }}>
              <div className="flex items-center gap-2 mb-3">
                <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                <span className="text-xs font-bold uppercase tracking-wider" style={{ color: '#a78bfa' }}>MITRE ATT&CK</span>
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

          {/* raw log */}
          {alert.raw_log && (
            <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
              <div className="px-4 py-2.5 text-xs font-bold uppercase tracking-wider flex items-center gap-2"
                style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                <span className="w-1.5 h-1.5 rounded-full bg-green-400" /> Raw Log
              </div>
              <pre className="p-4 text-xs overflow-x-auto leading-relaxed"
                style={{ background: '#060c17', color: '#86efac', fontFamily: 'monospace', maxHeight: 140 }}>
                {alert.raw_log}
              </pre>
            </div>
          )}

          {/* notes / timeline */}
          <NotesPanel alertId={alert.id} />

          {/* status transition buttons */}
          <div className="flex flex-wrap gap-2 pt-1">
            {transitionButtons
              .filter(b => b.from.includes(alert.status))
              .map(b => {
                const [bg, clr, bdr] = colors[b.cls]
                return (
                  <button key={b.to}
                    onClick={() => { onStatus(alert.id, b.to); onClose() }}
                    className="flex-1 min-w-28 py-2 rounded-xl text-xs font-bold transition-all"
                    style={{ background: bg, color: clr, border: `1px solid ${bdr}` }}>
                    {b.label}
                  </button>
                )
              })
            }
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Bulk action bar ────────────────────────────────────────────────────────── */
function BulkBar({ selected, onAction, onClear }) {
  if (selected.size === 0) return null
  const ids = [...selected]
  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 flex items-center gap-3 px-5 py-3 rounded-2xl shadow-2xl"
      style={{ background: '#1e293b', border: '1px solid rgba(99,102,241,0.4)', backdropFilter: 'blur(12px)' }}>
      <span className="text-sm font-bold text-white">{ids.length} selected</span>
      <div className="w-px h-5 bg-white/20" />
      {[
        { action: 'investigate',   label: 'Investigate', color: '#f59e0b' },
        { action: 'acknowledge',   label: 'Ack',         color: '#3b82f6' },
        { action: 'resolve',       label: 'Resolve',     color: '#10b981' },
        { action: 'false_positive',label: 'FP',          color: '#6b7280' },
        { action: 'close',         label: 'Close',       color: '#475569' },
        { action: 'delete',        label: 'Delete',      color: '#ef4444' },
      ].map(({ action, label, color }) => (
        <button key={action} onClick={() => onAction(ids, action)}
          className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all hover:brightness-110"
          style={{ background: `${color}22`, color, border: `1px solid ${color}44` }}>
          {label}
        </button>
      ))}
      <button onClick={onClear}
        className="px-3 py-1.5 rounded-lg text-xs font-semibold"
        style={{ color: 'var(--text-muted)' }}>
        ✕ Clear
      </button>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════ */
export default function Alerts() {
  const { t } = useLang()

  const [alerts, setAlerts]     = useState([])
  const [total, setTotal]       = useState(0)
  const [loading, setLoading]   = useState(true)
  const [page, setPage]         = useState(1)
  const [search, setSearch]     = useState('')
  const [sevFilter, setSevFilter]       = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('all')
  const [selected, setSelected] = useState(null)       // modal
  const [checked, setChecked]   = useState(new Set())  // bulk
  const SIZE = 20

  const fetchAlerts = useCallback(async () => {
    setLoading(true)
    try {
      const params = {
        page, size: SIZE,
        sort: 'last_seen_at', order: 'desc',
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

  useEffect(() => { setPage(1); setChecked(new Set()) }, [sevFilter, statusFilter, search])
  useEffect(() => { fetchAlerts() }, [fetchAlerts])

  /* ── Status change ── */
  const handleStatus = async (id, status) => {
    try {
      await updateAlertStatus(id, status)
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, status } : a))
      if (selected?.id === id) setSelected(p => ({ ...p, status }))
    } catch {}
  }

  /* ── Bulk action ── */
  const handleBulkAction = async (ids, action) => {
    if (action === 'delete' && !window.confirm(`Delete ${ids.length} alert(s)?`)) return
    try {
      await bulkAlertAction({ alert_ids: ids, action })
      setChecked(new Set())
      fetchAlerts()
    } catch {}
  }

  /* ── Checkbox helpers ── */
  const toggleCheck = (id, e) => {
    e.stopPropagation()
    setChecked(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }
  const allChecked  = alerts.length > 0 && alerts.every(a => checked.has(a.id))
  const toggleAll   = () => setChecked(allChecked ? new Set() : new Set(alerts.map(a => a.id)))

  /* ── Export ── */
  const handleExportCSV = async () => {
    try {
      const r = await exportAlertsCSV({ days: 30 })
      const url = URL.createObjectURL(new Blob([r.data], { type: 'text/csv' }))
      Object.assign(document.createElement('a'), { href: url, download: `alerts_${Date.now()}.csv` }).click()
      URL.revokeObjectURL(url)
    } catch {}
  }
  const handleExportJSON = async () => {
    try {
      const r = await exportAlertsJSON({ days: 30 })
      const url = URL.createObjectURL(new Blob([r.data], { type: 'application/json' }))
      Object.assign(document.createElement('a'), { href: url, download: `alerts_${Date.now()}.json` }).click()
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
        style={{ background: 'linear-gradient(135deg,#0f172a 0%,#1c0a0a 60%,#0f172a 100%)',
          border: '1px solid rgba(239,68,68,0.2)' }}>
        <div className="absolute top-0 right-0 w-72 h-72 rounded-full pointer-events-none"
          style={{ background: 'radial-gradient(circle,rgba(239,68,68,0.08) 0%,transparent 70%)', transform: 'translate(30%,-30%)' }} />
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
            <button onClick={handleExportCSV} className="btn-ghost py-2 px-3 text-xs">CSV</button>
            <button onClick={handleExportJSON} className="btn-ghost py-2 px-3 text-xs">JSON</button>
          </div>
        </div>
      </div>

      {/* ── Severity cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => {
          const c = SEV[s]; const active = sevFilter === s
          return (
            <button key={s} onClick={() => setSevFilter(active ? 'ALL' : s)}
              className="rounded-2xl p-5 text-left transition-all"
              style={{
                background: active ? c.bg : 'var(--bg-card)',
                border: `1px solid ${active ? c.color : 'var(--border-color)'}`,
                boxShadow: active ? `0 0 24px ${c.glow}` : 'none',
                transform: active ? 'translateY(-2px)' : 'none',
              }}>
              <div className="flex items-center justify-between mb-3">
                <span className="text-lg">{{ CRITICAL:'🔴', HIGH:'🟠', MEDIUM:'🟡', LOW:'🔵' }[s]}</span>
                {active && <span className="text-xs px-2 py-0.5 rounded-full font-bold"
                  style={{ background: c.bg, color: c.color }}>✓</span>}
              </div>
              <div className="text-3xl font-black mb-1" style={{ color: c.color, textShadow: active ? `0 0 20px ${c.color}` : 'none' }}>
                {sevCounts[s]}
              </div>
              <div className="text-xs font-semibold uppercase tracking-wider"
                style={{ color: active ? c.color : 'var(--text-muted)' }}>{t(`severity.${s}`)}</div>
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
          <input type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder={t('alerts.searchPlaceholder')} className="w-full" style={{ paddingLeft: 36 }} />
        </div>

        <div className="flex rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
          {[
            { key: 'all',           label: 'All',           dot: null },
            { key: 'open',          label: 'Open',          dot: '#ef4444' },
            { key: 'investigating', label: 'Investigating', dot: '#f59e0b' },
            { key: 'acknowledged',  label: 'Acked',         dot: '#3b82f6' },
            { key: 'resolved',      label: 'Resolved',      dot: '#10b981' },
            { key: 'false_positive',label: 'FP',            dot: '#6b7280' },
          ].map(({ key, label, dot }) => (
            <button key={key} onClick={() => setStatusFilter(key)}
              className="px-3 py-2 text-xs font-semibold transition-all flex items-center gap-1 whitespace-nowrap"
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

      {/* ── Table ── */}
      <div className="rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
                <th className="px-4 py-3.5 w-10">
                  <input type="checkbox" checked={allChecked} onChange={toggleAll}
                    className="rounded cursor-pointer" />
                </th>
                {['Severity', 'Rule / Title', 'Agent', 'Source IP', 'MITRE', 'Status', 'Last Seen', 'SLA', ''].map(h => (
                  <th key={h} className="text-left px-4 py-3.5 text-xs font-bold uppercase tracking-wider whitespace-nowrap"
                    style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border-color)' }}>
                    {[30, 60, 160, 90, 80, 100, 80, 90, 60, 30].map((w, j) => (
                      <td key={j} className="px-4 py-4">
                        <div className="skeleton h-4 rounded" style={{ width: w }} />
                      </td>
                    ))}
                  </tr>
                ))
                : alerts.length === 0
                ? (
                  <tr><td colSpan={10} className="py-20">
                    <div className="flex flex-col items-center gap-3" style={{ color: 'var(--text-muted)' }}>
                      <div className="w-16 h-16 rounded-2xl flex items-center justify-center" style={{ background: 'var(--bg-secondary)' }}>
                        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="opacity-40">
                          <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                        </svg>
                      </div>
                      <p className="text-sm font-medium">{t('alerts.noAlerts')}</p>
                    </div>
                  </td></tr>
                )
                : alerts.map(alert => {
                  const sev  = SEV[alert.severity] || SEV.LOW
                  const isChecked = checked.has(alert.id)
                  return (
                    <tr key={alert.id}
                      className="group cursor-pointer transition-all"
                      style={{
                        borderBottom: '1px solid var(--border-color)',
                        background: isChecked ? 'rgba(99,102,241,0.07)' : 'transparent',
                      }}
                      onClick={() => setSelected(alert)}
                      onMouseEnter={e => !isChecked && (e.currentTarget.style.background = 'var(--bg-secondary)')}
                      onMouseLeave={e => !isChecked && (e.currentTarget.style.background = 'transparent')}>

                      {/* checkbox */}
                      <td className="px-4 py-3.5 w-10" onClick={e => toggleCheck(alert.id, e)}>
                        <input type="checkbox" checked={isChecked} onChange={() => {}}
                          className="rounded cursor-pointer pointer-events-none" />
                      </td>

                      {/* severity */}
                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-2">
                          <div className="w-0.5 h-8 rounded-full flex-shrink-0" style={{ background: sev.color }} />
                          <SevBadge s={alert.severity} />
                        </div>
                      </td>

                      {/* title + event count */}
                      <td className="px-4 py-3.5" style={{ maxWidth: 220 }}>
                        <div className="flex items-center gap-1 flex-wrap">
                          <span className="font-semibold text-white truncate text-sm">{alert.title}</span>
                          <EventCountBadge n={alert.event_count} />
                        </div>
                        {alert.category && (
                          <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{alert.category}</div>
                        )}
                      </td>

                      {/* agent */}
                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-2">
                          <div className="w-6 h-6 rounded-lg flex items-center justify-center text-xs font-bold"
                            style={{ background: 'rgba(59,130,246,0.15)', color: '#93c5fd' }}>
                            {(alert.agent_hostname || '?')[0]?.toUpperCase()}
                          </div>
                          <span className="text-sm truncate max-w-28" style={{ color: 'var(--text-secondary)' }}>
                            {alert.agent_hostname || alert.agent_id?.slice(0,8)}
                          </span>
                        </div>
                      </td>

                      {/* src ip */}
                      <td className="px-4 py-3.5 font-mono text-xs"
                        style={{ color: alert.src_ip ? '#93c5fd' : 'var(--text-muted)' }}>
                        {alert.src_ip || '—'}
                      </td>

                      {/* mitre */}
                      <td className="px-4 py-3.5">
                        {alert.mitre_tactic
                          ? <span className="text-xs px-2 py-0.5 rounded-full font-medium"
                              style={{ background: 'rgba(139,92,246,0.15)', color: '#c4b5fd', border: '1px solid rgba(139,92,246,0.2)' }}>
                              {alert.mitre_tactic}
                            </span>
                          : <span style={{ color: 'var(--text-muted)' }}>—</span>
                        }
                      </td>

                      {/* status */}
                      <td className="px-4 py-3.5">
                        <div className="space-y-1">
                          <StatusBadge s={alert.status} />
                          {alert.assigned_to_name && (
                            <div className="text-xs" style={{ color: '#93c5fd' }}>→ {alert.assigned_to_name}</div>
                          )}
                        </div>
                      </td>

                      {/* last seen */}
                      <td className="px-4 py-3.5 text-xs font-mono whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {alert.last_seen_at ? new Date(alert.last_seen_at).toLocaleString() : '—'}
                      </td>

                      {/* sla */}
                      <td className="px-4 py-3.5">
                        {alert.status === 'open' || alert.status === 'investigating'
                          ? <SlaChip minutes={alert.sla_minutes} />
                          : <span style={{ color: 'var(--text-muted)' }}>—</span>
                        }
                      </td>

                      {/* quick resolve */}
                      <td className="px-4 py-3.5" onClick={e => e.stopPropagation()}>
                        {(alert.status === 'open' || alert.status === 'investigating') && (
                          <button onClick={() => handleStatus(alert.id, 'resolved')}
                            className="w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold transition-all"
                            style={{ background: 'rgba(16,185,129,0.1)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.2)' }}
                            title="Quick Resolve">✓</button>
                        )}
                      </td>
                    </tr>
                  )
                })
              }
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
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="btn-ghost py-1.5 px-3.5 text-xs disabled:opacity-30">{t('common.prev')}</button>
              <button onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page === pages}
                className="btn-ghost py-1.5 px-3.5 text-xs disabled:opacity-30">{t('common.next')}</button>
            </div>
          </div>
        )}
      </div>

      {/* ── Bulk action bar ── */}
      <BulkBar selected={checked} onAction={handleBulkAction} onClear={() => setChecked(new Set())} />

      {/* ── Alert detail modal ── */}
      {selected && (
        <AlertModal
          alert={selected}
          onClose={() => setSelected(null)}
          onStatus={handleStatus}
        />
      )}
    </div>
  )
}
