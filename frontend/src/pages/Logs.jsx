import React, { useState, useEffect, useCallback, useRef } from 'react'
import { getLogs, getAgents, getEventTypes } from '../api'
import { useLang } from '../context/LanguageContext'

const LEVEL_STYLE = {
  CRITICAL: { bg: 'rgba(239,68,68,0.15)',  color: '#fca5a5' },
  ERROR:    { bg: 'rgba(239,68,68,0.12)',  color: '#fca5a5' },
  WARNING:  { bg: 'rgba(245,158,11,0.12)', color: '#fcd34d' },
  INFO:     { bg: 'rgba(59,130,246,0.12)', color: '#93c5fd' },
  DEBUG:    { bg: 'rgba(107,114,128,0.12)',color: '#9ca3af' },
}

const EVENT_LABELS = {
  screen_lock:          'Ekran qulflandi',
  screen_unlock:        'Ekran ochildi',
  screen_auth_failure:  'Ekran parol xato',
  user_login:           'Foydalanuvchi kirdi',
  user_logout:          'Foydalanuvchi chiqdi',
  ssh_login:            'SSH kirish',
  ssh_failed:           'SSH xato',
  ssh_auth_failure:     'SSH auth xato',
  ssh_invalid_user:     'SSH noto\'g\'ri user',
  ssh_disconnect:       'SSH uzildi',
  sudo_command:         'Sudo buyruq',
  sudo_auth_failure:    'Sudo auth xato',
  sudo_denied:          'Sudo rad etildi',
  user_created:         'User yaratildi',
  user_deleted:         'User o\'chirildi',
  group_created:        'Guruh yaratildi',
  password_changed:     'Parol o\'zgartirildi',
  usb_connected:        'USB ulandi',
  usb_disconnected:     'USB uzildi',
  network_up:           'Tarmoq ulandi',
  network_down:         'Tarmoq uzildi',
  wifi_connected:       'Wi-Fi ulandi',
  system_shutdown:      'Tizim o\'chdi',
  process_crash:        'Jarayon crash',
  oom_kill:             'OOM Kill',
  package_installed:    'Paket o\'rnatildi',
  package_removed:      'Paket o\'chirildi',
  cron_exec:            'Cron ishga tushdi',
  firewall_block:       'Firewall blokladi',
  firewall_allow:       'Firewall ruxsat',
  windows_event:        'Windows hodisa',
  auditd_event:         'Audit hodisa',
  system_log:           'Tizim logi',
}

// Quick filter presets
const QUICK_FILTERS = [
  { label: 'Autentifikatsiya', event_types: ['screen_auth_failure','ssh_failed','ssh_auth_failure','sudo_auth_failure','sudo_denied'] },
  { label: 'Ekran qulfi',      event_types: ['screen_lock','screen_unlock','screen_auth_failure'] },
  { label: 'SSH',              event_types: ['ssh_login','ssh_failed','ssh_invalid_user','ssh_disconnect','ssh_auth_failure'] },
  { label: 'Sudo',             event_types: ['sudo_command','sudo_auth_failure','sudo_denied'] },
  { label: 'USB / Qurilma',    event_types: ['usb_connected','usb_disconnected'] },
  { label: 'Tarmoq',           event_types: ['network_up','network_down','wifi_connected'] },
  { label: 'Xavfli',           level: 'ERROR' },
  { label: 'Kritik',           level: 'CRITICAL' },
]

function LogModal({ log, onClose }) {
  const { t } = useLang()
  const ef = log.parsed_fields || {}
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in"
      style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(6px)' }}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        className="w-full max-w-2xl rounded-2xl overflow-hidden animate-slide-down"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-light)', maxHeight: '85vh', overflowY: 'auto' }}
      >
        <div
          className="flex items-center justify-between px-6 py-4"
          style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}
        >
          <h3 className="font-semibold text-white text-sm">Log Details</h3>
          <button onClick={onClose} className="text-lg p-1.5 rounded-lg"
            style={{ color: 'var(--text-secondary)', background: 'var(--bg-card)' }}>×</button>
        </div>
        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            {[
              ['Vaqt',    log.timestamp ? new Date(log.timestamp).toLocaleString() : '—'],
              ['Agent',   log.agent_id?.slice(0, 16) || '—'],
              ['Daraja',  log.level || 'INFO'],
              ['Manba',   log.source || '—'],
              ...(ef.event_type ? [['Hodisa turi', EVENT_LABELS[ef.event_type] || ef.event_type]] : []),
              ...(ef.uid        ? [['UID',          ef.uid]] : []),
              ...(ef.pid        ? [['PID',          ef.pid]] : []),
            ].map(([k, v]) => (
              <div key={k} className="rounded-xl p-3" style={{ background: 'var(--bg-secondary)' }}>
                <div className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>{k}</div>
                <div className="text-sm font-medium text-white">{v}</div>
              </div>
            ))}
          </div>
          <div className="rounded-xl p-4" style={{ background: 'var(--bg-secondary)' }}>
            <div className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>Xabar</div>
            <p className="text-sm text-white leading-relaxed">{log.message || '—'}</p>
          </div>
          {log.raw && (
            <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
              <div className="px-4 py-2 text-xs font-semibold uppercase"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', borderBottom: '1px solid var(--border-color)' }}>
                Raw Log
              </div>
              <pre className="p-4 text-xs overflow-x-auto leading-relaxed whitespace-pre-wrap break-all"
                style={{ background: '#080d16', color: '#86efac', fontFamily: 'monospace' }}>
                {log.raw}
              </pre>
            </div>
          )}
          {ef && Object.keys(ef).length > 0 && (
            <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
              <div className="px-4 py-2 text-xs font-semibold uppercase"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', borderBottom: '1px solid var(--border-color)' }}>
                Parsed Fields
              </div>
              <pre className="p-4 text-xs overflow-x-auto"
                style={{ background: '#080d16', color: '#a5b4fc', fontFamily: 'monospace' }}>
                {JSON.stringify(ef, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function Logs() {
  const { t } = useLang()
  const [logs, setLogs]           = useState([])
  const [total, setTotal]         = useState(0)
  const [loading, setLoading]     = useState(true)
  const [page, setPage]           = useState(1)
  const [agentId, setAgentId]     = useState('')
  const [level, setLevel]         = useState('')
  const [keyword, setKeyword]     = useState('')
  const [eventType, setEventType] = useState('')
  const [source, setSource]       = useState('')
  const [startTime, setStartTime] = useState('')
  const [endTime, setEndTime]     = useState('')
  const [agents, setAgents]       = useState([])
  const [eventTypes, setEventTypes] = useState([])
  const [liveMode, setLiveMode]   = useState(false)
  const [viewLog, setViewLog]     = useState(null)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const liveRef = useRef(null)
  const SIZE = 50

  useEffect(() => {
    getAgents().then((r) => setAgents(r.data)).catch(() => {})
    getEventTypes().then((r) => setEventTypes(r.data.event_types || [])).catch(() => {})
  }, [])

  const fetchLogs = useCallback(async (prepend = false) => {
    if (!prepend) setLoading(true)
    try {
      const params = {
        page:       prepend ? 1 : page,
        size:       prepend ? 10 : SIZE,
        agent_id:   agentId    || undefined,
        level:      level      || undefined,
        keyword:    keyword    || undefined,
        event_type: eventType  || undefined,
        source:     source     || undefined,
        start_time: startTime  || undefined,
        end_time:   endTime    || undefined,
      }
      const resp = await getLogs(params)
      const newLogs = resp.data.logs || []
      if (prepend) {
        setLogs((prev) => {
          const ids = new Set(prev.map((l) => l.id))
          return [...newLogs.filter((l) => !ids.has(l.id)), ...prev].slice(0, 300)
        })
      } else {
        setLogs(newLogs)
        setTotal(resp.data.total || 0)
      }
    } catch {}
    if (!prepend) setLoading(false)
  }, [page, agentId, level, keyword, eventType, source, startTime, endTime])

  useEffect(() => { fetchLogs() }, [fetchLogs])

  useEffect(() => {
    if (liveMode) liveRef.current = setInterval(() => fetchLogs(true), 4000)
    else clearInterval(liveRef.current)
    return () => clearInterval(liveRef.current)
  }, [liveMode, fetchLogs])

  const applyQuickFilter = (qf) => {
    setLevel(qf.level || '')
    setEventType(qf.event_types ? qf.event_types[0] : '')
    setPage(1)
  }

  const clearAll = () => {
    setAgentId(''); setLevel(''); setKeyword('')
    setEventType(''); setSource(''); setStartTime(''); setEndTime('')
    setPage(1)
  }

  const hasActiveFilter = agentId || level || keyword || eventType || source || startTime || endTime
  const pages = Math.ceil(total / SIZE) || 1

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Loglar</h2>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {total.toLocaleString()} ta yozuv
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            {liveMode && <span className="live-dot" />}
            <button
              onClick={() => setLiveMode(!liveMode)}
              className="relative w-10 h-5 rounded-full transition-colors cursor-pointer flex-shrink-0"
              style={{ background: liveMode ? '#10b981' : 'rgba(255,255,255,0.1)' }}
            >
              <div className="absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform"
                style={{ transform: liveMode ? 'translateX(22px)' : 'translateX(2px)' }} />
            </button>
            <span className="text-xs" style={{ color: liveMode ? '#6ee7b7' : 'var(--text-secondary)' }}>Live</span>
          </div>
          <button onClick={() => fetchLogs()} className="btn-ghost py-2 px-3 text-xs">↻</button>
        </div>
      </div>

      {/* Quick filters */}
      <div className="flex flex-wrap gap-2">
        {QUICK_FILTERS.map((qf) => (
          <button
            key={qf.label}
            onClick={() => applyQuickFilter(qf)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
            style={{
              background: (level === qf.level && qf.level) || (eventType && qf.event_types?.includes(eventType))
                ? 'rgba(99,102,241,0.3)' : 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              color: 'var(--text-secondary)',
            }}
          >
            {qf.label}
          </button>
        ))}
        {hasActiveFilter && (
          <button onClick={clearAll}
            className="px-3 py-1.5 rounded-lg text-xs font-medium"
            style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.3)' }}>
            ✕ Tozalash
          </button>
        )}
      </div>

      {/* Main filters */}
      <div className="rounded-xl p-4 space-y-3"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>

        {/* Row 1: agent, level, event_type, keyword */}
        <div className="flex flex-wrap gap-3">
          <select value={agentId} onChange={(e) => { setAgentId(e.target.value); setPage(1) }}
            style={{ minWidth: 150 }}>
            <option value="">Barcha agentlar</option>
            {agents.map((a) => <option key={a.agent_id} value={a.agent_id}>{a.hostname}</option>)}
          </select>

          <select value={level} onChange={(e) => { setLevel(e.target.value); setPage(1) }}
            style={{ minWidth: 120 }}>
            <option value="">Barcha darajalar</option>
            {['CRITICAL','ERROR','WARNING','INFO','DEBUG'].map((l) => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>

          <select value={eventType} onChange={(e) => { setEventType(e.target.value); setPage(1) }}
            style={{ minWidth: 180 }}>
            <option value="">Barcha hodisa turlari</option>
            {eventTypes.map((et) => (
              <option key={et} value={et}>{EVENT_LABELS[et] || et}</option>
            ))}
          </select>

          <div className="relative flex-1 min-w-48">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2" width="14" height="14"
              viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
              style={{ color: 'var(--text-muted)' }}>
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            <input type="text" placeholder="Kalit so'z bo'yicha qidirish..." value={keyword}
              onChange={(e) => { setKeyword(e.target.value); setPage(1) }}
              className="w-full" style={{ paddingLeft: 36 }} />
          </div>

          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="btn-ghost px-3 py-2 text-xs flex items-center gap-1"
            style={{ color: showAdvanced ? '#a5b4fc' : 'var(--text-secondary)' }}
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="4" y1="6" x2="20" y2="6"/><line x1="8" y1="12" x2="16" y2="12"/>
              <line x1="12" y1="18" x2="12" y2="18" strokeLinecap="round" strokeWidth="3"/>
            </svg>
            Qo'shimcha
          </button>
        </div>

        {/* Row 2: advanced — source + date range */}
        {showAdvanced && (
          <div className="flex flex-wrap gap-3 pt-2" style={{ borderTop: '1px solid var(--border-color)' }}>
            <div className="relative" style={{ minWidth: 200 }}>
              <input type="text" placeholder="Manba (masalan: journald/gdm-password)"
                value={source}
                onChange={(e) => { setSource(e.target.value); setPage(1) }}
                className="w-full" />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs" style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>Boshlanish:</label>
              <input type="datetime-local" value={startTime}
                onChange={(e) => { setStartTime(e.target.value); setPage(1) }}
                className="text-xs" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 8, padding: '6px 10px', color: 'white' }} />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs" style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>Tugash:</label>
              <input type="datetime-local" value={endTime}
                onChange={(e) => { setEndTime(e.target.value); setPage(1) }}
                className="text-xs" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 8, padding: '6px 10px', color: 'white' }} />
            </div>
          </div>
        )}
      </div>

      {/* Active filter badges */}
      {hasActiveFilter && (
        <div className="flex flex-wrap gap-2">
          {agentId    && <FilterBadge label={`Agent: ${agents.find(a=>a.agent_id===agentId)?.hostname||agentId.slice(0,8)}`} onRemove={() => setAgentId('')} />}
          {level      && <FilterBadge label={`Daraja: ${level}`} onRemove={() => setLevel('')} />}
          {eventType  && <FilterBadge label={`Hodisa: ${EVENT_LABELS[eventType] || eventType}`} onRemove={() => setEventType('')} />}
          {source     && <FilterBadge label={`Manba: ${source}`} onRemove={() => setSource('')} />}
          {keyword    && <FilterBadge label={`Kalit: "${keyword}"`} onRemove={() => setKeyword('')} />}
          {startTime  && <FilterBadge label={`Dan: ${new Date(startTime).toLocaleString()}`} onRemove={() => setStartTime('')} />}
          {endTime    && <FilterBadge label={`Gacha: ${new Date(endTime).toLocaleString()}`} onRemove={() => setEndTime('')} />}
        </div>
      )}

      {/* Log table */}
      <div className="rounded-2xl overflow-hidden" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                {['Vaqt', 'Daraja', 'Hodisa turi', 'Agent', 'Manba', 'Xabar'].map((h) => (
                  <th key={h} className="text-left px-4 py-3 font-semibold uppercase tracking-wide"
                    style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border-color)' }}>
                    {[70, 60, 100, 80, 90, 200].map((w, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="skeleton h-3 rounded" style={{ width: w }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : logs.length === 0 ? (
                <tr><td colSpan={6} className="text-center py-12" style={{ color: 'var(--text-muted)' }}>
                  Log topilmadi
                </td></tr>
              ) : (
                logs.map((log, i) => {
                  const ls = LEVEL_STYLE[log.level] || LEVEL_STYLE.INFO
                  const et = log.parsed_fields?.event_type
                  return (
                    <tr key={log.id || i} className="table-row-hover cursor-pointer"
                      style={{ borderBottom: '1px solid var(--border-color)' }}
                      onClick={() => setViewLog(log)}>
                      <td className="px-4 py-2.5 whitespace-nowrap font-mono" style={{ color: 'var(--text-muted)' }}>
                        {log.timestamp ? new Date(log.timestamp).toLocaleString() : '—'}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="px-2 py-0.5 rounded-full text-xs font-bold"
                          style={{ background: ls.bg, color: ls.color }}>
                          {log.level || 'INFO'}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        {et ? (
                          <span className="px-2 py-0.5 rounded-md text-xs"
                            style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc' }}>
                            {EVENT_LABELS[et] || et}
                          </span>
                        ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                      </td>
                      <td className="px-4 py-2.5" style={{ color: '#93c5fd' }}>
                        {log.agent_id?.slice(0, 8) || '—'}
                      </td>
                      <td className="px-4 py-2.5 max-w-xs truncate" style={{ color: 'var(--text-secondary)' }}>
                        {log.source || '—'}
                      </td>
                      <td className="px-4 py-2.5 text-white max-w-sm truncate">{log.message}</td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>

        {pages > 1 && !liveMode && (
          <div className="flex items-center justify-between px-5 py-3"
            style={{ borderTop: '1px solid var(--border-color)' }}>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
              {page}-sahifa / {pages}
            </span>
            <div className="flex gap-2">
              <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
                className="btn-ghost py-1.5 px-3 text-xs disabled:opacity-40">← Oldingi</button>
              <button onClick={() => setPage((p) => Math.min(pages, p + 1))} disabled={page === pages}
                className="btn-ghost py-1.5 px-3 text-xs disabled:opacity-40">Keyingi →</button>
            </div>
          </div>
        )}
      </div>

      {viewLog && <LogModal log={viewLog} onClose={() => setViewLog(null)} />}
    </div>
  )
}

function FilterBadge({ label, onRemove }) {
  return (
    <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs"
      style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)' }}>
      {label}
      <button onClick={onRemove} className="opacity-70 hover:opacity-100 text-xs leading-none">×</button>
    </span>
  )
}
