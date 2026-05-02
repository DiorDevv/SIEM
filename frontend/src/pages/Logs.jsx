import React, { useState, useEffect, useCallback, useRef } from 'react'
import { getLogs, getAgents, getLogSources, getLogStats, getLogTimeline, exportLogsCSV, getEventTypes } from '../api'

// ── Constants ─────────────────────────────────────────────────────────────────

const LEVEL_META = {
  CRITICAL: { bg: 'rgba(239,68,68,0.18)',   color: '#fca5a5', dot: '#ef4444', border: 'rgba(239,68,68,0.4)' },
  ERROR:    { bg: 'rgba(249,115,22,0.15)',  color: '#fdba74', dot: '#f97316', border: 'rgba(249,115,22,0.4)' },
  WARNING:  { bg: 'rgba(245,158,11,0.15)',  color: '#fcd34d', dot: '#f59e0b', border: 'rgba(245,158,11,0.4)' },
  INFO:     { bg: 'rgba(59,130,246,0.12)',  color: '#93c5fd', dot: '#3b82f6', border: 'rgba(59,130,246,0.3)' },
  DEBUG:    { bg: 'rgba(107,114,128,0.10)', color: '#9ca3af', dot: '#6b7280', border: 'rgba(107,114,128,0.3)' },
  HIGH:     { bg: 'rgba(239,68,68,0.14)',   color: '#fca5a5', dot: '#ef4444', border: 'rgba(239,68,68,0.35)' },
}

// Source-based quick filters — ishlaydi event_type bo'lmasa ham
const QUICK_FILTERS = [
  {
    id: 'auth_log',
    label: 'Auth.log',
    icon: '🔐',
    desc: 'Autentifikatsiya loglari',
    source: 'auth.log',
  },
  {
    id: 'ssh_fail',
    label: 'SSH Xato',
    icon: '⚡',
    desc: 'SSH kirish xatolari',
    source: 'auth.log',
    keyword: 'Failed',
  },
  {
    id: 'sudo',
    label: 'Sudo',
    icon: '👤',
    desc: 'Sudo buyruqlari',
    source: 'auth.log',
    keyword: 'sudo',
  },
  {
    id: 'fim',
    label: 'FIM',
    icon: '📁',
    desc: 'Fayl yaxlitligi',
    source: 'fim',
  },
  {
    id: 'rootcheck',
    label: 'Rootcheck',
    icon: '🛡️',
    desc: 'Rootkit tekshiruvi',
    source: 'rootcheck',
  },
  {
    id: 'kernel',
    label: 'Kernel',
    icon: '🔧',
    desc: 'Kernel hodisalari',
    source: 'kern.log',
  },
  {
    id: 'syslog',
    label: 'Syslog',
    icon: '📋',
    desc: 'Tizim loglari',
    source: 'syslog',
  },
  {
    id: 'system',
    label: 'Metrika',
    icon: '📊',
    desc: 'CPU/RAM/Disk',
    source: 'system_metrics',
  },
  {
    id: 'critical',
    label: 'Kritik',
    icon: '🚨',
    desc: 'CRITICAL darajali loglar',
    level: 'CRITICAL',
  },
  {
    id: 'error',
    label: 'Xato',
    icon: '❌',
    desc: 'ERROR darajali loglar',
    level: 'ERROR',
  },
]

const PAGE_SIZES = [25, 50, 100, 200]
const TIME_PRESETS = [
  { label: '1s',  hours: 1  },
  { label: '6s',  hours: 6  },
  { label: '24s', hours: 24 },
  { label: '7k',  hours: 168 },
  { label: 'Barchasi', hours: null },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function useDebounce(value, delay = 400) {
  const [deb, setDeb] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDeb(value), delay)
    return () => clearTimeout(t)
  }, [value, delay])
  return deb
}

function fmtTs(ts) {
  if (!ts) return '—'
  try {
    const d = new Date(ts)
    const pad = (n) => String(n).padStart(2, '0')
    return `${pad(d.getDate())}.${pad(d.getMonth()+1)} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  } catch { return ts.slice(0, 16) }
}

// Extract process name from ISO syslog message
// "2026-04-24T00:44:15+05:00 hostname proc[123]: msg" → "proc"
function extractProcess(msg) {
  if (!msg) return null
  const m = msg.match(/^\d{4}-\d{2}-\d{2}T[\d:.+-]+\s+\S+\s+(\S+?)(?:\[\d+\])?:/)
  if (m) return m[1].replace(/[[\]]/g, '')
  // Standard syslog: "Apr 17 12:34:56 hostname proc[123]: msg"
  const m2 = msg.match(/^\w{3}\s+\d+\s+[\d:]+\s+\S+\s+(\S+?)(?:\[\d+\])?:/)
  if (m2) return m2[1]
  return null
}

// Extract the actual message body (strip timestamp prefix)
function extractBody(msg) {
  if (!msg) return ''
  // ISO format
  const m = msg.match(/^\d{4}-\d{2}-\d{2}T[\d:.+-]+\s+\S+\s+\S+?(?:\[\d+\])?:\s*(.+)$/)
  if (m) return m[1]
  // Standard syslog
  const m2 = msg.match(/^\w{3}\s+\d+\s+[\d:]+\s+\S+\s+\S+?(?:\[\d+\])?:\s*(.+)$/)
  if (m2) return m2[1]
  return msg
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = Object.assign(document.createElement('a'), { href: url, download: filename })
  a.click()
  URL.revokeObjectURL(url)
}

// ── Sub-components ────────────────────────────────────────────────────────────

function LevelBadge({ level }) {
  const m = LEVEL_META[level] || LEVEL_META.INFO
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold"
      style={{ background: m.bg, color: m.color, border: `1px solid ${m.border}` }}>
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: m.dot }} />
      {level || 'INFO'}
    </span>
  )
}

function FilterBadge({ label, onRemove }) {
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs"
      style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)' }}>
      {label}
      <button onClick={onRemove} className="opacity-60 hover:opacity-100">×</button>
    </span>
  )
}

// ── Timeline mini chart ───────────────────────────────────────────────────────

function TimelineChart({ data }) {
  if (!data || data.length === 0) return null
  const max = Math.max(...data.map(d => d.count), 1)

  return (
    <div className="rounded-xl p-4" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
          Log hajmi (so'nggi 24 soat)
        </span>
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Jami: {data.reduce((s, d) => s + d.count, 0).toLocaleString()}
        </span>
      </div>
      <div className="flex items-end gap-0.5" style={{ height: 48 }}>
        {data.map((bucket, i) => {
          const h = max > 0 ? Math.max(2, Math.round((bucket.count / max) * 46)) : 2
          const hour = new Date(bucket.hour).getHours()
          const isEmpty = bucket.count === 0
          return (
            <div key={i} className="flex-1 flex flex-col items-center group relative" title={`${hour}:00 — ${bucket.count} ta`}>
              <div
                className="w-full rounded-sm transition-all"
                style={{
                  height: h,
                  background: isEmpty ? 'rgba(255,255,255,0.05)' : 'rgba(99,102,241,0.6)',
                  minHeight: 2,
                }}
              />
              {/* Tooltip on hover */}
              <div className="absolute bottom-full mb-1 hidden group-hover:block z-10 pointer-events-none">
                <div className="rounded px-2 py-1 text-xs whitespace-nowrap"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'white' }}>
                  {hour}:00 · {bucket.count}
                </div>
              </div>
            </div>
          )
        })}
      </div>
      <div className="flex justify-between mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
        {data.length > 0 && (
          <>
            <span>{new Date(data[0].hour).getHours()}:00</span>
            <span>Hozir</span>
          </>
        )}
      </div>
    </div>
  )
}

// ── Stats bar ─────────────────────────────────────────────────────────────────

function StatsBar({ stats, loading }) {
  const items = [
    { label: 'Jami (24s)',   value: stats?.total ?? '—',                          color: '#e2e8f0', dot: '#64748b' },
    { label: 'Kritik',       value: stats?.by_level?.CRITICAL ?? 0,               color: '#fca5a5', dot: '#ef4444' },
    { label: 'Xato',         value: stats?.by_level?.ERROR ?? 0,                  color: '#fdba74', dot: '#f97316' },
    { label: "Ogohlantirish",value: stats?.by_level?.WARNING ?? 0,                color: '#fcd34d', dot: '#f59e0b' },
    { label: "Ma'lumot",     value: stats?.by_level?.INFO ?? 0,                   color: '#93c5fd', dot: '#3b82f6' },
  ]
  return (
    <div className="grid grid-cols-5 gap-3">
      {items.map(({ label, value, color, dot }) => (
        <div key={label} className="rounded-xl p-3 flex flex-col gap-1"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full" style={{ background: dot }} />
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</span>
          </div>
          {loading
            ? <div className="skeleton h-6 w-12 rounded" />
            : <span className="text-lg font-bold" style={{ color }}>
                {typeof value === 'number' ? value.toLocaleString() : value}
              </span>
          }
        </div>
      ))}
    </div>
  )
}

// ── Log Modal ─────────────────────────────────────────────────────────────────

function LogModal({ log, onClose }) {
  const [copied, setCopied] = useState(false)
  const pf = log.parsed_fields || {}
  const proc = pf.process || extractProcess(log.message)
  const body = extractBody(log.message)
  const threatInfo = pf.threat_intel?.[0]

  const copyRaw = () => {
    navigator.clipboard.writeText(log.raw || log.message || '')
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const meta = [
    ['Vaqt',         fmtTs(log.timestamp)],
    ['Hostname',     log.hostname || pf.hostname || '—'],
    ['Agent ID',     log.agent_id ? log.agent_id.slice(0, 16) + '...' : '—'],
    ['Manba',        log.source   || '—'],
    ...(proc            ? [['Jarayon',     proc]]              : []),
    ...(pf.pid          ? [['PID',         pf.pid]]            : []),
    ...(pf.event_type   ? [['Hodisa',      pf.event_type]]     : []),
    ...(pf.ssh_user     ? [['SSH user',    pf.ssh_user]]       : []),
    ...(pf.ssh_src_ip   ? [['SSH IP',      pf.ssh_src_ip]]     : []),
    ...(pf.sudo_user    ? [['Sudo user',   pf.sudo_user]]      : []),
    ...(pf.sudo_command ? [['Sudo cmd',    pf.sudo_command?.slice(0,100)]] : []),
    ...(pf.pam_user          ? [['PAM user',        pf.pam_user]]                      : []),
    ...(pf.pam_service       ? [['PAM service',     pf.pam_service]]                   : []),
    ...(pf.cron_cmd          ? [['Cron cmd',        pf.cron_cmd?.slice(0, 80)]]        : []),
    ...(pf.oom_proc          ? [['OOM jarayon',     pf.oom_proc]]                      : []),
    ...(pf.file_path         ? [['Fayl yo\'li',     pf.file_path]]                     : []),
    ...(pf.rootcheck_detail  ? [['Rootcheck',       pf.rootcheck_detail?.slice(0,120)]]: []),
    ...(pf.fw_action         ? [['Firewall',        pf.fw_action]]                     : []),
    ...(pf.dst_ip            ? [['DST IP',          pf.dst_ip]]                        : []),
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(6px)' }}
      onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="w-full max-w-2xl rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', maxHeight: '90vh', overflowY: 'auto' }}>

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 sticky top-0 z-10"
          style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
          <div className="flex items-center gap-3">
            <LevelBadge level={log.level} />
            <span className="text-sm font-semibold text-white">Log Tafsilotlari</span>
          </div>
          <button onClick={onClose} className="w-7 h-7 rounded-lg flex items-center justify-center"
            style={{ color: 'var(--text-secondary)', background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            ×
          </button>
        </div>

        <div className="p-5 space-y-4">
          {/* Meta */}
          <div className="grid grid-cols-2 gap-2">
            {meta.map(([k, v]) => (
              <div key={k} className="rounded-xl p-3" style={{ background: 'var(--bg-secondary)' }}>
                <div className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>{k}</div>
                <div className="text-sm font-medium text-white break-all">{v}</div>
              </div>
            ))}
          </div>

          {/* Message body */}
          <div className="rounded-xl p-4" style={{ background: 'var(--bg-secondary)' }}>
            <div className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>Xabar</div>
            <p className="text-sm text-white leading-relaxed break-words">{body || log.message || '—'}</p>
          </div>

          {/* Threat intel */}
          {(pf.has_malicious_ip || pf.src_ip || pf.ssh_src_ip) && (
            <div className="rounded-xl p-4"
              style={{
                background: pf.has_malicious_ip ? 'rgba(239,68,68,0.08)' : 'var(--bg-secondary)',
                border: `1px solid ${pf.has_malicious_ip ? 'rgba(239,68,68,0.3)' : 'var(--border-color)'}`,
              }}>
              <div className="flex items-center gap-2 mb-3">
                <span>{pf.has_malicious_ip ? '⚠️' : '🌍'}</span>
                <span className="text-xs font-semibold uppercase tracking-wide"
                  style={{ color: pf.has_malicious_ip ? '#fca5a5' : 'var(--text-muted)' }}>
                  {pf.has_malicious_ip ? 'Zararli IP aniqlandi' : "IP ma'lumoti"}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                {[
                  ['IP manzil',  pf.src_ip || pf.ssh_src_ip],
                  ['Mamlakat',   pf.geo_country ? `${pf.geo_country} ${pf.geo_country_code ? `(${pf.geo_country_code})` : ''}` : null],
                  ['Shahar',     pf.geo_city],
                  ['ISP',        pf.geo_isp],
                  ...(threatInfo ? [
                    ['Abuse bali',  threatInfo.abuse_score != null ? `${threatInfo.abuse_score}/100` : null],
                    ['TOR exit',    threatInfo.is_tor ? 'Ha' : null],
                  ] : []),
                ].filter(([, v]) => v).map(([k, v]) => (
                  <div key={k}>
                    <span style={{ color: 'var(--text-muted)' }}>{k}: </span>
                    <span className="text-white">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* System metrics */}
          {pf.event_type === 'system_metrics' && (
            <div className="rounded-xl p-4" style={{ background: 'var(--bg-secondary)' }}>
              <div className="text-xs mb-3 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                Tizim Metrikasi
              </div>
              <div className="grid grid-cols-3 gap-3">
                {[
                  ['CPU', pf.cpu_percent != null ? `${pf.cpu_percent}%` : null, pf.cpu_percent > 80 ? '#fca5a5' : '#6ee7b7'],
                  ['RAM', pf.memory_percent != null ? `${pf.memory_percent}%` : null, pf.memory_percent > 85 ? '#fca5a5' : '#6ee7b7'],
                  ['DISK', pf.disk_percent != null ? `${pf.disk_percent}%` : null, pf.disk_percent > 90 ? '#fca5a5' : '#6ee7b7'],
                  ['SWAP', pf.swap_percent != null ? `${pf.swap_percent}%` : null, '#93c5fd'],
                  ['Load (1m)', pf.load_avg_1m != null ? pf.load_avg_1m : null, '#a5b4fc'],
                  ['Jarayonlar', pf.process_count != null ? pf.process_count : null, '#e2e8f0'],
                ].filter(([, v]) => v != null).map(([k, v, color]) => (
                  <div key={k} className="rounded-lg p-2 text-center" style={{ background: 'var(--bg-card)' }}>
                    <div className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>{k}</div>
                    <div className="font-bold text-sm" style={{ color }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Raw log */}
          {log.raw && (
            <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
              <div className="flex items-center justify-between px-4 py-2"
                style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
                <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                  Raw Log
                </span>
                <button onClick={copyRaw} className="text-xs px-2 py-1 rounded"
                  style={{
                    background: copied ? 'rgba(16,185,129,0.15)' : 'var(--bg-card)',
                    color: copied ? '#6ee7b7' : 'var(--text-secondary)',
                    border: '1px solid var(--border-color)',
                  }}>
                  {copied ? '✓ Nusxalandi' : 'Nusxalash'}
                </button>
              </div>
              <pre className="p-4 text-xs overflow-x-auto whitespace-pre-wrap break-all"
                style={{ background: '#080d16', color: '#86efac', fontFamily: 'monospace', maxHeight: 180 }}>
                {log.raw}
              </pre>
            </div>
          )}

          {/* Parsed fields */}
          {Object.keys(pf).filter(k => !['threat_intel'].includes(k)).length > 0 && (
            <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
              <div className="px-4 py-2 text-xs font-semibold uppercase tracking-wide"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', borderBottom: '1px solid var(--border-color)' }}>
                Parsed Fields
              </div>
              <pre className="p-4 text-xs overflow-x-auto"
                style={{ background: '#080d16', color: '#a5b4fc', fontFamily: 'monospace', maxHeight: 220 }}>
                {JSON.stringify(
                  Object.fromEntries(Object.entries(pf).filter(([k]) => k !== 'threat_intel')),
                  null, 2
                )}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Logs() {
  // Filter state
  const [agentId,    setAgentId]    = useState('')
  const [hostname,   setHostname]   = useState('')
  const [level,      setLevel]      = useState('')
  const [eventType,  setEventType]  = useState('')
  const [kwRaw,      setKwRaw]      = useState('')
  const [source,     setSource]     = useState('')
  const [startTime,  setStartTime]  = useState('')
  const [endTime,    setEndTime]    = useState('')
  const [sortOrder,  setSortOrder]  = useState('desc')
  const [page,       setPage]       = useState(1)
  const [pageSize,   setPageSize]   = useState(50)
  const [timePreset, setTimePreset] = useState(null)
  const [showAdv,    setShowAdv]    = useState(false)

  // Quick filter active id
  const [activeQF, setActiveQF] = useState(null)

  // Data
  const [logs,     setLogs]     = useState([])
  const [total,    setTotal]    = useState(0)
  const [loading,  setLoading]  = useState(true)

  // Meta
  const [agents,      setAgents]      = useState([])
  const [sources,     setSources]     = useState([])
  const [eventTypes,  setEventTypes]  = useState([])
  const [stats,       setStats]       = useState(null)
  const [timeline,    setTimeline]    = useState([])
  const [statsLoading, setStatsLoading] = useState(true)

  // UI
  const [viewLog,   setViewLog]   = useState(null)
  const [liveMode,  setLiveMode]  = useState(false)
  const [newIds,    setNewIds]    = useState(new Set())
  const [exporting, setExporting] = useState(false)

  const liveRef = useRef(null)
  const keyword  = useDebounce(kwRaw, 400)
  const hostnameD = useDebounce(hostname, 400)

  // ── Load meta ──────────────────────────────────────────────────────────────

  useEffect(() => {
    getAgents().then(r => setAgents(r.data || [])).catch(() => {})
    getLogSources().then(r => setSources(r.data?.sources || [])).catch(() => {})
    getEventTypes().then(r => setEventTypes(r.data?.event_types || [])).catch(() => {})
    setStatsLoading(true)
    Promise.all([
      getLogStats(24).catch(() => null),
      getLogTimeline(24).catch(() => null),
    ]).then(([s, t]) => {
      if (s) setStats(s.data)
      if (t) setTimeline(t.data?.buckets || [])
    }).finally(() => setStatsLoading(false))
  }, [])

  // ── Time preset helpers ────────────────────────────────────────────────────

  const applyTimePreset = (hours) => {
    setTimePreset(hours)
    if (!hours) {
      setStartTime(''); setEndTime('')
    } else {
      const now = new Date()
      const from = new Date(now.getTime() - hours * 3600 * 1000)
      setStartTime(from.toISOString().slice(0, 16))
      setEndTime('')
    }
    setPage(1)
  }

  // ── Build query params ─────────────────────────────────────────────────────

  const buildParams = useCallback((overridePage, overrideSize) => {
    const qf = QUICK_FILTERS.find(f => f.id === activeQF)
    return {
      page:        overridePage ?? page,
      size:        overrideSize ?? pageSize,
      sort_order:  sortOrder,
      agent_id:    agentId    || undefined,
      hostname:    hostnameD  || undefined,
      level:       (qf?.level     || level)     || undefined,
      event_type:  (qf?.eventType || eventType) || undefined,
      keyword:     (qf?.keyword   || keyword)   || undefined,
      source:      (qf?.source    || source)    || undefined,
      start_time:  startTime || undefined,
      end_time:    endTime   || undefined,
    }
  }, [page, pageSize, agentId, hostnameD, level, eventType, keyword, source, startTime, endTime, sortOrder, activeQF])

  // ── Fetch logs ─────────────────────────────────────────────────────────────

  const fetchLogs = useCallback(async (prepend = false) => {
    if (!prepend) setLoading(true)
    try {
      const params = buildParams(prepend ? 1 : undefined, prepend ? 15 : undefined)
      const resp = await getLogs(params)
      const fetched = resp.data.logs || []

      if (prepend) {
        setLogs(prev => {
          const existIds = new Set(prev.map(l => l.id))
          const fresh = fetched.filter(l => !existIds.has(l.id))
          if (fresh.length) {
            setNewIds(new Set(fresh.map(l => l.id)))
            setTimeout(() => setNewIds(new Set()), 2500)
          }
          return [...fresh, ...prev].slice(0, 500)
        })
      } else {
        setLogs(fetched)
        setTotal(resp.data.total || 0)
      }
    } catch {}
    if (!prepend) setLoading(false)
  }, [buildParams])

  useEffect(() => { fetchLogs() }, [fetchLogs])

  useEffect(() => {
    if (liveMode) liveRef.current = setInterval(() => fetchLogs(true), 5000)
    else clearInterval(liveRef.current)
    return () => clearInterval(liveRef.current)
  }, [liveMode, fetchLogs])

  // ── Quick filter ───────────────────────────────────────────────────────────

  const applyQF = (id) => {
    if (activeQF === id) {
      setActiveQF(null)
    } else {
      setActiveQF(id)
      setAgentId(''); setHostname(''); setLevel(''); setEventType('')
      setKwRaw(''); setSource(''); setStartTime(''); setEndTime('')
      setTimePreset(null)
    }
    setPage(1)
  }

  const clearAll = () => {
    setActiveQF(null)
    setAgentId(''); setHostname(''); setLevel(''); setEventType('')
    setKwRaw(''); setSource(''); setStartTime(''); setEndTime('')
    setTimePreset(null); setPage(1)
  }

  // ── Export ─────────────────────────────────────────────────────────────────

  const handleExport = async () => {
    setExporting(true)
    try {
      const p = buildParams(1, 5000)
      const resp = await exportLogsCSV(p)
      downloadBlob(resp.data, `siem_logs_${new Date().toISOString().slice(0,10)}.csv`)
    } catch { alert('Export xatoligi') }
    finally { setExporting(false) }
  }

  // ── Derived ────────────────────────────────────────────────────────────────

  const hasManualFilter = agentId || hostname || level || eventType || kwRaw || source || startTime || endTime
  const hasAnyFilter    = activeQF || hasManualFilter
  const pages           = Math.ceil(total / pageSize) || 1
  const qfObj           = QUICK_FILTERS.find(f => f.id === activeQF)

  const agentName = (id) => agents.find(a => a.agent_id === id)?.hostname || id.slice(0, 10)

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-4 animate-fade-in">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Loglar</h2>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {loading ? '...' : (
              <>
                <span>{total.toLocaleString()} ta yozuv</span>
                {hasAnyFilter && <span className="ml-1.5 text-indigo-400">· filtr qo'llanilgan</span>}
              </>
            )}
            {qfObj && <span className="ml-2 text-indigo-400">· {qfObj.icon} {qfObj.label}</span>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { setSortOrder(o => o === 'desc' ? 'asc' : 'desc'); setPage(1) }}
            className="btn-ghost px-3 py-2 text-xs"
            title="Tartib o'zgartirish">
            {sortOrder === 'desc' ? '↓ Yangi' : '↑ Eski'}
          </button>

          {/* Live */}
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            {liveMode && <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />}
            <button onClick={() => setLiveMode(v => !v)}
              className="relative w-9 h-5 rounded-full flex-shrink-0"
              style={{ background: liveMode ? '#10b981' : 'rgba(255,255,255,0.1)' }}>
              <div className="absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform"
                style={{ transform: liveMode ? 'translateX(18px)' : 'translateX(2px)' }} />
            </button>
            <span className="text-xs" style={{ color: liveMode ? '#6ee7b7' : 'var(--text-muted)' }}>Live</span>
          </div>

          <button onClick={() => fetchLogs()} className="btn-ghost px-3 py-2 text-xs">↻</button>

          <button onClick={handleExport} disabled={exporting}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium disabled:opacity-50"
            style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)' }}>
            {exporting ? '...' : '⬇ CSV'}
          </button>
        </div>
      </div>

      {/* Stats bar */}
      <StatsBar stats={stats} loading={statsLoading} />

      {/* Timeline chart */}
      <TimelineChart data={timeline} />

      {/* Quick filters */}
      <div className="flex flex-wrap gap-2">
        {QUICK_FILTERS.map(qf => {
          const isActive = activeQF === qf.id
          return (
            <button key={qf.id} onClick={() => applyQF(qf.id)}
              title={qf.desc}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
              style={{
                background: isActive ? 'rgba(99,102,241,0.25)' : 'var(--bg-card)',
                border: `1px solid ${isActive ? 'rgba(99,102,241,0.5)' : 'var(--border-color)'}`,
                color: isActive ? '#a5b4fc' : 'var(--text-secondary)',
                boxShadow: isActive ? '0 0 0 1px rgba(99,102,241,0.2)' : 'none',
              }}>
              <span>{qf.icon}</span>
              {qf.label}
            </button>
          )
        })}
        {hasAnyFilter && (
          <button onClick={clearAll} className="px-3 py-1.5 rounded-lg text-xs font-medium"
            style={{ background: 'rgba(239,68,68,0.12)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.25)' }}>
            ✕ Tozalash
          </button>
        )}
      </div>

      {/* Manual filter panel */}
      <div className="rounded-xl p-4 space-y-3"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>

        {/* Row 1 — primary filters */}
        <div className="flex flex-wrap gap-3">
          {/* Agent */}
          <select value={agentId} onChange={e => { setAgentId(e.target.value); setActiveQF(null); setPage(1) }}
            style={{ minWidth: 150 }}>
            <option value="">Barcha agentlar</option>
            {agents.map(a => <option key={a.agent_id} value={a.agent_id}>{a.hostname}</option>)}
          </select>

          {/* Level */}
          <select value={level} onChange={e => { setLevel(e.target.value); setActiveQF(null); setPage(1) }}
            style={{ minWidth: 120 }}>
            <option value="">Daraja</option>
            {['CRITICAL','ERROR','WARNING','INFO','DEBUG'].map(l => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>

          {/* Source */}
          <select value={source} onChange={e => { setSource(e.target.value); setActiveQF(null); setPage(1) }}
            style={{ minWidth: 140 }}>
            <option value="">Manba</option>
            {sources.map(s => <option key={s} value={s}>{s}</option>)}
          </select>

          {/* Event Type */}
          <select value={eventType} onChange={e => { setEventType(e.target.value); setActiveQF(null); setPage(1) }}
            style={{ minWidth: 170 }}>
            <option value="">Hodisa turi</option>
            {eventTypes.map(et => <option key={et} value={et}>{et}</option>)}
          </select>

          {/* Keyword */}
          <div className="relative flex-1 min-w-44">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2" width="13" height="13"
              viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
              style={{ color: 'var(--text-muted)' }}>
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            <input type="text" placeholder="Kalit so'z..."
              value={kwRaw}
              onChange={e => { setKwRaw(e.target.value); setActiveQF(null); setPage(1) }}
              className="w-full" style={{ paddingLeft: 34 }} />
          </div>

          <button onClick={() => setShowAdv(v => !v)}
            className="btn-ghost px-3 py-2 text-xs flex items-center gap-1"
            style={{ color: showAdv ? '#a5b4fc' : 'var(--text-secondary)' }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="4" y1="6" x2="20" y2="6"/><line x1="8" y1="12" x2="16" y2="12"/>
              <line x1="12" y1="18" x2="12" y2="18" strokeLinecap="round" strokeWidth="3"/>
            </svg>
            Qo'shimcha
          </button>
        </div>

        {/* Advanced */}
        {showAdv && (
          <div className="flex flex-wrap gap-3 pt-3" style={{ borderTop: '1px solid var(--border-color)' }}>
            {/* Hostname */}
            <div className="flex items-center gap-2">
              <label className="text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>Hostname:</label>
              <input type="text" placeholder="server-01"
                value={hostname}
                onChange={e => { setHostname(e.target.value); setActiveQF(null); setPage(1) }}
                className="text-xs"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)',
                  borderRadius: 8, padding: '6px 10px', color: 'white', width: 140 }} />
            </div>

            {/* Time presets */}
            <div className="flex items-center gap-1.5">
              <label className="text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>Vaqt:</label>
              {TIME_PRESETS.map(({ label, hours }) => (
                <button key={label}
                  onClick={() => { applyTimePreset(hours); setActiveQF(null) }}
                  className="px-2 py-1 rounded text-xs font-medium"
                  style={{
                    background: timePreset === hours ? 'rgba(99,102,241,0.25)' : 'var(--bg-secondary)',
                    color:      timePreset === hours ? '#a5b4fc' : 'var(--text-secondary)',
                    border:     `1px solid ${timePreset === hours ? 'rgba(99,102,241,0.4)' : 'var(--border-color)'}`,
                  }}>
                  {label}
                </button>
              ))}
            </div>

            {/* Dan/Gacha — manual override */}
            <div className="flex items-center gap-2">
              <label className="text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>Dan:</label>
              <input type="datetime-local" value={startTime}
                onChange={e => { setStartTime(e.target.value); setTimePreset(null); setPage(1) }}
                className="text-xs"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)',
                  borderRadius: 8, padding: '6px 10px', color: 'white' }} />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>Gacha:</label>
              <input type="datetime-local" value={endTime}
                onChange={e => { setEndTime(e.target.value); setPage(1) }}
                className="text-xs"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)',
                  borderRadius: 8, padding: '6px 10px', color: 'white' }} />
            </div>
          </div>
        )}
      </div>

      {/* Active filter badges */}
      {hasAnyFilter && (
        <div className="flex flex-wrap gap-2 items-center">
          {activeQF && (
            <FilterBadge
              label={`${qfObj?.icon} ${qfObj?.label}${qfObj?.keyword ? ` · "${qfObj.keyword}"` : ''}`}
              onRemove={() => setActiveQF(null)} />
          )}
          {agentId     && <FilterBadge label={`Agent: ${agentName(agentId)}`}          onRemove={() => setAgentId('')} />}
          {hostname    && <FilterBadge label={`Host: ${hostname}`}                      onRemove={() => setHostname('')} />}
          {level       && <FilterBadge label={`Daraja: ${level}`}                       onRemove={() => setLevel('')} />}
          {eventType   && <FilterBadge label={`Hodisa: ${eventType}`}                   onRemove={() => setEventType('')} />}
          {source      && <FilterBadge label={`Manba: ${source}`}                       onRemove={() => setSource('')} />}
          {kwRaw       && <FilterBadge label={`Kalit: "${kwRaw}"`}                      onRemove={() => setKwRaw('')} />}
          {startTime   && <FilterBadge label={`Dan: ${new Date(startTime).toLocaleString()}`}  onRemove={() => { setStartTime(''); setTimePreset(null) }} />}
          {endTime     && <FilterBadge label={`Gacha: ${new Date(endTime).toLocaleString()}`}  onRemove={() => setEndTime('')} />}
        </div>
      )}

      {/* Log table */}
      <div className="rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                {['Vaqt', 'Daraja', 'Hostname', 'Manba / Jarayon', 'IP', 'Xabar'].map(h => (
                  <th key={h} className="text-left px-4 py-3 font-semibold uppercase tracking-wide"
                    style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border-color)' }}>
                    {[80, 70, 90, 110, 80, 220].map((w, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="skeleton h-3 rounded" style={{ width: w }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-16" style={{ color: 'var(--text-muted)' }}>
                    <div className="text-3xl mb-2">📭</div>
                    <div>Log topilmadi</div>
                    {hasAnyFilter && (
                      <button onClick={clearAll} className="mt-3 text-xs text-indigo-400 underline">
                        Filterlarni tozalash
                      </button>
                    )}
                  </td>
                </tr>
              ) : logs.map((log, i) => {
                const pf        = log.parsed_fields || {}
                const isNew     = newIds.has(log.id)
                const isCrit    = log.level === 'CRITICAL'
                const proc      = pf.process || extractProcess(log.message)
                const srcIp     = pf.src_ip || pf.ssh_src_ip
                const body      = extractBody(log.message)
                const geo       = pf.geo_country_code
                const malicious = pf.has_malicious_ip
                const evType    = pf.event_type
                const filePath  = pf.file_path

                return (
                  <tr key={log.id || i}
                    className="table-row-hover cursor-pointer transition-colors"
                    style={{
                      borderBottom: '1px solid var(--border-color)',
                      background: isNew
                        ? 'rgba(16,185,129,0.07)'
                        : isCrit
                        ? 'rgba(239,68,68,0.04)'
                        : undefined,
                    }}
                    onClick={() => setViewLog(log)}>

                    {/* Vaqt */}
                    <td className="px-4 py-2.5 whitespace-nowrap font-mono"
                      style={{ color: 'var(--text-muted)', minWidth: 115 }}>
                      {isNew && <span className="inline-block w-1.5 h-1.5 rounded-full bg-green-400 mr-1 mb-0.5 animate-pulse" />}
                      {fmtTs(log.timestamp)}
                    </td>

                    {/* Daraja */}
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <LevelBadge level={log.level} />
                    </td>

                    {/* Hostname */}
                    <td className="px-4 py-2.5 whitespace-nowrap font-medium"
                      style={{ color: '#93c5fd', maxWidth: 110, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {log.hostname || pf.hostname || '—'}
                    </td>

                    {/* Manba / Jarayon */}
                    <td className="px-4 py-2.5 whitespace-nowrap" style={{ maxWidth: 160 }}>
                      <div className="flex flex-col gap-0.5">
                        <span className="font-medium" style={{ color: '#c4b5fd' }}>
                          {log.source || '—'}
                        </span>
                        {proc && proc !== log.source && (
                          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {proc}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* IP */}
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      {srcIp ? (
                        <span className="font-mono text-xs flex items-center gap-1">
                          {malicious && <span style={{ color: '#ef4444' }} title="Zararli IP">⚠</span>}
                          <span style={{ color: malicious ? '#fca5a5' : '#6ee7b7' }}>{srcIp}</span>
                          {geo && <span style={{ color: 'var(--text-muted)' }}>{geo}</span>}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>—</span>
                      )}
                    </td>

                    {/* Xabar */}
                    <td className="px-4 py-2.5" style={{ maxWidth: 360 }}>
                      <div className="flex flex-col gap-0.5">
                        {evType && (
                          <span className="inline-flex w-fit items-center px-1.5 py-0.5 rounded text-xs font-mono"
                            style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.2)' }}>
                            {evType}
                          </span>
                        )}
                        {filePath ? (
                          <span className="text-xs font-mono truncate" style={{ color: '#6ee7b7' }} title={filePath}>
                            {filePath}
                          </span>
                        ) : (
                          <span className="text-sm text-white truncate">{body || log.message}</span>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {!liveMode && (
          <div className="flex items-center justify-between px-5 py-3"
            style={{ borderTop: '1px solid var(--border-color)' }}>
            <div className="flex items-center gap-3">
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {((page-1)*pageSize+1).toLocaleString()}–{Math.min(page*pageSize, total).toLocaleString()} / {total.toLocaleString()} ta
              </span>
              {/* Page size selector */}
              <div className="flex gap-1">
                {PAGE_SIZES.map(s => (
                  <button key={s} onClick={() => { setPageSize(s); setPage(1) }}
                    className="px-2 py-0.5 rounded text-xs"
                    style={{
                      background: pageSize === s ? 'rgba(99,102,241,0.2)' : 'transparent',
                      color:      pageSize === s ? '#a5b4fc' : 'var(--text-muted)',
                      border:     `1px solid ${pageSize === s ? 'rgba(99,102,241,0.35)' : 'transparent'}`,
                    }}>
                    {s}
                  </button>
                ))}
              </div>
            </div>
            {pages > 1 && (
              <div className="flex gap-1">
                {[
                  ['«', () => setPage(1),                            page === 1],
                  ['‹', () => setPage(p => Math.max(1, p-1)),        page === 1],
                  ['›', () => setPage(p => Math.min(pages, p+1)),    page >= pages],
                  ['»', () => setPage(pages),                        page >= pages],
                ].map(([label, fn, disabled]) => (
                  <button key={label} onClick={fn} disabled={disabled}
                    className="btn-ghost py-1 px-2.5 text-xs disabled:opacity-30">
                    {label}
                  </button>
                ))}
                <span className="px-2 py-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                  {page}/{pages}
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {viewLog && <LogModal log={viewLog} onClose={() => setViewLog(null)} />}
    </div>
  )
}
