import React, { useState, useEffect, useCallback } from 'react'
import {
  getInventoryAgents, getInventorySummary,
  getInventoryPackages, getInventoryPorts,
  getInventoryProcesses, getInventoryInterfaces,
} from '../api'

/* ── Icons ────────────────────────────────────────────────── */
const Icon = ({ d, size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    {Array.isArray(d) ? d.map((p, i) => <path key={i} d={p} />) : <path d={d} />}
  </svg>
)

const ICONS = {
  pkg:    ['M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z'],
  port:   ['M5 12h14', 'M12 5l7 7-7 7'],
  proc:   ['M22 12h-4l-3 9L9 3l-3 9H2'],
  iface:  ['M1 6l5 6-5 6', 'M23 6l-5 6 5 6', 'M8 12h8'],
  search: ['M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0'],
  agent:  ['M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2', 'M12 11a4 4 0 100-8 4 4 0 000 8'],
  clock:  ['M12 2a10 10 0 100 20A10 10 0 0012 2z', 'M12 6v6l4 2'],
  up:     ['M5 15l7-7 7 7'],
  down:   ['M19 9l-7 7-7-7'],
  refresh:['M23 4v6h-6', 'M20.49 15a9 9 0 11-2.12-9.36L23 10'],
}

/* ── Ecosystem badge ──────────────────────────────────────── */
const ECO_CFG = {
  apt:     { color: '#f97316', bg: 'rgba(249,115,22,0.12)',  label: 'APT' },
  rpm:     { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',   label: 'RPM' },
  pip:     { color: '#3b82f6', bg: 'rgba(59,130,246,0.12)',  label: 'PIP' },
  npm:     { color: '#10b981', bg: 'rgba(16,185,129,0.12)',  label: 'NPM' },
  windows: { color: '#6366f1', bg: 'rgba(99,102,241,0.12)',  label: 'WIN' },
  brew:    { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)',  label: 'BREW' },
}
const EcoBadge = ({ eco }) => {
  const c = ECO_CFG[eco?.toLowerCase()] || { color: '#6b7280', bg: 'rgba(107,114,128,0.12)', label: (eco || '?').toUpperCase().slice(0, 5) }
  return (
    <span className="text-xs font-bold px-2 py-0.5 rounded"
      style={{ background: c.bg, color: c.color, border: `1px solid ${c.color}30` }}>
      {c.label}
    </span>
  )
}

/* ── Status pill ──────────────────────────────────────────── */
const UpDown = ({ up }) => (
  <span className="flex items-center gap-1 text-xs font-semibold"
    style={{ color: up ? '#10b981' : '#ef4444' }}>
    <span className="w-1.5 h-1.5 rounded-full" style={{ background: up ? '#10b981' : '#ef4444' }} />
    {up ? 'UP' : 'DOWN'}
  </span>
)

/* ── Agent sidebar card ───────────────────────────────────── */
function AgentCard({ agent, selected, onClick }) {
  const ago = agent.scanned_at
    ? Math.round((Date.now() - new Date(agent.scanned_at)) / 60000)
    : null
  return (
    <button onClick={onClick}
      className="w-full text-left px-4 py-3 rounded-xl transition-all"
      style={{
        background: selected ? 'rgba(99,102,241,0.15)' : 'transparent',
        border: selected ? '1px solid rgba(99,102,241,0.4)' : '1px solid transparent',
      }}>
      <div className="flex items-center gap-2 mb-1">
        <span style={{ color: selected ? '#a5b4fc' : 'var(--text-muted)' }}>
          <Icon d={ICONS.agent} size={14} />
        </span>
        <span className="text-sm font-semibold truncate"
          style={{ color: selected ? '#e2e8f0' : 'var(--text-secondary)' }}>
          {agent.hostname || agent.agent_id}
        </span>
      </div>
      <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
        <span>{agent.pkg_count} pkgs</span>
        <span>{agent.port_count} ports</span>
        <span>{agent.process_count} procs</span>
      </div>
      {ago !== null && (
        <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
          Scanned {ago < 2 ? 'just now' : `${ago}m ago`}
        </div>
      )}
    </button>
  )
}

/* ── Summary header ───────────────────────────────────────── */
function InventorySummary({ summary }) {
  if (!summary) return null
  const ms = summary.scan_duration_ms
  const dur = ms ? (ms > 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`) : '—'
  const tiles = [
    { label: 'Packages',   val: summary.pkg_count,     color: '#f97316', icon: ICONS.pkg },
    { label: 'Open Ports', val: summary.port_count,    color: '#ef4444', icon: ICONS.port },
    { label: 'Processes',  val: summary.process_count, color: '#6366f1', icon: ICONS.proc },
    { label: 'Interfaces', val: summary.iface_count,   color: '#10b981', icon: ICONS.iface },
  ]
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
      {tiles.map(({ label, val, color, icon }) => (
        <div key={label} className="rounded-xl p-4 flex items-center gap-3"
          style={{ background: 'var(--bg-card)', border: `1px solid ${color}25` }}>
          <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: `${color}18`, color }}>
            <Icon d={icon} size={18} />
          </div>
          <div>
            <p className="text-xl font-black" style={{ color }}>{val ?? '—'}</p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</p>
          </div>
        </div>
      ))}
    </div>
  )
}

/* ── Packages tab ─────────────────────────────────────────── */
function PackagesTab({ agentId }) {
  const [data, setData]       = useState(null)
  const [search, setSearch]   = useState('')
  const [eco, setEco]         = useState('')
  const [page, setPage]       = useState(1)
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    if (!agentId) return
    setLoading(true)
    try {
      const r = await getInventoryPackages(agentId, { search: search || undefined, ecosystem: eco || undefined, page, per_page: 50 })
      setData(r.data)
    } catch { setData(null) }
    finally { setLoading(false) }
  }, [agentId, search, eco, page])

  useEffect(() => { setPage(1) }, [search, eco, agentId])
  useEffect(() => { load() }, [load])

  const ecosystems = ['apt', 'rpm', 'pip', 'npm', 'windows']
  const items = data?.items || []
  const total = data?.total || 0
  const pages = Math.ceil(total / 50)

  return (
    <div>
      {/* Filters */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <div className="relative flex-1 min-w-48">
          <span className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-muted)' }}>
            <Icon d={ICONS.search} size={14} />
          </span>
          <input value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search packages..."
            className="w-full pl-9 pr-3 py-2 rounded-xl text-sm"
            style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)',
              color: 'var(--text-primary)', outline: 'none' }} />
        </div>
        <div className="flex gap-2 flex-wrap">
          <button onClick={() => setEco('')}
            className="text-xs px-3 py-2 rounded-lg font-medium transition-all"
            style={{
              background: eco === '' ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)',
              color: eco === '' ? '#a5b4fc' : 'var(--text-muted)',
              border: `1px solid ${eco === '' ? 'rgba(99,102,241,0.4)' : 'var(--border-color)'}`,
            }}>All</button>
          {ecosystems.map((e) => (
            <button key={e} onClick={() => setEco(e)}
              className="text-xs px-3 py-2 rounded-lg font-medium transition-all"
              style={{
                background: eco === e ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)',
                color: eco === e ? '#a5b4fc' : 'var(--text-muted)',
                border: `1px solid ${eco === e ? 'rgba(99,102,241,0.4)' : 'var(--border-color)'}`,
              }}>
              {e.toUpperCase()}
            </button>
          ))}
        </div>
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{total} total</span>
      </div>

      {/* Table */}
      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
              {['Package', 'Version', 'Ecosystem'].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide"
                  style={{ color: 'var(--text-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={3} className="px-4 py-8 text-center" style={{ color: 'var(--text-muted)' }}>Loading...</td></tr>
            ) : items.length === 0 ? (
              <tr><td colSpan={3} className="px-4 py-8 text-center" style={{ color: 'var(--text-muted)' }}>No packages found</td></tr>
            ) : items.map((p, i) => (
              <tr key={i} className="table-row-hover"
                style={{ borderBottom: '1px solid var(--border-color)' }}>
                <td className="px-4 py-2.5 font-mono text-sm" style={{ color: 'var(--text-primary)' }}>{p.name}</td>
                <td className="px-4 py-2.5 text-xs font-mono" style={{ color: '#a5b4fc' }}>{p.version || '—'}</td>
                <td className="px-4 py-2.5"><EcoBadge eco={p.ecosystem} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div className="flex items-center justify-between mt-3">
          <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
            className="btn-ghost text-xs px-3 py-1.5 disabled:opacity-40">← Prev</button>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Page {page} / {pages}</span>
          <button onClick={() => setPage((p) => Math.min(pages, p + 1))} disabled={page === pages}
            className="btn-ghost text-xs px-3 py-1.5 disabled:opacity-40">Next →</button>
        </div>
      )}
    </div>
  )
}

/* ── Ports tab ────────────────────────────────────────────── */
function PortsTab({ agentId }) {
  const [data, setData]     = useState([])
  const [loading, setLoading] = useState(false)
  const [proto, setProto]   = useState('')

  useEffect(() => {
    if (!agentId) return
    setLoading(true)
    getInventoryPorts(agentId, { protocol: proto || undefined })
      .then((r) => setData(r.data))
      .catch(() => setData([]))
      .finally(() => setLoading(false))
  }, [agentId, proto])

  const WELL_KNOWN = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 5432: 'PostgreSQL',
    6379: 'Redis', 9200: 'Elasticsearch', 27017: 'MongoDB',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 3000: 'Dev',
  }

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        {['', 'tcp', 'udp'].map((p) => (
          <button key={p || 'all'} onClick={() => setProto(p)}
            className="text-xs px-3 py-2 rounded-lg font-medium"
            style={{
              background: proto === p ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)',
              color: proto === p ? '#a5b4fc' : 'var(--text-muted)',
              border: `1px solid ${proto === p ? 'rgba(99,102,241,0.4)' : 'var(--border-color)'}`,
            }}>
            {p === '' ? 'All' : p.toUpperCase()}
          </button>
        ))}
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{data.length} ports</span>
      </div>

      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
              {['Port', 'Protocol', 'Bind', 'Service', 'Process', 'User'].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide"
                  style={{ color: 'var(--text-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center" style={{ color: 'var(--text-muted)' }}>Loading...</td></tr>
            ) : data.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center" style={{ color: 'var(--text-muted)' }}>No ports found</td></tr>
            ) : data.map((p, i) => {
              const svc = WELL_KNOWN[p.port]
              return (
                <tr key={i} className="table-row-hover"
                  style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td className="px-4 py-2.5">
                    <span className="font-mono font-bold text-sm" style={{ color: '#60a5fa' }}>{p.port}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-xs font-bold px-2 py-0.5 rounded"
                      style={{
                        background: p.protocol === 'tcp' ? 'rgba(99,102,241,0.15)' : 'rgba(245,158,11,0.15)',
                        color: p.protocol === 'tcp' ? '#a5b4fc' : '#fbbf24',
                      }}>
                      {(p.protocol || 'tcp').toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
                    {p.bind_addr || '*'}
                  </td>
                  <td className="px-4 py-2.5">
                    {svc ? (
                      <span className="text-xs px-2 py-0.5 rounded font-semibold"
                        style={{ background: 'rgba(16,185,129,0.12)', color: '#34d399' }}>
                        {svc}
                      </span>
                    ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                  </td>
                  <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-primary)' }}>
                    {p.process_name || '—'}
                    {p.pid && <span className="ml-1 font-mono" style={{ color: 'var(--text-muted)' }}>({p.pid})</span>}
                  </td>
                  <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {p.process_user || '—'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* ── Processes tab ────────────────────────────────────────── */
function ProcessesTab({ agentId }) {
  const [data, setData]       = useState(null)
  const [search, setSearch]   = useState('')
  const [page, setPage]       = useState(1)
  const [sort, setSort]       = useState('cpu_pct')
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    if (!agentId) return
    setLoading(true)
    try {
      const r = await getInventoryProcesses(agentId, { search: search || undefined, page, per_page: 50, sort })
      setData(r.data)
    } catch { setData(null) }
    finally { setLoading(false) }
  }, [agentId, search, page, sort])

  useEffect(() => { setPage(1) }, [search, sort, agentId])
  useEffect(() => { load() }, [load])

  const items = data?.items || []
  const total = data?.total || 0
  const pages = Math.ceil(total / 50)

  const cpuBar = (pct) => {
    const color = pct > 80 ? '#ef4444' : pct > 40 ? '#f59e0b' : '#10b981'
    return (
      <div className="flex items-center gap-2">
        <span className="text-xs font-mono font-semibold w-10 text-right" style={{ color }}>{pct?.toFixed(1)}%</span>
        <div className="h-1.5 w-16 rounded-full" style={{ background: 'var(--border-color)' }}>
          <div className="h-full rounded-full" style={{ width: `${Math.min(pct || 0, 100)}%`, background: color }} />
        </div>
      </div>
    )
  }

  const memColor = (mb) => {
    if (mb > 1024) return '#ef4444'
    if (mb > 256)  return '#f59e0b'
    return 'var(--text-secondary)'
  }

  return (
    <div>
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <div className="relative flex-1 min-w-48">
          <span className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-muted)' }}>
            <Icon d={ICONS.search} size={14} />
          </span>
          <input value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name or cmdline..."
            className="w-full pl-9 pr-3 py-2 rounded-xl text-sm"
            style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)',
              color: 'var(--text-primary)', outline: 'none' }} />
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Sort:</span>
          {[['cpu_pct', 'CPU'], ['mem_mb', 'RAM'], ['name', 'Name'], ['pid', 'PID']].map(([val, label]) => (
            <button key={val} onClick={() => setSort(val)}
              className="text-xs px-2.5 py-1.5 rounded-lg"
              style={{
                background: sort === val ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)',
                color: sort === val ? '#a5b4fc' : 'var(--text-muted)',
                border: `1px solid ${sort === val ? 'rgba(99,102,241,0.4)' : 'var(--border-color)'}`,
              }}>{label}</button>
          ))}
        </div>
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{total} total</span>
      </div>

      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
              {['PID', 'Name', 'User', 'CPU', 'RAM', 'Status'].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide"
                  style={{ color: 'var(--text-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center" style={{ color: 'var(--text-muted)' }}>Loading...</td></tr>
            ) : items.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center" style={{ color: 'var(--text-muted)' }}>No processes found</td></tr>
            ) : items.map((p, i) => (
              <tr key={i} className="table-row-hover"
                style={{ borderBottom: '1px solid var(--border-color)' }}>
                <td className="px-4 py-2 font-mono text-xs" style={{ color: '#94a3b8' }}>{p.pid}</td>
                <td className="px-4 py-2">
                  <div className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>{p.name}</div>
                  {p.cmdline && p.cmdline !== p.name && (
                    <div className="text-xs font-mono truncate max-w-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                      {p.cmdline}
                    </div>
                  )}
                </td>
                <td className="px-4 py-2 text-xs" style={{ color: '#93c5fd' }}>{p.user || '—'}</td>
                <td className="px-4 py-2">{cpuBar(p.cpu_pct ?? 0)}</td>
                <td className="px-4 py-2 text-xs font-mono font-semibold"
                  style={{ color: memColor(p.mem_mb ?? 0) }}>
                  {p.mem_mb != null ? `${p.mem_mb.toFixed(0)} MB` : '—'}
                </td>
                <td className="px-4 py-2">
                  <span className="text-xs px-2 py-0.5 rounded font-medium capitalize"
                    style={{
                      background: p.status === 'running' ? 'rgba(16,185,129,0.12)' : 'rgba(107,114,128,0.12)',
                      color:      p.status === 'running' ? '#34d399' : '#9ca3af',
                    }}>
                    {p.status || '—'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {pages > 1 && (
        <div className="flex items-center justify-between mt-3">
          <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
            className="btn-ghost text-xs px-3 py-1.5 disabled:opacity-40">← Prev</button>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Page {page} / {pages}</span>
          <button onClick={() => setPage((p) => Math.min(pages, p + 1))} disabled={page === pages}
            className="btn-ghost text-xs px-3 py-1.5 disabled:opacity-40">Next →</button>
        </div>
      )}
    </div>
  )
}

/* ── Interfaces tab ───────────────────────────────────────── */
function InterfacesTab({ agentId }) {
  const [data, setData]       = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!agentId) return
    setLoading(true)
    getInventoryInterfaces(agentId)
      .then((r) => setData(r.data))
      .catch(() => setData([]))
      .finally(() => setLoading(false))
  }, [agentId])

  if (loading) return (
    <div className="flex justify-center py-16" style={{ color: 'var(--text-muted)' }}>Loading...</div>
  )

  if (!data.length) return (
    <div className="flex flex-col items-center justify-center py-16" style={{ color: 'var(--text-muted)' }}>
      <Icon d={ICONS.iface} size={36} />
      <p className="mt-3 text-sm">No interfaces found</p>
    </div>
  )

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {data.map((iface) => (
        <div key={iface.name} className="rounded-xl p-5"
          style={{ background: 'var(--bg-card)', border: `1px solid ${iface.is_up ? 'rgba(16,185,129,0.25)' : 'rgba(239,68,68,0.2)'}` }}>
          {/* Header */}
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <span style={{ color: iface.is_up ? '#10b981' : '#ef4444' }}>
                <Icon d={ICONS.iface} size={18} />
              </span>
              <span className="font-bold text-base" style={{ color: 'var(--text-primary)' }}>
                {iface.name}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <UpDown up={iface.is_up} />
              {iface.speed_mbps > 0 && (
                <span className="text-xs px-2 py-0.5 rounded"
                  style={{ background: 'rgba(99,102,241,0.12)', color: '#a5b4fc' }}>
                  {iface.speed_mbps >= 1000 ? `${iface.speed_mbps / 1000}G` : `${iface.speed_mbps}M`}
                </span>
              )}
            </div>
          </div>

          {/* MAC */}
          {iface.mac && (
            <div className="flex items-center gap-2 mb-3">
              <span className="text-xs font-semibold w-10" style={{ color: 'var(--text-muted)' }}>MAC</span>
              <span className="font-mono text-xs" style={{ color: '#94a3b8' }}>{iface.mac}</span>
            </div>
          )}

          {/* IPv4 */}
          {iface.ipv4?.length > 0 && (
            <div className="mb-2">
              <span className="text-xs font-semibold mb-1 block" style={{ color: 'var(--text-muted)' }}>IPv4</span>
              <div className="space-y-1">
                {iface.ipv4.map((a, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <span className="font-mono text-sm font-semibold" style={{ color: '#60a5fa' }}>{a.ip}</span>
                    {a.netmask && (
                      <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>/{a.netmask}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* IPv6 */}
          {iface.ipv6?.length > 0 && (
            <div className="mb-2">
              <span className="text-xs font-semibold mb-1 block" style={{ color: 'var(--text-muted)' }}>IPv6</span>
              <div className="space-y-1">
                {iface.ipv6.map((addr, i) => (
                  <div key={i} className="font-mono text-xs truncate" style={{ color: '#a5b4fc' }}>{addr}</div>
                ))}
              </div>
            </div>
          )}

          {/* Meta */}
          <div className="flex gap-4 mt-3 pt-3" style={{ borderTop: '1px solid var(--border-color)' }}>
            {iface.mtu > 0 && (
              <div>
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>MTU </span>
                <span className="text-xs font-mono font-semibold" style={{ color: 'var(--text-secondary)' }}>{iface.mtu}</span>
              </div>
            )}
            {iface.duplex && iface.duplex !== 'NIC_DUPLEX_UNKNOWN' && (
              <div>
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Duplex </span>
                <span className="text-xs font-semibold capitalize" style={{ color: 'var(--text-secondary)' }}>
                  {iface.duplex.replace('NIC_DUPLEX_', '').toLowerCase()}
                </span>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════ */
const TABS = [
  { key: 'packages',   label: 'Packages',    icon: ICONS.pkg },
  { key: 'ports',      label: 'Ports',       icon: ICONS.port },
  { key: 'processes',  label: 'Processes',   icon: ICONS.proc },
  { key: 'interfaces', label: 'Interfaces',  icon: ICONS.iface },
]

export default function Inventory() {
  const [agents, setAgents]       = useState([])
  const [selected, setSelected]   = useState(null)   // agent_id
  const [summary, setSummary]     = useState(null)
  const [tab, setTab]             = useState('packages')
  const [loading, setLoading]     = useState(true)

  // Load agent list
  const loadAgents = useCallback(async () => {
    setLoading(true)
    try {
      const r = await getInventoryAgents()
      const list = r.data || []
      setAgents(list)
      if (!selected && list.length > 0) {
        setSelected(list[0].agent_id)
      }
    } catch {}
    finally { setLoading(false) }
  }, [selected])

  useEffect(() => { loadAgents() }, [])

  // Load summary when agent changes
  useEffect(() => {
    if (!selected) return
    setSummary(null)
    getInventorySummary(selected)
      .then((r) => setSummary(r.data))
      .catch(() => setSummary(null))
  }, [selected])

  const selectedAgent = agents.find((a) => a.agent_id === selected)

  return (
    <div className="flex gap-5 h-full animate-fade-in" style={{ minHeight: 0 }}>

      {/* ── Sidebar ── */}
      <div className="w-56 flex-shrink-0 rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        <div className="px-4 py-4" style={{ borderBottom: '1px solid var(--border-color)' }}>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>Agents</h3>
            <button onClick={loadAgents} style={{ color: 'var(--text-muted)' }}>
              <Icon d={ICONS.refresh} size={13} />
            </button>
          </div>
        </div>
        <div className="p-2 space-y-1 overflow-y-auto" style={{ maxHeight: 'calc(100vh - 200px)' }}>
          {loading ? (
            <div className="py-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>Loading...</div>
          ) : agents.length === 0 ? (
            <div className="py-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
              No inventory data yet.<br />Agents scan every hour.
            </div>
          ) : agents.map((a) => (
            <AgentCard key={a.agent_id} agent={a}
              selected={selected === a.agent_id}
              onClick={() => setSelected(a.agent_id)} />
          ))}
        </div>
      </div>

      {/* ── Main panel ── */}
      <div className="flex-1 min-w-0">
        {!selected ? (
          <div className="flex flex-col items-center justify-center h-64 gap-3"
            style={{ color: 'var(--text-muted)' }}>
            <Icon d={ICONS.agent} size={40} />
            <p className="text-sm">Select an agent to view inventory</p>
          </div>
        ) : (
          <>
            {/* Header */}
            <div className="rounded-2xl p-5 mb-5"
              style={{ background: 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 60%, #0f172a 100%)',
                border: '1px solid rgba(99,102,241,0.3)' }}>
              <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                  <h2 className="text-lg font-black gradient-text mb-1">
                    {selectedAgent?.hostname || selected}
                  </h2>
                  <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                    <span className="font-mono">{selected}</span>
                    {summary?.scanned_at && (
                      <span className="flex items-center gap-1">
                        <Icon d={ICONS.clock} size={11} />
                        {new Date(summary.scanned_at).toLocaleString()}
                      </span>
                    )}
                    {summary?.scan_duration_ms && (
                      <span className="px-2 py-0.5 rounded"
                        style={{ background: 'rgba(16,185,129,0.12)', color: '#34d399' }}>
                        scan: {summary.scan_duration_ms > 1000
                          ? `${(summary.scan_duration_ms / 1000).toFixed(1)}s`
                          : `${summary.scan_duration_ms}ms`}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Summary tiles */}
            <InventorySummary summary={summary} />

            {/* Tabs */}
            <div className="flex gap-1 mb-4 rounded-xl p-1" style={{ background: 'var(--bg-secondary)' }}>
              {TABS.map(({ key, label, icon }) => (
                <button key={key} onClick={() => setTab(key)}
                  className="flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium transition-all"
                  style={{
                    background: tab === key ? 'var(--bg-card)' : 'transparent',
                    color: tab === key ? 'var(--text-primary)' : 'var(--text-muted)',
                    boxShadow: tab === key ? '0 1px 4px rgba(0,0,0,0.3)' : 'none',
                  }}>
                  <span style={{ color: tab === key ? '#a5b4fc' : 'var(--text-muted)' }}>
                    <Icon d={icon} size={14} />
                  </span>
                  {label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div className="rounded-2xl p-5"
              style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
              {tab === 'packages'   && <PackagesTab   agentId={selected} />}
              {tab === 'ports'      && <PortsTab      agentId={selected} />}
              {tab === 'processes'  && <ProcessesTab  agentId={selected} />}
              {tab === 'interfaces' && <InterfacesTab agentId={selected} />}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
