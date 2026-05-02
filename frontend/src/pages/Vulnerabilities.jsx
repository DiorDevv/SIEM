import React, { useState, useEffect, useCallback } from 'react'
import { getVulns, getVulnSummary, updateVulnStatus, exportVulnsCSV } from '../api'

const SEV = {
  CRITICAL: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.3)' },
  HIGH:     { color: '#f97316', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.3)' },
  MEDIUM:   { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.3)' },
  LOW:      { color: '#3b82f6', bg: 'rgba(59,130,246,0.12)',  border: 'rgba(59,130,246,0.3)' },
  UNKNOWN:  { color: '#6b7280', bg: 'rgba(107,114,128,0.12)', border: 'rgba(107,114,128,0.3)' },
}

const STATUS_OPT = [
  { value: 'open',     label: 'Open',           color: '#ef4444' },
  { value: 'patched',  label: 'Patched',         color: '#10b981' },
  { value: 'accepted', label: 'Risk Accepted',   color: '#6b7280' },
]

function SevBadge({ s }) {
  const c = SEV[s] || SEV.UNKNOWN
  return (
    <span className="text-xs font-bold px-2.5 py-0.5 rounded-full"
      style={{ color: c.color, background: c.bg, border: `1px solid ${c.border}` }}>{s}</span>
  )
}

function ScoreBar({ score }) {
  if (score == null) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>
  const pct   = Math.min((score / 10) * 100, 100)
  const color = score >= 9 ? '#ef4444' : score >= 7 ? '#f97316' : score >= 4 ? '#f59e0b' : '#3b82f6'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--border-color)', maxWidth: 60 }}>
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="text-xs font-bold" style={{ color }}>{score.toFixed(1)}</span>
    </div>
  )
}

function VulnDetail({ vuln, onClose, onStatus }) {
  if (!vuln) return null
  const c = SEV[vuln.severity] || SEV.UNKNOWN
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(6px)' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="w-full max-w-2xl rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: `1px solid ${c.border}`,
          boxShadow: `0 24px 60px rgba(0,0,0,0.6), 0 0 40px ${c.color}15`,
          maxHeight: '90vh', overflowY: 'auto' }}>

        <div className="px-6 py-4 flex items-center justify-between"
          style={{ background: 'var(--bg-secondary)', borderBottom: `1px solid ${c.border}` }}>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <SevBadge s={vuln.severity} />
              <span className="text-xs font-mono px-2 py-0.5 rounded"
                style={{ background: 'var(--border-color)', color: 'var(--accent-cyan)' }}>
                {vuln.vuln_id}
              </span>
            </div>
            <h3 className="font-bold text-white text-sm">{vuln.package_name} @ {vuln.package_version}</h3>
          </div>
          <button onClick={onClose} className="w-7 h-7 rounded-lg flex items-center justify-center text-lg"
            style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)' }}>×</button>
        </div>

        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            {[
              ['Package',    `${vuln.package_name} ${vuln.package_version}`],
              ['Ecosystem',  vuln.ecosystem || '—'],
              ['CVSS Score', vuln.cvss_score != null ? vuln.cvss_score.toFixed(1) : '—'],
              ['Fixed In',   vuln.fixed_version || 'No fix available'],
              ['Agent',      vuln.hostname || vuln.agent_id],
              ['First Seen', vuln.first_seen ? new Date(vuln.first_seen).toLocaleString() : '—'],
            ].map(([k, v]) => (
              <div key={k} className="rounded-xl p-3" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
                <p className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>{k}</p>
                <p className="text-sm font-semibold text-white break-all">{v}</p>
              </div>
            ))}
          </div>

          {vuln.title && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>Summary</p>
              <p className="text-sm text-white">{vuln.title}</p>
            </div>
          )}

          {vuln.description && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>Description</p>
              <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{vuln.description}</p>
            </div>
          )}

          {vuln.references?.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>References</p>
              <div className="space-y-1">
                {vuln.references.map((ref, i) => (
                  <a key={i} href={ref} target="_blank" rel="noreferrer"
                    className="block text-xs text-blue-400 hover:text-blue-300 underline truncate">
                    {ref}
                  </a>
                ))}
              </div>
            </div>
          )}

          <div>
            <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>Update Status</p>
            <div className="flex gap-2">
              {STATUS_OPT.map(opt => (
                <button key={opt.value}
                  onClick={() => onStatus(vuln.id, opt.value)}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all"
                  style={{
                    background: vuln.status === opt.value ? `${opt.color}20` : 'var(--bg-card-hover)',
                    color: vuln.status === opt.value ? opt.color : 'var(--text-secondary)',
                    border: `1px solid ${vuln.status === opt.value ? opt.color + '40' : 'var(--border-color)'}`,
                  }}>
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function Vulnerabilities() {
  const [vulns,    setVulns]    = useState([])
  const [summary,  setSummary]  = useState(null)
  const [total,    setTotal]    = useState(0)
  const [page,     setPage]     = useState(1)
  const [selected, setSelected] = useState(null)
  const [filters,  setFilters]  = useState({ severity: '', status: 'open', ecosystem: '' })
  const [loading,  setLoading]  = useState(false)
  const [toast,    setToast]    = useState(null)

  const showToast = (msg, type = 'success') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3500)
  }

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, size: 50, ...Object.fromEntries(Object.entries(filters).filter(([,v]) => v)) }
      const r = await getVulns(params)
      setVulns(r.data.vulnerabilities)
      setTotal(r.data.total)
    } catch { /* silent */ }
    setLoading(false)
  }, [page, filters])

  const loadSummary = useCallback(async () => {
    try { setSummary((await getVulnSummary()).data) } catch { /* silent */ }
  }, [])

  useEffect(() => { load(); loadSummary() }, [load, loadSummary])

  const handleStatus = async (id, status) => {
    try {
      const updated = (await updateVulnStatus(id, status)).data
      setVulns(v => v.map(x => x.id === id ? updated : x))
      if (selected?.id === id) setSelected(updated)
      showToast(`Marked as ${status}`)
      loadSummary()
    } catch { showToast('Update failed', 'error') }
  }

  const handleExport = async () => {
    try {
      const resp = await exportVulnsCSV(filters.severity ? { severity: filters.severity } : {})
      const url  = URL.createObjectURL(new Blob([resp.data]))
      const a    = document.createElement('a')
      a.href     = url
      a.download = `vulns_${Date.now()}.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch { showToast('Export failed', 'error') }
  }

  const pages = Math.ceil(total / 50)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Vulnerability Management</h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
            CVE findings from agent package scans via OSV.dev
          </p>
        </div>
        <button onClick={handleExport}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold transition-opacity hover:opacity-80"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
          ↓ Export CSV
        </button>
      </div>

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-5 gap-4">
          {[
            { label: 'Critical', count: summary.by_severity?.CRITICAL, color: '#ef4444' },
            { label: 'High',     count: summary.by_severity?.HIGH,     color: '#f97316' },
            { label: 'Medium',   count: summary.by_severity?.MEDIUM,   color: '#f59e0b' },
            { label: 'Low',      count: summary.by_severity?.LOW,      color: '#3b82f6' },
            { label: 'Total',    count: summary.total_open,            color: '#8b5cf6' },
          ].map(s => (
            <div key={s.label} className="rounded-2xl p-4"
              style={{ background: 'var(--bg-card)', border: `1px solid ${s.color}25` }}>
              <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>{s.label}</p>
              <p className="text-2xl font-black" style={{ color: s.color }}>{s.count ?? 0}</p>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        {[
          { key: 'severity',  placeholder: 'Severity',  options: ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
          { key: 'status',    placeholder: 'Status',    options: ['', 'open', 'patched', 'accepted'] },
          { key: 'ecosystem', placeholder: 'Ecosystem', options: ['', 'pip', 'npm', 'apt', 'rpm', 'PyPI'] },
        ].map(({ key, options }) => (
          <select key={key} value={filters[key]}
            onChange={e => { setFilters(f => ({ ...f, [key]: e.target.value })); setPage(1) }}
            className="rounded-xl px-3 py-2 text-sm text-white outline-none"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            {options.map(o => (
              <option key={o} value={o}>{o ? o.charAt(0).toUpperCase() + o.slice(1) : `All ${key}s`}</option>
            ))}
          </select>
        ))}
        <span className="text-xs ml-auto" style={{ color: 'var(--text-muted)' }}>
          {total} vulnerabilities
        </span>
      </div>

      {/* Table */}
      <div className="rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-8 h-8 rounded-full border-2 border-t-transparent animate-spin"
              style={{ borderColor: 'rgba(59,130,246,0.3)', borderTopColor: '#3b82f6' }} />
          </div>
        ) : vulns.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3">
            <span className="text-4xl">🛡️</span>
            <p className="text-sm font-semibold text-white">No vulnerabilities found</p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Agents submit package lists which are checked against OSV.dev
            </p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
                {['Severity', 'CVE ID', 'Package', 'Version', 'Ecosystem', 'CVSS', 'Agent', 'Fixed In', 'Status', ''].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider"
                    style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {vulns.map((v, i) => (
                <tr key={v.id}
                  className="group cursor-pointer transition-colors"
                  style={{ borderBottom: i < vulns.length - 1 ? '1px solid var(--border-color)' : 'none' }}
                  onClick={() => setSelected(v)}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                  <td className="px-4 py-3.5"><SevBadge s={v.severity} /></td>
                  <td className="px-4 py-3.5 font-mono text-xs" style={{ color: '#93c5fd' }}>{v.vuln_id}</td>
                  <td className="px-4 py-3.5 font-semibold text-white">{v.package_name}</td>
                  <td className="px-4 py-3.5 font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{v.package_version}</td>
                  <td className="px-4 py-3.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{v.ecosystem || '—'}</td>
                  <td className="px-4 py-3.5"><ScoreBar score={v.cvss_score} /></td>
                  <td className="px-4 py-3.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{v.hostname || v.agent_id?.slice(0,8)}</td>
                  <td className="px-4 py-3.5 text-xs font-mono"
                    style={{ color: v.fixed_version ? '#6ee7b7' : '#f87171' }}>
                    {v.fixed_version || 'No fix'}
                  </td>
                  <td className="px-4 py-3.5">
                    <span className="text-xs font-semibold px-2 py-0.5 rounded-full"
                      style={{
                        color: STATUS_OPT.find(s => s.value === v.status)?.color || '#6b7280',
                        background: 'var(--bg-card-hover)',
                      }}>
                      {v.status}
                    </span>
                  </td>
                  <td className="px-4 py-3.5" onClick={e => e.stopPropagation()}>
                    {v.status === 'open' && (
                      <button onClick={() => handleStatus(v.id, 'patched')}
                        className="w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold"
                        style={{ background: 'rgba(16,185,129,0.1)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.2)' }}
                        title="Mark patched">✓</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {pages > 1 && (
        <div className="flex items-center justify-center gap-3">
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
            className="px-4 py-2 rounded-xl text-xs font-semibold disabled:opacity-40"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
            Previous
          </button>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Page {page} / {pages}
          </span>
          <button disabled={page >= pages} onClick={() => setPage(p => p + 1)}
            className="px-4 py-2 rounded-xl text-xs font-semibold disabled:opacity-40"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
            Next
          </button>
        </div>
      )}

      {selected && <VulnDetail vuln={selected} onClose={() => setSelected(null)} onStatus={handleStatus} />}

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 px-4 py-3 rounded-xl text-sm font-medium animate-fade-in"
          style={{
            background: toast.type === 'error' ? 'rgba(239,68,68,0.95)' : 'rgba(16,185,129,0.95)',
            color: '#fff', boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          }}>
          {toast.type === 'error' ? '❌' : '✅'} {toast.msg}
        </div>
      )}
    </div>
  )
}
