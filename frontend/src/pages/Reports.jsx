import React, { useState, useEffect, useCallback } from 'react'
import {
  getReportSummary,
  exportAlertsCSV, exportAlertsJSON,
  exportVulnsCSV, exportSCACSV,
} from '../api'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts'

const SEV_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#3b82f6' }
const PIE_COLORS = ['#ef4444', '#f97316', '#f59e0b', '#3b82f6']

function StatCard({ label, value, sub, color = '#818cf8', icon }) {
  return (
    <div className="rounded-2xl p-5 flex flex-col gap-1"
      style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{label}</span>
        <span style={{ color }}>{icon}</span>
      </div>
      <span className="text-3xl font-black" style={{ color }}>{value ?? '—'}</span>
      {sub && <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{sub}</span>}
    </div>
  )
}

function ExportCard({ title, icon, color, children }) {
  return (
    <div className="rounded-2xl p-5 flex flex-col gap-4"
      style={{ background: 'var(--bg-card)', border: `1px solid ${color}30` }}>
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-xl flex items-center justify-center text-lg"
          style={{ background: `${color}18` }}>{icon}</div>
        <span className="font-bold text-white">{title}</span>
      </div>
      {children}
    </div>
  )
}

function FilterRow({ filters, setFilters, agents }) {
  return (
    <div className="flex flex-wrap gap-3">
      <select value={filters.severity} onChange={e => setFilters(p => ({ ...p, severity: e.target.value }))} className="w-32">
        <option value="">All severities</option>
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{s}</option>)}
      </select>
      <select value={filters.status} onChange={e => setFilters(p => ({ ...p, status: e.target.value }))} className="w-36">
        <option value="">All statuses</option>
        {['open', 'investigating', 'resolved', 'closed', 'false_positive'].map(s =>
          <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
      </select>
      <select value={filters.days} onChange={e => setFilters(p => ({ ...p, days: Number(e.target.value) }))} className="w-28">
        {[1, 3, 7, 14, 30, 90].map(d => <option key={d} value={d}>{d} days</option>)}
      </select>
    </div>
  )
}

function ExportBtn({ label, color, onClick, loading }) {
  return (
    <button onClick={onClick} disabled={loading}
      className="px-4 py-2 rounded-xl text-sm font-bold transition-all disabled:opacity-50"
      style={{ background: `${color}18`, color, border: `1px solid ${color}35` }}>
      {loading ? 'Exporting...' : label}
    </button>
  )
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

export default function Reports() {
  const [summary, setSummary]   = useState(null)
  const [days, setDays]         = useState(7)
  const [loading, setLoading]   = useState(true)
  const [exporting, setExporting] = useState({})

  const [alertFilters, setAlertFilters] = useState({ severity: '', status: '', days: 7 })
  const [vulnFilters,  setVulnFilters]  = useState({ severity: '', days: 7 })

  const loadSummary = useCallback(async () => {
    setLoading(true)
    try {
      const r = await getReportSummary(days)
      setSummary(r.data)
    } catch {}
    setLoading(false)
  }, [days])

  useEffect(() => { loadSummary() }, [loadSummary])

  const doExport = async (key, fn, filename) => {
    setExporting(p => ({ ...p, [key]: true }))
    try {
      const r = await fn()
      downloadBlob(new Blob([r.data]), filename)
    } catch {}
    setExporting(p => ({ ...p, [key]: false }))
  }

  const sev = summary?.alerts?.by_severity || {}
  const sevData = Object.entries(sev).map(([name, value]) => ({ name, value }))
  const totalAlerts = Object.values(sev).reduce((a, b) => a + b, 0)

  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="relative rounded-2xl overflow-hidden p-6"
        style={{ background: 'linear-gradient(135deg,#0f172a,#1a1f35,#0f172a)',
          border: '1px solid rgba(99,102,241,0.2)' }}>
        <div className="absolute top-0 right-0 w-72 h-72 pointer-events-none"
          style={{ background: 'radial-gradient(circle,rgba(99,102,241,0.07) 0%,transparent 70%)',
            transform: 'translate(30%,-30%)' }} />
        <div className="relative flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-black text-white">Reports & Export</h1>
            <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
              Executive summary, compliance exports and data downloads
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>Period:</span>
            <select value={days} onChange={e => setDays(Number(e.target.value))} className="w-28">
              {[1, 3, 7, 14, 30, 90].map(d => <option key={d} value={d}>{d} days</option>)}
            </select>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      {loading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="rounded-2xl p-5 h-28 animate-pulse"
              style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }} />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Total Alerts" value={summary?.alerts?.total ?? 0}
            sub={`last ${days} days`} color="#818cf8"
            icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>} />
          <StatCard label="Critical Alerts" value={sev.CRITICAL ?? 0}
            sub={totalAlerts ? `${Math.round(((sev.CRITICAL||0)/totalAlerts)*100)}% of total` : ''}
            color="#ef4444"
            icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>} />
          <StatCard label="Open Vulns" value={summary?.vulnerabilities?.open ?? 0}
            sub={`${summary?.vulnerabilities?.critical ?? 0} critical`}
            color="#f97316"
            icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>} />
          <StatCard label="Online Agents" value={summary?.agents?.online ?? 0}
            sub="currently active" color="#10b981"
            icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>} />
        </div>
      )}

      {/* Charts row */}
      {summary && totalAlerts > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Severity bar chart */}
          <div className="rounded-2xl p-5"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            <h3 className="text-sm font-bold text-white mb-4">Alerts by Severity</h3>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={sevData} barCategoryGap="35%">
                <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 8 }}
                  labelStyle={{ color: '#fff' }} itemStyle={{ color: 'var(--text-muted)' }} />
                <Bar dataKey="value" radius={[4,4,0,0]}>
                  {sevData.map((e, i) => <Cell key={i} fill={SEV_COLORS[e.name] || '#6b7280'} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Severity pie chart */}
          <div className="rounded-2xl p-5"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            <h3 className="text-sm font-bold text-white mb-4">Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={sevData} cx="50%" cy="50%" outerRadius={65}
                  dataKey="value" nameKey="name" label={({ name, percent }) =>
                    percent > 0.05 ? `${name} ${Math.round(percent*100)}%` : ''}>
                  {sevData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % 4]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 8 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Export Section */}
      <div>
        <h2 className="text-sm font-bold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
          Data Export
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">

          {/* Alerts export */}
          <ExportCard title="Alerts" icon="🚨" color="#ef4444">
            <FilterRow filters={alertFilters} setFilters={setAlertFilters} />
            <div className="flex gap-2 flex-wrap">
              <ExportBtn label="Export CSV" color="#ef4444" loading={exporting.alertCsv}
                onClick={() => doExport('alertCsv',
                  () => exportAlertsCSV(alertFilters),
                  `alerts_${ts}.csv`)} />
              <ExportBtn label="Export JSON" color="#818cf8" loading={exporting.alertJson}
                onClick={() => doExport('alertJson',
                  () => exportAlertsJSON(alertFilters),
                  `alerts_${ts}.json`)} />
            </div>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Includes ID, severity, title, rule, agent, MITRE, status
            </p>
          </ExportCard>

          {/* Vulnerabilities export */}
          <ExportCard title="Vulnerabilities" icon="🛡️" color="#f97316">
            <FilterRow filters={vulnFilters} setFilters={setVulnFilters} />
            <div className="flex gap-2">
              <ExportBtn label="Export CSV" color="#f97316" loading={exporting.vulnCsv}
                onClick={() => doExport('vulnCsv',
                  () => exportVulnsCSV({ severity: vulnFilters.severity }),
                  `vulnerabilities_${ts}.csv`)} />
            </div>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Includes agent, package, version, CVE ID, CVSS score, fix version
            </p>
          </ExportCard>

          {/* SCA export */}
          <ExportCard title="SCA / Compliance" icon="✅" color="#10b981">
            <div className="flex gap-2 mt-2">
              <ExportBtn label="Export CSV" color="#10b981" loading={exporting.scaCsv}
                onClick={() => doExport('scaCsv',
                  () => exportSCACSV({}),
                  `sca_${ts}.csv`)} />
            </div>
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              Includes agent, hostname, score%, passed/failed/skipped checks
            </p>
          </ExportCard>
        </div>
      </div>

      {/* Severity breakdown table */}
      {summary && (
        <div className="rounded-2xl overflow-hidden"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          <div className="px-5 py-4 border-b flex items-center justify-between"
            style={{ borderColor: 'var(--border-color)' }}>
            <h3 className="font-bold text-white">Executive Summary — Last {days} days</h3>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Generated: {new Date().toLocaleString()}
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
                  {['Category', 'Metric', 'Value', 'Status'].map(h => (
                    <th key={h} className="text-left px-5 py-3 text-xs font-bold uppercase tracking-wider"
                      style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[
                  { cat: 'Alerts', metric: 'Total Alerts', value: summary.alerts?.total ?? 0, status: 'info' },
                  { cat: 'Alerts', metric: 'Critical', value: sev.CRITICAL ?? 0, status: (sev.CRITICAL||0) > 0 ? 'danger' : 'ok' },
                  { cat: 'Alerts', metric: 'High', value: sev.HIGH ?? 0, status: (sev.HIGH||0) > 10 ? 'warn' : 'ok' },
                  { cat: 'Alerts', metric: 'Medium', value: sev.MEDIUM ?? 0, status: 'info' },
                  { cat: 'Alerts', metric: 'Low', value: sev.LOW ?? 0, status: 'info' },
                  { cat: 'Vulnerabilities', metric: 'Open Vulns', value: summary.vulnerabilities?.open ?? 0, status: (summary.vulnerabilities?.open||0) > 0 ? 'warn' : 'ok' },
                  { cat: 'Vulnerabilities', metric: 'Critical Vulns', value: summary.vulnerabilities?.critical ?? 0, status: (summary.vulnerabilities?.critical||0) > 0 ? 'danger' : 'ok' },
                  { cat: 'Infrastructure', metric: 'Online Agents', value: summary.agents?.online ?? 0, status: 'ok' },
                ].map((row, i) => {
                  const statusCfg = {
                    ok:     { color: '#10b981', label: 'OK' },
                    warn:   { color: '#f59e0b', label: 'Warning' },
                    danger: { color: '#ef4444', label: 'Critical' },
                    info:   { color: '#818cf8', label: 'Info' },
                  }
                  const s = statusCfg[row.status]
                  return (
                    <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}
                      className="hover:bg-white/5 transition-colors">
                      <td className="px-5 py-3 text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>{row.cat}</td>
                      <td className="px-5 py-3 text-white font-medium">{row.metric}</td>
                      <td className="px-5 py-3 text-white font-black text-base">{row.value}</td>
                      <td className="px-5 py-3">
                        <span className="px-2.5 py-0.5 rounded-full text-xs font-bold"
                          style={{ background: `${s.color}18`, color: s.color }}>
                          {s.label}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
