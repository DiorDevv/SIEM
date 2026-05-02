import React, { useState, useEffect, useCallback } from 'react'
import { getSCAScans, getLatestSCAScans, getSCASummary, exportSCACSV } from '../api'

const RESULT_STYLE = {
  pass: { color: '#10b981', bg: 'rgba(16,185,129,0.12)',  label: 'PASS',  icon: '✅' },
  fail: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',   label: 'FAIL',  icon: '❌' },
  skip: { color: '#6b7280', bg: 'rgba(107,114,128,0.12)', label: 'SKIP',  icon: '⏭️' },
}

const SEV_COLOR = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#3b82f6',
}

function ScoreCircle({ score, size = 80 }) {
  const radius      = (size - 8) / 2
  const circumference = 2 * Math.PI * radius
  const pct         = Math.max(0, Math.min(score, 100))
  const offset      = circumference - (pct / 100) * circumference
  const color       = score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : score >= 40 ? '#f97316' : '#ef4444'

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size/2} cy={size/2} r={radius} fill="none"
          stroke="var(--border-color)" strokeWidth="5" />
        <circle cx={size/2} cy={size/2} r={radius} fill="none"
          stroke={color} strokeWidth="5"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round" />
      </svg>
      <div className="absolute text-center">
        <p className="text-base font-black leading-none" style={{ color }}>{score}%</p>
      </div>
    </div>
  )
}

function CheckRow({ check }) {
  const [open, setOpen] = useState(false)
  const rs = RESULT_STYLE[check.result] || RESULT_STYLE.skip
  const sevColor = SEV_COLOR[check.severity] || '#6b7280'

  return (
    <div className="border-b last:border-0" style={{ borderColor: 'var(--border-color)' }}>
      <button className="w-full flex items-center gap-3 px-4 py-3 text-left transition-colors"
        onClick={() => setOpen(!open)}
        onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
        <span className="text-base flex-shrink-0">{rs.icon}</span>
        <span className="font-mono text-xs flex-shrink-0 w-24" style={{ color: '#94a3b8' }}>{check.id}</span>
        <span className="flex-1 text-sm text-white">{check.title}</span>
        <span className="text-xs font-bold flex-shrink-0" style={{ color: sevColor }}>{check.severity}</span>
        <span className="text-xs font-bold px-2 py-0.5 rounded-full flex-shrink-0 ml-2"
          style={{ color: rs.color, background: rs.bg }}>{rs.label}</span>
        <span className="text-xs ml-2" style={{ color: 'var(--text-muted)' }}>{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="px-16 pb-4 space-y-2">
          {check.rationale && (
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              <span className="font-semibold text-white">Rationale: </span>{check.rationale}
            </p>
          )}
          {check.remediation && (
            <div className="rounded-lg p-3" style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.15)' }}>
              <p className="text-xs" style={{ color: '#93c5fd' }}>
                <span className="font-semibold">Fix: </span>{check.remediation}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function ScanCard({ scan, onClick, selected }) {
  const color = scan.score_pct >= 80 ? '#10b981' : scan.score_pct >= 60 ? '#f59e0b' : '#ef4444'
  return (
    <button onClick={() => onClick(scan)}
      className="w-full text-left rounded-2xl p-4 transition-all"
      style={{
        background: selected ? `${color}10` : 'var(--bg-secondary)',
        border: `1px solid ${selected ? color + '40' : 'var(--border-color)'}`,
        boxShadow: selected ? `0 0 20px ${color}15` : 'none',
      }}>
      <div className="flex items-center gap-4">
        <ScoreCircle score={scan.score_pct} size={64} />
        <div className="flex-1 min-w-0">
          <p className="font-bold text-white truncate">{scan.hostname || scan.agent_id?.slice(0, 16)}</p>
          <div className="flex items-center gap-3 mt-1">
            <span className="text-xs font-semibold" style={{ color: '#10b981' }}>✓ {scan.passed}</span>
            <span className="text-xs font-semibold" style={{ color: '#ef4444' }}>✗ {scan.failed}</span>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>⏭ {scan.skipped}</span>
          </div>
          <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
            {scan.scanned_at ? new Date(scan.scanned_at).toLocaleString() : '—'}
          </p>
        </div>
      </div>
    </button>
  )
}

export default function SCA() {
  const [latestScans, setLatestScans] = useState([])
  const [summary,     setSummary]     = useState(null)
  const [selected,    setSelected]    = useState(null)
  const [filterResult, setFilterResult] = useState('')
  const [toast,       setToast]       = useState(null)

  const showToast = (msg, type = 'success') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3500)
  }

  const load = useCallback(async () => {
    try {
      const [latest, sum] = await Promise.all([getLatestSCAScans(), getSCASummary()])
      setLatestScans(latest.data)
      setSummary(sum.data)
      if (!selected && latest.data.length > 0) setSelected(latest.data[0])
    } catch { /* silent */ }
  }, [])

  useEffect(() => { load() }, [load])

  const handleExport = async () => {
    try {
      const resp = await exportSCACSV()
      const url  = URL.createObjectURL(new Blob([resp.data]))
      const a    = document.createElement('a')
      a.href     = url
      a.download = `sca_${Date.now()}.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch { showToast('Export failed', 'error') }
  }

  const filteredChecks = (selected?.checks || []).filter(c =>
    !filterResult || c.result === filterResult
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Security Configuration Assessment</h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
            CIS benchmark-style configuration checks per agent
          </p>
        </div>
        <button onClick={handleExport}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold transition-opacity hover:opacity-80"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
          ↓ Export CSV
        </button>
      </div>

      {/* Summary */}
      {summary && (
        <div className="grid grid-cols-3 gap-4">
          {[
            { label: 'Scans Total',         value: summary.total_scans,     color: '#3b82f6' },
            { label: 'Avg Score',            value: `${summary.avg_score_pct}%`, color: '#10b981' },
            { label: 'Agents Below 50%',     value: summary.critical_agents, color: '#ef4444' },
          ].map(s => (
            <div key={s.label} className="rounded-2xl p-4"
              style={{ background: 'var(--bg-card)', border: `1px solid ${s.color}25` }}>
              <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>{s.label}</p>
              <p className="text-2xl font-black" style={{ color: s.color }}>{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {latestScans.length === 0 ? (
        <div className="rounded-2xl flex flex-col items-center justify-center py-20 gap-3"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          <span className="text-4xl">🔍</span>
          <p className="text-sm font-semibold text-white">No SCA scans yet</p>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Agents run SCA checks every hour</p>
        </div>
      ) : (
        <div className="grid grid-cols-12 gap-6">
          {/* Agent list */}
          <div className="col-span-4 space-y-3">
            <p className="text-xs font-bold uppercase tracking-wider px-1" style={{ color: 'var(--text-muted)' }}>
              Agents ({latestScans.length})
            </p>
            {latestScans.map(scan => (
              <ScanCard key={scan.id} scan={scan}
                onClick={setSelected}
                selected={selected?.id === scan.id} />
            ))}
          </div>

          {/* Check detail */}
          <div className="col-span-8 space-y-4">
            {selected && (
              <>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <ScoreCircle score={selected.score_pct} size={72} />
                    <div>
                      <h3 className="font-bold text-white text-lg">
                        {selected.hostname || selected.agent_id?.slice(0, 16)}
                      </h3>
                      <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        {selected.passed} passed · {selected.failed} failed · {selected.skipped} skipped
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    {[['', 'All'], ['pass', 'Pass'], ['fail', 'Fail'], ['skip', 'Skip']].map(([v, l]) => (
                      <button key={v} onClick={() => setFilterResult(v)}
                        className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all"
                        style={{
                          background: filterResult === v ? 'rgba(59,130,246,0.15)' : 'var(--bg-secondary)',
                          color: filterResult === v ? '#3b82f6' : 'var(--text-secondary)',
                          border: `1px solid ${filterResult === v ? 'rgba(59,130,246,0.3)' : 'var(--border-color)'}`,
                        }}>
                        {l}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="rounded-2xl overflow-hidden"
                  style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
                  {filteredChecks.length === 0 ? (
                    <div className="py-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                      No checks matching filter
                    </div>
                  ) : (
                    filteredChecks.map(check => <CheckRow key={check.id} check={check} />)
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}

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
