import React, { useState, useEffect, useCallback } from 'react'
import { useAuth } from '../context/AuthContext'

const api = (path, opts = {}) => {
  const token = localStorage.getItem('token')
  return fetch(path, {
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  }).then(r => {
    if (!r.ok) return r.json().then(e => Promise.reject(e.detail || 'Error'))
    if (r.status === 204) return null
    return r.json()
  })
}

const SEV_CFG = {
  CRITICAL: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)' },
  HIGH:     { color: '#f97316', bg: 'rgba(249,115,22,0.12)' },
  MEDIUM:   { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
  LOW:      { color: '#3b82f6', bg: 'rgba(59,130,246,0.12)' },
}

const TYPE_COLORS = {
  ip: '#6366f1', domain: '#8b5cf6', md5: '#ec4899',
  sha256: '#f43f5e', sha1: '#f97316', url: '#10b981', email: '#06b6d4',
}

function SevBadge({ sev }) {
  const c = SEV_CFG[sev] || SEV_CFG.MEDIUM
  return (
    <span style={{ color: c.color, background: c.bg, padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700 }}>
      {sev}
    </span>
  )
}

function TypeBadge({ type }) {
  const color = TYPE_COLORS[type] || '#6b7280'
  return (
    <span style={{ color, background: color + '22', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700 }}>
      {type?.toUpperCase()}
    </span>
  )
}

function StatCard({ label, value, color = '#6366f1', sub }) {
  return (
    <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 10, padding: '16px 20px', minWidth: 120 }}>
      <div style={{ fontSize: 24, fontWeight: 800, color }}>{value ?? '—'}</div>
      <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>{label}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>{sub}</div>}
    </div>
  )
}

// ── Lookup panel ──────────────────────────────────────────────────────────────
function LookupPanel({ onSaved }) {
  const [type, setType] = useState('ip')
  const [value, setValue] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  const run = async () => {
    if (!value.trim()) return
    setLoading(true); setErr(''); setResult(null)
    try {
      const r = await api('/api/threat-intel/lookup', {
        method: 'POST',
        body: JSON.stringify({ ioc_type: type, value: value.trim(), enrich: true }),
      })
      setResult(r)
    } catch (e) { setErr(String(e)) }
    finally { setLoading(false) }
  }

  const addToDb = async () => {
    if (!result) return
    try {
      await api('/api/threat-intel/iocs', {
        method: 'POST',
        body: JSON.stringify({ ioc_type: type, value: value.trim(), source: 'manual', severity: 'MEDIUM' }),
      })
      onSaved?.()
      setResult(r => ({ ...r, saved: true }))
    } catch (e) { setErr(String(e)) }
  }

  const verdictColor = result?.verdict === 'malicious' ? '#ef4444'
    : result?.verdict === 'suspicious' ? '#f97316'
    : result?.verdict === 'unknown' ? '#6b7280' : '#10b981'

  return (
    <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 10, padding: 20, marginBottom: 20 }}>
      <div style={{ fontWeight: 700, marginBottom: 14, fontSize: 15 }}>Real-time IOC Lookup</div>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <select
          value={type}
          onChange={e => setType(e.target.value)}
          style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '8px 10px', fontSize: 13 }}
        >
          {['ip','domain','md5','sha1','sha256','url','email'].map(t => (
            <option key={t} value={t}>{t.toUpperCase()}</option>
          ))}
        </select>
        <input
          value={value}
          onChange={e => setValue(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && run()}
          placeholder={`Enter ${type}...`}
          style={{ flex: 1, minWidth: 200, background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '8px 12px', fontSize: 13 }}
        />
        <button
          onClick={run}
          disabled={loading || !value.trim()}
          style={{ background: '#6366f1', color: '#fff', border: 'none', borderRadius: 6, padding: '8px 20px', cursor: 'pointer', fontWeight: 700, fontSize: 13, opacity: loading ? 0.6 : 1 }}
        >
          {loading ? 'Checking…' : 'Lookup'}
        </button>
      </div>

      {err && <div style={{ color: '#ef4444', marginTop: 10, fontSize: 13 }}>{err}</div>}

      {result && (
        <div style={{ marginTop: 16, background: 'var(--bg)', borderRadius: 8, padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
            <TypeBadge type={result.ioc_type} />
            <span style={{ fontFamily: 'monospace', fontWeight: 600, fontSize: 14 }}>{result.value}</span>
            <span style={{ fontWeight: 800, color: verdictColor, fontSize: 13, textTransform: 'uppercase' }}>
              {result.verdict}
            </span>
            {!result.saved && !result.db_match && (
              <button
                onClick={addToDb}
                style={{ marginLeft: 'auto', background: 'var(--card)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '4px 12px', cursor: 'pointer', fontSize: 12 }}
              >
                + Add to IOC DB
              </button>
            )}
            {result.saved && <span style={{ marginLeft: 'auto', color: '#10b981', fontSize: 12 }}>✓ Saved</span>}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
            {result.db_match && (
              <div style={{ background: 'var(--card)', borderRadius: 6, padding: 12, border: '1px solid rgba(239,68,68,0.3)' }}>
                <div style={{ fontSize: 11, color: '#ef4444', fontWeight: 700, marginBottom: 6 }}>LOCAL IOC DB MATCH</div>
                <div style={{ fontSize: 12 }}>Severity: <SevBadge sev={result.db_match.severity} /></div>
                <div style={{ fontSize: 12, marginTop: 4 }}>Hits: {result.db_match.hit_count}</div>
                {result.db_match.malware_family && <div style={{ fontSize: 12, marginTop: 4 }}>Family: {result.db_match.malware_family}</div>}
              </div>
            )}

            {result.virustotal && (
              <div style={{ background: 'var(--card)', borderRadius: 6, padding: 12, border: '1px solid rgba(99,102,241,0.3)' }}>
                <div style={{ fontSize: 11, color: '#6366f1', fontWeight: 700, marginBottom: 6 }}>VIRUSTOTAL</div>
                <div style={{ fontSize: 20, fontWeight: 800, color: result.virustotal.malicious > 0 ? '#ef4444' : '#10b981' }}>
                  {result.virustotal.malicious}/{result.virustotal.total}
                </div>
                <div style={{ fontSize: 11, color: 'var(--muted)' }}>engines flagged</div>
                {result.virustotal.permalink && (
                  <a href={result.virustotal.permalink} target="_blank" rel="noopener noreferrer" style={{ color: '#6366f1', fontSize: 11, display: 'block', marginTop: 4 }}>
                    View on VT →
                  </a>
                )}
              </div>
            )}

            {result.abuseipdb && (
              <div style={{ background: 'var(--card)', borderRadius: 6, padding: 12, border: '1px solid rgba(249,115,22,0.3)' }}>
                <div style={{ fontSize: 11, color: '#f97316', fontWeight: 700, marginBottom: 6 }}>ABUSEIPDB</div>
                <div style={{ fontSize: 20, fontWeight: 800, color: (result.abuseipdb.abuse_score || 0) > 50 ? '#ef4444' : '#10b981' }}>
                  {result.abuseipdb.abuse_score ?? '?'}%
                </div>
                <div style={{ fontSize: 11, color: 'var(--muted)' }}>confidence score</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── IOC Add Modal ─────────────────────────────────────────────────────────────
function IOCModal({ onClose, onSaved }) {
  const [form, setForm] = useState({
    ioc_type: 'ip', value: '', severity: 'MEDIUM', confidence: 50,
    source: 'manual', description: '', malware_family: '', tags: '', expires_days: '',
  })
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  const save = async () => {
    if (!form.value.trim()) return
    setLoading(true); setErr('')
    try {
      await api('/api/threat-intel/iocs', {
        method: 'POST',
        body: JSON.stringify({
          ...form,
          confidence: Number(form.confidence),
          tags: form.tags ? form.tags.split(',').map(t => t.trim()) : [],
          expires_days: form.expires_days ? Number(form.expires_days) : null,
        }),
      })
      onSaved(); onClose()
    } catch (e) { setErr(String(e)) }
    finally { setLoading(false) }
  }

  const inp = { background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '8px 10px', fontSize: 13, width: '100%', boxSizing: 'border-box' }
  const lbl = { fontSize: 12, color: 'var(--muted)', marginBottom: 4, display: 'block' }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
      <div style={{ background: 'var(--card)', borderRadius: 12, padding: 24, width: 480, maxHeight: '90vh', overflowY: 'auto' }}>
        <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 20 }}>Add IOC</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
          <div>
            <label style={lbl}>Type</label>
            <select value={form.ioc_type} onChange={e => setForm(f => ({ ...f, ioc_type: e.target.value }))} style={inp}>
              {['ip','domain','md5','sha1','sha256','url','email','cve'].map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
            </select>
          </div>
          <div>
            <label style={lbl}>Severity</label>
            <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} style={inp}>
              {['LOW','MEDIUM','HIGH','CRITICAL'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div style={{ gridColumn: '1 / -1' }}>
            <label style={lbl}>Value *</label>
            <input value={form.value} onChange={e => setForm(f => ({ ...f, value: e.target.value }))} placeholder="192.168.1.1 / malware.com / abc123..." style={inp} />
          </div>
          <div>
            <label style={lbl}>Source</label>
            <select value={form.source} onChange={e => setForm(f => ({ ...f, source: e.target.value }))} style={inp}>
              {['manual','virustotal','abuseipdb','feed','misp','otx'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <label style={lbl}>Confidence (0-100)</label>
            <input type="number" min="0" max="100" value={form.confidence} onChange={e => setForm(f => ({ ...f, confidence: e.target.value }))} style={inp} />
          </div>
          <div>
            <label style={lbl}>Malware Family</label>
            <input value={form.malware_family} onChange={e => setForm(f => ({ ...f, malware_family: e.target.value }))} placeholder="Mirai, Cobalt Strike..." style={inp} />
          </div>
          <div>
            <label style={lbl}>Expires in (days)</label>
            <input type="number" value={form.expires_days} onChange={e => setForm(f => ({ ...f, expires_days: e.target.value }))} placeholder="30, 90, 365..." style={inp} />
          </div>
          <div style={{ gridColumn: '1 / -1' }}>
            <label style={lbl}>Tags (comma separated)</label>
            <input value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))} placeholder="ransomware, c2, botnet" style={inp} />
          </div>
          <div style={{ gridColumn: '1 / -1' }}>
            <label style={lbl}>Description</label>
            <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} rows={3} style={{ ...inp, resize: 'vertical' }} />
          </div>
        </div>
        {err && <div style={{ color: '#ef4444', fontSize: 13, marginTop: 10 }}>{err}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 20 }}>
          <button onClick={onClose} style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', fontSize: 13 }}>Cancel</button>
          <button onClick={save} disabled={loading || !form.value.trim()} style={{ background: '#6366f1', color: '#fff', border: 'none', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', fontWeight: 700, fontSize: 13, opacity: loading ? 0.6 : 1 }}>
            {loading ? 'Saving…' : 'Save IOC'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function ThreatIntel() {
  const { user } = useAuth()
  const [stats, setStats] = useState(null)
  const [iocs, setIocs] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [scanLoading, setScanLoading] = useState(false)
  const [scanResult, setScanResult] = useState(null)

  // Filters
  const [search, setSearch] = useState('')
  const [filterType, setFilterType] = useState('')
  const [filterSev, setFilterSev] = useState('')

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const [s, list] = await Promise.all([
        api('/api/threat-intel/stats'),
        api(`/api/threat-intel/iocs?limit=100${search ? `&search=${encodeURIComponent(search)}` : ''}${filterType ? `&ioc_type=${filterType}` : ''}${filterSev ? `&severity=${filterSev}` : ''}`),
      ])
      setStats(s)
      setIocs(list.items || [])
      setTotal(list.total || 0)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [search, filterType, filterSev])

  useEffect(() => { loadData() }, [loadData])

  const deleteIOC = async (id) => {
    if (!confirm('Delete this IOC?')) return
    await api(`/api/threat-intel/iocs/${id}`, { method: 'DELETE' })
    loadData()
  }

  const enrichIOC = async (id) => {
    try {
      await api(`/api/threat-intel/iocs/${id}/enrich`, { method: 'POST' })
      loadData()
    } catch (e) { alert(String(e)) }
  }

  const scanAlerts = async () => {
    setScanLoading(true); setScanResult(null)
    try {
      const r = await api('/api/threat-intel/scan-alerts?days=1', { method: 'POST' })
      setScanResult(r)
    } catch (e) { alert(String(e)) }
    finally { setScanLoading(false) }
  }

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Threat Intelligence</h2>
          <div style={{ color: 'var(--muted)', fontSize: 13, marginTop: 2 }}>IOC database · VirusTotal · AbuseIPDB enrichment</div>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            onClick={scanAlerts}
            disabled={scanLoading}
            style={{ background: 'var(--card)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 8, padding: '8px 16px', cursor: 'pointer', fontSize: 13, opacity: scanLoading ? 0.6 : 1 }}
          >
            {scanLoading ? '⟳ Scanning…' : '⟳ Scan Alerts'}
          </button>
          <button
            onClick={() => setShowModal(true)}
            style={{ background: '#6366f1', color: '#fff', border: 'none', borderRadius: 8, padding: '8px 18px', cursor: 'pointer', fontWeight: 700, fontSize: 13 }}
          >
            + Add IOC
          </button>
        </div>
      </div>

      {/* Scan result banner */}
      {scanResult && (
        <div style={{ background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.3)', borderRadius: 8, padding: '10px 16px', marginBottom: 16, fontSize: 13, color: '#10b981' }}>
          Scan complete: {scanResult.scanned} alerts scanned, {scanResult.enriched} enriched, {scanResult.total_hits} IOC hits found.
          <button onClick={() => setScanResult(null)} style={{ float: 'right', background: 'none', border: 'none', color: '#10b981', cursor: 'pointer', fontSize: 16 }}>×</button>
        </div>
      )}

      {/* Stats */}
      {stats && (
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 20 }}>
          <StatCard label="Total IOCs" value={stats.total} color="#6366f1" />
          <StatCard label="Active" value={stats.active} color="#10b981" />
          <StatCard label="Critical" value={stats.critical} color="#ef4444" />
          <StatCard label="High" value={stats.high} color="#f97316" />
          <StatCard label="Total Hits" value={stats.total_hits} color="#f59e0b" sub="alert matches" />
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
            {stats.vt_enabled && (
              <span style={{ background: 'rgba(99,102,241,0.15)', color: '#6366f1', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 6, padding: '4px 10px', fontSize: 11, fontWeight: 700 }}>
                VT ENABLED
              </span>
            )}
            {stats.abuseipdb_enabled && (
              <span style={{ background: 'rgba(249,115,22,0.15)', color: '#f97316', border: '1px solid rgba(249,115,22,0.3)', borderRadius: 6, padding: '4px 10px', fontSize: 11, fontWeight: 700 }}>
                ABUSEIPDB ENABLED
              </span>
            )}
          </div>
        </div>
      )}

      {/* By-type breakdown */}
      {stats?.by_type && Object.keys(stats.by_type).length > 0 && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 20 }}>
          {Object.entries(stats.by_type).map(([t, c]) => (
            <div key={t} style={{ background: (TYPE_COLORS[t] || '#6b7280') + '22', border: `1px solid ${TYPE_COLORS[t] || '#6b7280'}44`, borderRadius: 6, padding: '4px 12px', fontSize: 12 }}>
              <span style={{ fontWeight: 700, color: TYPE_COLORS[t] || '#6b7280' }}>{t.toUpperCase()}</span>
              <span style={{ color: 'var(--muted)', marginLeft: 6 }}>{c}</span>
            </div>
          ))}
        </div>
      )}

      {/* Lookup */}
      <LookupPanel onSaved={loadData} />

      {/* Filters + Table */}
      <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden' }}>
        <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search IOC value…"
            style={{ flex: 1, minWidth: 180, background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}
          />
          <select value={filterType} onChange={e => setFilterType(e.target.value)} style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}>
            <option value="">All Types</option>
            {['ip','domain','md5','sha1','sha256','url','email','cve'].map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
          </select>
          <select value={filterSev} onChange={e => setFilterSev(e.target.value)} style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}>
            <option value="">All Severities</option>
            {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <span style={{ color: 'var(--muted)', fontSize: 13 }}>{total} IOCs</span>
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)' }}>Loading…</div>
        ) : iocs.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)' }}>
            No IOCs found. Add your first IOC or import a feed.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ background: 'var(--bg)' }}>
                  {['Type','Value','Severity','Source','VT','Hits','Family','Active','Added',''].map(h => (
                    <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: 'var(--muted)', fontSize: 11, fontWeight: 600, whiteSpace: 'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {iocs.map(ioc => (
                  <tr key={ioc.id} style={{ borderTop: '1px solid var(--border)' }}>
                    <td style={{ padding: '8px 12px' }}><TypeBadge type={ioc.ioc_type} /></td>
                    <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: 12, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <span title={ioc.value}>{ioc.value}</span>
                    </td>
                    <td style={{ padding: '8px 12px' }}><SevBadge sev={ioc.severity} /></td>
                    <td style={{ padding: '8px 12px', color: 'var(--muted)', fontSize: 12 }}>{ioc.source}</td>
                    <td style={{ padding: '8px 12px', fontSize: 12 }}>
                      {ioc.vt_malicious != null
                        ? <span style={{ color: ioc.vt_malicious > 0 ? '#ef4444' : '#10b981', fontWeight: 700 }}>{ioc.vt_malicious}/{ioc.vt_total}</span>
                        : <span style={{ color: 'var(--muted)' }}>—</span>}
                    </td>
                    <td style={{ padding: '8px 12px', fontWeight: ioc.hit_count > 0 ? 700 : 400, color: ioc.hit_count > 0 ? '#f59e0b' : 'var(--muted)' }}>{ioc.hit_count}</td>
                    <td style={{ padding: '8px 12px', color: 'var(--muted)', fontSize: 12 }}>{ioc.malware_family || '—'}</td>
                    <td style={{ padding: '8px 12px' }}>
                      <span style={{ color: ioc.is_active ? '#10b981' : '#6b7280', fontSize: 12 }}>{ioc.is_active ? '✓ Active' : 'Inactive'}</span>
                    </td>
                    <td style={{ padding: '8px 12px', color: 'var(--muted)', fontSize: 11, whiteSpace: 'nowrap' }}>
                      {ioc.created_at ? new Date(ioc.created_at).toLocaleDateString() : '—'}
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        {stats?.vt_enabled && (
                          <button
                            onClick={() => enrichIOC(ioc.id)}
                            title="Re-enrich with VirusTotal"
                            style={{ background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.3)', color: '#6366f1', borderRadius: 4, padding: '2px 8px', cursor: 'pointer', fontSize: 11 }}
                          >
                            VT
                          </button>
                        )}
                        <button
                          onClick={() => deleteIOC(ioc.id)}
                          title="Delete IOC"
                          style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444', borderRadius: 4, padding: '2px 8px', cursor: 'pointer', fontSize: 11 }}
                        >
                          ✕
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showModal && <IOCModal onClose={() => setShowModal(false)} onSaved={loadData} />}
    </div>
  )
}
