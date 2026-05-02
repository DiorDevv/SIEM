import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useAuth } from '../context/AuthContext'

// ── API helpers ───────────────────────────────────────────────────────────────
const api = (path, opts = {}) => {
  const token = localStorage.getItem('access_token')
  return fetch(path, {
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  }).then(r => {
    if (!r.ok) return r.json().then(e => Promise.reject(e.detail || 'Error'))
    if (r.status === 204) return null
    return r.json()
  })
}

// ── Constants ─────────────────────────────────────────────────────────────────
const STATUS_CFG = {
  open:        { label: 'Open',        color: '#ef4444', bg: 'rgba(239,68,68,0.12)' },
  in_progress: { label: 'In Progress', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
  pending:     { label: 'Pending',     color: '#6366f1', bg: 'rgba(99,102,241,0.12)' },
  resolved:    { label: 'Resolved',    color: '#10b981', bg: 'rgba(16,185,129,0.12)' },
  closed:      { label: 'Closed',      color: '#6b7280', bg: 'rgba(107,114,128,0.12)' },
}
const SEV_CFG = {
  CRITICAL: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)' },
  HIGH:     { color: '#f97316', bg: 'rgba(249,115,22,0.12)' },
  MEDIUM:   { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
  LOW:      { color: '#3b82f6', bg: 'rgba(59,130,246,0.12)' },
}
const TLP_CFG = {
  WHITE: { color: '#f1f5f9', label: 'TLP:WHITE' },
  GREEN: { color: '#22c55e', label: 'TLP:GREEN' },
  AMBER: { color: '#f59e0b', label: 'TLP:AMBER' },
  RED:   { color: '#ef4444', label: 'TLP:RED' },
}
const NOTE_CFG = {
  note:     { color: '#818cf8', icon: '📝', label: 'Note' },
  action:   { color: '#f59e0b', icon: '⚡', label: 'Action' },
  evidence: { color: '#10b981', icon: '🔍', label: 'Evidence' },
  ioc:      { color: '#ef4444', icon: '🎯', label: 'IOC' },
}
const MITRE_TACTICS = [
  'Initial Access','Execution','Persistence','Privilege Escalation',
  'Defense Evasion','Credential Access','Discovery','Lateral Movement',
  'Collection','Exfiltration','Command and Control','Impact','Reconnaissance',
]
const STATUS_FLOW = ['open','in_progress','pending','resolved','closed']

// ── Small components ──────────────────────────────────────────────────────────
function SevBadge({ sev }) {
  const c = SEV_CFG[sev] || SEV_CFG.MEDIUM
  return <span className="px-2 py-0.5 rounded-full text-xs font-black"
    style={{ background: c.bg, color: c.color }}>{sev}</span>
}
function StatusBadge({ status }) {
  const c = STATUS_CFG[status] || STATUS_CFG.open
  return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold"
    style={{ background: c.bg, color: c.color }}>{c.label}</span>
}
function TLPBadge({ tlp }) {
  const c = TLP_CFG[tlp] || TLP_CFG.AMBER
  return <span className="px-2 py-0.5 rounded text-xs font-black"
    style={{ background: `${c.color}18`, color: c.color, border: `1px solid ${c.color}40` }}>
    {c.label}
  </span>
}
function SlaTag({ deadline, resolved_at }) {
  if (!deadline || resolved_at) return null
  const diff = new Date(deadline) - Date.now()
  const hours = Math.round(diff / 3600000)
  const ok = diff > 0
  return (
    <span className="px-2 py-0.5 rounded text-xs font-bold"
      style={{ background: ok ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
        color: ok ? '#6ee7b7' : '#f87171', border: `1px solid ${ok ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}` }}>
      SLA {ok ? `${hours}h left` : `${Math.abs(hours)}h over`}
    </span>
  )
}
function Spinner() {
  return <div className="w-4 h-4 rounded-full border-2 animate-spin flex-shrink-0"
    style={{ borderColor: 'rgba(99,102,241,0.15)', borderTopColor: '#818cf8' }} />
}
function StatCard({ label, value, color, sub }) {
  return (
    <div className="rounded-xl p-4"
      style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
      <div className="text-xs font-bold uppercase tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>{label}</div>
      <div className="text-2xl font-black" style={{ color }}>{value ?? '—'}</div>
      {sub && <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{sub}</div>}
    </div>
  )
}
function timeAgo(iso) {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso)
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

// ── Create/Edit Modal ─────────────────────────────────────────────────────────
function CaseModal({ caseData, onClose, onSaved, prelinkedAlerts = [] }) {
  const isEdit = !!caseData
  const [form, setForm] = useState({
    title: caseData?.title || '',
    description: caseData?.description || '',
    severity: caseData?.severity || 'HIGH',
    tlp: caseData?.tlp || 'AMBER',
    tags: (caseData?.tags || []).join(', '),
    mitre_tactics: caseData?.mitre_tactics || [],
    sla_hours: caseData?.sla_hours || '',
  })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')

  const save = async () => {
    if (!form.title.trim()) { setErr('Title is required'); return }
    setSaving(true); setErr('')
    try {
      const body = {
        title:            form.title,
        description:      form.description,
        severity:         form.severity,
        tlp:              form.tlp,
        tags:             form.tags.split(',').map(t => t.trim()).filter(Boolean),
        mitre_tactics:    form.mitre_tactics,
        sla_hours:        form.sla_hours ? parseInt(form.sla_hours) : null,
        alert_ids:        prelinkedAlerts,
      }
      const result = isEdit
        ? await api(`/api/cases/${caseData.id}`, { method: 'PUT', body: JSON.stringify(body) })
        : await api('/api/cases', { method: 'POST', body: JSON.stringify(body) })
      onSaved(result)
    } catch (e) { setErr(String(e)) }
    setSaving(false)
  }

  const toggleTactic = (t) =>
    setForm(p => ({
      ...p,
      mitre_tactics: p.mitre_tactics.includes(t)
        ? p.mitre_tactics.filter(x => x !== t)
        : [...p.mitre_tactics, t],
    }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.75)' }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="w-full max-w-2xl rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', maxHeight: '90vh', overflowY: 'auto' }}>
        <div className="px-6 py-4 border-b flex items-center justify-between"
          style={{ borderColor: 'var(--border-color)', background: 'var(--bg-secondary)' }}>
          <h3 className="text-base font-black text-white">{isEdit ? 'Edit Case' : 'New Case'}</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-xl">×</button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>Title *</label>
            <input value={form.title} onChange={e => setForm(p => ({ ...p, title: e.target.value }))}
              placeholder="Suspicious lateral movement detected..." className="w-full" />
          </div>
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>Description</label>
            <textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
              placeholder="Detailed description of the incident..." rows={3}
              className="w-full rounded-xl p-3 text-sm resize-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', outline: 'none' }} />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>Severity</label>
              <select value={form.severity} onChange={e => setForm(p => ({ ...p, severity: e.target.value }))} className="w-full">
                {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>TLP</label>
              <select value={form.tlp} onChange={e => setForm(p => ({ ...p, tlp: e.target.value }))} className="w-full">
                {['WHITE','GREEN','AMBER','RED'].map(t => <option key={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>SLA (hours)</label>
              <input type="number" value={form.sla_hours} onChange={e => setForm(p => ({ ...p, sla_hours: e.target.value }))}
                placeholder="24" className="w-full" />
            </div>
          </div>
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>Tags (comma separated)</label>
            <input value={form.tags} onChange={e => setForm(p => ({ ...p, tags: e.target.value }))}
              placeholder="ransomware, lateral-movement, t1078" className="w-full" />
          </div>
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>MITRE ATT&CK Tactics</label>
            <div className="flex flex-wrap gap-2">
              {MITRE_TACTICS.map(t => {
                const active = form.mitre_tactics.includes(t)
                return (
                  <button key={t} onClick={() => toggleTactic(t)}
                    className="px-2.5 py-1 rounded-lg text-xs font-semibold transition-all"
                    style={{
                      background: active ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)',
                      color: active ? '#a5b4fc' : 'var(--text-muted)',
                      border: `1px solid ${active ? 'rgba(99,102,241,0.4)' : 'var(--border-color)'}`,
                    }}>{t}</button>
                )
              })}
            </div>
          </div>
          {prelinkedAlerts.length > 0 && (
            <div className="px-3 py-2 rounded-xl text-xs font-semibold"
              style={{ background: 'rgba(16,185,129,0.1)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.2)' }}>
              {prelinkedAlerts.length} alert{prelinkedAlerts.length > 1 ? 's' : ''} will be linked
            </div>
          )}
          {err && <div className="px-3 py-2 rounded-xl text-xs font-semibold"
            style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)' }}>{err}</div>}
          <div className="flex gap-3 justify-end pt-2">
            <button onClick={onClose} className="px-4 py-2 rounded-xl text-sm font-bold"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>
              Cancel
            </button>
            <button onClick={save} disabled={saving} className="px-5 py-2 rounded-xl text-sm font-bold disabled:opacity-50"
              style={{ background: 'rgba(99,102,241,0.2)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.35)' }}>
              {saving ? 'Saving...' : isEdit ? 'Save Changes' : 'Create Case'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Case Detail Panel ─────────────────────────────────────────────────────────
function CaseDetail({ caseId, onClose, onUpdated, users }) {
  const { user } = useAuth()
  const [data, setData]   = useState(null)
  const [tab, setTab]     = useState('overview')
  const [loading, setLoading] = useState(true)
  const [noteText, setNoteText] = useState('')
  const [noteType, setNoteType] = useState('note')
  const [addingNote, setAddingNote] = useState(false)
  const [editing, setEditing] = useState(false)
  const noteRef = useRef()

  const load = useCallback(async () => {
    try {
      const d = await api(`/api/cases/${caseId}`)
      setData(d)
    } catch {}
    setLoading(false)
  }, [caseId])

  useEffect(() => { setLoading(true); setTab('overview'); load() }, [load])

  const changeStatus = async (status) => {
    try {
      const d = await api(`/api/cases/${caseId}/status`, { method: 'POST', body: JSON.stringify({ status }) })
      setData(prev => ({ ...prev, ...d }))
      onUpdated()
    } catch {}
  }

  const assignTo = async (uid, uname) => {
    try {
      const d = await api(`/api/cases/${caseId}/assign`, { method: 'POST', body: JSON.stringify({ user_id: uid, username: uname }) })
      setData(prev => ({ ...prev, ...d }))
      onUpdated()
    } catch {}
  }

  const addNote = async () => {
    if (!noteText.trim()) return
    setAddingNote(true)
    try {
      const n = await api(`/api/cases/${caseId}/notes`, { method: 'POST', body: JSON.stringify({ content: noteText, note_type: noteType }) })
      setData(prev => ({
        ...prev,
        notes: [...(prev.notes || []), n],
        note_count: (prev.note_count || 0) + 1,
        timeline: [{ id: Date.now(), username: user?.username, action: 'Note added', created_at: new Date().toISOString() }, ...(prev.timeline || [])],
      }))
      setNoteText('')
      onUpdated()
    } catch {}
    setAddingNote(false)
  }

  const deleteNote = async (noteId) => {
    try {
      await api(`/api/cases/${caseId}/notes/${noteId}`, { method: 'DELETE' })
      setData(prev => ({ ...prev, notes: prev.notes.filter(n => n.id !== noteId), note_count: Math.max(0, (prev.note_count||1)-1) }))
    } catch {}
  }

  const unlinkAlert = async (alertId) => {
    try {
      await api(`/api/cases/${caseId}/alerts/${alertId}`, { method: 'DELETE' })
      setData(prev => ({ ...prev, alerts: prev.alerts.filter(a => a.id !== alertId), alert_count: Math.max(0, (prev.alert_count||1)-1) }))
      onUpdated()
    } catch {}
  }

  if (loading) return (
    <div className="flex items-center justify-center h-full" style={{ color: 'var(--text-muted)' }}>
      <Spinner />
    </div>
  )
  if (!data) return null

  const statusList = STATUS_FLOW.filter(s => s !== data.status)
  const tlp = TLP_CFG[data.tlp] || TLP_CFG.AMBER

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex-shrink-0 px-6 py-4 border-b" style={{ borderColor: 'var(--border-color)' }}>
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-2">
              <span className="text-xs font-black" style={{ color: '#818cf8' }}>{data.case_number}</span>
              <SevBadge sev={data.severity} />
              <StatusBadge status={data.status} />
              <TLPBadge tlp={data.tlp} />
              <SlaTag deadline={data.sla_deadline} resolved_at={data.resolved_at} />
            </div>
            <h2 className="text-base font-black text-white leading-tight">{data.title}</h2>
            <div className="flex items-center gap-3 mt-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
              <span>by {data.created_by_name || 'unknown'}</span>
              <span>•</span>
              <span>{new Date(data.created_at).toLocaleString()}</span>
              {data.assigned_to_name && <><span>•</span><span>Assigned: <strong style={{ color: '#a5b4fc' }}>{data.assigned_to_name}</strong></span></>}
            </div>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-xl flex-shrink-0">×</button>
        </div>

        {/* Quick actions row */}
        <div className="flex items-center gap-2 mt-3 flex-wrap">
          {/* Status change */}
          <div className="flex items-center gap-1">
            {statusList.slice(0,3).map(s => (
              <button key={s} onClick={() => changeStatus(s)}
                className="px-2.5 py-1 rounded-lg text-xs font-bold transition-all"
                style={{ background: STATUS_CFG[s].bg, color: STATUS_CFG[s].color, border: `1px solid ${STATUS_CFG[s].color}30` }}>
                → {STATUS_CFG[s].label}
              </button>
            ))}
          </div>
          <div style={{ width: 1, height: 20, background: 'var(--border-color)' }} />
          {/* Assign */}
          <select
            value={data.assigned_to || ''}
            onChange={e => {
              const u = users.find(u => u.id === parseInt(e.target.value))
              assignTo(u?.id || null, u?.username || null)
            }}
            className="text-xs h-7 px-2 rounded-lg"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>
            <option value="">Assign to...</option>
            {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select>
          <button onClick={() => setEditing(true)}
            className="px-2.5 py-1 rounded-lg text-xs font-bold"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>
            Edit
          </button>
        </div>

        {/* Tags */}
        {data.tags?.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-2">
            {data.tags.map(tag => (
              <span key={tag} className="px-2 py-0.5 rounded text-xs font-semibold"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>
                #{tag}
              </span>
            ))}
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-0.5 mt-4 border-b -mb-px" style={{ borderColor: 'var(--border-color)' }}>
          {[
            { id: 'overview', label: 'Overview' },
            { id: 'timeline', label: `Timeline` },
            { id: 'alerts',   label: `Alerts (${data.alert_count || 0})` },
            { id: 'notes',    label: `Notes (${data.note_count || 0})` },
          ].map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className="px-4 py-2 text-xs font-bold transition-all border-b-2"
              style={{
                borderBottomColor: tab === t.id ? '#818cf8' : 'transparent',
                color: tab === t.id ? '#a5b4fc' : 'var(--text-muted)',
                background: 'transparent',
              }}>{t.label}</button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto px-6 py-4">

        {/* ── OVERVIEW ── */}
        {tab === 'overview' && (
          <div className="space-y-4">
            {data.description && (
              <div className="rounded-xl p-4" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
                <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>Description</p>
                <p className="text-sm text-white whitespace-pre-wrap leading-relaxed">{data.description}</p>
              </div>
            )}
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-xl p-3" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
                <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>Details</p>
                <div className="space-y-1.5 text-xs">
                  {[
                    ['Status',   <StatusBadge status={data.status} />],
                    ['Severity', <SevBadge sev={data.severity} />],
                    ['TLP',      <TLPBadge tlp={data.tlp} />],
                    ['Created',  new Date(data.created_at).toLocaleString()],
                    ['By',       data.created_by_name || '—'],
                    ['Assigned', data.assigned_to_name || 'Unassigned'],
                    ['SLA',      data.sla_hours ? `${data.sla_hours}h` : '—'],
                    ['Alerts',   data.alert_count || 0],
                    ['Notes',    data.note_count || 0],
                  ].map(([k, v]) => (
                    <div key={k} className="flex items-center justify-between">
                      <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                      <span className="font-semibold text-white">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
              {data.mitre_tactics?.length > 0 && (
                <div className="rounded-xl p-3" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
                  <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>MITRE ATT&CK</p>
                  <div className="flex flex-wrap gap-1.5">
                    {data.mitre_tactics.map(t => (
                      <span key={t} className="px-2 py-0.5 rounded text-xs font-semibold"
                        style={{ background: 'rgba(99,102,241,0.12)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.2)' }}>
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
            {data.resolved_at && (
              <div className="rounded-xl p-3 text-xs" style={{ background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)' }}>
                <span style={{ color: '#6ee7b7' }}>✓ Resolved at {new Date(data.resolved_at).toLocaleString()}</span>
              </div>
            )}
          </div>
        )}

        {/* ── TIMELINE ── */}
        {tab === 'timeline' && (
          <div className="space-y-2">
            {(data.timeline || []).length === 0 ? (
              <p className="text-sm text-center py-8" style={{ color: 'var(--text-muted)' }}>No timeline events yet</p>
            ) : (
              (data.timeline || []).map((t, i) => (
                <div key={t.id || i} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="w-2 h-2 rounded-full mt-1.5 flex-shrink-0"
                      style={{ background: t.action.includes('Status') ? '#f59e0b' : t.action.includes('Note') ? '#6366f1' : '#6b7280' }} />
                    {i < (data.timeline?.length || 1) - 1 && (
                      <div className="w-px flex-1 mt-1" style={{ background: 'var(--border-color)' }} />
                    )}
                  </div>
                  <div className="pb-3 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-white">{t.action}</span>
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>by {t.username || 'system'}</span>
                      <span className="text-xs ml-auto" style={{ color: 'var(--text-muted)' }}>{timeAgo(t.created_at)}</span>
                    </div>
                    {(t.old_value || t.new_value) && (
                      <div className="mt-1 flex items-center gap-2 text-xs">
                        {t.old_value && <span className="px-1.5 py-0.5 rounded" style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171' }}>{t.old_value}</span>}
                        {t.old_value && t.new_value && <span style={{ color: 'var(--text-muted)' }}>→</span>}
                        {t.new_value && <span className="px-1.5 py-0.5 rounded" style={{ background: 'rgba(16,185,129,0.1)', color: '#6ee7b7' }}>{t.new_value}</span>}
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* ── ALERTS ── */}
        {tab === 'alerts' && (
          <div className="space-y-2">
            {(data.alerts || []).length === 0 ? (
              <p className="text-sm text-center py-8" style={{ color: 'var(--text-muted)' }}>No alerts linked to this case</p>
            ) : (
              (data.alerts || []).map(a => (
                <div key={a.id} className="flex items-center gap-3 px-4 py-3 rounded-xl"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
                  <SevBadge sev={String(a.severity).replace('AlertSeverity.', '').toUpperCase()} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-bold text-white truncate">{a.title}</p>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                      {a.agent_hostname} • {a.mitre_tactic || '—'} • {timeAgo(a.created_at)}
                    </p>
                  </div>
                  <span className="text-xs px-2 py-0.5 rounded-full"
                    style={{ background: 'rgba(107,114,128,0.1)', color: '#9ca3af' }}>
                    #{a.id}
                  </span>
                  <button onClick={() => unlinkAlert(a.id)}
                    className="text-xs px-2 py-1 rounded-lg hover:text-red-400 transition-colors"
                    style={{ color: 'var(--text-muted)', background: 'var(--bg-card)' }}>
                    Unlink
                  </button>
                </div>
              ))
            )}
          </div>
        )}

        {/* ── NOTES ── */}
        {tab === 'notes' && (
          <div className="space-y-4">
            {/* Add note */}
            <div className="rounded-xl p-4 space-y-3"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Add Note</span>
                <div className="flex gap-1 ml-2">
                  {Object.entries(NOTE_CFG).map(([k, v]) => (
                    <button key={k} onClick={() => setNoteType(k)}
                      className="px-2 py-0.5 rounded text-xs font-semibold transition-all"
                      style={{
                        background: noteType === k ? `${v.color}18` : 'var(--bg-card)',
                        color: noteType === k ? v.color : 'var(--text-muted)',
                        border: `1px solid ${noteType === k ? v.color + '35' : 'var(--border-color)'}`,
                      }}>
                      {v.icon} {v.label}
                    </button>
                  ))}
                </div>
              </div>
              <textarea ref={noteRef} value={noteText} onChange={e => setNoteText(e.target.value)}
                placeholder={noteType === 'ioc' ? 'IP: 1.2.3.4, Domain: evil.com, Hash: abc123...' : 'Add your note here...'}
                rows={3} className="w-full rounded-xl p-3 text-sm resize-none"
                style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', outline: 'none' }}
                onKeyDown={e => { if (e.ctrlKey && e.key === 'Enter') addNote() }}
              />
              <div className="flex items-center justify-between">
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Ctrl+Enter to submit</span>
                <button onClick={addNote} disabled={addingNote || !noteText.trim()}
                  className="px-4 py-2 rounded-xl text-xs font-bold disabled:opacity-40"
                  style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)' }}>
                  {addingNote ? 'Saving...' : 'Add Note'}
                </button>
              </div>
            </div>

            {/* Notes list */}
            {(data.notes || []).length === 0 ? (
              <p className="text-sm text-center py-4" style={{ color: 'var(--text-muted)' }}>No notes yet</p>
            ) : (
              [...(data.notes || [])].reverse().map(n => {
                const nc = NOTE_CFG[n.note_type] || NOTE_CFG.note
                return (
                  <div key={n.id} className="rounded-xl p-4"
                    style={{ background: 'var(--bg-card)', border: `1px solid ${nc.color}20` }}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs px-2 py-0.5 rounded font-bold"
                          style={{ background: `${nc.color}15`, color: nc.color }}>
                          {nc.icon} {nc.label}
                        </span>
                        <span className="text-xs font-semibold text-white">{n.username}</span>
                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{timeAgo(n.created_at)}</span>
                      </div>
                      {n.username === user?.username && (
                        <button onClick={() => deleteNote(n.id)} className="text-xs hover:text-red-400 transition-colors"
                          style={{ color: 'var(--text-muted)' }}>✕</button>
                      )}
                    </div>
                    <p className="text-sm text-white whitespace-pre-wrap leading-relaxed">{n.content}</p>
                  </div>
                )
              })
            )}
          </div>
        )}
      </div>

      {editing && (
        <CaseModal caseData={data} onClose={() => setEditing(false)}
          onSaved={d => { setData(prev => ({ ...prev, ...d })); setEditing(false); onUpdated() }} />
      )}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function Cases() {
  const { user } = useAuth()
  const [cases, setCases]       = useState([])
  const [stats, setStats]       = useState(null)
  const [total, setTotal]       = useState(0)
  const [loading, setLoading]   = useState(true)
  const [selected, setSelected] = useState(null)
  const [showCreate, setShowCreate] = useState(false)
  const [users, setUsers]       = useState([])
  const [page, setPage]         = useState(1)
  const SIZE = 20

  const [filters, setFilters] = useState({ status: '', severity: '', search: '' })

  const loadCases = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ page, size: SIZE })
      if (filters.status)   params.set('status', filters.status)
      if (filters.severity) params.set('severity', filters.severity)
      if (filters.search)   params.set('search', filters.search)
      const d = await api(`/api/cases?${params}`)
      setCases(d.cases)
      setTotal(d.total)
    } catch {}
    setLoading(false)
  }, [page, filters])

  const loadStats = useCallback(async () => {
    try { setStats(await api('/api/cases/stats')) } catch {}
  }, [])

  useEffect(() => {
    loadCases()
    loadStats()
    api('/api/users').then(d => setUsers(Array.isArray(d) ? d : [])).catch(() => {})
  }, [loadCases, loadStats])

  const totalPages = Math.max(1, Math.ceil(total / SIZE))

  return (
    <div className="flex flex-col h-full animate-fade-in" style={{ minHeight: 0 }}>
      {/* Header */}
      <div className="flex-shrink-0 relative rounded-2xl overflow-hidden p-6 mb-5"
        style={{ background: 'linear-gradient(135deg,#0f172a,#1a1f35,#0f172a)', border: '1px solid rgba(239,68,68,0.2)' }}>
        <div className="absolute top-0 right-0 w-64 h-64 pointer-events-none"
          style={{ background: 'radial-gradient(circle,rgba(239,68,68,0.06) 0%,transparent 70%)', transform: 'translate(25%,-25%)' }} />
        <div className="relative flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-black text-white">Case Management</h1>
            <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
              Incident tracking, investigation notes and alert correlation
            </p>
          </div>
          <button onClick={() => setShowCreate(true)}
            className="px-5 py-2.5 rounded-xl text-sm font-bold transition-all"
            style={{ background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)' }}>
            + New Case
          </button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="flex-shrink-0 grid grid-cols-2 md:grid-cols-5 gap-3 mb-5">
          <StatCard label="Total" value={stats.total} color="#818cf8" />
          <StatCard label="Open" value={stats.open} color="#ef4444"
            sub={stats.critical_open > 0 ? `${stats.critical_open} critical` : ''} />
          <StatCard label="In Progress" value={stats.in_progress} color="#f59e0b" />
          <StatCard label="Resolved" value={stats.resolved} color="#10b981" />
          <StatCard label="SLA Breached" value={stats.sla_breached}
            color={stats.sla_breached > 0 ? '#ef4444' : '#10b981'}
            sub={stats.avg_resolution_hours ? `Avg ${stats.avg_resolution_hours}h` : ''} />
        </div>
      )}

      {/* Body: list + detail */}
      <div className="flex-1 flex gap-5 min-h-0">
        {/* Left: Case list */}
        <div className={`flex flex-col ${selected ? 'w-96 flex-shrink-0' : 'flex-1'} min-h-0`}>
          {/* Filters */}
          <div className="flex-shrink-0 flex flex-wrap gap-2 mb-3">
            <input value={filters.search} placeholder="Search cases..."
              onChange={e => { setFilters(p => ({ ...p, search: e.target.value })); setPage(1) }}
              className="flex-1 min-w-36" />
            <select value={filters.status}
              onChange={e => { setFilters(p => ({ ...p, status: e.target.value })); setPage(1) }}
              className="w-36">
              <option value="">All statuses</option>
              {Object.entries(STATUS_CFG).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
            <select value={filters.severity}
              onChange={e => { setFilters(p => ({ ...p, severity: e.target.value })); setPage(1) }}
              className="w-32">
              <option value="">All severities</option>
              {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s}>{s}</option>)}
            </select>
          </div>

          {/* List */}
          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            {loading ? (
              <div className="flex items-center gap-3 p-6" style={{ color: 'var(--text-muted)' }}><Spinner /><span className="text-sm">Loading...</span></div>
            ) : cases.length === 0 ? (
              <div className="text-center py-16">
                <div className="text-4xl mb-3">📁</div>
                <p className="text-sm font-semibold text-white mb-1">No cases found</p>
                <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>Create your first case to start tracking incidents</p>
                <button onClick={() => setShowCreate(true)}
                  className="px-4 py-2 rounded-xl text-sm font-bold"
                  style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)' }}>
                  + New Case
                </button>
              </div>
            ) : (
              cases.map(c => {
                const isActive = selected === c.id
                const sc = STATUS_CFG[c.status] || STATUS_CFG.open
                const sev = SEV_CFG[c.severity] || SEV_CFG.MEDIUM
                return (
                  <div key={c.id} onClick={() => setSelected(isActive ? null : c.id)}
                    className="rounded-2xl p-4 cursor-pointer transition-all"
                    style={{
                      background: isActive ? 'rgba(99,102,241,0.1)' : 'var(--bg-card)',
                      border: isActive ? '1px solid rgba(99,102,241,0.4)' : '1px solid var(--border-color)',
                    }}>
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-xs font-black" style={{ color: '#818cf8' }}>{c.case_number}</span>
                        <SevBadge sev={c.severity} />
                        <StatusBadge status={c.status} />
                      </div>
                      <SlaTag deadline={c.sla_deadline} resolved_at={c.resolved_at} />
                    </div>
                    <p className="text-sm font-bold text-white leading-tight mb-2 line-clamp-2">{c.title}</p>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-muted)' }}>
                        {c.assigned_to_name && <span style={{ color: '#a5b4fc' }}>{c.assigned_to_name}</span>}
                        {c.alert_count > 0 && <span>🚨 {c.alert_count}</span>}
                        {c.note_count > 0 && <span>📝 {c.note_count}</span>}
                      </div>
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{timeAgo(c.updated_at)}</span>
                    </div>
                    {c.tags?.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {c.tags.slice(0,3).map(tag => (
                          <span key={tag} className="text-xs px-1.5 py-0.5 rounded"
                            style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)' }}>#{tag}</span>
                        ))}
                        {c.tags.length > 3 && <span className="text-xs" style={{ color: 'var(--text-muted)' }}>+{c.tags.length - 3}</span>}
                      </div>
                    )}
                  </div>
                )
              })
            )}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex-shrink-0 flex items-center justify-between pt-3">
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{total} cases</span>
              <div className="flex gap-2">
                <button onClick={() => setPage(p => Math.max(1, p-1))} disabled={page===1}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold disabled:opacity-40"
                  style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>←</button>
                <button onClick={() => setPage(p => Math.min(totalPages, p+1))} disabled={page===totalPages}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold disabled:opacity-40"
                  style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>→</button>
              </div>
            </div>
          )}
        </div>

        {/* Right: Case detail */}
        {selected && (
          <div className="flex-1 rounded-2xl overflow-hidden min-h-0"
            style={{ background: 'var(--bg-card)', border: '1px solid rgba(99,102,241,0.2)' }}>
            <CaseDetail
              key={selected}
              caseId={selected}
              users={users}
              onClose={() => setSelected(null)}
              onUpdated={() => { loadCases(); loadStats() }}
            />
          </div>
        )}
      </div>

      {showCreate && (
        <CaseModal onClose={() => setShowCreate(false)}
          onSaved={c => { setShowCreate(false); loadCases(); loadStats(); setSelected(c.id) }} />
      )}
    </div>
  )
}
