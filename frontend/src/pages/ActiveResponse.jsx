import React, { useState, useEffect, useCallback } from 'react'
import {
  getARPolicies, createARPolicy, updateARPolicy, deleteARPolicy,
  getARExecutions, triggerAR,
} from '../api'

// ── Constants ─────────────────────────────────────────────────────────────────

const TRIGGER_OPTIONS = [
  { value: 'severity',  label: 'By Severity' },
  { value: 'rule_name', label: 'By Rule Name' },
  { value: 'category',  label: 'By Category' },
  { value: 'any_alert', label: 'Any Alert' },
]

const ACTION_OPTIONS = [
  { value: 'block_ip',     label: 'Block IP',      icon: '🚫' },
  { value: 'unblock_ip',   label: 'Unblock IP',    icon: '✅' },
  { value: 'kill_process', label: 'Kill Process',  icon: '💀' },
  { value: 'disable_user', label: 'Disable User',  icon: '🔒' },
  { value: 'enable_user',  label: 'Enable User',   icon: '🔓' },
  { value: 'run_script',   label: 'Run Script',    icon: '📜' },
  { value: 'email_alert',  label: 'Send Email',    icon: '📧' },
  { value: 'slack_alert',  label: 'Send Slack',    icon: '💬' },
]

const STATUS_STYLE = {
  pending: { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)'  },
  sent:    { color: '#3b82f6', bg: 'rgba(59,130,246,0.12)'  },
  success: { color: '#10b981', bg: 'rgba(16,185,129,0.12)'  },
  failed:  { color: '#ef4444', bg: 'rgba(239,68,68,0.12)'   },
  timeout: { color: '#6b7280', bg: 'rgba(107,114,128,0.12)' },
}

// ── Small helpers ─────────────────────────────────────────────────────────────

function Badge({ text, color, bg }) {
  return (
    <span className="inline-block text-xs font-bold px-2.5 py-0.5 rounded-full"
      style={{ color, background: bg, border: `1px solid ${color}30` }}>
      {text}
    </span>
  )
}

function ActionIcon({ action }) {
  const opt = ACTION_OPTIONS.find(a => a.value === action)
  return <span className="mr-1.5">{opt?.icon || '⚡'}</span>
}

function timeAgo(dt) {
  if (!dt) return '—'
  const diff = Math.floor((Date.now() - new Date(dt)) / 1000)
  if (diff < 60)  return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`
  return new Date(dt).toLocaleDateString()
}

// ── Policy form modal ─────────────────────────────────────────────────────────

const EMPTY_FORM = {
  name: '', description: '', enabled: true,
  trigger_on: 'severity', trigger_severity: 'CRITICAL,HIGH',
  trigger_rule: '', trigger_category: '',
  action: 'block_ip', action_params: '{}',
  target_agent: '', cooldown_seconds: 300,
}

function PolicyModal({ policy, onClose, onSaved }) {
  const [form, setForm] = useState(policy ? {
    ...EMPTY_FORM,
    ...policy,
    action_params: JSON.stringify(policy.action_params || {}, null, 2),
  } : { ...EMPTY_FORM })
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    let params
    try { params = JSON.parse(form.action_params || '{}') }
    catch { setError('action_params must be valid JSON'); return }

    setLoading(true)
    try {
      const payload = { ...form, action_params: params }
      if (policy) await updateARPolicy(policy.id, payload)
      else        await createARPolicy(payload)
      onSaved()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Save failed')
    }
    setLoading(false)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(6px)' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="w-full max-w-xl rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid rgba(99,102,241,0.4)',
          boxShadow: '0 24px 60px rgba(0,0,0,0.6), 0 0 40px rgba(99,102,241,0.15)',
          maxHeight: '90vh', overflowY: 'auto' }}>

        <div className="flex items-center justify-between px-6 py-4"
          style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
          <h3 className="font-bold text-white">{policy ? 'Edit Policy' : 'New AR Policy'}</h3>
          <button onClick={onClose} className="w-7 h-7 rounded-lg flex items-center justify-center text-lg"
            style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)' }}>×</button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="px-4 py-3 rounded-xl text-sm text-red-400"
              style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)' }}>
              {error}
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-xs font-semibold mb-1.5" style={{ color: 'var(--text-muted)' }}>
                Policy Name *
              </label>
              <input value={form.name} onChange={e => set('name', e.target.value)} required
                className="w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}
                placeholder="e.g. Block SSH Brute Force" />
            </div>

            <div>
              <label className="block text-xs font-semibold mb-1.5" style={{ color: 'var(--text-muted)' }}>
                Trigger On
              </label>
              <select value={form.trigger_on} onChange={e => set('trigger_on', e.target.value)}
                className="w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
                {TRIGGER_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold mb-1.5" style={{ color: 'var(--text-muted)' }}>
                {form.trigger_on === 'severity' ? 'Severity (comma-sep)' :
                 form.trigger_on === 'rule_name' ? 'Rule Name Pattern' :
                 form.trigger_on === 'category' ? 'Category' : '—'}
              </label>
              {form.trigger_on === 'severity' && (
                <input value={form.trigger_severity} onChange={e => set('trigger_severity', e.target.value)}
                  className="w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}
                  placeholder="CRITICAL,HIGH" />
              )}
              {form.trigger_on === 'rule_name' && (
                <input value={form.trigger_rule} onChange={e => set('trigger_rule', e.target.value)}
                  className="w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}
                  placeholder="Brute Force" />
              )}
              {form.trigger_on === 'category' && (
                <input value={form.trigger_category} onChange={e => set('trigger_category', e.target.value)}
                  className="w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}
                  placeholder="authentication" />
              )}
              {form.trigger_on === 'any_alert' && (
                <div className="rounded-xl px-3 py-2.5 text-sm"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)',
                    color: 'var(--text-muted)' }}>
                  Fires on every alert
                </div>
              )}
            </div>

            <div>
              <label className="block text-xs font-semibold mb-1.5" style={{ color: 'var(--text-muted)' }}>
                Action
              </label>
              <select value={form.action} onChange={e => set('action', e.target.value)}
                className="w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
                {ACTION_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.icon} {o.label}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold mb-1.5" style={{ color: 'var(--text-muted)' }}>
                Cooldown (seconds)
              </label>
              <input type="number" min="0" value={form.cooldown_seconds}
                onChange={e => set('cooldown_seconds', parseInt(e.target.value) || 0)}
                className="w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }} />
            </div>

            <div className="col-span-2">
              <label className="block text-xs font-semibold mb-1.5" style={{ color: 'var(--text-muted)' }}>
                Action Params (JSON)
              </label>
              <textarea value={form.action_params}
                onChange={e => set('action_params', e.target.value)} rows={4}
                className="w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none font-mono"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)',
                  resize: 'vertical' }}
                placeholder={'{\n  "src_ip": "auto"\n}'} />
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                block_ip: src_ip auto-filled · email_alert: recipients · run_script: script, timeout
              </p>
            </div>

            <div className="col-span-2">
              <label className="block text-xs font-semibold mb-1.5" style={{ color: 'var(--text-muted)' }}>
                Target Agent ID (leave blank = all agents)
              </label>
              <input value={form.target_agent} onChange={e => set('target_agent', e.target.value)}
                className="w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}
                placeholder="Optional: restrict to specific agent" />
            </div>

            <div className="col-span-2 flex items-center gap-3">
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" checked={form.enabled}
                  onChange={e => set('enabled', e.target.checked)} className="sr-only peer" />
                <div className="w-10 h-5 rounded-full peer transition-colors"
                  style={{ background: form.enabled ? '#3b82f6' : 'rgba(255,255,255,0.1)' }}>
                  <div className="w-4 h-4 rounded-full bg-white shadow absolute top-0.5 transition-transform"
                    style={{ transform: form.enabled ? 'translateX(21px)' : 'translateX(2px)' }} />
                </div>
              </label>
              <span className="text-sm text-white">Policy enabled</span>
            </div>
          </div>

          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose}
              className="flex-1 py-2.5 rounded-xl text-sm font-semibold transition-colors"
              style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)',
                border: '1px solid var(--border-color)' }}>
              Cancel
            </button>
            <button type="submit" disabled={loading}
              className="flex-1 py-2.5 rounded-xl text-sm font-semibold text-white transition-opacity"
              style={{ background: 'linear-gradient(135deg,#3b82f6,#8b5cf6)',
                color: '#fff', opacity: loading ? 0.7 : 1 }}>
              {loading ? 'Saving…' : (policy ? 'Update' : 'Create')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ActiveResponse() {
  const [policies,    setPolicies]    = useState([])
  const [executions,  setExecutions]  = useState([])
  const [execTotal,   setExecTotal]   = useState(0)
  const [tab,         setTab]         = useState('policies')
  const [modalPolicy, setModalPolicy] = useState(null)
  const [showModal,   setShowModal]   = useState(false)
  const [loading,     setLoading]     = useState(false)
  const [execPage,    setExecPage]    = useState(1)
  const [filterStatus, setFilterStatus] = useState('')
  const [toast,       setToast]       = useState(null)

  const showToast = (msg, type = 'success') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3500)
  }

  const loadPolicies = useCallback(async () => {
    try {
      const r = await getARPolicies()
      setPolicies(r.data)
    } catch { /* silent */ }
  }, [])

  const loadExecutions = useCallback(async () => {
    try {
      const r = await getARExecutions({ page: execPage, size: 50, status: filterStatus || undefined })
      setExecutions(r.data.executions)
      setExecTotal(r.data.total)
    } catch { /* silent */ }
  }, [execPage, filterStatus])

  useEffect(() => { loadPolicies() }, [loadPolicies])
  useEffect(() => { if (tab === 'history') loadExecutions() }, [tab, loadExecutions])

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this policy?')) return
    try {
      await deleteARPolicy(id)
      showToast('Policy deleted')
      loadPolicies()
    } catch { showToast('Delete failed', 'error') }
  }

  const handleToggle = async (policy) => {
    try {
      await updateARPolicy(policy.id, { enabled: !policy.enabled })
      showToast(policy.enabled ? 'Policy disabled' : 'Policy enabled')
      loadPolicies()
    } catch { showToast('Update failed', 'error') }
  }

  const handleSaved = () => {
    setShowModal(false)
    setModalPolicy(null)
    showToast('Policy saved')
    loadPolicies()
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Active Response</h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Automated threat response policies
          </p>
        </div>
        <button onClick={() => { setModalPolicy(null); setShowModal(true) }}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-white transition-opacity hover:opacity-80"
          style={{ background: 'linear-gradient(135deg,#3b82f6,#8b5cf6)', color: '#fff' }}>
          <span className="text-base">+</span> New Policy
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Policies',   value: policies.length,                          color: '#3b82f6' },
          { label: 'Active Policies',  value: policies.filter(p => p.enabled).length,   color: '#10b981' },
          { label: 'Executions Today', value: execTotal,                                color: '#f59e0b' },
          { label: 'Actions Available', value: ACTION_OPTIONS.length,                   color: '#8b5cf6' },
        ].map(s => (
          <div key={s.label} className="rounded-2xl p-4"
            style={{ background: 'var(--bg-card)', border: `1px solid ${s.color}25` }}>
            <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>{s.label}</p>
            <p className="text-2xl font-black" style={{ color: s.color }}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-xl w-fit"
        style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
        {[['policies', 'Policies'], ['history', 'Execution History']].map(([v, l]) => (
          <button key={v} onClick={() => setTab(v)}
            className="px-5 py-2 rounded-lg text-sm font-semibold transition-all"
            style={{
              background: tab === v ? 'linear-gradient(135deg,#3b82f6,#8b5cf6)' : 'transparent',
              color: tab === v ? '#fff' : 'var(--text-secondary)',
            }}>
            {l}
          </button>
        ))}
      </div>

      {/* Policies table */}
      {tab === 'policies' && (
        <div className="rounded-2xl overflow-hidden"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          {policies.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <span className="text-4xl">⚡</span>
              <p className="text-sm font-semibold text-white">No policies yet</p>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Create a policy to automatically respond to threats
              </p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
                  {['Status', 'Policy Name', 'Trigger', 'Action', 'Cooldown', 'Target', ''].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider"
                      style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {policies.map((p, i) => {
                  const actionOpt = ACTION_OPTIONS.find(a => a.value === p.action)
                  return (
                    <tr key={p.id} style={{
                      borderBottom: i < policies.length - 1 ? '1px solid var(--border-color)' : 'none',
                    }}>
                      <td className="px-4 py-3">
                        <button onClick={() => handleToggle(p)}
                          className="w-8 h-4 rounded-full transition-colors relative"
                          style={{ background: p.enabled ? '#3b82f6' : 'rgba(255,255,255,0.1)' }}>
                          <div className="w-3 h-3 rounded-full bg-white absolute top-0.5 transition-transform shadow"
                            style={{ transform: p.enabled ? 'translateX(17px)' : 'translateX(2px)' }} />
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <p className="font-semibold text-white">{p.name}</p>
                        {p.description && (
                          <p className="text-xs mt-0.5 truncate max-w-xs" style={{ color: 'var(--text-muted)' }}>
                            {p.description}
                          </p>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                          {p.trigger_on === 'severity' ? p.trigger_severity :
                           p.trigger_on === 'rule_name' ? p.trigger_rule :
                           p.trigger_on === 'category' ? p.trigger_category :
                           'Any alert'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-medium text-white">
                          {actionOpt?.icon} {actionOpt?.label || p.action}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                        {p.cooldown_seconds}s
                      </td>
                      <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                        {p.target_agent || 'All agents'}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <button onClick={() => { setModalPolicy(p); setShowModal(true) }}
                            className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors"
                            style={{ background: 'rgba(59,130,246,0.12)', color: '#3b82f6',
                              border: '1px solid rgba(59,130,246,0.2)' }}>
                            Edit
                          </button>
                          <button onClick={() => handleDelete(p.id)}
                            className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors"
                            style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444',
                              border: '1px solid rgba(239,68,68,0.2)' }}>
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Execution history */}
      {tab === 'history' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <select value={filterStatus} onChange={e => { setFilterStatus(e.target.value); setExecPage(1) }}
              className="rounded-xl px-3 py-2 text-sm text-white outline-none"
              style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
              <option value="">All statuses</option>
              {Object.keys(STATUS_STYLE).map(s => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
            <button onClick={loadExecutions}
              className="px-3 py-2 rounded-xl text-xs font-semibold transition-colors"
              style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)',
                color: 'var(--text-secondary)' }}>
              Refresh
            </button>
            <span className="text-xs ml-auto" style={{ color: 'var(--text-muted)' }}>
              {execTotal} total executions
            </span>
          </div>

          <div className="rounded-2xl overflow-hidden"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            {executions.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 gap-2">
                <span className="text-3xl">📋</span>
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No executions found</p>
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
                    {['Time', 'Policy', 'Agent', 'Action', 'Source IP', 'Status', 'Result'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider"
                        style={{ color: 'var(--text-muted)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {executions.map((ex, i) => {
                    const st = STATUS_STYLE[ex.status] || STATUS_STYLE.pending
                    return (
                      <tr key={ex.id} style={{
                        borderBottom: i < executions.length - 1 ? '1px solid var(--border-color)' : 'none',
                      }}>
                        <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                          {timeAgo(ex.created_at)}
                        </td>
                        <td className="px-4 py-3 font-medium text-white text-xs">
                          {ex.policy_name || `#${ex.policy_id}`}
                        </td>
                        <td className="px-4 py-3 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                          {ex.agent_id?.slice(0, 8)}…
                        </td>
                        <td className="px-4 py-3 text-xs text-white">
                          <ActionIcon action={ex.action} />{ex.action}
                        </td>
                        <td className="px-4 py-3 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                          {ex.src_ip || '—'}
                        </td>
                        <td className="px-4 py-3">
                          <Badge text={ex.status} color={st.color} bg={st.bg} />
                        </td>
                        <td className="px-4 py-3 text-xs max-w-xs truncate" style={{ color: 'var(--text-muted)' }}
                          title={ex.result || ''}>
                          {ex.result || '—'}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>

          {execTotal > 50 && (
            <div className="flex items-center justify-center gap-3 pt-2">
              <button disabled={execPage === 1}
                onClick={() => setExecPage(p => p - 1)}
                className="px-4 py-2 rounded-xl text-xs font-semibold disabled:opacity-40"
                style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)',
                  color: 'var(--text-secondary)' }}>
                Previous
              </button>
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Page {execPage} / {Math.ceil(execTotal / 50)}
              </span>
              <button disabled={execPage >= Math.ceil(execTotal / 50)}
                onClick={() => setExecPage(p => p + 1)}
                className="px-4 py-2 rounded-xl text-xs font-semibold disabled:opacity-40"
                style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)',
                  color: 'var(--text-secondary)' }}>
                Next
              </button>
            </div>
          )}
        </div>
      )}

      {/* Modal */}
      {showModal && (
        <PolicyModal
          policy={modalPolicy}
          onClose={() => { setShowModal(false); setModalPolicy(null) }}
          onSaved={handleSaved}
        />
      )}

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-5 right-5 z-50 flex items-center gap-2 px-4 py-3 rounded-xl text-sm font-medium animate-fade-in"
          style={{
            background: toast.type === 'error' ? 'rgba(239,68,68,0.95)' : 'rgba(16,185,129,0.95)',
            border: '1px solid rgba(255,255,255,0.1)',
            color: '#fff',
            boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          }}>
          {toast.type === 'error' ? '❌' : '✅'} {toast.msg}
        </div>
      )}
    </div>
  )
}
