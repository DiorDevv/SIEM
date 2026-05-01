import React, { useState, useEffect, useCallback, useRef } from 'react'
import {
  getARPolicies, createARPolicy, updateARPolicy, deleteARPolicy,
  cloneARPolicy, bulkToggleARPolicies,
  getARExecutions, cancelARExecution, triggerAR, retryARExecution,
  getARStats, getARTemplates,
} from '../api'

// ── Constants ─────────────────────────────────────────────────────────────────

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const TRIGGER_OPTIONS = [
  { value: 'severity',  label: 'By Severity' },
  { value: 'rule_name', label: 'By Rule Name' },
  { value: 'category',  label: 'By Category' },
  { value: 'src_ip',    label: 'Has Source IP' },
  { value: 'any_alert', label: 'Any Alert' },
]

const ACTION_OPTIONS = [
  { value: 'block_ip',     label: 'Block IP',      icon: '🚫', desc: 'Firewall-block source IP on agent',        danger: true  },
  { value: 'unblock_ip',   label: 'Unblock IP',    icon: '✅', desc: 'Remove firewall block for IP',            danger: false },
  { value: 'kill_process', label: 'Kill Process',  icon: '💀', desc: 'Terminate process by name or PID',        danger: true  },
  { value: 'disable_user', label: 'Disable User',  icon: '🔒', desc: 'Lock user account (usermod -L)',           danger: true  },
  { value: 'enable_user',  label: 'Enable User',   icon: '🔓', desc: 'Unlock user account (usermod -U)',         danger: false },
  { value: 'run_script',   label: 'Run Script',    icon: '📜', desc: 'Execute approved script on agent',        danger: true  },
  { value: 'email_alert',  label: 'Send Email',    icon: '📧', desc: 'Send email alert (server-side)',          danger: false },
  { value: 'slack_alert',  label: 'Send Slack',    icon: '💬', desc: 'Post to Slack channel (server-side)',     danger: false },
]

const STATUS_STYLE = {
  pending:   { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)'  },
  sent:      { color: '#3b82f6', bg: 'rgba(59,130,246,0.12)'  },
  success:   { color: '#10b981', bg: 'rgba(16,185,129,0.12)'  },
  failed:    { color: '#ef4444', bg: 'rgba(239,68,68,0.12)'   },
  timeout:   { color: '#6b7280', bg: 'rgba(107,114,128,0.12)' },
  cancelled: { color: '#94a3b8', bg: 'rgba(148,163,184,0.10)' },
}

const CATEGORY_COLORS = {
  'Network Defense':  '#3b82f6',
  'Notification':     '#8b5cf6',
  'Account Response': '#ef4444',
  'Process Response': '#f59e0b',
  'Malware Response': '#ec4899',
}

const SEV_COLORS = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#3b82f6', INFO: '#6b7280',
}

// ── Utility helpers ───────────────────────────────────────────────────────────

function timeAgo(dt) {
  if (!dt) return '—'
  const diff = Math.floor((Date.now() - new Date(dt)) / 1000)
  if (diff < 60)    return `${diff}s ago`
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return new Date(dt).toLocaleDateString()
}

function fmtDatetime(dt) {
  if (!dt) return '—'
  return new Date(dt).toLocaleString()
}

function truncate(str, n = 120) {
  if (!str) return ''
  return str.length > n ? str.slice(0, n) + '…' : str
}

// ── Reusable primitives ───────────────────────────────────────────────────────

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

function StatCard({ label, value, color, sub }) {
  return (
    <div className="rounded-2xl p-4" style={{ background: 'var(--bg-card)', border: `1px solid ${color}25` }}>
      <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>{label}</p>
      <p className="text-2xl font-black" style={{ color }}>{value}</p>
      {sub && <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{sub}</p>}
    </div>
  )
}

function Toggle({ checked, onChange, disabled }) {
  return (
    <button type="button" onClick={() => !disabled && onChange(!checked)} disabled={disabled}
      className="w-8 h-4 rounded-full transition-colors relative flex-shrink-0"
      style={{ background: checked ? '#3b82f6' : 'rgba(255,255,255,0.1)', opacity: disabled ? 0.5 : 1 }}>
      <div className="w-3 h-3 rounded-full bg-white absolute top-0.5 shadow transition-transform"
        style={{ transform: checked ? 'translateX(17px)' : 'translateX(2px)' }} />
    </button>
  )
}

// ── Confirm modal ─────────────────────────────────────────────────────────────

function ConfirmModal({ title, message, confirmLabel, danger, onConfirm, onCancel }) {
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(4px)' }}>
      <div className="w-full max-w-sm rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: `1px solid ${danger ? 'rgba(239,68,68,0.4)' : 'var(--border-color)'}`,
          boxShadow: '0 24px 60px rgba(0,0,0,0.7)' }}>
        <div className="px-6 pt-6 pb-4">
          <h3 className="text-base font-bold text-white mb-2">{title}</h3>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{message}</p>
        </div>
        <div className="flex gap-3 px-6 pb-6">
          <button onClick={onCancel}
            className="flex-1 py-2.5 rounded-xl text-sm font-semibold"
            style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)', border: '1px solid var(--border-color)' }}>
            Cancel
          </button>
          <button onClick={onConfirm}
            className="flex-1 py-2.5 rounded-xl text-sm font-semibold text-white"
            style={{ background: danger ? 'linear-gradient(135deg,#ef4444,#dc2626)' : 'linear-gradient(135deg,#3b82f6,#8b5cf6)' }}>
            {confirmLabel || 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Action Params Form ────────────────────────────────────────────────────────

function ActionParamsForm({ action, params, onChange }) {
  const set = (key, val) => onChange({ ...params, [key]: val })
  const ic  = "w-full rounded-xl px-3 py-2 text-sm text-white outline-none"
  const is  = { background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }
  const lc  = "block text-xs font-semibold mb-1"
  const ls  = { color: 'var(--text-muted)' }

  if (action === 'block_ip') return (
    <div className="grid grid-cols-2 gap-3">
      <div>
        <label className={lc} style={ls}>Auto-unblock after (seconds)</label>
        <input type="number" min="0" placeholder="0 = never"
          value={params.unblock_after || ''} onChange={e => set('unblock_after', parseInt(e.target.value) || 0)}
          className={ic} style={is} />
        <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>3600 = 1h · 86400 = 24h</p>
      </div>
      <div>
        <label className={lc} style={ls}>Min Alert Level (1–15)</label>
        <input type="number" min="1" max="15" placeholder="1–15"
          value={params.trigger_min_level || ''}
          onChange={e => set('trigger_min_level', parseInt(e.target.value) || undefined)}
          className={ic} style={is} />
      </div>
    </div>
  )

  if (action === 'kill_process') return (
    <div className="grid grid-cols-2 gap-3">
      <div>
        <label className={lc} style={ls}>Process Name</label>
        <input placeholder="e.g. nc, python3" value={params.process_name || ''}
          onChange={e => set('process_name', e.target.value)} className={ic} style={is} />
        <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Exact name match</p>
      </div>
      <div>
        <label className={lc} style={ls}>Min Alert Level (1–15)</label>
        <input type="number" min="1" max="15" placeholder="1–15"
          value={params.trigger_min_level || ''}
          onChange={e => set('trigger_min_level', parseInt(e.target.value) || undefined)}
          className={ic} style={is} />
      </div>
    </div>
  )

  if (action === 'disable_user' || action === 'enable_user') return (
    <div className="grid grid-cols-2 gap-3">
      <div>
        <label className={lc} style={ls}>Username (blank = from alert)</label>
        <input placeholder="Optional: fixed username" value={params.user || ''}
          onChange={e => set('user', e.target.value)} className={ic} style={is} />
      </div>
      <div>
        <label className={lc} style={ls}>Min Alert Level (1–15)</label>
        <input type="number" min="1" max="15" placeholder="1–15"
          value={params.trigger_min_level || ''}
          onChange={e => set('trigger_min_level', parseInt(e.target.value) || undefined)}
          className={ic} style={is} />
      </div>
    </div>
  )

  if (action === 'email_alert') return (
    <div>
      <label className={lc} style={ls}>Recipients (comma-separated)</label>
      <input placeholder="soc@company.com, admin@company.com" value={params.recipients || ''}
        onChange={e => set('recipients', e.target.value)} className={ic} style={is} />
    </div>
  )

  if (action === 'run_script') return (
    <div className="space-y-3">
      <div>
        <label className={lc} style={ls}>Script Path (absolute)</label>
        <input placeholder="/opt/siem/scripts/isolate.sh" value={params.script || ''}
          onChange={e => set('script', e.target.value)} className={ic} style={is} />
        <p className="text-xs mt-1" style={{ color: '#f59e0b' }}>Script must exist and be executable on the agent</p>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className={lc} style={ls}>Timeout (5–300 s)</label>
          <input type="number" min="5" max="300" placeholder="60" value={params.timeout || ''}
            onChange={e => set('timeout', parseInt(e.target.value) || 60)} className={ic} style={is} />
        </div>
        <div>
          <label className={lc} style={ls}>Min Alert Level (1–15)</label>
          <input type="number" min="1" max="15" placeholder="1–15"
            value={params.trigger_min_level || ''}
            onChange={e => set('trigger_min_level', parseInt(e.target.value) || undefined)}
            className={ic} style={is} />
        </div>
      </div>
    </div>
  )

  return (
    <div>
      <label className={lc} style={ls}>Min Alert Level (optional)</label>
      <input type="number" min="1" max="15" placeholder="1–15"
        value={params.trigger_min_level || ''}
        onChange={e => set('trigger_min_level', parseInt(e.target.value) || undefined)}
        className={ic} style={is} />
    </div>
  )
}

// ── Policy form modal ─────────────────────────────────────────────────────────

const EMPTY_FORM = {
  name: '', description: '', enabled: true,
  trigger_on: 'severity', trigger_severity: 'CRITICAL,HIGH',
  trigger_rule: '', trigger_category: '',
  action: 'block_ip', action_params: {},
  target_agent: '', cooldown_seconds: 300, max_per_hour: '',
}

function PolicyModal({ policy, onClose, onSaved }) {
  const [form,    setForm]    = useState(
    policy
      ? { ...EMPTY_FORM, ...policy, action_params: policy.action_params || {}, max_per_hour: policy.max_per_hour || '' }
      : { ...EMPTY_FORM }
  )
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const toggleSeverity = (sev) => {
    const parts  = (form.trigger_severity || '').split(',').map(s => s.trim()).filter(Boolean)
    const exists = parts.includes(sev)
    const next   = exists ? parts.filter(s => s !== sev) : [...parts, sev]
    set('trigger_severity', next.join(','))
  }

  const selectedSevs = (form.trigger_severity || '').split(',').map(s => s.trim()).filter(Boolean)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const payload = {
        ...form,
        max_per_hour: form.max_per_hour ? parseInt(form.max_per_hour) : null,
        target_agent: form.target_agent?.trim() || null,
      }
      if (policy?.id) await updateARPolicy(policy.id, payload)
      else            await createARPolicy(payload)
      onSaved()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Save failed')
    }
    setLoading(false)
  }

  const inputCls = "w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none"
  const inputStyle = { background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }
  const labelCls = "block text-xs font-semibold mb-1.5"
  const labelStyle = { color: 'var(--text-muted)' }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(6px)' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="w-full max-w-xl rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid rgba(99,102,241,0.4)',
          boxShadow: '0 24px 60px rgba(0,0,0,0.6)', maxHeight: '90vh', overflowY: 'auto' }}>

        <div className="flex items-center justify-between px-6 py-4"
          style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
          <h3 className="font-bold text-white">{policy?.id ? 'Edit Policy' : 'New AR Policy'}</h3>
          <button onClick={onClose}
            className="w-7 h-7 rounded-lg flex items-center justify-center text-lg"
            style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)' }}>×</button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="px-4 py-3 rounded-xl text-sm text-red-400"
              style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)' }}>
              {error}
            </div>
          )}

          {/* Name */}
          <div>
            <label className={labelCls} style={labelStyle}>Policy Name *</label>
            <input value={form.name} onChange={e => set('name', e.target.value)} required
              maxLength={256} placeholder="e.g. Block SSH Brute Force"
              className={inputCls} style={inputStyle} />
          </div>

          {/* Description */}
          <div>
            <label className={labelCls} style={labelStyle}>Description</label>
            <input value={form.description || ''} onChange={e => set('description', e.target.value)}
              placeholder="What does this policy do?" className={inputCls} style={inputStyle} />
          </div>

          {/* Trigger */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={labelCls} style={labelStyle}>Trigger On</label>
              <select value={form.trigger_on} onChange={e => set('trigger_on', e.target.value)}
                className={inputCls} style={inputStyle}>
                {TRIGGER_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>

            <div>
              {form.trigger_on === 'severity' && (
                <>
                  <label className={labelCls} style={labelStyle}>Severity levels</label>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {SEVERITIES.map(s => {
                      const active = selectedSevs.includes(s)
                      return (
                        <button key={s} type="button" onClick={() => toggleSeverity(s)}
                          className="px-2.5 py-1 rounded-lg text-xs font-bold transition-all"
                          style={{
                            background: active ? SEV_COLORS[s] + '22' : 'var(--bg-secondary)',
                            color:      active ? SEV_COLORS[s] : 'var(--text-muted)',
                            border:     `1px solid ${active ? SEV_COLORS[s] + '60' : 'var(--border-color)'}`,
                          }}>
                          {s}
                        </button>
                      )
                    })}
                  </div>
                  {!selectedSevs.length && (
                    <p className="text-xs mt-1 text-red-400">Select at least one severity</p>
                  )}
                </>
              )}
              {form.trigger_on === 'rule_name' && (
                <>
                  <label className={labelCls} style={labelStyle}>Rule Name (substring)</label>
                  <input value={form.trigger_rule || ''} onChange={e => set('trigger_rule', e.target.value)}
                    placeholder="Brute Force SSH" className={inputCls} style={inputStyle} />
                </>
              )}
              {form.trigger_on === 'category' && (
                <>
                  <label className={labelCls} style={labelStyle}>Category</label>
                  <input value={form.trigger_category || ''} onChange={e => set('trigger_category', e.target.value)}
                    placeholder="authentication" className={inputCls} style={inputStyle} />
                </>
              )}
              {(form.trigger_on === 'any_alert' || form.trigger_on === 'src_ip') && (
                <div className="mt-6 rounded-xl px-3 py-2.5 text-xs"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                  {form.trigger_on === 'any_alert' ? 'Fires on every alert' : 'Fires when alert has a source IP'}
                </div>
              )}
            </div>
          </div>

          {/* Action */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={labelCls} style={labelStyle}>Action</label>
              <select value={form.action} onChange={e => { set('action', e.target.value); set('action_params', {}) }}
                className={inputCls} style={inputStyle}>
                {ACTION_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.icon} {o.label}</option>
                ))}
              </select>
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                {ACTION_OPTIONS.find(a => a.value === form.action)?.desc}
              </p>
            </div>
            <div>
              <label className={labelCls} style={labelStyle}>Cooldown (0–86400 s)</label>
              <input type="number" min="0" max="86400" value={form.cooldown_seconds}
                onChange={e => set('cooldown_seconds', parseInt(e.target.value) || 0)}
                className={inputCls} style={inputStyle} />
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                Min gap between triggers per IP
              </p>
            </div>
          </div>

          {/* Action params */}
          <div>
            <label className={labelCls} style={labelStyle}>Action Parameters</label>
            <div className="p-3 rounded-xl" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
              <ActionParamsForm action={form.action} params={form.action_params || {}}
                onChange={v => set('action_params', v)} />
            </div>
          </div>

          {/* Advanced */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={labelCls} style={labelStyle}>Target Agent ID (blank = all)</label>
              <input value={form.target_agent || ''} onChange={e => set('target_agent', e.target.value)}
                placeholder="Optional agent UUID" className={inputCls} style={inputStyle} />
            </div>
            <div>
              <label className={labelCls} style={labelStyle}>Max executions / hour</label>
              <input type="number" min="1" placeholder="Unlimited"
                value={form.max_per_hour || ''}
                onChange={e => set('max_per_hour', e.target.value)}
                className={inputCls} style={inputStyle} />
            </div>
          </div>

          {/* Enabled toggle */}
          <div className="flex items-center gap-3">
            <Toggle checked={form.enabled} onChange={v => set('enabled', v)} />
            <span className="text-sm text-white">Policy enabled</span>
            {ACTION_OPTIONS.find(a => a.value === form.action)?.danger && (
              <span className="ml-auto text-xs px-2 py-0.5 rounded-lg font-semibold"
                style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.25)' }}>
                Destructive action
              </span>
            )}
          </div>

          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose}
              className="flex-1 py-2.5 rounded-xl text-sm font-semibold"
              style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)', border: '1px solid var(--border-color)' }}>
              Cancel
            </button>
            <button type="submit" disabled={loading || (form.trigger_on === 'severity' && !selectedSevs.length)}
              className="flex-1 py-2.5 rounded-xl text-sm font-semibold text-white"
              style={{ background: 'linear-gradient(135deg,#3b82f6,#8b5cf6)', opacity: loading ? 0.7 : 1 }}>
              {loading ? 'Saving…' : (policy?.id ? 'Update' : 'Create')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Manual Trigger modal ──────────────────────────────────────────────────────

function TriggerModal({ policy, onClose, showToast }) {
  const [agentId, setAgentId] = useState('')
  const [srcIp,   setSrcIp]   = useState('')
  const [loading, setLoading] = useState(false)
  const [confirm, setConfirm] = useState(false)

  const isDangerous = ACTION_OPTIONS.find(a => a.value === policy.action)?.danger

  const doTrigger = async () => {
    setLoading(true)
    try {
      await triggerAR({ policy_id: policy.id, agent_id: agentId.trim(), src_ip: srcIp.trim() || undefined })
      showToast(`Action queued for agent ${agentId.slice(0, 8)}…`)
      onClose()
    } catch (err) {
      showToast(err?.response?.data?.detail || 'Trigger failed', 'error')
      setLoading(false)
    }
  }

  const handleTrigger = () => {
    if (!agentId.trim()) return
    if (isDangerous) { setConfirm(true); return }
    doTrigger()
  }

  return (
    <>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
        style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(6px)' }}
        onClick={e => e.target === e.currentTarget && onClose()}>
        <div className="w-full max-w-sm rounded-2xl overflow-hidden"
          style={{ background: 'var(--bg-card)', border: '1px solid rgba(245,158,11,0.4)', boxShadow: '0 24px 60px rgba(0,0,0,0.6)' }}>
          <div className="flex items-center justify-between px-6 py-4"
            style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
            <h3 className="font-bold text-white">Manual Trigger</h3>
            <button onClick={onClose}
              className="w-7 h-7 rounded-lg flex items-center justify-center"
              style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)' }}>×</button>
          </div>
          <div className="p-6 space-y-4">
            <div className="p-3 rounded-xl text-sm"
              style={{ background: isDangerous ? 'rgba(239,68,68,0.08)' : 'rgba(245,158,11,0.08)',
                border: `1px solid ${isDangerous ? 'rgba(239,68,68,0.2)' : 'rgba(245,158,11,0.2)'}`,
                color: 'var(--text-secondary)' }}>
              <ActionIcon action={policy.action} />
              <strong className="text-white">{policy.name}</strong>
              {isDangerous && (
                <span className="ml-2 text-xs text-red-400 font-bold">[DESTRUCTIVE]</span>
              )}
            </div>
            <div>
              <label className="block text-xs font-semibold mb-1.5" style={{ color: 'var(--text-muted)' }}>Agent ID *</label>
              <input value={agentId} onChange={e => setAgentId(e.target.value)}
                className="w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none font-mono"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}
                placeholder="agent UUID" />
            </div>
            <div>
              <label className="block text-xs font-semibold mb-1.5" style={{ color: 'var(--text-muted)' }}>Source IP (optional)</label>
              <input value={srcIp} onChange={e => setSrcIp(e.target.value)}
                className="w-full rounded-xl px-3 py-2.5 text-sm text-white outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}
                placeholder="1.2.3.4" />
            </div>
            <div className="flex gap-3">
              <button onClick={onClose}
                className="flex-1 py-2.5 rounded-xl text-sm font-semibold"
                style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)', border: '1px solid var(--border-color)' }}>
                Cancel
              </button>
              <button onClick={handleTrigger} disabled={loading || !agentId.trim()}
                className="flex-1 py-2.5 rounded-xl text-sm font-semibold text-white"
                style={{ background: isDangerous ? 'linear-gradient(135deg,#ef4444,#dc2626)' : 'linear-gradient(135deg,#f59e0b,#d97706)',
                  opacity: (loading || !agentId.trim()) ? 0.5 : 1 }}>
                {loading ? 'Queuing…' : 'Execute Now'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {confirm && (
        <ConfirmModal
          title="Confirm Destructive Action"
          message={`You are about to execute "${policy.name}" (${policy.action}) on agent ${agentId.slice(0, 12)}…. This action cannot be undone.`}
          confirmLabel="Execute"
          danger
          onConfirm={() => { setConfirm(false); doTrigger() }}
          onCancel={() => setConfirm(false)}
        />
      )}
    </>
  )
}

// ── Execution Detail slide-over ───────────────────────────────────────────────

function ExecutionDetail({ execution, onClose, onRetry, onCancel }) {
  if (!execution) return null
  const st = STATUS_STYLE[execution.status] || STATUS_STYLE.pending
  const canRetry  = execution.status === 'failed' || execution.status === 'timeout'
  const canCancel = execution.status === 'pending'

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-end p-0 sm:p-4"
      style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="w-full sm:max-w-md h-full sm:h-auto sm:rounded-2xl overflow-y-auto"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', boxShadow: '-8px 0 60px rgba(0,0,0,0.5)' }}>

        <div className="flex items-center justify-between px-6 py-4 sticky top-0"
          style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
          <h3 className="font-bold text-white">Execution #{execution.id}</h3>
          <button onClick={onClose}
            className="w-7 h-7 rounded-lg flex items-center justify-center"
            style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)' }}>×</button>
        </div>

        <div className="p-6 space-y-4">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge text={execution.status} color={st.color} bg={st.bg} />
            {execution.triggered_by && (
              <Badge text={execution.triggered_by}
                color={execution.triggered_by === 'manual' ? '#f59e0b' : '#6b7280'}
                bg={execution.triggered_by === 'manual' ? 'rgba(245,158,11,0.12)' : 'rgba(107,114,128,0.1)'} />
            )}
            {(execution.retry_count > 0) && (
              <Badge text={`retry #${execution.retry_count}`} color="#8b5cf6" bg="rgba(139,92,246,0.12)" />
            )}
          </div>

          {[
            ['Policy',    execution.policy_name || `#${execution.policy_id}`],
            ['Action',    <><ActionIcon action={execution.action} />{execution.action}</>],
            ['Agent ID',  execution.agent_id || '—'],
            ['Source IP', execution.src_ip   || '—'],
            ['Alert ID',  execution.alert_id  ? `#${execution.alert_id}` : '—'],
            ['Created',   fmtDatetime(execution.created_at)],
            ['Completed', fmtDatetime(execution.completed_at)],
          ].map(([k, v]) => (
            <div key={k} className="flex gap-2">
              <span className="text-xs font-semibold w-24 flex-shrink-0 pt-0.5"
                style={{ color: 'var(--text-muted)' }}>{k}</span>
              <span className="text-sm text-white font-mono break-all">{v}</span>
            </div>
          ))}

          {execution.action_params && Object.keys(execution.action_params).length > 0 && (
            <div>
              <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-muted)' }}>Action Params</p>
              <pre className="text-xs p-3 rounded-xl overflow-x-auto"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)',
                  border: '1px solid var(--border-color)' }}>
                {JSON.stringify(execution.action_params, null, 2)}
              </pre>
            </div>
          )}

          {execution.result && (
            <div>
              <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-muted)' }}>Result</p>
              <pre className="text-xs p-3 rounded-xl overflow-x-auto whitespace-pre-wrap"
                style={{ background: 'var(--bg-secondary)',
                  color: execution.status === 'success' ? '#10b981' : execution.status === 'failed' ? '#ef4444' : 'var(--text-secondary)',
                  border: '1px solid var(--border-color)' }}>
                {execution.result}
              </pre>
            </div>
          )}

          <div className="flex gap-3 pt-2">
            {canCancel && (
              <button onClick={() => onCancel(execution.id)}
                className="flex-1 py-2.5 rounded-xl text-sm font-semibold"
                style={{ background: 'rgba(107,114,128,0.12)', color: '#94a3b8', border: '1px solid rgba(107,114,128,0.2)' }}>
                Cancel
              </button>
            )}
            {canRetry && (
              <button onClick={() => onRetry(execution.id)}
                className="flex-1 py-2.5 rounded-xl text-sm font-semibold text-white"
                style={{ background: 'linear-gradient(135deg,#6366f1,#8b5cf6)' }}>
                Retry
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Stats tab ─────────────────────────────────────────────────────────────────

function StatsTab({ stats }) {
  if (!stats) return (
    <div className="flex items-center justify-center py-20 text-sm" style={{ color: 'var(--text-muted)' }}>
      Loading stats…
    </div>
  )

  const statusOrder = ['pending', 'sent', 'success', 'failed', 'timeout', 'cancelled']
  const byStatus = stats.by_status || {}
  const totalExec = Math.max(Object.values(byStatus).reduce((a, b) => a + b, 0), 1)

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Policies"    value={stats.total_policies}   color="#3b82f6" />
        <StatCard label="Enabled Policies"  value={stats.enabled_policies} color="#10b981" />
        <StatCard label="Executions (24h)"  value={stats.executions_today} color="#f59e0b" />
        <StatCard label="Success Rate"      value={`${stats.success_rate}%`} color="#8b5cf6"
          sub={`${byStatus.success || 0} ok / ${(byStatus.failed || 0) + (byStatus.timeout || 0)} fail`} />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="rounded-2xl p-5" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          <h3 className="text-sm font-bold text-white mb-4">Executions by Status</h3>
          <div className="space-y-2.5">
            {statusOrder.map(s => {
              const count = byStatus[s] || 0
              const pct   = Math.round(count / totalExec * 100)
              const st    = STATUS_STYLE[s] || STATUS_STYLE.pending
              return (
                <div key={s}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold capitalize" style={{ color: st.color }}>{s}</span>
                    <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{count}</span>
                  </div>
                  <div className="h-1.5 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
                    <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: st.color }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        <div className="rounded-2xl p-5" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          <h3 className="text-sm font-bold text-white mb-4">Top Policies (7 days)</h3>
          {stats.top_policies?.length > 0 ? (
            <div className="space-y-3">
              {stats.top_policies.map((p, i) => (
                <div key={i} className="flex items-center justify-between">
                  <span className="text-xs text-white truncate max-w-[180px]">{p.name}</span>
                  <span className="text-xs font-bold ml-2" style={{ color: '#3b82f6' }}>{p.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No executions yet</p>
          )}
        </div>
      </div>

      {Object.keys(stats.by_action || {}).length > 0 && (
        <div className="rounded-2xl p-5" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          <h3 className="text-sm font-bold text-white mb-4">Executions by Action Type</h3>
          <div className="grid grid-cols-4 gap-3">
            {Object.entries(stats.by_action).map(([action, count]) => {
              const opt = ACTION_OPTIONS.find(a => a.value === action)
              return (
                <div key={action} className="rounded-xl p-3 text-center" style={{ background: 'var(--bg-secondary)' }}>
                  <div className="text-xl mb-1">{opt?.icon || '⚡'}</div>
                  <div className="text-lg font-black text-white">{count}</div>
                  <div className="text-xs mt-0.5 truncate" style={{ color: 'var(--text-muted)' }}>{opt?.label || action}</div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {stats.daily_trend?.length > 0 && (
        <div className="rounded-2xl p-5" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          <h3 className="text-sm font-bold text-white mb-4">Daily Executions (7 days)</h3>
          <div className="flex items-end gap-2 h-20">
            {stats.daily_trend.map((d, i) => {
              const maxVal = Math.max(...stats.daily_trend.map(x => x.count), 1)
              const pct    = (d.count / maxVal) * 100
              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-1">
                  <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{d.count}</span>
                  <div className="w-full rounded-sm transition-all"
                    style={{ height: `${Math.max(pct, 4)}%`, background: '#3b82f6', minHeight: 4 }} />
                  <span className="text-xs" style={{ color: 'var(--text-muted)', fontSize: 9 }}>
                    {d.day.slice(5)}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Templates tab ─────────────────────────────────────────────────────────────

function TemplatesTab({ templates, onInstall }) {
  const byCategory = templates.reduce((acc, t) => {
    if (!acc[t.category]) acc[t.category] = []
    acc[t.category].push(t)
    return acc
  }, {})

  return (
    <div className="space-y-6">
      <div className="p-4 rounded-xl text-sm"
        style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)', color: 'var(--text-secondary)' }}>
        Click <strong className="text-white">Install</strong> to pre-fill the policy form. Customize before saving.
      </div>
      {Object.entries(byCategory).map(([cat, items]) => (
        <div key={cat}>
          <h3 className="text-xs font-bold uppercase tracking-widest mb-3"
            style={{ color: CATEGORY_COLORS[cat] || '#6b7280' }}>
            {cat}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {items.map(t => (
              <div key={t.id} className="rounded-2xl p-4 flex items-start gap-4"
                style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
                <div className="text-2xl flex-shrink-0 mt-0.5">{t.icon}</div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-bold text-white">{t.name}</p>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{t.description}</p>
                  <div className="flex items-center gap-2 mt-2 flex-wrap">
                    <Badge text={t.policy.action} color="#3b82f6" bg="rgba(59,130,246,0.12)" />
                    <Badge text={`cooldown ${t.policy.cooldown_seconds}s`} color="#6b7280" bg="rgba(107,114,128,0.12)" />
                  </div>
                </div>
                <button onClick={() => onInstall(t.policy)}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold flex-shrink-0"
                  style={{ background: 'rgba(16,185,129,0.12)', color: '#10b981', border: '1px solid rgba(16,185,129,0.2)' }}>
                  Install
                </button>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ActiveResponse() {
  const [policies,      setPolicies]      = useState([])
  const [executions,    setExecutions]    = useState([])
  const [execTotal,     setExecTotal]     = useState(0)
  const [execPages,     setExecPages]     = useState(1)
  const [stats,         setStats]         = useState(null)
  const [templates,     setTemplates]     = useState([])
  const [tab,           setTab]           = useState('policies')
  const [modalPolicy,   setModalPolicy]   = useState(null)
  const [showModal,     setShowModal]     = useState(false)
  const [triggerPolicy, setTriggerPolicy] = useState(null)
  const [detailExec,    setDetailExec]    = useState(null)
  const [execPage,      setExecPage]      = useState(1)
  const [filterStatus,  setFilterStatus]  = useState('')
  const [filterAction,  setFilterAction]  = useState('')
  const [policySearch,  setPolicySearch]  = useState('')
  const [selected,      setSelected]      = useState(new Set())
  const [toasts,        setToasts]        = useState([])
  const [confirmDelete, setConfirmDelete] = useState(null)
  const [toggling,      setToggling]      = useState(new Set())
  const refreshRef = useRef(null)
  const toastId    = useRef(0)

  const showToast = useCallback((msg, type = 'success') => {
    const id = ++toastId.current
    setToasts(prev => [...prev, { id, msg, type }])
    if (type !== 'error') {
      setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000)
    }
  }, [])

  const dismissToast = (id) => setToasts(prev => prev.filter(t => t.id !== id))

  // ── Data loaders ─────────────────────────────────────────────────────────

  const loadPolicies = useCallback(async () => {
    try {
      const r = await getARPolicies()
      setPolicies(r.data)
    } catch { /* silent — token refresh handles 401 */ }
  }, [])

  const loadExecutions = useCallback(async () => {
    try {
      const params = {
        page:   execPage,
        size:   50,
        status: filterStatus || undefined,
        action: filterAction || undefined,
      }
      const r = await getARExecutions(params)
      setExecutions(r.data.executions)
      setExecTotal(r.data.total)
      setExecPages(r.data.pages)
    } catch { /* silent */ }
  }, [execPage, filterStatus, filterAction])

  const loadStats = useCallback(async () => {
    try {
      const r = await getARStats()
      setStats(r.data)
    } catch { /* silent */ }
  }, [])

  const loadTemplates = useCallback(async () => {
    try {
      const r = await getARTemplates()
      setTemplates(r.data)
    } catch { /* silent */ }
  }, [])

  // ── Effects ───────────────────────────────────────────────────────────────

  useEffect(() => { loadPolicies(); loadStats(); loadTemplates() }, [loadPolicies, loadStats, loadTemplates])

  useEffect(() => {
    if (refreshRef.current) clearInterval(refreshRef.current)
    if (tab === 'history') {
      loadExecutions()
      refreshRef.current = setInterval(loadExecutions, 15000)
    } else if (tab === 'stats') {
      loadStats()
      refreshRef.current = setInterval(loadStats, 30000)
    } else if (tab === 'policies') {
      loadPolicies()
    }
    return () => { if (refreshRef.current) clearInterval(refreshRef.current) }
  }, [tab, loadExecutions, loadStats, loadPolicies])

  useEffect(() => {
    if (tab === 'history') loadExecutions()
  }, [execPage, filterStatus, filterAction]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Policy actions ────────────────────────────────────────────────────────

  const handleDeletePolicy = (policy) => setConfirmDelete(policy)

  const confirmDoDelete = async () => {
    const policy = confirmDelete
    setConfirmDelete(null)
    try {
      await deleteARPolicy(policy.id)
      showToast(`Policy "${policy.name}" deleted`)
      loadPolicies(); loadStats()
    } catch { showToast('Delete failed', 'error') }
  }

  const handleToggle = async (policy) => {
    if (toggling.has(policy.id)) return
    setToggling(prev => new Set(prev).add(policy.id))
    try {
      await updateARPolicy(policy.id, { enabled: !policy.enabled })
      showToast(policy.enabled ? 'Policy disabled' : 'Policy enabled')
      loadPolicies()
    } catch { showToast('Toggle failed', 'error') }
    finally { setToggling(prev => { const s = new Set(prev); s.delete(policy.id); return s }) }
  }

  const handleClone = async (policy) => {
    try {
      const r = await cloneARPolicy(policy.id)
      showToast(`Cloned as "${r.data.name}"`)
      loadPolicies()
    } catch (err) {
      showToast(err?.response?.data?.detail || 'Clone failed', 'error')
    }
  }

  const handleBulkToggle = async (enabled) => {
    if (!selected.size) return
    try {
      await bulkToggleARPolicies({ policy_ids: [...selected], enabled })
      showToast(`${selected.size} polic${selected.size > 1 ? 'ies' : 'y'} ${enabled ? 'enabled' : 'disabled'}`)
      setSelected(new Set())
      loadPolicies()
    } catch { showToast('Bulk toggle failed', 'error') }
  }

  const handleSaved = () => {
    setShowModal(false); setModalPolicy(null)
    showToast('Policy saved'); loadPolicies(); loadStats()
  }

  // ── Execution actions ─────────────────────────────────────────────────────

  const handleRetry = async (execId) => {
    try {
      await retryARExecution(execId)
      showToast('Execution re-queued')
      loadExecutions()
      setDetailExec(null)
    } catch (err) {
      showToast(err?.response?.data?.detail || 'Retry failed', 'error')
    }
  }

  const handleCancel = async (execId) => {
    try {
      await cancelARExecution(execId)
      showToast('Execution cancelled')
      loadExecutions()
      setDetailExec(null)
    } catch (err) {
      showToast(err?.response?.data?.detail || 'Cancel failed', 'error')
    }
  }

  const handleInstallTemplate = (policy) => {
    setModalPolicy({ ...policy, id: undefined })
    setShowModal(true)
    setTab('policies')
  }

  // ── Derived data ──────────────────────────────────────────────────────────

  const filteredPolicies = policies.filter(p =>
    !policySearch || p.name.toLowerCase().includes(policySearch.toLowerCase()) ||
    (p.description || '').toLowerCase().includes(policySearch.toLowerCase())
  )

  const allSelected   = filteredPolicies.length > 0 && filteredPolicies.every(p => selected.has(p.id))
  const someSelected  = selected.size > 0

  const TABS = [
    ['stats',     'Stats',   stats?.executions_today ?? null],
    ['policies',  'Policies', policies.length || null],
    ['history',   'History',  execTotal || null],
    ['templates', 'Templates', null],
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Active Response</h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Automated threat response — detect, contain, notify
          </p>
        </div>
        <button onClick={() => { setModalPolicy(null); setShowModal(true) }}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-white hover:opacity-80 transition-opacity"
          style={{ background: 'linear-gradient(135deg,#3b82f6,#8b5cf6)' }}>
          + New Policy
        </button>
      </div>

      {/* Quick stats strip */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Policies',   value: policies.length,                         color: '#3b82f6' },
          { label: 'Active Policies',  value: policies.filter(p => p.enabled).length,  color: '#10b981' },
          { label: 'Executions Today', value: stats?.executions_today ?? '—',          color: '#f59e0b' },
          { label: 'Success Rate',     value: stats ? `${stats.success_rate}%` : '—',  color: '#8b5cf6' },
        ].map(s => <StatCard key={s.label} {...s} />)}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-xl w-fit"
        style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
        {TABS.map(([v, l, badge]) => (
          <button key={v} onClick={() => setTab(v)}
            className="px-4 py-2 rounded-lg text-sm font-semibold transition-all flex items-center gap-1.5"
            style={{
              background: tab === v ? 'linear-gradient(135deg,#3b82f6,#8b5cf6)' : 'transparent',
              color: tab === v ? '#fff' : 'var(--text-secondary)',
            }}>
            {l}
            {badge != null && (
              <span className="text-xs px-1.5 py-0.5 rounded-full font-bold"
                style={{ background: tab === v ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.08)', minWidth: 20, textAlign: 'center' }}>
                {badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Stats ──────────────────────────────────────── */}
      {tab === 'stats' && <StatsTab stats={stats} />}

      {/* ── Templates ──────────────────────────────────── */}
      {tab === 'templates' && (
        templates.length > 0
          ? <TemplatesTab templates={templates} onInstall={handleInstallTemplate} />
          : <div className="flex items-center justify-center py-16 text-sm" style={{ color: 'var(--text-muted)' }}>Loading templates…</div>
      )}

      {/* ── Policies ───────────────────────────────────── */}
      {tab === 'policies' && (
        <div className="space-y-3">
          {/* Toolbar */}
          <div className="flex items-center gap-3">
            <input
              value={policySearch} onChange={e => setPolicySearch(e.target.value)}
              placeholder="Search policies…"
              className="rounded-xl px-3 py-2 text-sm text-white outline-none flex-1 max-w-xs"
              style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }} />

            {someSelected && (
              <div className="flex items-center gap-2 ml-auto">
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{selected.size} selected</span>
                <button onClick={() => handleBulkToggle(true)}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold"
                  style={{ background: 'rgba(16,185,129,0.12)', color: '#10b981', border: '1px solid rgba(16,185,129,0.2)' }}>
                  Enable all
                </button>
                <button onClick={() => handleBulkToggle(false)}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold"
                  style={{ background: 'rgba(107,114,128,0.12)', color: '#6b7280', border: '1px solid rgba(107,114,128,0.2)' }}>
                  Disable all
                </button>
              </div>
            )}
          </div>

          <div className="rounded-2xl overflow-hidden"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            {filteredPolicies.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <span className="text-4xl">⚡</span>
                <p className="text-sm font-semibold text-white">
                  {policySearch ? 'No matching policies' : 'No policies yet'}
                </p>
                {!policySearch && (
                  <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    Create a policy or install one from Templates
                  </p>
                )}
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
                    <th className="px-4 py-3 w-8">
                      <input type="checkbox" checked={allSelected}
                        onChange={e => setSelected(e.target.checked ? new Set(filteredPolicies.map(p => p.id)) : new Set())}
                        className="rounded" />
                    </th>
                    {['On', 'Policy', 'Trigger', 'Action', 'Cooldown', ''].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider"
                        style={{ color: 'var(--text-muted)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredPolicies.map((p, i) => {
                    const actionOpt = ACTION_OPTIONS.find(a => a.value === p.action)
                    const triggerLabel = p.trigger_on === 'severity'  ? p.trigger_severity :
                                         p.trigger_on === 'rule_name' ? p.trigger_rule :
                                         p.trigger_on === 'category'  ? p.trigger_category :
                                         p.trigger_on === 'src_ip'    ? 'Has src IP' : 'Any'
                    const isSelected = selected.has(p.id)
                    return (
                      <tr key={p.id}
                        style={{
                          borderBottom: i < filteredPolicies.length - 1 ? '1px solid var(--border-color)' : 'none',
                          background: isSelected ? 'rgba(59,130,246,0.05)' : 'transparent',
                        }}>
                        <td className="px-4 py-3">
                          <input type="checkbox" checked={isSelected}
                            onChange={e => {
                              const s = new Set(selected)
                              e.target.checked ? s.add(p.id) : s.delete(p.id)
                              setSelected(s)
                            }} className="rounded" />
                        </td>
                        <td className="px-4 py-3">
                          <Toggle checked={p.enabled} onChange={() => handleToggle(p)} disabled={toggling.has(p.id)} />
                        </td>
                        <td className="px-4 py-3">
                          <p className="font-semibold text-white">{p.name}</p>
                          {p.description && (
                            <p className="text-xs mt-0.5 truncate max-w-xs" style={{ color: 'var(--text-muted)' }}>
                              {p.description}
                            </p>
                          )}
                          {p.target_agent && (
                            <p className="text-xs mt-0.5 font-mono" style={{ color: '#8b5cf6' }}>
                              ↳ {p.target_agent.slice(0, 12)}…
                            </p>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{triggerLabel}</span>
                          {p.action_params?.trigger_min_level && (
                            <span className="ml-1 text-xs" style={{ color: '#f59e0b' }}>
                              (lv≥{p.action_params.trigger_min_level})
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-medium text-white">
                            {actionOpt?.icon} {actionOpt?.label || p.action}
                          </span>
                          {actionOpt?.danger && (
                            <span className="ml-1 text-xs" style={{ color: '#ef4444' }}>⚠</span>
                          )}
                          {p.action_params?.unblock_after > 0 && (
                            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                              auto-unblock {p.action_params.unblock_after >= 3600
                                ? `${p.action_params.unblock_after / 3600}h`
                                : `${p.action_params.unblock_after / 60}m`}
                            </p>
                          )}
                          {p.max_per_hour && (
                            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                              cap: {p.max_per_hour}/h
                            </p>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                          {p.cooldown_seconds}s
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1">
                            <button onClick={() => setTriggerPolicy(p)}
                              className="px-2 py-1.5 rounded-lg text-xs font-semibold"
                              style={{ background: 'rgba(245,158,11,0.12)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.2)' }}>
                              Run
                            </button>
                            <button onClick={() => { setModalPolicy(p); setShowModal(true) }}
                              className="px-2 py-1.5 rounded-lg text-xs font-semibold"
                              style={{ background: 'rgba(59,130,246,0.12)', color: '#3b82f6', border: '1px solid rgba(59,130,246,0.2)' }}>
                              Edit
                            </button>
                            <button onClick={() => handleClone(p)}
                              className="px-2 py-1.5 rounded-lg text-xs font-semibold"
                              style={{ background: 'rgba(139,92,246,0.12)', color: '#8b5cf6', border: '1px solid rgba(139,92,246,0.2)' }}>
                              Clone
                            </button>
                            <button onClick={() => handleDeletePolicy(p)}
                              className="px-2 py-1.5 rounded-lg text-xs font-semibold"
                              style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }}>
                              Del
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
        </div>
      )}

      {/* ── Execution History ──────────────────────────── */}
      {tab === 'history' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <select value={filterStatus} onChange={e => { setFilterStatus(e.target.value); setExecPage(1) }}
              className="rounded-xl px-3 py-2 text-sm text-white outline-none"
              style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
              <option value="">All statuses</option>
              {Object.keys(STATUS_STYLE).map(s => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>

            <select value={filterAction} onChange={e => { setFilterAction(e.target.value); setExecPage(1) }}
              className="rounded-xl px-3 py-2 text-sm text-white outline-none"
              style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
              <option value="">All actions</option>
              {ACTION_OPTIONS.map(a => (
                <option key={a.value} value={a.value}>{a.icon} {a.label}</option>
              ))}
            </select>

            <button onClick={loadExecutions}
              className="px-3 py-2 rounded-xl text-xs font-semibold"
              style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
              Refresh
            </button>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Auto-refreshes every 15s</span>
            <span className="text-xs ml-auto" style={{ color: 'var(--text-muted)' }}>
              {execTotal} total
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
                    {['Time', 'Policy', 'Action', 'Agent', 'Source IP', 'Status', 'Result'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider"
                        style={{ color: 'var(--text-muted)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {executions.map((ex, i) => {
                    const st = STATUS_STYLE[ex.status] || STATUS_STYLE.pending
                    return (
                      <tr key={ex.id}
                        onClick={() => setDetailExec(ex)}
                        className="cursor-pointer hover:bg-white/5 transition-colors"
                        style={{ borderBottom: i < executions.length - 1 ? '1px solid var(--border-color)' : 'none' }}>
                        <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}
                          title={fmtDatetime(ex.created_at)}>
                          {timeAgo(ex.created_at)}
                        </td>
                        <td className="px-4 py-3 text-xs font-medium text-white max-w-[130px] truncate"
                          title={ex.policy_name || ''}>
                          {ex.policy_name || `Policy #${ex.policy_id}`}
                          {ex.triggered_by === 'manual' && (
                            <span className="ml-1 text-xs" style={{ color: '#f59e0b' }}>M</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-white whitespace-nowrap">
                          <ActionIcon action={ex.action} />{ex.action}
                        </td>
                        <td className="px-4 py-3 text-xs font-mono max-w-[90px] truncate"
                          style={{ color: 'var(--text-muted)' }}
                          title={ex.agent_id || ''}>
                          {ex.agent_id ? ex.agent_id.slice(0, 8) + '…' : '—'}
                        </td>
                        <td className="px-4 py-3 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                          {ex.src_ip || '—'}
                        </td>
                        <td className="px-4 py-3">
                          <Badge text={ex.status} color={st.color} bg={st.bg} />
                        </td>
                        <td className="px-4 py-3 text-xs max-w-[160px] truncate"
                          style={{ color: 'var(--text-muted)' }}
                          title={ex.result || ''}>
                          {truncate(ex.result, 60) || '—'}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>

          {execPages > 1 && (
            <div className="flex items-center justify-center gap-3 pt-2">
              <button disabled={execPage === 1} onClick={() => setExecPage(p => p - 1)}
                className="px-4 py-2 rounded-xl text-xs font-semibold disabled:opacity-40"
                style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
                Previous
              </button>
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {execPage} / {execPages}
              </span>
              <button disabled={execPage >= execPages} onClick={() => setExecPage(p => p + 1)}
                className="px-4 py-2 rounded-xl text-xs font-semibold disabled:opacity-40"
                style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
                Next
              </button>
            </div>
          )}
        </div>
      )}

      {/* ── Modals ───────────────────────────────────────── */}
      {showModal && (
        <PolicyModal
          policy={modalPolicy?.id ? modalPolicy : (modalPolicy ? { ...modalPolicy, id: undefined } : null)}
          onClose={() => { setShowModal(false); setModalPolicy(null) }}
          onSaved={handleSaved}
        />
      )}

      {triggerPolicy && (
        <TriggerModal
          policy={triggerPolicy}
          onClose={() => setTriggerPolicy(null)}
          showToast={showToast}
        />
      )}

      {detailExec && (
        <ExecutionDetail
          execution={detailExec}
          onClose={() => setDetailExec(null)}
          onRetry={handleRetry}
          onCancel={handleCancel}
        />
      )}

      {confirmDelete && (
        <ConfirmModal
          title="Delete Policy"
          message={`Delete "${confirmDelete.name}"? All associated execution history will be preserved.`}
          confirmLabel="Delete"
          danger
          onConfirm={confirmDoDelete}
          onCancel={() => setConfirmDelete(null)}
        />
      )}

      {/* ── Toast stack ──────────────────────────────────── */}
      <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2" style={{ maxWidth: 340 }}>
        {toasts.map(toast => (
          <div key={toast.id}
            className="flex items-start gap-3 px-4 py-3 rounded-xl text-sm font-medium"
            style={{
              background: toast.type === 'error' ? 'rgba(239,68,68,0.95)' : 'rgba(16,185,129,0.95)',
              border: '1px solid rgba(255,255,255,0.1)',
              color: '#fff',
              boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
              animation: 'slideIn 0.2s ease',
            }}>
            <span className="flex-shrink-0">{toast.type === 'error' ? '✕' : '✓'}</span>
            <span className="flex-1">{toast.msg}</span>
            <button onClick={() => dismissToast(toast.id)} className="flex-shrink-0 opacity-70 hover:opacity-100">×</button>
          </div>
        ))}
      </div>
    </div>
  )
}
