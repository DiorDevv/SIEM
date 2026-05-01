import React, { useState, useEffect, useCallback } from 'react'

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

const TYPE_CFG = {
  threshold:   { label: 'Threshold',   color: '#6366f1', desc: 'N events within time window' },
  sequence:    { label: 'Sequence',    color: '#f97316', desc: 'Event A followed by Event B' },
  aggregation: { label: 'Aggregation', color: '#10b981', desc: 'Field aggregate threshold' },
}

function SevBadge({ sev }) {
  const c = SEV_CFG[sev] || SEV_CFG.HIGH
  return <span style={{ color: c.color, background: c.bg, padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700 }}>{sev}</span>
}

function TypeBadge({ type }) {
  const c = TYPE_CFG[type] || TYPE_CFG.threshold
  return <span style={{ color: c.color, background: c.color + '22', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700 }}>{c.label}</span>
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

function fmtWindow(s) {
  if (!s) return '?'
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.round(s/60)}m`
  return `${Math.round(s/3600)}h`
}

// ── Condition Builder ─────────────────────────────────────────────────────────
const FIELD_OPTIONS_LOGS = [
  { value: 'message__contains', label: 'Message contains' },
  { value: 'level',             label: 'Log level =' },
  { value: 'source__contains',  label: 'Source contains' },
  { value: 'agent_id',          label: 'Agent ID =' },
]
const FIELD_OPTIONS_ALERTS = [
  { value: 'title__contains',    label: 'Title contains' },
  { value: 'rule_name__contains',label: 'Rule name contains' },
  { value: 'severity',           label: 'Severity =' },
  { value: 'agent_id',           label: 'Agent ID =' },
  { value: 'status',             label: 'Status =' },
]
const GROUP_OPTIONS_LOGS   = ['agent_id','source','level']
const GROUP_OPTIONS_ALERTS = ['agent_id','src_ip','agent_hostname','rule_name']

function ConditionBuilder({ value, onChange, ruleType }) {
  const cond = value || { source: 'logs', filters: {}, group_by: 'agent_id', steps: [] }
  const isSeq = ruleType === 'sequence'

  const setField = (key, val) => onChange({ ...cond, [key]: val })
  const fieldOpts = cond.source === 'alerts' ? FIELD_OPTIONS_ALERTS : FIELD_OPTIONS_LOGS
  const groupOpts = cond.source === 'alerts' ? GROUP_OPTIONS_ALERTS : GROUP_OPTIONS_LOGS

  // Filter rows
  const filters = Object.entries(cond.filters || {})
  const addFilter = () => {
    const first = fieldOpts[0].value
    setField('filters', { ...cond.filters, [first + '_' + Date.now()]: '' })
  }
  const updateFilter = (oldKey, newKey, val) => {
    const f = { ...cond.filters }
    delete f[oldKey]
    f[newKey] = val
    setField('filters', f)
  }
  const removeFilter = (key) => {
    const f = { ...cond.filters }
    delete f[key]
    setField('filters', f)
  }

  // Sequence steps
  const steps = cond.steps || [{filters:{}},{filters:{}}]
  const updateStep = (i, filters) => {
    const s = [...steps]
    s[i] = { ...s[i], filters }
    setField('steps', s)
  }

  const inp = { background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '6px 10px', fontSize: 12 }
  const lbl = { fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 3 }

  return (
    <div style={{ background: 'var(--bg)', borderRadius: 8, padding: 14, border: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
        <div style={{ flex: 1 }}>
          <label style={lbl}>Data Source</label>
          <select value={cond.source || 'logs'} onChange={e => setField('source', e.target.value)} style={inp}>
            <option value="logs">Logs</option>
            <option value="alerts">Alerts</option>
          </select>
        </div>
        {!isSeq && (
          <div style={{ flex: 1 }}>
            <label style={lbl}>Group By</label>
            <select value={cond.group_by || 'agent_id'} onChange={e => setField('group_by', e.target.value)} style={inp}>
              {groupOpts.map(o => <option key={o} value={o}>{o}</option>)}
            </select>
          </div>
        )}
      </div>

      {!isSeq ? (
        <div>
          <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 6, fontWeight: 600 }}>FILTERS</div>
          {filters.map(([k, v]) => (
            <div key={k} style={{ display: 'flex', gap: 8, marginBottom: 6, alignItems: 'center' }}>
              <select
                value={k.replace(/_\d+$/, '')}
                onChange={e => updateFilter(k, e.target.value, v)}
                style={{ ...inp, flex: 1 }}
              >
                {fieldOpts.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              <input
                value={v}
                onChange={e => updateFilter(k, k.replace(/_\d+$/, ''), e.target.value)}
                placeholder="value"
                style={{ ...inp, flex: 1 }}
              />
              <button onClick={() => removeFilter(k)} style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: 16 }}>×</button>
            </div>
          ))}
          <button onClick={addFilter} style={{ background: 'none', border: '1px dashed var(--border)', color: 'var(--muted)', borderRadius: 6, padding: '4px 12px', cursor: 'pointer', fontSize: 12, marginTop: 2 }}>
            + Add filter
          </button>
        </div>
      ) : (
        <div>
          {/* Sequence steps */}
          {[0, 1].map(i => (
            <div key={i} style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: TYPE_CFG.sequence.color, fontWeight: 700, marginBottom: 6 }}>
                STEP {i + 1} {i === 0 ? '(First Event)' : '(Then Event)'}
              </div>
              {Object.entries(steps[i]?.filters || {}).map(([k, v]) => (
                <div key={k} style={{ display: 'flex', gap: 8, marginBottom: 6, alignItems: 'center' }}>
                  <select value={k.replace(/_\d+$/, '')} onChange={e => { const f = {...(steps[i]?.filters||{})}; delete f[k]; f[e.target.value] = v; updateStep(i, f) }} style={{ ...inp, flex: 1 }}>
                    {FIELD_OPTIONS_ALERTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                  <input value={v} onChange={e => { const f = {...(steps[i]?.filters||{})}; f[k] = e.target.value; updateStep(i, f) }} placeholder="value" style={{ ...inp, flex: 1 }} />
                  <button onClick={() => { const f = {...(steps[i]?.filters||{})}; delete f[k]; updateStep(i, f) }} style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: 16 }}>×</button>
                </div>
              ))}
              <button onClick={() => { const f = {...(steps[i]?.filters||{})}; f['title__contains_' + Date.now()] = ''; updateStep(i, f) }} style={{ background: 'none', border: '1px dashed var(--border)', color: 'var(--muted)', borderRadius: 6, padding: '4px 12px', cursor: 'pointer', fontSize: 12 }}>
                + Add filter
              </button>
            </div>
          ))}
          <div style={{ marginTop: 8 }}>
            <label style={lbl}>Group By</label>
            <select value={cond.group_by || 'agent_id'} onChange={e => setField('group_by', e.target.value)} style={inp}>
              {GROUP_OPTIONS_ALERTS.map(o => <option key={o} value={o}>{o}</option>)}
            </select>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Rule Modal ────────────────────────────────────────────────────────────────
function RuleModal({ rule, onClose, onSaved }) {
  const isEdit = !!rule
  const [form, setForm] = useState({
    name: rule?.name || '',
    description: rule?.description || '',
    rule_type: rule?.rule_type || 'threshold',
    severity: rule?.severity || 'HIGH',
    threshold_count: rule?.threshold_count || 5,
    time_window_seconds: rule?.time_window_seconds || 300,
    cooldown_seconds: rule?.cooldown_seconds || 300,
    conditions: rule?.conditions || { source: 'logs', filters: {}, group_by: 'agent_id' },
    alert_title_template: rule?.alert_title_template || '',
    mitre_tactics: (rule?.mitre_tactics || []).join(', '),
    mitre_techniques: (rule?.mitre_techniques || []).join(', '),
    enabled: rule?.enabled ?? true,
  })
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  const save = async () => {
    if (!form.name.trim()) return
    setLoading(true); setErr('')
    const payload = {
      ...form,
      threshold_count: Number(form.threshold_count),
      time_window_seconds: Number(form.time_window_seconds),
      cooldown_seconds: Number(form.cooldown_seconds),
      mitre_tactics: form.mitre_tactics ? form.mitre_tactics.split(',').map(t => t.trim()).filter(Boolean) : [],
      mitre_techniques: form.mitre_techniques ? form.mitre_techniques.split(',').map(t => t.trim()).filter(Boolean) : [],
    }
    try {
      if (isEdit) {
        await api(`/api/correlation/rules/${rule.id}`, { method: 'PUT', body: JSON.stringify(payload) })
      } else {
        await api('/api/correlation/rules', { method: 'POST', body: JSON.stringify(payload) })
      }
      onSaved(); onClose()
    } catch (e) { setErr(String(e)) }
    finally { setLoading(false) }
  }

  const inp = { background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '8px 10px', fontSize: 13, width: '100%', boxSizing: 'border-box' }
  const lbl = { fontSize: 12, color: 'var(--muted)', marginBottom: 4, display: 'block' }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
      <div style={{ background: 'var(--card)', borderRadius: 12, padding: 24, width: 580, maxHeight: '92vh', overflowY: 'auto' }}>
        <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 20 }}>{isEdit ? 'Edit Rule' : 'New Correlation Rule'}</div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
          <div style={{ gridColumn: '1 / -1' }}>
            <label style={lbl}>Name *</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="SSH Brute Force Detection" style={inp} />
          </div>

          <div>
            <label style={lbl}>Rule Type</label>
            <select value={form.rule_type} onChange={e => setForm(f => ({ ...f, rule_type: e.target.value }))} style={inp}>
              {Object.entries(TYPE_CFG).map(([v, c]) => <option key={v} value={v}>{c.label} — {c.desc}</option>)}
            </select>
          </div>

          <div>
            <label style={lbl}>Severity</label>
            <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} style={inp}>
              {['LOW','MEDIUM','HIGH','CRITICAL'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>

          {form.rule_type !== 'sequence' && (
            <>
              <div>
                <label style={lbl}>Threshold Count</label>
                <input type="number" min="1" value={form.threshold_count} onChange={e => setForm(f => ({ ...f, threshold_count: e.target.value }))} style={inp} />
              </div>
              <div>
                <label style={lbl}>Time Window (seconds)</label>
                <input type="number" min="10" value={form.time_window_seconds} onChange={e => setForm(f => ({ ...f, time_window_seconds: e.target.value }))} style={inp} />
              </div>
            </>
          )}
          {form.rule_type === 'sequence' && (
            <div>
              <label style={lbl}>Sequence Window (seconds)</label>
              <input type="number" min="10" value={form.time_window_seconds} onChange={e => setForm(f => ({ ...f, time_window_seconds: e.target.value }))} style={inp} />
            </div>
          )}

          <div>
            <label style={lbl}>Cooldown (seconds)</label>
            <input type="number" min="0" value={form.cooldown_seconds} onChange={e => setForm(f => ({ ...f, cooldown_seconds: e.target.value }))} style={inp} />
          </div>

          <div style={{ gridColumn: '1 / -1' }}>
            <label style={lbl}>Conditions</label>
            <ConditionBuilder
              value={form.conditions}
              onChange={c => setForm(f => ({ ...f, conditions: c }))}
              ruleType={form.rule_type}
            />
          </div>

          <div style={{ gridColumn: '1 / -1' }}>
            <label style={lbl}>Alert Title Template <span style={{ color: 'var(--muted)', fontWeight: 400 }}>(vars: {'{rule_name}'}, {'{count}'}, {'{window}'}, {'{group_value}'})</span></label>
            <input value={form.alert_title_template} onChange={e => setForm(f => ({ ...f, alert_title_template: e.target.value }))} placeholder="{rule_name}: {count} events in {window}s from {group_value}" style={inp} />
          </div>

          <div>
            <label style={lbl}>MITRE Tactics (comma sep.)</label>
            <input value={form.mitre_tactics} onChange={e => setForm(f => ({ ...f, mitre_tactics: e.target.value }))} placeholder="Credential Access, Lateral Movement" style={inp} />
          </div>

          <div>
            <label style={lbl}>MITRE Techniques (comma sep.)</label>
            <input value={form.mitre_techniques} onChange={e => setForm(f => ({ ...f, mitre_techniques: e.target.value }))} placeholder="T1110, T1046" style={inp} />
          </div>

          <div style={{ gridColumn: '1 / -1' }}>
            <label style={lbl}>Description</label>
            <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} rows={2} style={{ ...inp, resize: 'vertical' }} />
          </div>

          <div style={{ gridColumn: '1 / -1', display: 'flex', alignItems: 'center', gap: 8 }}>
            <input type="checkbox" id="enabled" checked={form.enabled} onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} />
            <label htmlFor="enabled" style={{ fontSize: 13, cursor: 'pointer' }}>Enabled</label>
          </div>
        </div>

        {err && <div style={{ color: '#ef4444', fontSize: 13, marginTop: 10 }}>{err}</div>}

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 20 }}>
          <button onClick={onClose} style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', fontSize: 13 }}>Cancel</button>
          <button onClick={save} disabled={loading || !form.name.trim()} style={{ background: '#6366f1', color: '#fff', border: 'none', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', fontWeight: 700, fontSize: 13, opacity: loading ? 0.6 : 1 }}>
            {loading ? 'Saving…' : isEdit ? 'Update Rule' : 'Create Rule'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function CorrelationRules() {
  const [stats, setStats] = useState(null)
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editRule, setEditRule] = useState(null)
  const [testResult, setTestResult] = useState(null)
  const [testLoading, setTestLoading] = useState(null)
  const [filterType, setFilterType] = useState('')
  const [filterEnabled, setFilterEnabled] = useState('')

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const [s, r] = await Promise.all([
        api('/api/correlation/stats'),
        api(`/api/correlation/rules${filterType ? `?rule_type=${filterType}` : ''}${filterEnabled !== '' ? `${filterType ? '&' : '?'}enabled=${filterEnabled}` : ''}`),
      ])
      setStats(s)
      setRules(r || [])
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [filterType, filterEnabled])

  useEffect(() => { loadData() }, [loadData])

  const deleteRule = async (id) => {
    if (!confirm('Delete this correlation rule?')) return
    await api(`/api/correlation/rules/${id}`, { method: 'DELETE' })
    loadData()
  }

  const toggleRule = async (id) => {
    await api(`/api/correlation/rules/${id}/toggle`, { method: 'POST' })
    loadData()
  }

  const testRule = async (id) => {
    setTestLoading(id); setTestResult(null)
    try {
      const r = await api(`/api/correlation/rules/${id}/test`, { method: 'POST' })
      setTestResult(r)
    } catch (e) { alert(String(e)) }
    finally { setTestLoading(null) }
  }

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800 }}>Correlation Rules</h2>
          <div style={{ color: 'var(--muted)', fontSize: 13, marginTop: 2 }}>Multi-event detection · Brute force · Attack sequences · Alert storms</div>
        </div>
        <button
          onClick={() => { setEditRule(null); setShowModal(true) }}
          style={{ background: '#6366f1', color: '#fff', border: 'none', borderRadius: 8, padding: '8px 18px', cursor: 'pointer', fontWeight: 700, fontSize: 13 }}
        >
          + New Rule
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 20 }}>
          <StatCard label="Total Rules"    value={stats.total}            color="#6366f1" />
          <StatCard label="Active"         value={stats.enabled}          color="#10b981" />
          <StatCard label="Disabled"       value={stats.disabled}         color="#6b7280" />
          <StatCard label="Total Triggers" value={stats.total_triggers}   color="#f97316" />
          <StatCard label="Alerts (24h)"   value={stats.recent_alerts_24h} color="#ef4444" sub="correlated" />
        </div>
      )}

      {/* Top rules */}
      {stats?.top_rules?.length > 0 && (
        <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 10, padding: 16, marginBottom: 20 }}>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 12, color: 'var(--muted)' }}>MOST ACTIVE RULES</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {stats.top_rules.map(r => (
              <div key={r.id} style={{ background: 'var(--bg)', borderRadius: 8, padding: '8px 14px', border: '1px solid var(--border)', minWidth: 160 }}>
                <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2 }}>{r.name}</div>
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>Triggered: <span style={{ color: '#f97316', fontWeight: 700 }}>{r.trigger_count}×</span></div>
                <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
                  {r.last_triggered ? `Last: ${new Date(r.last_triggered).toLocaleDateString()}` : 'Never triggered'}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Test result banner */}
      {testResult && (
        <div style={{ background: testResult.would_fire > 0 ? 'rgba(249,115,22,0.1)' : 'rgba(16,185,129,0.1)', border: `1px solid ${testResult.would_fire > 0 ? 'rgba(249,115,22,0.3)' : 'rgba(16,185,129,0.3)'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 16, fontSize: 13 }}>
          <div style={{ fontWeight: 700, marginBottom: 4 }}>
            Test: "{testResult.rule_name}" — would fire <span style={{ color: testResult.would_fire > 0 ? '#f97316' : '#10b981' }}>{testResult.would_fire}</span> alert(s)
          </div>
          {testResult.alerts.map((a, i) => (
            <div key={i} style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>• {a.title} ({a.severity})</div>
          ))}
          <button onClick={() => setTestResult(null)} style={{ float: 'right', background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer', fontSize: 16, marginTop: -24 }}>×</button>
        </div>
      )}

      {/* Filter bar + Table */}
      <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <select value={filterType} onChange={e => setFilterType(e.target.value)} style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}>
            <option value="">All Types</option>
            {Object.entries(TYPE_CFG).map(([v, c]) => <option key={v} value={v}>{c.label}</option>)}
          </select>
          <select value={filterEnabled} onChange={e => setFilterEnabled(e.target.value)} style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}>
            <option value="">All Status</option>
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </select>
          <span style={{ color: 'var(--muted)', fontSize: 13, marginLeft: 'auto' }}>{rules.length} rules</span>
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)' }}>Loading…</div>
        ) : rules.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)' }}>No correlation rules. Create your first rule.</div>
        ) : (
          <div>
            {rules.map(rule => (
              <div key={rule.id} style={{ borderTop: '1px solid var(--border)', padding: '14px 16px' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                  {/* Toggle */}
                  <button
                    onClick={() => toggleRule(rule.id)}
                    title={rule.enabled ? 'Disable' : 'Enable'}
                    style={{
                      width: 36, height: 20, borderRadius: 10, border: 'none', cursor: 'pointer',
                      background: rule.enabled ? '#10b981' : '#374151',
                      position: 'relative', flexShrink: 0, marginTop: 2,
                    }}
                  >
                    <span style={{
                      position: 'absolute', top: 2, left: rule.enabled ? 18 : 2,
                      width: 16, height: 16, borderRadius: '50%', background: '#fff',
                      transition: 'left 0.15s',
                    }} />
                  </button>

                  {/* Info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                      <span style={{ fontWeight: 700, fontSize: 14 }}>{rule.name}</span>
                      <TypeBadge type={rule.rule_type} />
                      <SevBadge sev={rule.severity} />
                      {!rule.enabled && <span style={{ color: '#6b7280', fontSize: 11, background: 'rgba(107,114,128,0.12)', padding: '2px 6px', borderRadius: 4 }}>DISABLED</span>}
                    </div>
                    {rule.description && <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 6 }}>{rule.description}</div>}
                    <div style={{ display: 'flex', gap: 16, fontSize: 12, color: 'var(--muted)', flexWrap: 'wrap' }}>
                      {rule.rule_type !== 'sequence' && (
                        <span>Threshold: <b style={{ color: 'var(--text)' }}>{rule.threshold_count}</b> events in <b style={{ color: 'var(--text)' }}>{fmtWindow(rule.time_window_seconds)}</b></span>
                      )}
                      {rule.rule_type === 'sequence' && (
                        <span>Sequence window: <b style={{ color: 'var(--text)' }}>{fmtWindow(rule.time_window_seconds)}</b></span>
                      )}
                      <span>Cooldown: <b style={{ color: 'var(--text)' }}>{fmtWindow(rule.cooldown_seconds)}</b></span>
                      <span>Source: <b style={{ color: 'var(--text)' }}>{rule.conditions?.source || 'logs'}</b></span>
                      {rule.conditions?.group_by && <span>Group by: <b style={{ color: 'var(--text)' }}>{rule.conditions.group_by}</b></span>}
                      <span style={{ color: rule.trigger_count > 0 ? '#f97316' : 'var(--muted)' }}>
                        Fired: <b>{rule.trigger_count}×</b>
                      </span>
                      {rule.last_triggered && <span>Last: {new Date(rule.last_triggered).toLocaleString()}</span>}
                    </div>
                    {rule.mitre_tactics?.length > 0 && (
                      <div style={{ marginTop: 6, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {rule.mitre_tactics.map(t => (
                          <span key={t} style={{ background: 'rgba(99,102,241,0.12)', color: '#6366f1', padding: '2px 6px', borderRadius: 4, fontSize: 11 }}>{t}</span>
                        ))}
                        {rule.mitre_techniques?.map(t => (
                          <span key={t} style={{ background: 'rgba(99,102,241,0.08)', color: '#818cf8', padding: '2px 6px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace' }}>{t}</span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                    <button
                      onClick={() => testRule(rule.id)}
                      disabled={testLoading === rule.id}
                      title="Dry-run test"
                      style={{ background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.3)', color: '#10b981', borderRadius: 6, padding: '4px 10px', cursor: 'pointer', fontSize: 12, opacity: testLoading === rule.id ? 0.6 : 1 }}
                    >
                      {testLoading === rule.id ? '⟳' : '▶ Test'}
                    </button>
                    <button
                      onClick={() => { setEditRule(rule); setShowModal(true) }}
                      title="Edit"
                      style={{ background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.3)', color: '#6366f1', borderRadius: 6, padding: '4px 10px', cursor: 'pointer', fontSize: 12 }}
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => deleteRule(rule.id)}
                      title="Delete"
                      style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444', borderRadius: 6, padding: '4px 10px', cursor: 'pointer', fontSize: 12 }}
                    >
                      ✕
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {showModal && (
        <RuleModal
          rule={editRule}
          onClose={() => { setShowModal(false); setEditRule(null) }}
          onSaved={loadData}
        />
      )}
    </div>
  )
}
