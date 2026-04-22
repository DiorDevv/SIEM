import React, { useState, useEffect, useCallback } from 'react'
import { getRules, createRule, updateRule, deleteRule } from '../api'
import { useLang } from '../context/LanguageContext'

const SEV = {
  CRITICAL: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',  border: 'rgba(239,68,68,0.3)' },
  HIGH:     { color: '#f97316', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.3)' },
  MEDIUM:   { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.3)' },
  LOW:      { color: '#3b82f6', bg: 'rgba(59,130,246,0.12)', border: 'rgba(59,130,246,0.3)' },
}
const EMPTY = { name: '', description: '', pattern: '', severity: 'MEDIUM', category: 'general', enabled: true, cooldown_seconds: 300 }

/* ── Rule form modal ──────────────────────────────────────── */
function RuleFormModal({ initial, onSave, onClose }) {
  const { t } = useLang()
  const isEdit = !!initial?.id
  const [form, setForm] = useState(initial || EMPTY)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }))
  const sev = SEV[form.severity] || SEV.MEDIUM

  const handleSave = async () => {
    if (!form.name.trim()) { setError(t('rules.nameRequired')); return }
    setSaving(true); setError('')
    try { await onSave(form); onClose() }
    catch (err) { setError(err?.response?.data?.detail || t('rules.saveFailed')) }
    setSaving(false)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in"
      style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(8px)' }}
      onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="w-full max-w-lg rounded-2xl overflow-hidden animate-slide-down"
        style={{ background: 'var(--bg-card)', border: `1px solid ${sev.border}`,
          boxShadow: `0 25px 60px rgba(0,0,0,0.7)` }}>

        {/* header */}
        <div className="relative px-6 py-5 overflow-hidden"
          style={{ background: `linear-gradient(135deg, var(--bg-secondary), ${sev.bg})`,
            borderBottom: `1px solid ${sev.border}` }}>
          <div className="absolute top-0 right-0 w-48 h-48 pointer-events-none"
            style={{ background: `radial-gradient(circle, ${sev.color}10, transparent 70%)`,
              transform: 'translate(30%,-30%)' }} />
          <div className="relative flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                style={{ background: sev.bg, border: `1px solid ${sev.border}` }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={sev.color} strokeWidth="2">
                  <path d="M9 11l3 3L22 4"/>
                  <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
                </svg>
              </div>
              <h2 className="font-black text-white">{isEdit ? t('rules.editRule') : t('rules.createRule')}</h2>
            </div>
            <button onClick={onClose} className="w-8 h-8 flex items-center justify-center rounded-xl text-lg"
              style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)' }}>×</button>
          </div>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-bold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
              {t('rules.name')} *
            </label>
            <input className="w-full" value={form.name} onChange={(e) => set('name', e.target.value)}
              placeholder="Brute Force Detection" />
          </div>
          <div>
            <label className="block text-xs font-bold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
              {t('rules.description')}
            </label>
            <textarea className="w-full h-16 resize-none" value={form.description}
              onChange={(e) => set('description', e.target.value)}
              placeholder="Describe what this rule detects..." />
          </div>
          <div>
            <label className="block text-xs font-bold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
              {t('rules.pattern')}
            </label>
            <div className="relative">
              <input className="w-full font-mono text-sm pr-24" value={form.pattern}
                onChange={(e) => set('pattern', e.target.value)}
                placeholder="Failed password|auth failure" />
              <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs px-2 py-0.5 rounded font-mono"
                style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc' }}>regex</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-bold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                {t('rules.severity')}
              </label>
              <select className="w-full" value={form.severity} onChange={(e) => set('severity', e.target.value)}>
                {['LOW','MEDIUM','HIGH','CRITICAL'].map((s) => (
                  <option key={s} value={s}>{t(`severity.${s}`)}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-bold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                {t('rules.category')}
              </label>
              <input className="w-full" value={form.category}
                onChange={(e) => set('category', e.target.value)} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-bold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                {t('rules.cooldown')} (s)
              </label>
              <input type="number" className="w-full" value={form.cooldown_seconds}
                onChange={(e) => set('cooldown_seconds', parseInt(e.target.value) || 60)} />
            </div>
            <div>
              <label className="block text-xs font-bold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                Status
              </label>
              <button type="button" onClick={() => set('enabled', !form.enabled)}
                className="flex items-center gap-3 w-full px-3 py-2 rounded-xl transition-all"
                style={{ background: form.enabled ? 'rgba(16,185,129,0.1)' : 'var(--bg-card-hover)',
                  border: `1px solid ${form.enabled ? 'rgba(16,185,129,0.3)' : 'var(--border-color)'}` }}>
                <div className="relative w-9 h-5 rounded-full transition-colors flex-shrink-0"
                  style={{ background: form.enabled ? '#10b981' : 'var(--border-light)' }}>
                  <div className="absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform"
                    style={{ transform: form.enabled ? 'translateX(18px)' : 'translateX(2px)' }} />
                </div>
                <span className="text-sm font-semibold"
                  style={{ color: form.enabled ? '#6ee7b7' : 'var(--text-secondary)' }}>
                  {form.enabled ? t('rules.enabled') : t('rules.disabled')}
                </span>
              </button>
            </div>
          </div>

          {error && (
            <div className="text-sm px-4 py-3 rounded-xl flex items-center gap-2"
              style={{ background: 'rgba(220,38,38,0.1)', color: '#fca5a5', border: '1px solid rgba(220,38,38,0.2)' }}>
              <span>⚠</span> {error}
            </div>
          )}
        </div>

        <div className="flex gap-3 px-6 pb-6">
          <button onClick={handleSave} disabled={saving}
            className="flex-1 py-2.5 rounded-xl text-sm font-bold transition-all"
            style={{ background: saving ? 'rgba(99,102,241,0.3)' : 'var(--accent)', color: '#fff',
              opacity: saving ? 0.7 : 1 }}>
            {saving ? `${t('rules.saving')}...` : t('rules.saveRule')}
          </button>
          <button onClick={onClose} className="btn-ghost flex-1 py-2.5 text-sm">
            {t('common.cancel')}
          </button>
        </div>
      </div>
    </div>
  )
}

/* ── Rule card ────────────────────────────────────────────── */
function RuleCard({ rule, onEdit, onToggle, onDelete, t }) {
  const sev = SEV[rule.severity] || SEV.MEDIUM
  return (
    <div className="rounded-2xl p-5 transition-all group"
      style={{ background: 'var(--bg-card)', border: `1px solid ${rule.enabled ? 'var(--border-color)' : 'var(--border-color)'}`,
        opacity: rule.enabled ? 1 : 0.6 }}>
      <div className="flex items-start justify-between mb-3 gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <div className="w-2 h-8 rounded-full flex-shrink-0" style={{ background: sev.color }} />
          <div className="min-w-0">
            <div className="font-bold text-white text-sm truncate">{rule.name}</div>
            {rule.description && (
              <div className="text-xs mt-0.5 truncate" style={{ color: 'var(--text-muted)' }}>
                {rule.description}
              </div>
            )}
          </div>
        </div>
        <button onClick={() => onToggle(rule)}
          className="relative w-9 h-5 rounded-full transition-colors flex-shrink-0 mt-0.5"
          style={{ background: rule.enabled ? '#10b981' : 'rgba(255,255,255,0.1)' }}>
          <div className="absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform"
            style={{ transform: rule.enabled ? 'translateX(18px)' : 'translateX(2px)' }} />
        </button>
      </div>

      {rule.pattern && (
        <div className="mb-3 px-3 py-2 rounded-xl font-mono text-xs truncate"
          style={{ background: '#060c17', color: '#86efac', border: '1px solid rgba(16,185,129,0.15)' }}>
          {rule.pattern}
        </div>
      )}

      <div className="flex flex-wrap gap-1.5 mb-3">
        <span className="text-xs px-2.5 py-0.5 rounded-full font-bold"
          style={{ background: sev.bg, color: sev.color, border: `1px solid ${sev.border}` }}>
          {t(`severity.${rule.severity}`)}
        </span>
        <span className="text-xs px-2.5 py-0.5 rounded-full font-medium capitalize"
          style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)', border: '1px solid var(--border-color)' }}>
          {rule.category}
        </span>
        {rule.mitre_tactic && (
          <span className="text-xs px-2.5 py-0.5 rounded-full font-medium"
            style={{ background: 'rgba(139,92,246,0.12)', color: '#c4b5fd', border: '1px solid rgba(139,92,246,0.25)' }}>
            {rule.mitre_tactic}
          </span>
        )}
        {rule.custom_logic && (
          <span className="text-xs px-2.5 py-0.5 rounded-full font-medium"
            style={{ background: 'rgba(59,130,246,0.12)', color: '#93c5fd', border: '1px solid rgba(59,130,246,0.25)' }}>
            {t('rules.builtIn')}
          </span>
        )}
      </div>

      <div className="flex items-center justify-between pt-3" style={{ borderTop: '1px solid var(--border-color)' }}>
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
          ⏱ {rule.cooldown_seconds}s cooldown
        </span>
        <div className="flex gap-1.5">
          <button onClick={() => onEdit(rule)}
            className="text-xs px-2.5 py-1.5 rounded-lg font-medium transition-all"
            style={{ background: 'rgba(59,130,246,0.1)', color: '#93c5fd', border: '1px solid rgba(59,130,246,0.2)' }}>
            {t('common.edit')}
          </button>
          {!rule.custom_logic && (
            <button onClick={() => onDelete(rule)}
              className="text-xs px-2.5 py-1.5 rounded-lg font-medium transition-all"
              style={{ background: 'rgba(239,68,68,0.08)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.15)' }}>
              {t('common.delete')}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════ */
export default function Rules() {
  const { t } = useLang()
  const [rules, setRules]         = useState([])
  const [loading, setLoading]     = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [editRule, setEditRule]   = useState(null)
  const [confirmDelete, setConfirmDelete] = useState(null)
  const [viewMode, setViewMode]   = useState('grid')
  const [search, setSearch]       = useState('')

  const fetchRules = useCallback(async () => {
    setLoading(true)
    try { const resp = await getRules(); setRules(resp.data) } catch {}
    setLoading(false)
  }, [])

  useEffect(() => { fetchRules() }, [fetchRules])

  const handleCreate = async (form) => { const r = await createRule(form); setRules((p) => [...p, r.data]) }
  const handleEdit   = async (form) => {
    const r = await updateRule(editRule.id, form)
    setRules((p) => p.map((x) => x.id === editRule.id ? r.data : x))
    setEditRule(null)
  }
  const handleToggle = async (rule) => {
    try {
      const r = await updateRule(rule.id, { enabled: !rule.enabled })
      setRules((p) => p.map((x) => x.id === rule.id ? r.data : x))
    } catch {}
  }
  const handleDelete = async (rule) => {
    try { await deleteRule(rule.id); setRules((p) => p.filter((x) => x.id !== rule.id)) } catch {}
    setConfirmDelete(null)
  }

  const enabled  = rules.filter((r) => r.enabled).length
  const disabled = rules.filter((r) => !r.enabled).length
  const byCrit   = rules.filter((r) => r.severity === 'CRITICAL').length
  const filtered = rules.filter((r) => !search ||
    r.name?.toLowerCase().includes(search.toLowerCase()) ||
    r.category?.toLowerCase().includes(search.toLowerCase()))

  return (
    <div className="space-y-5 animate-fade-in">

      {/* ── Banner ── */}
      <div className="page-header-banner relative rounded-2xl overflow-hidden p-6"
        style={{ background: 'linear-gradient(135deg, #0f172a, #111827, #0f172a)',
          border: '1px solid rgba(99,102,241,0.25)' }}>
        <div className="absolute top-0 right-0 w-72 h-72 pointer-events-none"
          style={{ background: 'radial-gradient(circle, rgba(99,102,241,0.1) 0%, transparent 70%)',
            transform: 'translate(25%,-25%)' }} />
        <div className="relative flex items-center justify-between flex-wrap gap-4">
          <div>
            <h2 className="text-2xl font-black text-white mb-1">{t('rules.title')}</h2>
            <p className="text-sm" style={{ color: 'rgba(148,163,184,0.7)' }}>{t('rules.subtitle')}</p>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => setShowCreate(true)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold transition-all"
              style={{ background: 'var(--accent)', color: '#fff', boxShadow: '0 0 20px rgba(99,102,241,0.3)' }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
              </svg>
              {t('rules.createNew')}
            </button>
            <div className="flex rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
              {[['grid', '⊞'], ['table', '☰']].map(([mode, icon]) => (
                <button key={mode} onClick={() => setViewMode(mode)}
                  className="px-3 py-2 text-sm transition-all"
                  style={{ background: viewMode === mode ? 'var(--accent)' : 'transparent',
                    color: viewMode === mode ? '#fff' : 'var(--text-muted)' }}>
                  {icon}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── Stats ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: t('common.count'),    value: rules.length, color: '#6366f1', icon: '⚙️' },
          { label: t('rules.enabled'),   value: enabled,      color: '#10b981', icon: '✅' },
          { label: t('rules.disabled'),  value: disabled,     color: '#6b7280', icon: '🔕' },
          { label: 'Critical Rules',     value: byCrit,       color: '#ef4444', icon: '🔴' },
        ].map(({ label, value, color, icon }) => (
          <div key={label} className="rounded-2xl p-5"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-lg">{icon}</span>
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background: `${color}15` }}>
                <div className="w-2 h-2 rounded-full" style={{ background: color }} />
              </div>
            </div>
            <div className="text-2xl font-black" style={{ color }}>{value}</div>
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{label}</div>
          </div>
        ))}
      </div>

      {/* ── Search ── */}
      <div className="relative">
        <svg className="absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" width="14" height="14"
          viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
          style={{ color: 'var(--text-muted)' }}>
          <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <input type="text" placeholder={`${t('common.search')} rules...`}
          value={search} onChange={(e) => setSearch(e.target.value)}
          className="w-full" style={{ paddingLeft: 40 }} />
      </div>

      {/* ── Content ── */}
      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-10 h-10 border-2 rounded-full animate-spin"
            style={{ borderColor: 'rgba(99,102,241,0.2)', borderTopColor: '#6366f1' }} />
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 gap-4" style={{ color: 'var(--text-muted)' }}>
          <div className="w-20 h-20 rounded-2xl flex items-center justify-center"
            style={{ background: 'var(--bg-card)' }}>
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="opacity-30">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>
            </svg>
          </div>
          <p className="text-sm font-medium">{t('rules.noRules')}</p>
          <button onClick={() => setShowCreate(true)}
            className="px-4 py-2 rounded-xl text-sm font-semibold"
            style={{ background: 'var(--accent)', color: '#fff' }}>
            + {t('rules.createNew')}
          </button>
        </div>
      ) : viewMode === 'grid' ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map((rule) => (
            <RuleCard key={rule.id} rule={rule} t={t}
              onEdit={setEditRule} onToggle={handleToggle} onDelete={setConfirmDelete} />
          ))}
        </div>
      ) : (
        <div className="rounded-2xl overflow-hidden"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
                  {[t('rules.name'), t('rules.pattern'), t('rules.severity'),
                    t('rules.category'), t('rules.cooldown'), t('rules.status'), t('rules.actions')].map((h) => (
                    <th key={h} className="text-left px-4 py-3.5 text-xs font-bold uppercase tracking-wider"
                      style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((rule) => {
                  const sev = SEV[rule.severity] || SEV.MEDIUM
                  return (
                    <tr key={rule.id} className="transition-all"
                      style={{ borderBottom: '1px solid var(--border-color)', opacity: rule.enabled ? 1 : 0.55 }}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-secondary)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}>
                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-2">
                          <div className="w-1.5 h-6 rounded-full" style={{ background: sev.color }} />
                          <div>
                            <div className="font-semibold text-white">{rule.name}</div>
                            {rule.mitre_tactic && (
                              <span className="text-xs px-1.5 py-0.5 rounded mt-0.5 inline-block"
                                style={{ background: 'rgba(139,92,246,0.12)', color: '#c4b5fd' }}>
                                {rule.mitre_tactic}
                              </span>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        {rule.pattern ? (
                          <code className="text-xs px-2 py-1 rounded-lg truncate block max-w-[180px]"
                            style={{ background: '#060c17', color: '#86efac', border: '1px solid rgba(16,185,129,0.15)' }}
                            title={rule.pattern}>{rule.pattern}</code>
                        ) : (
                          <span className="text-xs italic" style={{ color: 'var(--text-muted)' }}>{t('rules.customLogic')}</span>
                        )}
                      </td>
                      <td className="px-4 py-3.5">
                        <span className="text-xs font-bold px-2.5 py-0.5 rounded-full"
                          style={{ background: sev.bg, color: sev.color, border: `1px solid ${sev.border}` }}>
                          {t(`severity.${rule.severity}`)}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-sm capitalize" style={{ color: 'var(--text-secondary)' }}>{rule.category}</td>
                      <td className="px-4 py-3.5 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{rule.cooldown_seconds}s</td>
                      <td className="px-4 py-3.5">
                        <button onClick={() => handleToggle(rule)}
                          className="relative w-9 h-5 rounded-full transition-colors"
                          style={{ background: rule.enabled ? '#10b981' : 'rgba(255,255,255,0.1)' }}>
                          <div className="absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform"
                            style={{ transform: rule.enabled ? 'translateX(18px)' : 'translateX(2px)' }} />
                        </button>
                      </td>
                      <td className="px-4 py-3.5">
                        <div className="flex gap-1.5">
                          <button onClick={() => setEditRule(rule)}
                            className="text-xs px-2.5 py-1.5 rounded-lg"
                            style={{ background: 'rgba(59,130,246,0.1)', color: '#93c5fd' }}>
                            {t('common.edit')}
                          </button>
                          {!rule.custom_logic && (
                            <button onClick={() => setConfirmDelete(rule)}
                              className="text-xs px-2.5 py-1.5 rounded-lg"
                              style={{ background: 'rgba(239,68,68,0.08)', color: '#fca5a5' }}>
                              {t('common.delete')}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {showCreate && <RuleFormModal onSave={handleCreate} onClose={() => setShowCreate(false)} />}
      {editRule   && <RuleFormModal initial={editRule} onSave={handleEdit} onClose={() => setEditRule(null)} />}

      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in"
          style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(8px)' }}>
          <div className="w-full max-w-sm rounded-2xl p-6 animate-slide-down"
            style={{ background: 'var(--bg-card)', border: '1px solid rgba(239,68,68,0.3)',
              boxShadow: '0 25px 60px rgba(0,0,0,0.7)' }}>
            <div className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4"
              style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)' }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            </div>
            <h3 className="font-black text-white text-center mb-2">{t('rules.deleteRule')}</h3>
            <p className="text-sm text-center mb-6" style={{ color: 'var(--text-secondary)' }}>
              {t('rules.deleteConfirm')} <span className="text-white font-semibold">"{confirmDelete.name}"</span>?
            </p>
            <div className="flex gap-3">
              <button onClick={() => handleDelete(confirmDelete)}
                className="flex-1 py-2.5 rounded-xl font-bold text-sm"
                style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.3)' }}>
                {t('common.delete')}
              </button>
              <button onClick={() => setConfirmDelete(null)} className="btn-ghost flex-1 py-2.5 text-sm">
                {t('common.cancel')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
