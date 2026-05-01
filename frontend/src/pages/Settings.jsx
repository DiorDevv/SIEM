import React, { useState, useEffect, useCallback } from 'react'
import {
  changePassword, getSystemInfo,
  getUsers, createUser, updateUser, deleteUser, adminResetPw,
  totpSetup, totpVerifySetup, totpDisable, totpRegenerateCodes, totpBackupCodesCount,
  getSystemConfig, updateSystemConfig, getAuditdScript,
} from '../api'
import { useAuth } from '../context/AuthContext'
import { useLang } from '../context/LanguageContext'
import { useTheme } from '../context/ThemeContext'

/* ─────────────────────────────────────────────────────────────────
   Helpers
───────────────────────────────────────────────────────────────── */
const ROLE_COLORS = { admin: '#f59e0b', analyst: '#3b82f6', viewer: '#6b7280' }

function Label({ children }) {
  return (
    <p className="text-xs font-bold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>
      {children}
    </p>
  )
}

function FieldRow({ label, value }) {
  return (
    <div className="flex items-center justify-between py-3"
      style={{ borderBottom: '1px solid var(--border-color)' }}>
      <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{label}</span>
      <span className="text-sm font-bold text-white capitalize">{value || '—'}</span>
    </div>
  )
}

function Alert({ type, children }) {
  const styles = {
    error:   { bg: 'rgba(220,38,38,0.1)',   color: '#fca5a5', border: 'rgba(220,38,38,0.25)',   icon: '⚠' },
    success: { bg: 'rgba(16,185,129,0.1)',  color: '#6ee7b7', border: 'rgba(16,185,129,0.25)',  icon: '✓' },
    info:    { bg: 'rgba(99,102,241,0.1)',  color: '#a5b4fc', border: 'rgba(99,102,241,0.25)',  icon: 'ℹ' },
  }
  const s = styles[type] || styles.info
  return (
    <div className="flex items-start gap-2 px-4 py-3 rounded-xl text-sm"
      style={{ background: s.bg, border: `1px solid ${s.border}`, color: s.color }}>
      <span className="flex-shrink-0 mt-0.5">{s.icon}</span>
      <span>{children}</span>
    </div>
  )
}

function Spinner() {
  return <div className="w-4 h-4 rounded-full border-2 animate-spin flex-shrink-0"
    style={{ borderColor: 'rgba(99,102,241,0.2)', borderTopColor: '#818cf8' }} />
}

function Btn({ children, onClick, type = 'button', variant = 'primary', disabled, full, small }) {
  const vars = {
    primary:  { bg: 'rgba(99,102,241,0.2)',  color: '#a5b4fc', border: 'rgba(99,102,241,0.35)' },
    danger:   { bg: 'rgba(220,38,38,0.12)',  color: '#f87171', border: 'rgba(220,38,38,0.3)'  },
    warning:  { bg: 'rgba(245,158,11,0.12)', color: '#fcd34d', border: 'rgba(245,158,11,0.3)' },
    ghost:    { bg: 'var(--bg-secondary)',   color: 'var(--text-muted)', border: 'var(--border-color)' },
    success:  { bg: 'rgba(16,185,129,0.12)', color: '#6ee7b7', border: 'rgba(16,185,129,0.3)' },
  }
  const v = vars[variant] || vars.primary
  return (
    <button type={type} onClick={onClick} disabled={disabled}
      className={`${full ? 'w-full' : ''} ${small ? 'px-3 py-1.5 text-xs' : 'px-4 py-2.5 text-sm'} rounded-xl font-bold transition-all`}
      style={{ background: v.bg, color: v.color, border: `1px solid ${v.border}`, opacity: disabled ? 0.55 : 1, cursor: disabled ? 'not-allowed' : 'pointer' }}>
      {children}
    </button>
  )
}

/* ─────────────────────────────────────────────────────────────────
   NAV
───────────────────────────────────────────────────────────────── */
const NAV_ITEMS = [
  { id: 'profile',    label: 'Profile',    labelUz: 'Profil',         icon: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
    </svg>
  )},
  { id: 'security',   label: 'Security',   labelUz: 'Xavfsizlik',     icon: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>
    </svg>
  )},
  { id: 'appearance', label: 'Appearance', labelUz: "Ko'rinish",      icon: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>
    </svg>
  )},
  { id: 'users',      label: 'Users',      labelUz: 'Foydalanuvchilar', adminOnly: true, icon: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>
      <path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
    </svg>
  )},
  { id: 'system',     label: 'System',     labelUz: 'Tizim',           icon: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
    </svg>
  )},
  { id: 'notifications', label: 'Notifications', labelUz: 'Bildirishnomalar', adminOnly: true, icon: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
      <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
    </svg>
  )},
]

/* ─────────────────────────────────────────────────────────────────
   PROFILE TAB
───────────────────────────────────────────────────────────────── */
function ProfileTab({ user, t }) {
  const roleColor = ROLE_COLORS[user?.role] || '#6b7280'
  return (
    <div className="space-y-6">
      {/* Avatar card */}
      <div className="flex items-center gap-5 p-5 rounded-2xl"
        style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
        <div className="w-16 h-16 rounded-2xl flex items-center justify-center text-2xl font-black flex-shrink-0"
          style={{ background: `${roleColor}18`, border: `1px solid ${roleColor}35`, color: roleColor }}>
          {user?.username?.[0]?.toUpperCase()}
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-lg font-black text-white truncate">{user?.username}</h3>
          <p className="text-xs truncate mt-0.5" style={{ color: 'var(--text-muted)' }}>{user?.email}</p>
          <span className="inline-block mt-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold capitalize"
            style={{ background: `${roleColor}15`, color: roleColor, border: `1px solid ${roleColor}30` }}>
            {user?.role}
          </span>
        </div>
      </div>

      {/* Fields */}
      <div className="rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
        <div className="px-5 py-3 text-xs font-bold uppercase tracking-wider"
          style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)',
            background: 'rgba(255,255,255,0.02)' }}>
          {t('settings.accountInfo')}
        </div>
        <div className="px-5">
          <FieldRow label={t('settings.username')} value={user?.username} />
          <FieldRow label={t('settings.email')}    value={user?.email} />
          <FieldRow label={t('settings.role')}     value={user?.role} />
          <FieldRow label="Member Since"
            value={user?.created_at ? new Date(user.created_at).toLocaleDateString() : '—'} />
          <FieldRow label="Last Login"
            value={user?.last_login ? new Date(user.last_login).toLocaleString() : '—'} />
        </div>
      </div>
    </div>
  )
}

/* ─────────────────────────────────────────────────────────────────
   SECURITY TAB  (Password + 2FA)
───────────────────────────────────────────────────────────────── */
function PasswordSection({ t }) {
  const [form, setForm]       = useState({ cur: '', new: '', conf: '' })
  const [show, setShow]       = useState({ cur: false, new: false, conf: false })
  const [loading, setLoading] = useState(false)
  const [err, setErr]         = useState('')
  const [ok, setOk]           = useState('')

  const handle = async (e) => {
    e.preventDefault(); setErr(''); setOk('')
    if (form.new !== form.conf) { setErr(t('settings.pwNoMatch')); return }
    if (form.new.length < 6)   { setErr(t('settings.pwTooShort')); return }
    setLoading(true)
    try {
      await changePassword({ current_password: form.cur, new_password: form.new })
      setOk(t('settings.pwChanged'))
      setForm({ cur: '', new: '', conf: '' })
    } catch (e) { setErr(e?.response?.data?.detail || t('settings.pwFailed')) }
    setLoading(false)
  }

  const EyeIcon = ({ on }) => on ? (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/>
      <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/>
      <line x1="1" y1="1" x2="23" y2="23"/>
    </svg>
  ) : (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
      <circle cx="12" cy="12" r="3"/>
    </svg>
  )

  return (
    <form onSubmit={handle} className="space-y-4">
      {[
        { key: 'cur',  label: t('settings.currentPw') },
        { key: 'new',  label: t('settings.newPw')     },
        { key: 'conf', label: t('settings.confirmPw') },
      ].map(({ key, label }) => (
        <div key={key}>
          <Label>{label}</Label>
          <div className="relative">
            <input type={show[key] ? 'text' : 'password'} value={form[key]}
              onChange={e => setForm(p => ({ ...p, [key]: e.target.value }))}
              className="w-full" style={{ paddingRight: 40 }} required />
            <button type="button" onClick={() => setShow(p => ({ ...p, [key]: !p[key] }))}
              className="absolute right-3 top-1/2 -translate-y-1/2"
              style={{ color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}>
              <EyeIcon on={show[key]} />
            </button>
          </div>
        </div>
      ))}

      {err && <Alert type="error">{err}</Alert>}
      {ok  && <Alert type="success">{ok}</Alert>}

      <Btn type="submit" disabled={loading} full>
        {loading ? <span className="flex items-center justify-center gap-2"><Spinner />{t('settings.changingPw')}...</span>
          : t('settings.changePwBtn')}
      </Btn>
    </form>
  )
}

function TwoFASection({ t, user, onUpdated }) {
  const [phase, setPhase]   = useState('idle')
  const [qrData, setQrData] = useState(null)
  const [code, setCode]     = useState('')
  const [backupCodes, setBackupCodes] = useState([])
  const [backupCount, setBackupCount] = useState(null)
  const [password, setPassword] = useState('')
  const [regenCode, setRegenCode] = useState('')
  const [err, setErr]       = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const enabled = user?.totp_enabled

  useEffect(() => {
    if (enabled) totpBackupCodesCount().then(r => setBackupCount(r.data.count)).catch(() => {})
  }, [enabled])

  const reset = () => {
    setPhase('idle'); setCode(''); setPassword(''); setRegenCode('')
    setErr(''); setQrData(null); setBackupCodes([])
  }

  const startSetup = async () => {
    setErr(''); setLoading(true)
    try { const r = await totpSetup(); setQrData(r.data); setPhase('setup') }
    catch (e) { setErr(e?.response?.data?.detail || 'Error') }
    setLoading(false)
  }

  const submitVerify = async (e) => {
    e.preventDefault(); setErr(''); setLoading(true)
    try {
      const r = await totpVerifySetup(code)
      setBackupCodes(r.data.backup_codes); setPhase('done_setup'); onUpdated()
    } catch (e) { setErr(e?.response?.data?.detail || t('settings.twofa.invalidCode')) }
    setLoading(false)
  }

  const submitDisable = async (e) => {
    e.preventDefault(); setErr(''); setLoading(true)
    try { await totpDisable(password, code); reset(); onUpdated() }
    catch (e) { setErr(e?.response?.data?.detail || 'Error') }
    setLoading(false)
  }

  const submitRegen = async (e) => {
    e.preventDefault(); setErr(''); setLoading(true)
    try {
      const r = await totpRegenerateCodes(regenCode)
      setBackupCodes(r.data.backup_codes); setPhase('done_regen')
      const rc = await totpBackupCodesCount(); setBackupCount(rc.data.count)
    } catch (e) { setErr(e?.response?.data?.detail || t('settings.twofa.invalidCode')) }
    setLoading(false)
  }

  const copyAll = () => {
    navigator.clipboard.writeText(backupCodes.join('\n'))
    setCopied(true); setTimeout(() => setCopied(false), 2000)
  }

  // ── Backup codes shown ──────────────────────────────────────
  if (phase === 'done_setup' || phase === 'done_regen') return (
    <div className="space-y-4">
      <Alert type="success">{phase === 'done_setup' ? t('settings.twofa.enabledMsg') : t('settings.twofa.regenMsg')}</Alert>
      <div>
        <p className="text-sm font-bold text-white mb-1">{t('settings.twofa.backupCodesTitle')}</p>
        <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>{t('settings.twofa.backupCodesDesc')}</p>
        <div className="grid grid-cols-2 gap-2 mb-3">
          {backupCodes.map(c => (
            <code key={c} className="block text-center py-2 px-3 rounded-xl text-sm font-mono font-bold tracking-widest"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: '#e2e8f0' }}>
              {c}
            </code>
          ))}
        </div>
      </div>
      <div className="flex gap-3">
        <Btn onClick={copyAll} variant={copied ? 'success' : 'primary'} full>
          {copied ? '✓ ' + t('settings.twofa.copied') : t('settings.twofa.copyAll')}
        </Btn>
        <Btn onClick={reset} variant="ghost" full>{t('common.close')}</Btn>
      </div>
    </div>
  )

  // ── QR Setup ────────────────────────────────────────────────
  if (phase === 'setup') return (
    <div className="space-y-4">
      <Alert type="info">{t('settings.twofa.scanQr')}</Alert>
      {qrData && (
        <div className="flex flex-col items-center gap-3 py-2">
          <div className="p-3 rounded-2xl" style={{ background: '#fff' }}>
            <img src={qrData.qr_code} alt="QR" style={{ width: 180, height: 180, display: 'block' }} />
          </div>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{t('settings.twofa.orEnterSecret')}</p>
          <code className="text-xs font-mono px-4 py-2 rounded-xl tracking-widest"
            style={{ background: 'var(--bg-secondary)', color: '#a5b4fc', border: '1px solid var(--border-color)' }}>
            {qrData.secret}
          </code>
        </div>
      )}
      <form onSubmit={submitVerify} className="space-y-3">
        <div>
          <Label>{t('settings.twofa.enterCode')}</Label>
          <input type="text" inputMode="numeric" value={code} autoFocus
            onChange={e => setCode(e.target.value.replace(/\D/g,'').slice(0,6))}
            placeholder="000000" maxLength={6}
            style={{ width: '100%', textAlign: 'center', fontSize: 24, letterSpacing: 10, fontWeight: 700 }} />
        </div>
        {err && <Alert type="error">{err}</Alert>}
        <div className="flex gap-3">
          <Btn onClick={reset} variant="ghost" full>{t('common.cancel')}</Btn>
          <Btn type="submit" disabled={loading || code.length < 6} full>
            {loading ? '...' : t('settings.twofa.enable')}
          </Btn>
        </div>
      </form>
    </div>
  )

  // ── Disable ─────────────────────────────────────────────────
  if (phase === 'disabling') return (
    <form onSubmit={submitDisable} className="space-y-4">
      <Alert type="error">{t('settings.twofa.disableDesc')}</Alert>
      <div>
        <Label>{t('settings.twofa.yourPassword')}</Label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)}
          style={{ width: '100%' }} required autoFocus />
      </div>
      <div>
        <Label>{t('settings.twofa.currentCode')}</Label>
        <input type="text" inputMode="numeric" value={code} maxLength={6}
          onChange={e => setCode(e.target.value.replace(/\D/g,'').slice(0,6))}
          placeholder="000000"
          style={{ width: '100%', textAlign: 'center', fontSize: 20, letterSpacing: 8, fontWeight: 700 }} />
      </div>
      {err && <Alert type="error">{err}</Alert>}
      <div className="flex gap-3">
        <Btn onClick={reset} variant="ghost" full>{t('common.cancel')}</Btn>
        <Btn type="submit" variant="danger" disabled={loading} full>
          {loading ? '...' : t('settings.twofa.disableBtn')}
        </Btn>
      </div>
    </form>
  )

  // ── Regen ───────────────────────────────────────────────────
  if (phase === 'regen') return (
    <form onSubmit={submitRegen} className="space-y-4">
      <Alert type="info">{t('settings.twofa.regenDesc')}</Alert>
      <div>
        <Label>{t('settings.twofa.currentCode')}</Label>
        <input type="text" inputMode="numeric" value={regenCode} maxLength={6} autoFocus
          onChange={e => setRegenCode(e.target.value.replace(/\D/g,'').slice(0,6))}
          placeholder="000000"
          style={{ width: '100%', textAlign: 'center', fontSize: 20, letterSpacing: 8, fontWeight: 700 }} />
      </div>
      {err && <Alert type="error">{err}</Alert>}
      <div className="flex gap-3">
        <Btn onClick={reset} variant="ghost" full>{t('common.cancel')}</Btn>
        <Btn type="submit" variant="warning" disabled={loading || regenCode.length < 6} full>
          {loading ? '...' : t('settings.twofa.regenBtn')}
        </Btn>
      </div>
    </form>
  )

  // ── Idle ────────────────────────────────────────────────────
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between p-4 rounded-2xl"
        style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: enabled ? 'rgba(16,185,129,0.15)' : 'rgba(107,114,128,0.12)',
              border: `1px solid ${enabled ? 'rgba(16,185,129,0.3)' : 'rgba(107,114,128,0.2)'}` }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
              stroke={enabled ? '#6ee7b7' : '#6b7280'} strokeWidth="2">
              <rect x="5" y="11" width="14" height="10" rx="2"/>
              <path d="M8 11V7a4 4 0 0 1 8 0v4"/>
              <circle cx="12" cy="16" r="1" fill={enabled ? '#6ee7b7' : '#6b7280'}/>
            </svg>
          </div>
          <div>
            <p className="text-sm font-bold text-white">{t('settings.twofa.status')}</p>
            <p className="text-xs mt-0.5" style={{ color: enabled ? '#6ee7b7' : 'var(--text-muted)' }}>
              {enabled ? t('settings.twofa.statusEnabled') : t('settings.twofa.statusDisabled')}
            </p>
          </div>
        </div>
        <span className="px-3 py-1 rounded-full text-xs font-black"
          style={{ background: enabled ? 'rgba(16,185,129,0.12)' : 'rgba(107,114,128,0.1)',
            color: enabled ? '#6ee7b7' : '#6b7280',
            border: `1px solid ${enabled ? 'rgba(16,185,129,0.3)' : 'rgba(107,114,128,0.2)'}` }}>
          {enabled ? 'ON' : 'OFF'}
        </span>
      </div>

      {!enabled ? (
        <Btn onClick={startSetup} disabled={loading} full>
          {loading ? <span className="flex items-center justify-center gap-2"><Spinner />{t('settings.twofa.setupBtn')}</span>
            : '+ ' + t('settings.twofa.setupBtn')}
        </Btn>
      ) : (
        <div className="space-y-3">
          {backupCount !== null && (
            <div className="flex items-center justify-between px-4 py-2 rounded-xl"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{t('settings.twofa.backupRemaining').replace('{n}', backupCount)}</span>
              <span className="text-xs font-bold" style={{ color: backupCount < 3 ? '#f87171' : '#6ee7b7' }}>
                {backupCount} left
              </span>
            </div>
          )}
          <div className="flex gap-3">
            <Btn onClick={() => { reset(); setPhase('regen') }} variant="warning" full>
              {t('settings.twofa.regenBtn')}
            </Btn>
            <Btn onClick={() => { reset(); setPhase('disabling') }} variant="danger" full>
              {t('settings.twofa.disableBtn')}
            </Btn>
          </div>
        </div>
      )}
    </div>
  )
}

function TokenSection({ t }) {
  const [show, setShow]     = useState(false)
  const [copied, setCopied] = useState('')

  const token = localStorage.getItem('access_token') || ''

  const copy = (text, key) => {
    navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 2000)
  }

  const curlCmd = `TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "username=admin&password=Admin@SIEM2024!" \\
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -fsSL \\
  "http://localhost:8000/api/installer/linux?manager_url=http://localhost:8000&agent_name=server-nomi" \\
  -H "Authorization: Bearer $TOKEN" | sudo bash`

  return (
    <div className="space-y-4">
      {/* Token display */}
      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
        <div className="flex items-center justify-between px-4 py-3"
          style={{ background: 'var(--bg-card)', borderBottom: '1px solid var(--border-color)' }}>
          <div>
            <p className="text-sm font-bold text-white">Access Token</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Joriy sessiya tokeni — agent o'rnatishda ishlatiladi
            </p>
          </div>
          <div className="flex gap-2">
            <Btn onClick={() => setShow(s => !s)} variant="ghost" small>
              {show ? 'Yashirish' : 'Ko\'rish'}
            </Btn>
            <Btn onClick={() => copy(token, 'token')} variant={copied === 'token' ? 'success' : 'primary'} small>
              {copied === 'token' ? '✓ Copied' : 'Copy'}
            </Btn>
          </div>
        </div>
        <div className="px-4 py-3" style={{ background: '#0d1117' }}>
          <code className="text-xs font-mono break-all leading-relaxed"
            style={{ color: show ? '#7ee787' : 'var(--text-muted)' }}>
            {show ? token : token.slice(0, 20) + '••••••••••••••••••••••••••••••••••••••••••••'}
          </code>
        </div>
      </div>

      {/* Terminal command */}
      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
        <div className="flex items-center justify-between px-4 py-2.5"
          style={{ background: '#161b22', borderBottom: '1px solid var(--border-color)' }}>
          <div className="flex items-center gap-1.5">
            {['#ef4444','#f59e0b','#10b981'].map(c => (
              <div key={c} className="w-2.5 h-2.5 rounded-full" style={{ background: c }} />
            ))}
            <span className="ml-2 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>bash — agent o'rnatish</span>
          </div>
          <Btn onClick={() => copy(curlCmd, 'cmd')} variant={copied === 'cmd' ? 'success' : 'ghost'} small>
            {copied === 'cmd' ? '✓ Copied' : 'Copy'}
          </Btn>
        </div>
        <pre className="px-4 py-3 text-xs font-mono overflow-x-auto leading-relaxed whitespace-pre-wrap"
          style={{ background: '#0d1117', color: '#e2e8f0' }}>
          <span style={{ color: '#9ca3af' }}># 1. Token oling</span>{'\n'}
          <span style={{ color: '#7ee787' }}>TOKEN</span>
          <span style={{ color: '#e2e8f0' }}>=$(curl -s -X POST http://localhost:8000/api/auth/login \</span>{'\n'}
          {'  '}<span style={{ color: '#79c0ff' }}>-H</span> <span style={{ color: '#a5d6ff' }}>"Content-Type: application/x-www-form-urlencoded"</span> \{'\n'}
          {'  '}<span style={{ color: '#79c0ff' }}>-d</span> <span style={{ color: '#a5d6ff' }}>"username=admin&password=Admin@SIEM2024!"</span> \{'\n'}
          {'  '}| python3 -c <span style={{ color: '#a5d6ff' }}>"import sys,json; print(json.load(sys.stdin)['access_token'])"</span>){'\n\n'}
          <span style={{ color: '#9ca3af' }}># 2. Agent o'rnatish</span>{'\n'}
          <span style={{ color: '#79c0ff' }}>curl</span> -fsSL \{'\n'}
          {'  '}<span style={{ color: '#a5d6ff' }}>"http://localhost:8000/api/installer/linux?manager_url=http://localhost:8000&agent_name=server-nomi"</span> \{'\n'}
          {'  '}<span style={{ color: '#79c0ff' }}>-H</span> <span style={{ color: '#a5d6ff' }}>"Authorization: Bearer $TOKEN"</span> \{'\n'}
          {'  '}| sudo bash
        </pre>
      </div>

      <Alert type="info">
        Token 24 soat amal qiladi. Muddati o'tsa qayta login qiling.
      </Alert>
    </div>
  )
}

function SecurityTab({ t, user, onUpdated }) {
  return (
    <div className="space-y-6">
      {/* API Token */}
      <div className="rounded-2xl overflow-hidden"
        style={{ border: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
        <div className="flex items-center gap-3 px-5 py-3.5"
          style={{ borderBottom: '1px solid var(--border-color)', background: 'rgba(16,185,129,0.05)' }}>
          <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: 'rgba(16,185,129,0.15)', border: '1px solid rgba(16,185,129,0.25)' }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#6ee7b7" strokeWidth="2">
              <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
            </svg>
          </div>
          <div>
            <p className="text-sm font-bold text-white">API Token</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Agent o'rnatish uchun token</p>
          </div>
        </div>
        <div className="p-5"><TokenSection t={t} /></div>
      </div>

      {/* Change password */}
      <div className="rounded-2xl overflow-hidden"
        style={{ border: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
        <div className="flex items-center gap-3 px-5 py-3.5"
          style={{ borderBottom: '1px solid var(--border-color)', background: 'rgba(245,158,11,0.05)' }}>
          <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: 'rgba(245,158,11,0.15)', border: '1px solid rgba(245,158,11,0.25)' }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#fcd34d" strokeWidth="2">
              <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </div>
          <p className="text-sm font-bold text-white">{t('settings.changePw')}</p>
        </div>
        <div className="p-5"><PasswordSection t={t} /></div>
      </div>

      {/* 2FA */}
      <div className="rounded-2xl overflow-hidden"
        style={{ border: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
        <div className="flex items-center gap-3 px-5 py-3.5"
          style={{ borderBottom: '1px solid var(--border-color)', background: 'rgba(99,102,241,0.05)' }}>
          <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.25)' }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#a5b4fc" strokeWidth="2">
              <rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>
              <circle cx="12" cy="16" r="1" fill="#a5b4fc"/>
            </svg>
          </div>
          <div className="flex-1">
            <p className="text-sm font-bold text-white">{t('settings.twofa.sectionTitle')}</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{t('settings.twofa.sectionDesc')}</p>
          </div>
        </div>
        <div className="p-5"><TwoFASection t={t} user={user} onUpdated={onUpdated} /></div>
      </div>
    </div>
  )
}

/* ─────────────────────────────────────────────────────────────────
   APPEARANCE TAB
───────────────────────────────────────────────────────────────── */
function AppearanceTab({ t, lang, toggle: toggleLang, theme, toggleTheme }) {
  return (
    <div className="space-y-6">
      {/* Theme */}
      <div>
        <p className="text-sm font-bold text-white mb-1">{t('settings.themeTitle')}</p>
        <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>{t('settings.themeDesc')}</p>
        <div className="grid grid-cols-2 gap-3">
          {[
            { key: 'dark',  icon: '🌙', name: t('settings.themeDark'),  sub: 'Dark Mode',  accent: '#3b82f6' },
            { key: 'light', icon: '☀️', name: t('settings.themeLight'), sub: 'Light Mode', accent: '#f59e0b' },
          ].map(({ key, icon, name, sub, accent }) => {
            const active = theme === key
            return (
              <button key={key} onClick={() => !active && toggleTheme()}
                className="flex items-center gap-3 p-4 rounded-2xl text-left transition-all"
                style={{ background: active ? `${accent}12` : 'var(--bg-secondary)',
                  border: `1px solid ${active ? `${accent}45` : 'var(--border-color)'}`,
                  boxShadow: active ? `0 0 20px ${accent}15` : 'none' }}>
                <span className="text-2xl">{icon}</span>
                <div className="flex-1">
                  <p className="text-sm font-bold" style={{ color: active ? accent : 'var(--text-primary)' }}>{name}</p>
                  <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{sub}</p>
                </div>
                {active && (
                  <div className="w-5 h-5 rounded-full flex items-center justify-center text-xs flex-shrink-0"
                    style={{ background: `${accent}20`, color: accent, border: `1px solid ${accent}40` }}>✓</div>
                )}
              </button>
            )
          })}
        </div>
      </div>

      {/* Language */}
      <div>
        <p className="text-sm font-bold text-white mb-1">{t('settings.langTitle')}</p>
        <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>{t('settings.langDesc')}</p>
        <div className="grid grid-cols-2 gap-3">
          {[
            { code: 'en', flag: '🇺🇸', name: 'English',    sub: 'English (US)' },
            { code: 'uz', flag: '🇺🇿', name: "O'zbekcha",  sub: "O'zbek tili"  },
          ].map(({ code, flag, name, sub }) => {
            const active = lang === code
            return (
              <button key={code} onClick={() => lang !== code && toggleLang()}
                className="flex items-center gap-3 p-4 rounded-2xl text-left transition-all"
                style={{ background: active ? 'rgba(16,185,129,0.1)' : 'var(--bg-secondary)',
                  border: `1px solid ${active ? 'rgba(16,185,129,0.35)' : 'var(--border-color)'}`,
                  boxShadow: active ? '0 0 18px rgba(16,185,129,0.1)' : 'none' }}>
                <span className="text-2xl">{flag}</span>
                <div className="flex-1">
                  <p className="text-sm font-bold" style={{ color: active ? '#6ee7b7' : 'var(--text-primary)' }}>{name}</p>
                  <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{sub}</p>
                </div>
                {active && (
                  <div className="w-5 h-5 rounded-full flex items-center justify-center text-xs flex-shrink-0"
                    style={{ background: 'rgba(16,185,129,0.2)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.35)' }}>✓</div>
                )}
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}

/* ─────────────────────────────────────────────────────────────────
   USERS TAB
───────────────────────────────────────────────────────────────── */
function UserModal({ mode, target, onClose, onSave, t }) {
  const [form, setForm] = useState({ username: target?.username || '', email: target?.email || '', password: '', role: target?.role || 'analyst' })
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')
  const isCreate = mode === 'create', isReset = mode === 'reset', isEdit = mode === 'edit'

  const handle = async (e) => {
    e.preventDefault(); setErr(''); setLoading(true)
    try {
      if (isCreate) await createUser(form)
      else if (isEdit) await updateUser(target.id, { role: form.role, email: form.email })
      else if (isReset) await adminResetPw(target.id, form.password)
      onSave()
    } catch (e) { setErr(e?.response?.data?.detail || 'Error') }
    setLoading(false)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)' }}
      onClick={onClose}>
      <div className="w-full max-w-md rounded-2xl overflow-hidden"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)',
          boxShadow: '0 25px 60px rgba(0,0,0,0.5)' }}
        onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 py-4"
          style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
          <h3 className="text-sm font-bold text-white">
            {isCreate ? t('settings.createUser') : isEdit ? t('settings.editUser') : t('settings.resetPw')}
          </h3>
          <button onClick={onClose} className="w-7 h-7 rounded-lg flex items-center justify-center text-sm"
            style={{ background: 'var(--bg-card-hover)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>✕</button>
        </div>
        <form onSubmit={handle} className="p-6 space-y-4">
          {isCreate && (
            <div>
              <Label>{t('settings.usernameLbl')}</Label>
              <input value={form.username} onChange={e => setForm(p => ({ ...p, username: e.target.value }))}
                className="w-full" required minLength={3} autoFocus />
            </div>
          )}
          {(isCreate || isEdit) && (
            <div>
              <Label>{t('settings.emailLbl')}</Label>
              <input type="email" value={form.email} onChange={e => setForm(p => ({ ...p, email: e.target.value }))}
                className="w-full" required />
            </div>
          )}
          {(isCreate || isReset) && (
            <div>
              <Label>{t('settings.newUserPw')}</Label>
              <input type="password" value={form.password} onChange={e => setForm(p => ({ ...p, password: e.target.value }))}
                className="w-full" required minLength={6} />
            </div>
          )}
          {(isCreate || isEdit) && (
            <div>
              <Label>{t('settings.roleLbl')}</Label>
              <select value={form.role} onChange={e => setForm(p => ({ ...p, role: e.target.value }))} className="w-full">
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
          )}
          {err && <Alert type="error">{err}</Alert>}
          <div className="flex gap-3 pt-1">
            <Btn onClick={onClose} variant="ghost" full>{t('common.cancel')}</Btn>
            <Btn type="submit" disabled={loading} full>{loading ? '...' : t('common.save')}</Btn>
          </div>
        </form>
      </div>
    </div>
  )
}

function UsersTab({ t, currentUserId }) {
  const [users, setUsers]     = useState([])
  const [loading, setLoading] = useState(true)
  const [modal, setModal]     = useState(null)
  const [toast, setToast]     = useState('')

  const load = useCallback(() => {
    setLoading(true)
    getUsers().then(r => setUsers(r.data)).catch(() => {}).finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const showToast = msg => { setToast(msg); setTimeout(() => setToast(''), 3000) }
  const handleSave = msg => { setModal(null); load(); showToast(msg) }

  const handleToggle = async u => {
    try { await updateUser(u.id, { is_active: !u.is_active }); load() } catch {}
  }
  const handleDelete = async u => {
    if (!window.confirm(t('settings.confirmDelete'))) return
    try { await deleteUser(u.id); load(); showToast(t('settings.userDeleted')) } catch {}
  }

  return (
    <div className="space-y-4">
      {toast && (
        <div className="fixed top-5 right-5 z-50 flex items-center gap-2 px-4 py-3 rounded-xl text-sm font-semibold shadow-xl"
          style={{ background: 'rgba(16,185,129,0.15)', color: '#6ee7b7',
            border: '1px solid rgba(16,185,129,0.3)', backdropFilter: 'blur(8px)' }}>
          ✓ {toast}
        </div>
      )}

      <div className="flex items-center justify-between">
        <p className="text-sm font-bold text-white">
          {users.length} {users.length === 1 ? 'user' : 'users'}
        </p>
        <Btn onClick={() => setModal({ mode: 'create', target: null })}>
          + {t('settings.createUser')}
        </Btn>
      </div>

      {loading ? (
        <div className="flex items-center gap-3 py-8 justify-center" style={{ color: 'var(--text-muted)' }}>
          <Spinner /><span className="text-sm">{t('common.loading')}</span>
        </div>
      ) : (
        <div className="rounded-2xl overflow-hidden" style={{ border: '1px solid var(--border-color)' }}>
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-color)' }}>
                {[t('settings.usernameLbl'), t('settings.roleLbl'), t('settings.statusLbl'),
                  t('settings.lastLoginLbl'), t('settings.actionsLbl')].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-xs font-bold uppercase tracking-wider"
                    style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id} className="hover:bg-white/5 transition-colors"
                  style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className="w-7 h-7 rounded-lg flex items-center justify-center text-xs font-black flex-shrink-0"
                        style={{ background: `${ROLE_COLORS[u.role] || '#6b7280'}15`,
                          color: ROLE_COLORS[u.role] || '#6b7280',
                          border: `1px solid ${ROLE_COLORS[u.role] || '#6b7280'}25` }}>
                        {u.username[0].toUpperCase()}
                      </div>
                      <div>
                        <p className="font-semibold text-white text-xs">{u.username}</p>
                        <p className="text-xs truncate max-w-32" style={{ color: 'var(--text-muted)' }}>{u.email}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded-full text-xs font-bold capitalize"
                      style={{ background: `${ROLE_COLORS[u.role] || '#6b7280'}15`,
                        color: ROLE_COLORS[u.role] || '#6b7280',
                        border: `1px solid ${ROLE_COLORS[u.role] || '#6b7280'}25` }}>
                      {u.role}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={() => u.id !== currentUserId && handleToggle(u)}
                      disabled={u.id === currentUserId}
                      className="px-2 py-0.5 rounded-full text-xs font-bold"
                      style={{ background: u.is_active ? 'rgba(16,185,129,0.1)' : 'rgba(107,114,128,0.1)',
                        color: u.is_active ? '#6ee7b7' : '#9ca3af',
                        border: `1px solid ${u.is_active ? 'rgba(16,185,129,0.25)' : 'rgba(107,114,128,0.2)'}`,
                        cursor: u.id === currentUserId ? 'default' : 'pointer' }}>
                      {u.is_active ? t('settings.activeLbl') : t('settings.inactiveLbl')}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {u.last_login ? new Date(u.last_login).toLocaleDateString() : t('settings.neverLbl')}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <Btn onClick={() => setModal({ mode: 'edit', target: u })} variant="primary" small>{t('common.edit')}</Btn>
                      <Btn onClick={() => setModal({ mode: 'reset', target: u })} variant="warning" small>PW</Btn>
                      {u.id !== currentUserId && (
                        <Btn onClick={() => handleDelete(u)} variant="danger" small>{t('common.delete')}</Btn>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {modal && (
        <UserModal mode={modal.mode} target={modal.target} t={t}
          onClose={() => setModal(null)}
          onSave={() => handleSave(
            modal.mode === 'create' ? t('settings.userCreated') :
            modal.mode === 'reset'  ? t('settings.pwReset') : t('settings.userUpdated')
          )} />
      )}
    </div>
  )
}

/* ─────────────────────────────────────────────────────────────────
   SYSTEM TAB — helpers
───────────────────────────────────────────────────────────────── */

function SectionCard({ title, accent = '#818cf8', children }) {
  return (
    <div className="rounded-2xl overflow-hidden"
      style={{ border: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
      <div className="px-5 py-3 text-xs font-bold uppercase tracking-wider"
        style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)',
          background: 'rgba(255,255,255,0.02)' }}>
        {title}
      </div>
      <div className="p-5">{children}</div>
    </div>
  )
}

function ApiKeyField({ label, keyMasked, hasKey, enabled, freeInfo, signupUrl, fieldKey, onSave }) {
  const [editing, setEditing]   = useState(false)
  const [value, setValue]       = useState('')
  const [show, setShow]         = useState(false)
  const [toggling, setToggling] = useState(false)
  const [saving, setSaving]     = useState(false)
  const [msg, setMsg]           = useState(null)

  const saveKey = async () => {
    if (!value.trim()) return
    setSaving(true); setMsg(null)
    try {
      await onSave({ [fieldKey + '_API_KEY']: value.trim() })
      setMsg({ type: 'success', text: 'API key saved. Restart backend to apply.' })
      setEditing(false); setValue('')
    } catch (e) {
      setMsg({ type: 'error', text: e?.response?.data?.detail || 'Save failed' })
    }
    setSaving(false)
  }

  const toggleEnabled = async () => {
    setToggling(true); setMsg(null)
    try {
      await onSave({ [fieldKey + '_ENABLED']: !enabled })
      setMsg({ type: 'success', text: `${label} ${!enabled ? 'enabled' : 'disabled'}. Restart to apply.` })
    } catch (e) {
      setMsg({ type: 'error', text: 'Failed to toggle' })
    }
    setToggling(false)
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between p-4 rounded-xl"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
        <div>
          <p className="text-sm font-bold text-white">{label}</p>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{freeInfo}</p>
          {hasKey && (
            <p className="text-xs mt-1 font-mono" style={{ color: '#a5b4fc' }}>{keyMasked}</p>
          )}
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {hasKey && (
            <button onClick={toggleEnabled} disabled={toggling}
              className="px-3 py-1.5 rounded-xl text-xs font-bold transition-all"
              style={{ background: enabled ? 'rgba(16,185,129,0.12)' : 'rgba(107,114,128,0.1)',
                color: enabled ? '#6ee7b7' : '#9ca3af',
                border: `1px solid ${enabled ? 'rgba(16,185,129,0.3)' : 'rgba(107,114,128,0.2)'}`,
                cursor: toggling ? 'not-allowed' : 'pointer' }}>
              {toggling ? '...' : enabled ? 'ON' : 'OFF'}
            </button>
          )}
          <Btn onClick={() => setEditing(e => !e)} small variant={hasKey ? 'ghost' : 'primary'}>
            {hasKey ? 'Update Key' : 'Set Key'}
          </Btn>
        </div>
      </div>

      {editing && (
        <div className="space-y-2 px-1">
          <Label>Paste your {label} API key</Label>
          <div className="relative">
            <input
              type={show ? 'text' : 'password'}
              value={value}
              onChange={e => setValue(e.target.value)}
              placeholder="Enter API key..."
              autoFocus
              style={{ width: '100%', paddingRight: 40, fontFamily: 'monospace' }}
            />
            <button type="button" onClick={() => setShow(s => !s)}
              className="absolute right-3 top-1/2 -translate-y-1/2"
              style={{ color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                {show
                  ? <><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></>
                  : <><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></>
                }
              </svg>
            </button>
          </div>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Don't have a key?{' '}
            <a href={signupUrl} target="_blank" rel="noreferrer"
              style={{ color: '#a5b4fc', textDecoration: 'underline' }}>
              Get it free here
            </a>
          </p>
          <div className="flex gap-2">
            <Btn onClick={() => { setEditing(false); setValue(''); setMsg(null) }} variant="ghost" small>Cancel</Btn>
            <Btn onClick={saveKey} disabled={saving || !value.trim()} small>
              {saving ? 'Saving...' : 'Save Key'}
            </Btn>
          </div>
        </div>
      )}

      {msg && <Alert type={msg.type}>{msg.text}</Alert>}
    </div>
  )
}

/* ─────────────────────────────────────────────────────────────────
   SYSTEM TAB
───────────────────────────────────────────────────────────────── */
function SystemTab({ t, isAdmin }) {
  const [sysInfo,    setSysInfo]    = useState(null)
  const [sysConfig,  setSysConfig]  = useState(null)
  const [saveMsg,    setSaveMsg]    = useState(null)

  useEffect(() => {
    getSystemInfo().then(r => setSysInfo(r.data)).catch(() => {})
    getSystemConfig().then(r => setSysConfig(r.data)).catch(() => {})
  }, [])

  const handleSaveConfig = async (fields) => {
    await updateSystemConfig(fields)
    const r = await getSystemConfig()
    setSysConfig(r.data)
  }

  const downloadAuditdScript = () => {
    const url = getAuditdScript()
    const token = localStorage.getItem('access_token')
    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.blob())
      .then(blob => {
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = 'setup_auditd.sh'
        a.click()
      })
  }

  const rows = sysInfo ? [
    { label: t('settings.version'),       value: sysInfo.version },
    { label: t('settings.platform'),      value: sysInfo.platform },
    { label: t('settings.pythonVersion'), value: sysInfo.python_version },
    { label: 'Uptime',                    value: sysInfo.uptime || 'Active' },
  ] : []

  return (
    <div className="space-y-5">
      {/* Status cards */}
      <div className="grid grid-cols-2 gap-3">
        {[
          { label: 'Backend',       color: '#6ee7b7', icon: '⚙️' },
          { label: 'Database',      color: '#6ee7b7', icon: '🗄️' },
          { label: 'Elasticsearch', color: '#6ee7b7', icon: '🔍' },
          { label: 'Redis',         color: '#6ee7b7', icon: '⚡' },
        ].map(({ label, color, icon }) => (
          <div key={label} className="flex items-center gap-3 p-3.5 rounded-xl"
            style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
            <span className="text-xl">{icon}</span>
            <div className="flex-1">
              <p className="text-xs font-bold text-white">{label}</p>
              <p className="text-xs mt-0.5" style={{ color }}>Running</p>
            </div>
            <div className="w-2 h-2 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
          </div>
        ))}
      </div>

      {/* System info */}
      <SectionCard title={t('settings.sysInfo')}>
        {!sysInfo ? (
          <div className="flex items-center gap-3" style={{ color: 'var(--text-muted)' }}>
            <Spinner /><span className="text-sm">{t('settings.sysLoading')}</span>
          </div>
        ) : (
          <div>{rows.map(({ label, value }) => <FieldRow key={label} label={label} value={value} />)}</div>
        )}
      </SectionCard>

      {/* ── Auditd Setup ─────────────────────────────────────────── */}
      <SectionCard title="Auditd / System Audit Setup">
        <div className="space-y-4">
          <div className="p-4 rounded-xl space-y-2"
            style={{ background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.2)' }}>
            <p className="text-sm font-bold text-white">What is auditd?</p>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-muted)' }}>
              <b style={{ color: '#a5b4fc' }}>auditd</b> is the Linux kernel audit daemon. It records
              system calls (file reads/writes, process execution, network connections, privilege changes)
              at the kernel level — even if an attacker covers their tracks in application logs.
              SecureWatch reads <code style={{ color: '#fcd34d' }}>/var/log/audit/audit.log</code> and
              converts events into alerts.
            </p>
          </div>

          <div className="space-y-2">
            <p className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
              Setup steps (run on each monitored host)
            </p>
            {[
              { n: '1', text: 'Download the setup script below' },
              { n: '2', text: 'Copy to your server: scp setup_auditd.sh user@host:~/' },
              { n: '3', text: 'Run as root: sudo bash setup_auditd.sh' },
              { n: '4', text: 'Restart the SecureWatch agent: sudo systemctl restart siem-agent' },
              { n: '5', text: 'Events appear in Logs within ~30 seconds' },
            ].map(({ n, text }) => (
              <div key={n} className="flex items-start gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                <span className="w-5 h-5 rounded-full flex items-center justify-center text-xs font-black flex-shrink-0"
                  style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.25)' }}>
                  {n}
                </span>
                <span className="pt-0.5">{text}</span>
              </div>
            ))}
          </div>

          <Btn onClick={downloadAuditdScript} variant="primary">
            Download setup_auditd.sh
          </Btn>

          <div className="p-3 rounded-xl text-xs font-mono leading-relaxed"
            style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', color: '#6ee7b7' }}>
            <span style={{ color: '#9ca3af' }}># Quick install on Ubuntu/Debian</span><br/>
            sudo bash setup_auditd.sh<br/>
            <span style={{ color: '#9ca3af' }}># Verify rules loaded</span><br/>
            sudo auditctl -l | wc -l<span style={{ color: '#9ca3af' }}>  # expect 40+</span>
          </div>
        </div>
      </SectionCard>

      {/* ── API Keys (admin only) ─────────────────────────────────── */}
      {isAdmin && (
        <SectionCard title="Integration API Keys">
          <div className="space-y-5">
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-muted)' }}>
              API keys are saved to the backend <code style={{ color: '#fcd34d' }}>.env</code> file.
              A backend restart is required for changes to take effect.
              Keys are never exposed in full — only masked previews are shown.
            </p>

            {/* AbuseIPDB */}
            <div className="space-y-2">
              <div className="flex items-center gap-2 mb-1">
                <div className="w-6 h-6 rounded-lg flex items-center justify-center text-xs"
                  style={{ background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.25)', color: '#f87171' }}>
                  ⚠
                </div>
                <p className="text-xs font-bold uppercase tracking-wider text-white">AbuseIPDB</p>
                <span className="px-2 py-0.5 rounded-full text-xs" style={{ background: 'rgba(16,185,129,0.1)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.2)' }}>Free</span>
              </div>
              <p className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
                IP reputation database. Checks every source IP in alerts against 1000s of reported malicious IPs.
                Without key: disabled. With key: 1,000 checks/day free.
              </p>
              {sysConfig ? (
                <ApiKeyField
                  label="AbuseIPDB"
                  keyMasked={sysConfig.abuseipdb.key_masked}
                  hasKey={sysConfig.abuseipdb.has_key}
                  enabled={sysConfig.abuseipdb.enabled}
                  freeInfo={sysConfig.abuseipdb.free_tier}
                  signupUrl={sysConfig.abuseipdb.signup_url}
                  fieldKey="ABUSEIPDB"
                  onSave={handleSaveConfig}
                />
              ) : <Spinner />}
            </div>

            <div style={{ height: 1, background: 'var(--border-color)' }} />

            {/* NVD */}
            <div className="space-y-2">
              <div className="flex items-center gap-2 mb-1">
                <div className="w-6 h-6 rounded-lg flex items-center justify-center text-xs"
                  style={{ background: 'rgba(245,158,11,0.15)', border: '1px solid rgba(245,158,11,0.25)', color: '#fcd34d' }}>
                  CVE
                </div>
                <p className="text-xs font-bold uppercase tracking-wider text-white">NVD / NIST</p>
                <span className="px-2 py-0.5 rounded-full text-xs" style={{ background: 'rgba(16,185,129,0.1)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.2)' }}>Free</span>
              </div>
              <p className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
                NIST National Vulnerability Database. Used for CVE lookups on system packages (apt/rpm).
                Without key: 5 req/s rate limit. With key: 50 req/s — much faster scans.
              </p>
              {sysConfig ? (
                <ApiKeyField
                  label="NVD (NIST)"
                  keyMasked={sysConfig.nvd.key_masked}
                  hasKey={sysConfig.nvd.has_key}
                  enabled={sysConfig.nvd.enabled}
                  freeInfo={sysConfig.nvd.free_tier}
                  signupUrl={sysConfig.nvd.signup_url}
                  fieldKey="NVD"
                  onSave={handleSaveConfig}
                />
              ) : <Spinner />}
            </div>

            <div style={{ height: 1, background: 'var(--border-color)' }} />

            {/* GeoIP */}
            <div className="flex items-center justify-between p-4 rounded-xl"
              style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
              <div>
                <p className="text-sm font-bold text-white">GeoIP (ip-api.com)</p>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                  Country/city/ISP lookup for source IPs. Free, no key required. 45 req/min.
                </p>
              </div>
              {sysConfig && (
                <button
                  onClick={() => handleSaveConfig({ GEOIP_ENABLED: !sysConfig.geoip.enabled })}
                  className="px-3 py-1.5 rounded-xl text-xs font-bold transition-all"
                  style={{ background: sysConfig.geoip.enabled ? 'rgba(16,185,129,0.12)' : 'rgba(107,114,128,0.1)',
                    color: sysConfig.geoip.enabled ? '#6ee7b7' : '#9ca3af',
                    border: `1px solid ${sysConfig.geoip.enabled ? 'rgba(16,185,129,0.3)' : 'rgba(107,114,128,0.2)'}`,
                    cursor: 'pointer' }}>
                  {sysConfig.geoip.enabled ? 'ON' : 'OFF'}
                </button>
              )}
            </div>
          </div>
        </SectionCard>
      )}

    </div>
  )
}

/* ─────────────────────────────────────────────────────────────────
   NOTIFICATIONS TAB
───────────────────────────────────────────────────────────────── */
const CHANNEL_TYPES = [
  { id: 'email',    label: 'Email (SMTP)',   icon: '📧', color: '#3b82f6' },
  { id: 'telegram', label: 'Telegram Bot',   icon: '✈️',  color: '#0ea5e9' },
  { id: 'slack',    label: 'Slack Webhook',  icon: '💬', color: '#10b981' },
  { id: 'discord',  label: 'Discord Webhook',icon: '🎮', color: '#8b5cf6' },
  { id: 'webhook',  label: 'Generic Webhook',icon: '🔗', color: '#f59e0b' },
]
const SEV_LIST = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const SEV_COLORS_N = { LOW: '#3b82f6', MEDIUM: '#f59e0b', HIGH: '#f97316', CRITICAL: '#ef4444' }

function ChannelConfigFields({ type, config, setConfig }) {
  const f = (key, placeholder, label, secret) => (
    <div key={key}>
      <Label>{label}</Label>
      <input
        type={secret ? 'password' : 'text'}
        value={config[key] || ''}
        placeholder={placeholder}
        onChange={e => setConfig(p => ({ ...p, [key]: e.target.value }))}
        className="w-full"
        autoComplete="off"
      />
    </div>
  )
  if (type === 'email') return (
    <div className="grid grid-cols-2 gap-3">
      {f('smtp_host', 'smtp.gmail.com', 'SMTP Host')}
      {f('smtp_port', '587', 'SMTP Port')}
      {f('smtp_user', 'user@example.com', 'Username')}
      {f('smtp_password', '••••••••', 'Password', true)}
      {f('to_email', 'alerts@company.com', 'To Email')}
      <div>
        <Label>Use TLS</Label>
        <select value={config.use_tls === false ? 'false' : 'true'}
          onChange={e => setConfig(p => ({ ...p, use_tls: e.target.value === 'true' }))}
          className="w-full">
          <option value="true">Yes</option>
          <option value="false">No</option>
        </select>
      </div>
    </div>
  )
  if (type === 'telegram') return (
    <div className="grid grid-cols-2 gap-3">
      {f('bot_token', '123456:ABC-DEF...', 'Bot Token', true)}
      {f('chat_id', '-100123456789', 'Chat ID')}
    </div>
  )
  return (
    <div>
      {f('webhook_url', 'https://hooks.slack.com/...', 'Webhook URL')}
    </div>
  )
}

function NotificationsTab({ t }) {
  const [channels, setChannels]   = useState([])
  const [loading, setLoading]     = useState(true)
  const [showForm, setShowForm]   = useState(false)
  const [editing, setEditing]     = useState(null)
  const [testing, setTesting]     = useState(null)
  const [testResult, setTestResult] = useState({})
  const [saving, setSaving]       = useState(false)
  const [form, setForm]           = useState({ name: '', type: 'email', config: {}, enabled: true, min_severity: 'HIGH' })
  const [error, setError]         = useState('')

  const token = () => localStorage.getItem('access_token')
  const authH = () => ({ Authorization: `Bearer ${token()}`, 'Content-Type': 'application/json' })

  const load = async () => {
    setLoading(true)
    try {
      const r = await fetch('/api/notifications', { headers: authH() })
      setChannels(await r.json())
    } catch {}
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  const openNew = () => {
    setEditing(null)
    setForm({ name: '', type: 'email', config: {}, enabled: true, min_severity: 'HIGH' })
    setError('')
    setShowForm(true)
  }

  const openEdit = (ch) => {
    setEditing(ch.id)
    setForm({ name: ch.name, type: ch.type, config: { ...ch.config }, enabled: ch.enabled, min_severity: ch.min_severity })
    setError('')
    setShowForm(true)
  }

  const save = async () => {
    if (!form.name.trim()) { setError('Name is required'); return }
    setSaving(true)
    setError('')
    try {
      const url    = editing ? `/api/notifications/${editing}` : '/api/notifications'
      const method = editing ? 'PUT' : 'POST'
      const r = await fetch(url, { method, headers: authH(), body: JSON.stringify(form) })
      if (!r.ok) {
        const e = await r.json()
        setError(e.detail || 'Save failed')
      } else {
        setShowForm(false)
        await load()
      }
    } catch (e) { setError(String(e)) }
    setSaving(false)
  }

  const del = async (id) => {
    if (!confirm('Delete this channel?')) return
    await fetch(`/api/notifications/${id}`, { method: 'DELETE', headers: authH() })
    await load()
  }

  const testChannel = async (id) => {
    setTesting(id)
    setTestResult(p => ({ ...p, [id]: null }))
    try {
      const r = await fetch(`/api/notifications/${id}/test`, { method: 'POST', headers: authH() })
      const d = await r.json()
      setTestResult(p => ({ ...p, [id]: d }))
    } catch (e) {
      setTestResult(p => ({ ...p, [id]: { success: false, message: String(e) } }))
    }
    setTesting(null)
  }

  const toggleEnabled = async (ch) => {
    await fetch(`/api/notifications/${ch.id}`, {
      method: 'PUT',
      headers: authH(),
      body: JSON.stringify({ ...ch, enabled: !ch.enabled }),
    })
    await load()
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-black text-white">Notification Channels</h3>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Alert notifications via Email, Telegram, Slack, Discord or Webhook
          </p>
        </div>
        <Btn onClick={openNew} variant="primary">+ Add Channel</Btn>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 py-8" style={{ color: 'var(--text-muted)' }}>
          <Spinner /><span className="text-sm">Loading...</span>
        </div>
      ) : channels.length === 0 ? (
        <div className="text-center py-12 rounded-2xl"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          <div className="text-4xl mb-3">🔔</div>
          <p className="text-sm font-semibold text-white mb-1">No channels configured</p>
          <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
            Add a channel to receive alert notifications
          </p>
          <Btn onClick={openNew}>Add First Channel</Btn>
        </div>
      ) : (
        <div className="space-y-3">
          {channels.map(ch => {
            const ct = CHANNEL_TYPES.find(c => c.id === ch.type) || CHANNEL_TYPES[0]
            const tr = testResult[ch.id]
            return (
              <div key={ch.id} className="rounded-2xl p-4"
                style={{ background: 'var(--bg-card)', border: `1px solid ${ch.enabled ? ct.color + '30' : 'var(--border-color)'}` }}>
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl flex items-center justify-center text-lg flex-shrink-0"
                    style={{ background: `${ct.color}15` }}>{ct.icon}</div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-white">{ch.name}</span>
                      <span className="text-xs px-2 py-0.5 rounded-full"
                        style={{ background: `${ct.color}15`, color: ct.color }}>{ct.label}</span>
                      <span className="text-xs px-2 py-0.5 rounded-full"
                        style={{ background: `${SEV_COLORS_N[ch.min_severity] || '#6b7280'}15`,
                          color: SEV_COLORS_N[ch.min_severity] || '#6b7280' }}>
                        ≥ {ch.min_severity}
                      </span>
                    </div>
                    {tr && (
                      <p className="text-xs mt-1" style={{ color: tr.success ? '#6ee7b7' : '#f87171' }}>
                        {tr.success ? '✓ Test sent successfully' : `✗ ${tr.message}`}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <button onClick={() => toggleEnabled(ch)}
                      className="px-3 py-1.5 rounded-xl text-xs font-bold transition-all"
                      style={{ background: ch.enabled ? 'rgba(16,185,129,0.12)' : 'rgba(107,114,128,0.1)',
                        color: ch.enabled ? '#6ee7b7' : '#9ca3af',
                        border: `1px solid ${ch.enabled ? 'rgba(16,185,129,0.3)' : 'rgba(107,114,128,0.2)'}` }}>
                      {ch.enabled ? 'ON' : 'OFF'}
                    </button>
                    <Btn small variant="ghost" onClick={() => testChannel(ch.id)}
                      disabled={testing === ch.id}>
                      {testing === ch.id ? '...' : 'Test'}
                    </Btn>
                    <Btn small variant="ghost" onClick={() => openEdit(ch)}>Edit</Btn>
                    <Btn small variant="danger" onClick={() => del(ch.id)}>Del</Btn>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Add/Edit Form Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.7)' }}>
          <div className="w-full max-w-lg rounded-2xl p-6 space-y-4"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            <h3 className="text-lg font-black text-white">
              {editing ? 'Edit Channel' : 'Add Notification Channel'}
            </h3>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Name</Label>
                <input value={form.name} placeholder="My Slack Channel"
                  onChange={e => setForm(p => ({ ...p, name: e.target.value }))} className="w-full" />
              </div>
              <div>
                <Label>Type</Label>
                <select value={form.type}
                  onChange={e => setForm(p => ({ ...p, type: e.target.value, config: {} }))}
                  className="w-full">
                  {CHANNEL_TYPES.map(c => <option key={c.id} value={c.id}>{c.label}</option>)}
                </select>
              </div>
              <div>
                <Label>Min Severity</Label>
                <select value={form.min_severity}
                  onChange={e => setForm(p => ({ ...p, min_severity: e.target.value }))}
                  className="w-full">
                  {SEV_LIST.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div>
                <Label>Enabled</Label>
                <select value={form.enabled ? 'true' : 'false'}
                  onChange={e => setForm(p => ({ ...p, enabled: e.target.value === 'true' }))}
                  className="w-full">
                  <option value="true">Yes</option>
                  <option value="false">No</option>
                </select>
              </div>
            </div>

            <div>
              <Label>Configuration</Label>
              <div className="rounded-xl p-4 space-y-3"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
                <ChannelConfigFields type={form.type} config={form.config}
                  setConfig={cfg => setForm(p => ({ ...p, config: typeof cfg === 'function' ? cfg(p.config) : cfg }))} />
              </div>
            </div>

            {error && <Alert type="error">{error}</Alert>}

            <div className="flex gap-3 justify-end">
              <Btn variant="ghost" onClick={() => setShowForm(false)}>Cancel</Btn>
              <Btn variant="primary" onClick={save} disabled={saving}>
                {saving ? 'Saving...' : editing ? 'Save Changes' : 'Add Channel'}
              </Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

/* ─────────────────────────────────────────────────────────────────
   MAIN
───────────────────────────────────────────────────────────────── */
export default function Settings() {
  const { user, refreshUser }            = useAuth()
  const { t, lang, toggle: toggleLang }  = useLang()
  const { theme, toggle: toggleTheme }   = useTheme()
  const [activeTab, setActiveTab]        = useState('profile')

  const tabs = NAV_ITEMS.filter(n => !n.adminOnly || user?.role === 'admin')
  const roleColor = ROLE_COLORS[user?.role] || '#6b7280'

  return (
    <div className="animate-fade-in h-full">
      {/* ── Page title ── */}
      <div className="mb-5">
        <h2 className="text-xl font-black text-white">{t('settings.title')}</h2>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>{t('settings.subtitle')}</p>
      </div>

      <div className="flex gap-5" style={{ minHeight: 600 }}>
        {/* ── Left sidebar nav ── */}
        <div className="flex-shrink-0 w-52">
          {/* Mini profile */}
          <div className="flex items-center gap-3 p-3 rounded-2xl mb-4"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
            <div className="w-9 h-9 rounded-xl flex items-center justify-center text-sm font-black flex-shrink-0"
              style={{ background: `${roleColor}18`, border: `1px solid ${roleColor}30`, color: roleColor }}>
              {user?.username?.[0]?.toUpperCase()}
            </div>
            <div className="min-w-0">
              <p className="text-xs font-bold text-white truncate">{user?.username}</p>
              <p className="text-xs truncate" style={{ color: roleColor }}>{user?.role}</p>
            </div>
          </div>

          {/* Nav items */}
          <nav className="space-y-1">
            {tabs.map(item => {
              const active = activeTab === item.id
              return (
                <button key={item.id} onClick={() => setActiveTab(item.id)}
                  className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-semibold text-left transition-all"
                  style={{
                    background: active ? 'rgba(99,102,241,0.15)' : 'transparent',
                    color: active ? '#a5b4fc' : 'var(--text-muted)',
                    border: active ? '1px solid rgba(99,102,241,0.25)' : '1px solid transparent',
                  }}>
                  <span style={{ color: active ? '#818cf8' : 'var(--text-muted)' }}>{item.icon}</span>
                  {lang === 'uz' ? item.labelUz : item.label}
                  {active && <div className="ml-auto w-1.5 h-1.5 rounded-full bg-indigo-400" />}
                </button>
              )
            })}
          </nav>
        </div>

        {/* ── Content ── */}
        <div className="flex-1 min-w-0 rounded-2xl p-6"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}>
          {/* Tab header */}
          <div className="flex items-center gap-3 mb-6 pb-4"
            style={{ borderBottom: '1px solid var(--border-color)' }}>
            <div className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
              style={{ background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.2)', color: '#818cf8' }}>
              {tabs.find(t => t.id === activeTab)?.icon}
            </div>
            <div>
              <h3 className="text-sm font-black text-white">
                {tabs.find(t => t.id === activeTab)?.[lang === 'uz' ? 'labelUz' : 'label']}
              </h3>
            </div>
          </div>

          {/* Tab content */}
          {activeTab === 'profile'       && <ProfileTab user={user} t={t} />}
          {activeTab === 'security'      && <SecurityTab t={t} user={user} onUpdated={refreshUser} />}
          {activeTab === 'appearance'    && <AppearanceTab t={t} lang={lang} toggle={toggleLang} theme={theme} toggleTheme={toggleTheme} />}
          {activeTab === 'users'         && <UsersTab t={t} currentUserId={user?.id} />}
          {activeTab === 'system'        && <SystemTab t={t} isAdmin={user?.role === 'admin'} />}
          {activeTab === 'notifications' && <NotificationsTab t={t} />}
        </div>
      </div>
    </div>
  )
}
