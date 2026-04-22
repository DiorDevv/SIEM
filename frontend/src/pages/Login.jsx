import React, { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useLang } from '../context/LanguageContext'

const DOTS = Array.from({ length: 25 }, (_, i) => ({
  x: Math.random() * 100,
  y: Math.random() * 100,
  size: Math.random() * 2 + 1,
  delay: Math.random() * 4,
}))

function Background() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      <div className="absolute rounded-full animate-float"
        style={{ width: 600, height: 600, top: -200, left: -200,
          background: 'radial-gradient(circle, rgba(59,130,246,0.07) 0%, transparent 70%)' }} />
      <div className="absolute rounded-full animate-float"
        style={{ width: 400, height: 400, bottom: -100, right: -100,
          background: 'radial-gradient(circle, rgba(139,92,246,0.07) 0%, transparent 70%)',
          animationDelay: '1.5s' }} />
      {DOTS.map((d, i) => (
        <div key={i} className="absolute rounded-full"
          style={{ left: `${d.x}%`, top: `${d.y}%`, width: d.size, height: d.size,
            background: 'rgba(59,130,246,0.4)',
            animation: `pulse-glow ${2 + d.delay}s ease-in-out infinite`,
            animationDelay: `${d.delay}s` }} />
      ))}
      <svg className="absolute inset-0 w-full h-full opacity-5" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse">
            <path d="M 60 0 L 0 0 0 60" fill="none" stroke="#3b82f6" strokeWidth="0.5"/>
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)"/>
      </svg>
    </div>
  )
}

function TotpStep({ tempToken, onSuccess, onBack, t }) {
  const { verifyTotp } = useAuth()
  const navigate = useNavigate()
  const [digits, setDigits] = useState(['', '', '', '', '', ''])
  const [backup, setBackup] = useState('')
  const [useBackup, setUseBackup] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const refs = [useRef(), useRef(), useRef(), useRef(), useRef(), useRef()]

  useEffect(() => { refs[0].current?.focus() }, [])

  const handleDigit = (i, val) => {
    if (!/^\d?$/.test(val)) return
    const next = [...digits]
    next[i] = val
    setDigits(next)
    if (val && i < 5) refs[i + 1].current?.focus()
  }

  const handleKeyDown = (i, e) => {
    if (e.key === 'Backspace' && !digits[i] && i > 0) {
      refs[i - 1].current?.focus()
    }
  }

  const handlePaste = (e) => {
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    if (pasted.length === 6) {
      setDigits(pasted.split(''))
      refs[5].current?.focus()
      e.preventDefault()
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    const code = useBackup ? backup.trim() : digits.join('')
    try {
      await verifyTotp(tempToken, code)
      navigate('/')
    } catch (err) {
      setError(err?.response?.data?.detail || t('login.twofa.invalidCode'))
      if (!useBackup) setDigits(['', '', '', '', '', ''])
      refs[0].current?.focus()
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      <div className="text-center mb-2">
        <div className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-3"
          style={{ background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.3)' }}>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#a5b4fc" strokeWidth="2">
            <rect x="5" y="11" width="14" height="10" rx="2"/>
            <path d="M8 11V7a4 4 0 0 1 8 0v4"/>
            <circle cx="12" cy="16" r="1" fill="#a5b4fc"/>
          </svg>
        </div>
        <h2 className="text-lg font-bold text-white">{t('login.twofa.title')}</h2>
        <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>{t('login.twofa.subtitle')}</p>
      </div>

      {!useBackup ? (
        <div>
          <label className="block text-xs font-bold mb-3 uppercase tracking-wider text-center"
            style={{ color: 'var(--text-muted)' }}>{t('login.twofa.enterCode')}</label>
          <div className="flex justify-center gap-2" onPaste={handlePaste}>
            {digits.map((d, i) => (
              <input key={i} ref={refs[i]} type="text" inputMode="numeric" maxLength={1}
                value={d} onChange={(e) => handleDigit(i, e.target.value)}
                onKeyDown={(e) => handleKeyDown(i, e)}
                className="text-center text-xl font-bold"
                style={{ width: 44, height: 52, borderRadius: 10,
                  background: 'var(--bg-secondary)', border: d ? '2px solid #818cf8' : '1px solid var(--border-color)',
                  color: '#fff', caretColor: '#818cf8' }} />
            ))}
          </div>
        </div>
      ) : (
        <div>
          <label className="block text-xs font-bold mb-2 uppercase tracking-wider"
            style={{ color: 'var(--text-muted)' }}>{t('login.twofa.backupCode')}</label>
          <input type="text" value={backup} onChange={(e) => setBackup(e.target.value)}
            placeholder="xxxx-xxxx" className="w-full text-center font-mono tracking-widest"
            style={{ fontSize: 16 }} autoFocus />
        </div>
      )}

      {error && (
        <div className="rounded-xl px-4 py-3 text-sm animate-fade-in"
          style={{ background: 'rgba(220,38,38,0.1)', border: '1px solid rgba(220,38,38,0.3)', color: '#fca5a5' }}>
          <span className="mr-2">⚠</span>{error}
        </div>
      )}

      <button type="submit" disabled={loading || (!useBackup && digits.join('').length < 6)}
        className="btn-primary w-full py-3 flex items-center justify-center gap-2 text-base">
        {loading && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
        {loading ? t('login.signingIn') : t('login.twofa.verify')}
      </button>

      <div className="flex items-center justify-between text-xs pt-1">
        <button type="button" onClick={onBack}
          style={{ color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}>
          ← {t('login.twofa.backToLogin')}
        </button>
        <button type="button" onClick={() => { setUseBackup(!useBackup); setError('') }}
          style={{ color: '#a5b4fc', background: 'none', border: 'none', cursor: 'pointer' }}>
          {useBackup ? t('login.twofa.useAuthApp') : t('login.twofa.useBackup')}
        </button>
      </div>
    </form>
  )
}

export default function Login() {
  const { login } = useAuth()
  const { t, lang, toggle } = useLang()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPw, setShowPw] = useState(false)
  const [totpPending, setTotpPending] = useState(null) // temp_token string

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const result = await login(username, password)
      if (result?.requires_2fa) {
        setTotpPending(result.temp_token)
      } else {
        navigate('/')
      }
    } catch (err) {
      setError(err?.response?.data?.detail || t('login.errorMsg'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 relative overflow-hidden"
      style={{ background: 'var(--bg-primary)' }}>
      <Background />

      <button onClick={toggle}
        className="absolute top-6 right-6 flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold"
        style={{ background: 'rgba(59,130,246,0.1)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)' }}>
        <span>{lang === 'en' ? '🇺🇸' : '🇺🇿'}</span>
        <span>{lang.toUpperCase()}</span>
      </button>

      <div className="w-full max-w-md rounded-3xl p-8 relative animate-fade-in"
        style={{ background: 'rgba(17,24,39,0.95)', border: '1px solid var(--border-light)',
          boxShadow: '0 25px 80px rgba(0,0,0,0.6), 0 0 60px rgba(59,130,246,0.06)',
          backdropFilter: 'blur(20px)' }}>

        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center font-black text-xl mb-4 animate-float"
            style={{ background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
              boxShadow: '0 0 32px rgba(59,130,246,0.5)', color: '#fff' }}>
            SW
          </div>
          <h1 className="text-2xl font-extrabold text-white">{t('login.title')}</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>{t('login.subtitle')}</p>
        </div>

        {totpPending ? (
          <TotpStep
            tempToken={totpPending}
            t={t}
            onBack={() => { setTotpPending(null); setError('') }}
          />
        ) : (
          <>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                  {t('login.username')}
                </label>
                <input type="text" value={username} onChange={(e) => setUsername(e.target.value)}
                  placeholder={t('login.usernamePlaceholder')} required className="w-full"
                  style={{ fontSize: 14 }} autoComplete="username" />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                  {t('login.password')}
                </label>
                <div className="relative">
                  <input type={showPw ? 'text' : 'password'} value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={t('login.passwordPlaceholder')} required className="w-full"
                    style={{ fontSize: 14, paddingRight: 44 }} autoComplete="current-password" />
                  <button type="button" onClick={() => setShowPw(!showPw)}
                    className="absolute right-3 top-1/2 -translate-y-1/2"
                    style={{ color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}>
                    {showPw ? (
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/>
                        <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/>
                        <line x1="1" y1="1" x2="23" y2="23"/>
                      </svg>
                    ) : (
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                        <circle cx="12" cy="12" r="3"/>
                      </svg>
                    )}
                  </button>
                </div>
              </div>

              {error && (
                <div className="rounded-xl px-4 py-3 text-sm animate-fade-in"
                  style={{ background: 'rgba(220,38,38,0.1)', border: '1px solid rgba(220,38,38,0.3)', color: '#fca5a5' }}>
                  <span className="mr-2">⚠</span>{error}
                </div>
              )}

              <button type="submit" disabled={loading}
                className="btn-primary w-full py-3 mt-2 flex items-center justify-center gap-2 text-base">
                {loading && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
                {loading ? t('login.signingIn') : t('login.signIn')}
              </button>
            </form>

            <div className="mt-6 text-center text-xs py-3 rounded-xl"
              style={{ background: 'rgba(59,130,246,0.06)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>
              {t('login.defaultCreds')}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
