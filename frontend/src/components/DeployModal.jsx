import React, { useState, useCallback, useRef } from 'react'
import { useLang } from '../context/LanguageContext'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// ── icons ────────────────────────────────────────────────────────────────────

const LinuxIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20">
    <path d="M12.5 0C9.8 0 8 2.2 8 5c0 1 .2 2 .6 2.8L7 9c-1 .5-2 1.3-2.5 2.4-.3.6-.5 1.3-.5 2 0 .8.2 1.5.5 2.2.3.6.8 1 1.3 1.4-.1.3-.2.6-.2 1 0 1.2.8 2.2 2 2.5-.1.2-.1.4-.1.5 0 1.1.7 2 1.6 2.3-.2.3-.3.7-.3 1.1 0 1.3 1 2.3 2.2 2.3.4 0 .8-.1 1.1-.3.3.2.7.3 1.1.3 1.2 0 2.2-1 2.2-2.3 0-.4-.1-.8-.3-1.1.9-.3 1.6-1.2 1.6-2.3 0-.1 0-.3-.1-.5 1.2-.3 2-1.3 2-2.5 0-.4-.1-.7-.2-1 .5-.4 1-.8 1.3-1.4.3-.7.5-1.4.5-2.2 0-.7-.2-1.4-.5-2C19 10.3 18 9.5 17 9l-1.6-1.2c.4-.8.6-1.8.6-2.8C16 2.2 14.2 0 12.5 0z"/>
  </svg>
)

const WindowsIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20">
    <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.9-1.801"/>
  </svg>
)

const DockerIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20">
    <path d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.186.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.186.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.186.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.184-.186h-2.12a.186.186 0 00-.186.186v1.887c0 .102.084.185.186.185m-2.92 0h2.12a.186.186 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.186v1.887c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288Z"/>
  </svg>
)

const CopyIcon = ({ copied }) => copied
  ? <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" width="14" height="14"><polyline points="20 6 9 17 4 12"/></svg>
  : <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>

// ── helpers ──────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'linux',   label: 'Linux',   Icon: LinuxIcon,   color: '#f97316' },
  { id: 'windows', label: 'Windows', Icon: WindowsIcon, color: '#3b82f6' },
  { id: 'docker',  label: 'Docker',  Icon: DockerIcon,  color: '#06b6d4' },
]

const STEPS = {
  linux: [
    { icon: '🔍', title: 'Pre-flight',   desc: 'Checks root, connectivity, disk space' },
    { icon: '🐍', title: 'Python',       desc: 'Detects or installs Python 3.8+' },
    { icon: '👤', title: 'System user',  desc: "Creates 'siemagt' unprivileged user" },
    { icon: '📦', title: 'Download',     desc: 'Fetches agent archive from backend' },
    { icon: '📚', title: 'Virtualenv',   desc: 'Isolated venv + pip install' },
    { icon: '⚙️', title: 'Config',       desc: 'Writes config.yaml with your settings' },
    { icon: '🚀', title: 'Systemd',      desc: 'Enables & starts siem-agent.service' },
  ],
  windows: [
    { icon: '🔍', title: 'Admin check',  desc: 'Verifies elevated PowerShell' },
    { icon: '🐍', title: 'Python',       desc: 'Detects or installs via winget' },
    { icon: '📦', title: 'Download',     desc: 'Fetches agent archive from backend' },
    { icon: '📚', title: 'Virtualenv',   desc: 'venv + pip install in ProgramData' },
    { icon: '🚀', title: 'Service',      desc: 'Registers & starts Windows Service' },
  ],
  docker: [
    { icon: '🐳', title: 'Docker Compose', desc: 'Add the snippet to your compose file' },
    { icon: '⚙️', title: 'Configure',      desc: 'Set MANAGER_URL in environment' },
    { icon: '🚀', title: 'Launch',         desc: 'docker compose --profile agent up -d' },
  ],
}

function useClipboard(timeout = 2000) {
  const [copied, setCopied] = useState(false)
  const copy = useCallback((text) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), timeout)
    })
  }, [timeout])
  return { copied, copy }
}

// ── component ────────────────────────────────────────────────────────────────

export default function DeployModal({ onClose }) {
  const { t } = useLang()
  const [tab, setTab]               = useState('linux')
  const [managerUrl, setManagerUrl] = useState(API_BASE)
  const [agentName, setAgentName]   = useState('')
  const [downloading, setDownloading] = useState(false)
  const [stepsOpen, setStepsOpen]   = useState(false)
  const { copied, copy }            = useClipboard()

  const effectiveName = agentName.trim() || 'my-agent'

  // one-liner curl command shown to user
  const oneLiner = {
    linux: `curl -fsSL "${managerUrl}/api/installer/linux?manager_url=${encodeURIComponent(managerUrl)}&agent_name=${encodeURIComponent(effectiveName)}" | sudo bash`,
    windows: `$url="${managerUrl}/api/installer/windows?manager_url=${encodeURIComponent(managerUrl)}&agent_name=${encodeURIComponent(effectiveName)}"; iwr $url -OutFile $env:TEMP\\install.ps1; .\\$env:TEMP\\install.ps1`,
    docker: `# See docker-compose snippet below — copy it into your compose file`,
  }

  const downloadUrl = {
    linux:   `${managerUrl}/api/installer/linux?manager_url=${encodeURIComponent(managerUrl)}&agent_name=${encodeURIComponent(effectiveName)}`,
    windows: `${managerUrl}/api/installer/windows?manager_url=${encodeURIComponent(managerUrl)}&agent_name=${encodeURIComponent(effectiveName)}`,
    docker:  `${managerUrl}/api/installer/docker?manager_url=${encodeURIComponent(managerUrl)}&agent_name=${encodeURIComponent(effectiveName)}`,
  }

  const downloadFilename = { linux: 'install-siem-agent.sh', windows: 'Install-SIEMAgent.ps1', docker: 'docker-compose-agent.yml' }

  const handleDownload = async () => {
    setDownloading(true)
    try {
      const token = localStorage.getItem('access_token')
      const res = await fetch(downloadUrl[tab], {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) throw new Error(res.statusText)
      const blob = await res.blob()
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href = url; a.download = downloadFilename[tab]; a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      alert('Download failed: ' + e.message)
    }
    setDownloading(false)
  }

  const activeTab  = TABS.find((t) => t.id === tab)
  const steps      = STEPS[tab] || []

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-4 animate-fade-in"
      style={{ background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(12px)' }}
      onClick={(e) => e.target === e.currentTarget && onClose()}>

      <div className="w-full max-w-2xl rounded-2xl overflow-hidden animate-slide-down"
        style={{ background: 'var(--bg-card)', border: `1px solid ${activeTab.color}30`,
          boxShadow: `0 25px 80px rgba(0,0,0,0.8), 0 0 0 1px ${activeTab.color}15` }}>

        {/* ── header ── */}
        <div className="relative px-6 pt-5 pb-4 overflow-hidden"
          style={{ background: `linear-gradient(135deg, var(--bg-secondary), ${activeTab.color}06)`,
            borderBottom: '1px solid var(--border-color)' }}>
          <div className="absolute top-0 right-0 w-48 h-48 pointer-events-none"
            style={{ background: `radial-gradient(circle, ${activeTab.color}10 0%, transparent 70%)`,
              transform: 'translate(30%,-30%)' }} />
          <div className="relative flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                  style={{ background: `${activeTab.color}18`, color: activeTab.color }}>
                  <activeTab.Icon />
                </div>
                <h2 className="text-lg font-black text-white">{t('agents.deployTitle')}</h2>
              </div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{t('agents.deploySubtitle')}</p>
            </div>
            <button onClick={onClose} className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0 text-lg"
              style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)' }}>×</button>
          </div>
        </div>

        {/* ── OS tabs ── */}
        <div className="flex px-6 pt-4 gap-2">
          {TABS.map(({ id, label, Icon, color }) => {
            const active = tab === id
            return (
              <button key={id} onClick={() => setTab(id)}
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-bold transition-all"
                style={{
                  background: active ? `${color}18` : 'var(--bg-secondary)',
                  color:      active ? color : 'var(--text-muted)',
                  border:     `1px solid ${active ? `${color}40` : 'var(--border-color)'}`,
                  boxShadow:  active ? `0 0 16px ${color}18` : 'none',
                }}>
                <Icon />
                {label}
              </button>
            )
          })}
        </div>

        {/* ── form ── */}
        <div className="px-6 py-4 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-bold mb-1.5 uppercase tracking-wider"
                style={{ color: 'var(--text-muted)' }}>
                {t('agents.deployManagerUrl')}
              </label>
              <input value={managerUrl} onChange={(e) => setManagerUrl(e.target.value)}
                className="w-full font-mono text-xs" placeholder="http://your-server:8000" />
            </div>
            <div>
              <label className="block text-xs font-bold mb-1.5 uppercase tracking-wider"
                style={{ color: 'var(--text-muted)' }}>
                {t('agents.deployAgentName')}
              </label>
              <input value={agentName} onChange={(e) => setAgentName(e.target.value)}
                className="w-full" placeholder="web-server-01" />
            </div>
          </div>

          {/* one-liner */}
          {tab !== 'docker' && (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-bold uppercase tracking-wider"
                  style={{ color: 'var(--text-muted)' }}>
                  {t('agents.deployOneLiner')}
                </label>
                <button onClick={() => copy(oneLiner[tab])}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition-all"
                  style={{
                    background: copied ? 'rgba(16,185,129,0.15)' : 'var(--bg-secondary)',
                    color:      copied ? '#6ee7b7' : 'var(--text-muted)',
                    border:     `1px solid ${copied ? 'rgba(16,185,129,0.3)' : 'var(--border-color)'}`,
                  }}>
                  <CopyIcon copied={copied} />
                  {copied ? t('agents.deployCopied') : t('agents.deployCopy')}
                </button>
              </div>
              <div className="relative rounded-xl overflow-hidden"
                style={{ background: '#0d1117', border: '1px solid var(--border-color)' }}>
                <div className="flex items-center gap-1.5 px-4 py-2 border-b"
                  style={{ borderColor: 'var(--border-color)', background: '#161b22' }}>
                  {['#ef4444','#f59e0b','#10b981'].map((c) => (
                    <div key={c} className="w-2.5 h-2.5 rounded-full" style={{ background: c }} />
                  ))}
                  <span className="ml-2 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                    {tab === 'linux' ? 'bash' : 'powershell'}
                  </span>
                </div>
                <pre className="px-4 py-3 text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all leading-relaxed"
                  style={{ color: '#e2e8f0', maxHeight: 80 }}>
                  <span style={{ color: '#7ee787' }}>$</span>{' '}
                  <span style={{ color: '#79c0ff' }}>{oneLiner[tab]}</span>
                </pre>
              </div>
            </div>
          )}

          {/* docker compose preview */}
          {tab === 'docker' && (
            <div className="rounded-xl overflow-hidden"
              style={{ background: '#0d1117', border: '1px solid var(--border-color)' }}>
              <div className="flex items-center gap-1.5 px-4 py-2 border-b"
                style={{ borderColor: 'var(--border-color)', background: '#161b22' }}>
                {['#ef4444','#f59e0b','#10b981'].map((c) => (
                  <div key={c} className="w-2.5 h-2.5 rounded-full" style={{ background: c }} />
                ))}
                <span className="ml-2 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>docker-compose.yml</span>
              </div>
              <pre className="px-4 py-3 text-xs font-mono overflow-x-auto leading-relaxed"
                style={{ color: '#e2e8f0', maxHeight: 160 }}>
{`  agent:
    build: ./agent
    environment:
      MANAGER_URL: `}<span style={{ color: '#a5d6ff' }}>{managerUrl}</span>{`
      AGENT_NAME:  `}<span style={{ color: '#a5d6ff' }}>{effectiveName}</span>{`
    volumes:
      - /var/log:/var/log:ro
    profiles: [agent]`}
              </pre>
            </div>
          )}

          {/* steps accordion */}
          <div className="rounded-xl overflow-hidden"
            style={{ border: '1px solid var(--border-color)' }}>
            <button onClick={() => setStepsOpen(!stepsOpen)}
              className="w-full flex items-center justify-between px-4 py-3 text-sm font-semibold transition-colors"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
              <span>{t('agents.deployWhatHappens')}</span>
              <span className="text-xs" style={{ color: 'var(--text-muted)', transform: stepsOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}>▼</span>
            </button>
            {stepsOpen && (
              <div className="divide-y" style={{ borderColor: 'var(--border-color)' }}>
                {steps.map(({ icon, title, desc }, i) => (
                  <div key={i} className="flex items-center gap-3 px-4 py-2.5"
                    style={{ background: 'var(--bg-card)' }}>
                    <span className="w-7 h-7 rounded-lg flex items-center justify-center text-base flex-shrink-0"
                      style={{ background: `${activeTab.color}12` }}>
                      {icon}
                    </span>
                    <div>
                      <div className="text-xs font-bold text-white">{i + 1}. {title}</div>
                      <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── footer ── */}
        <div className="flex items-center justify-between gap-3 px-6 py-4"
          style={{ borderTop: '1px solid var(--border-color)', background: 'var(--bg-secondary)' }}>
          <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
            <span>📡</span>
            <span>{t('agents.deployRequires')}</span>
          </div>
          <div className="flex gap-2">
            <button onClick={onClose} className="px-4 py-2 rounded-xl text-sm font-semibold"
              style={{ background: 'var(--bg-card)', color: 'var(--text-secondary)',
                border: '1px solid var(--border-color)' }}>
              {t('common.cancel')}
            </button>
            <button onClick={handleDownload} disabled={downloading}
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-bold transition-all"
              style={{
                background: downloading ? `${activeTab.color}20` : `${activeTab.color}18`,
                color:      activeTab.color,
                border:     `1px solid ${activeTab.color}40`,
                opacity:    downloading ? 0.7 : 1,
              }}>
              {downloading
                ? <><span className="w-3.5 h-3.5 border-2 rounded-full animate-spin flex-shrink-0"
                    style={{ borderColor: `${activeTab.color}30`, borderTopColor: activeTab.color }} />
                  {t('agents.deployDownloading')}</>
                : <><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                    <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                  </svg>
                  {t('agents.deployDownload')} {downloadFilename[tab]}</>
              }
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
