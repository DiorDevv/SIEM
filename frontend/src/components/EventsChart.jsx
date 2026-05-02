import React from 'react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import { useLang } from '../context/LanguageContext'

const CARD = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border-color)',
  borderRadius: '16px',
  padding: '20px',
}

const TIP = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border-light)',
  borderRadius: '10px',
  color: 'var(--text-primary)',
  fontSize: '12px',
  boxShadow: 'var(--shadow-card)',
  padding: '8px 12px',
}

const SEV_COLORS = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#f59e0b',
  LOW:      '#3b82f6',
}

/* ── Custom tooltip ─────────────────────────────────────── */
const CustomTip = ({ active, payload, label, unit = '' }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={TIP}>
      <p style={{ color: '#94a3b8', marginBottom: 4 }}>{label}</p>
      {payload.map((p) => (
        <p key={p.dataKey} style={{ color: p.color, fontWeight: 700, margin: 0 }}>
          {p.name}: <span style={{ color: 'var(--text-primary)' }}>{p.value}{unit}</span>
        </p>
      ))}
    </div>
  )
}

/* ── X-axis tick formatter — data already comes as "HH:00" ─ */
const fmtHour = (v) => v || ''

/* ── Alerts area chart ──────────────────────────────────── */
export function AlertsAreaChart({ data }) {
  const { t } = useLang()
  return (
    <div style={CARD}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
          {t('dashboard.alertsPerHour')}
        </h3>
        <span className="text-xs px-2.5 py-1 rounded-full font-semibold"
          style={{ background: 'rgba(59,130,246,0.12)', color: '#93c5fd', border: '1px solid rgba(59,130,246,0.2)' }}>
          24h
        </span>
      </div>
      <ResponsiveContainer width="100%" height={230}>
        <AreaChart data={data} margin={{ top: 10, right: 8, left: -22, bottom: 0 }}>
          <defs>
            <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.35} />
              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
            </linearGradient>
            <filter id="glowA">
              <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
              <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" vertical={false} />
          <XAxis dataKey="hour" tickFormatter={fmtHour}
            tick={{ fontSize: 10, fill: '#334155' }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fontSize: 10, fill: '#334155' }} axisLine={false} tickLine={false} />
          <Tooltip content={<CustomTip />} />
          <Area type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2.5}
            fill="url(#alertGrad)" dot={false}
            activeDot={{ r: 5, fill: '#3b82f6', stroke: '#1d4ed8', strokeWidth: 2,
              style: { filter: 'drop-shadow(0 0 6px #3b82f6)' } }}
            name="Alerts" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ── Logs bar chart ─────────────────────────────────────── */
export function LogsBarChart({ data }) {
  const { t } = useLang()
  return (
    <div style={CARD}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
          {t('dashboard.logsPerHour')}
        </h3>
        <span className="text-xs px-2.5 py-1 rounded-full font-semibold"
          style={{ background: 'rgba(139,92,246,0.12)', color: '#c4b5fd', border: '1px solid rgba(139,92,246,0.2)' }}>
          24h
        </span>
      </div>
      <ResponsiveContainer width="100%" height={230}>
        <BarChart data={data} margin={{ top: 10, right: 8, left: -22, bottom: 0 }}>
          <defs>
            <linearGradient id="logGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%"   stopColor="#8b5cf6" stopOpacity={0.95} />
              <stop offset="100%" stopColor="#6366f1" stopOpacity={0.5} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" vertical={false} />
          <XAxis dataKey="hour" tickFormatter={fmtHour}
            tick={{ fontSize: 10, fill: '#334155' }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fontSize: 10, fill: '#334155' }} axisLine={false} tickLine={false} />
          <Tooltip content={<CustomTip />} />
          <Bar dataKey="count" fill="url(#logGrad)" radius={[4, 4, 0, 0]}
            name="Logs" maxBarSize={24} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ── Severity donut ─────────────────────────────────────── */
const RADIAN = Math.PI / 180
const DonutLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, name }) => {
  if (percent < 0.06) return null
  const r = innerRadius + (outerRadius - innerRadius) * 0.5
  const x = cx + r * Math.cos(-midAngle * RADIAN)
  const y = cy + r * Math.sin(-midAngle * RADIAN)
  return (
    <text x={x} y={y} fill="#fff" textAnchor="middle" dominantBaseline="central"
      fontSize={11} fontWeight={700}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  )
}

export function SeverityPieChart({ data }) {
  const { t } = useLang()
  const pieData = Object.entries(data || {}).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }))
  const total = pieData.reduce((s, d) => s + d.value, 0)

  return (
    <div style={CARD}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
          {t('dashboard.alertsBySeverity')}
        </h3>
        <span className="text-xs font-bold px-2.5 py-1 rounded-full"
          style={{ background: 'var(--bg-card-hover)', color: 'var(--text-secondary)' }}>
          {total} total
        </span>
      </div>
      {pieData.length === 0 ? (
        <div className="flex items-center justify-center h-48 text-sm" style={{ color: 'var(--text-muted)' }}>
          {t('dashboard.noAlertData')}
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={230}>
          <PieChart>
            <defs>
              {pieData.map((e) => (
                <filter key={e.name} id={`glow_${e.name}`}>
                  <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                  <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
              ))}
            </defs>
            <Pie data={pieData} cx="50%" cy="50%"
              innerRadius={55} outerRadius={88}
              paddingAngle={3} dataKey="value"
              labelLine={false} label={DonutLabel}>
              {pieData.map((e) => (
                <Cell key={e.name} fill={SEV_COLORS[e.name] || '#8884d8'}
                  style={{ filter: `drop-shadow(0 0 4px ${SEV_COLORS[e.name] || '#8884d8'}60)` }} />
              ))}
            </Pie>
            {/* center label */}
            <text x="50%" y="44%" textAnchor="middle" fill="var(--text-primary)" fontSize={24} fontWeight={800}
              dominantBaseline="middle">
              {total}
            </text>
            <text x="50%" y="56%" textAnchor="middle" fill="#475569" fontSize={11}
              dominantBaseline="middle">
              alerts
            </text>
            <Tooltip contentStyle={TIP}
              formatter={(v, name) => [v, t(`severity.${name}`) || name]} />
            <Legend iconType="circle" iconSize={8}
              formatter={(v) => <span style={{ color: '#94a3b8', fontSize: 11 }}>{t(`severity.${v}`) || v}</span>} />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

/* ── MITRE Tactics radar ────────────────────────────────── */
const MITRE_MAP = [
  { label: 'Initial Access',    key: 'Initial Access' },
  { label: 'Execution',         key: 'Execution' },
  { label: 'Persistence',       key: 'Persistence' },
  { label: 'Priv. Escalation',  key: 'Privilege Escalation' },
  { label: 'Def. Evasion',      key: 'Defense Evasion' },
  { label: 'Cred. Access',      key: 'Credential Access' },
  { label: 'Discovery',         key: 'Discovery' },
  { label: 'Lateral Movement',  key: 'Lateral Movement' },
  { label: 'Collection',        key: 'Collection' },
  { label: 'Exfiltration',      key: 'Exfiltration' },
  { label: 'C2',                key: 'Command and Control' },
  { label: 'Impact',            key: 'Impact' },
]

const MitreTip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const { tactic, count, fullKey } = payload[0]?.payload || {}
  return (
    <div style={{ ...TIP, minWidth: 150 }}>
      <p style={{ color: '#c4b5fd', fontWeight: 700, marginBottom: 4 }}>{fullKey || tactic}</p>
      <p style={{ color: 'var(--text-primary)', margin: 0 }}>
        Alerts: <strong>{count}</strong>
      </p>
    </div>
  )
}

export function MitreRadarChart({ data }) {
  const { t } = useLang()
  const radarData = MITRE_MAP.map(({ label, key }) => ({
    tactic:  label,
    fullKey: key,
    count:   data?.[key] || 0,
  }))
  const total = radarData.reduce((s, d) => s + d.count, 0)
  const hasData = total > 0

  return (
    <div style={CARD}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
          {t('dashboard.mitreHeatmap')}
        </h3>
        <div className="flex items-center gap-2">
          {hasData && (
            <span className="text-xs font-bold px-2.5 py-1 rounded-full"
              style={{ background: 'rgba(16,185,129,0.12)', color: '#6ee7b7', border: '1px solid rgba(16,185,129,0.2)' }}>
              {total} alerts
            </span>
          )}
          <span className="text-xs px-2.5 py-1 rounded-full font-semibold"
            style={{ background: 'rgba(139,92,246,0.12)', color: '#c4b5fd', border: '1px solid rgba(139,92,246,0.2)' }}>
            MITRE ATT&CK
          </span>
        </div>
      </div>
      {!hasData ? (
        <div className="flex flex-col items-center justify-center gap-3 py-10">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#334155" strokeWidth="1.5">
            <path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>
          </svg>
          <p className="text-sm font-semibold" style={{ color: '#334155' }}>No MITRE data yet</p>
          <p className="text-xs text-center" style={{ color: '#1e293b' }}>
            Tactics appear here once alerts with MITRE tags are generated
          </p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={270}>
          <RadarChart cx="50%" cy="50%" outerRadius={90} data={radarData}>
            <defs>
              <radialGradient id="radarFill" cx="50%" cy="50%" r="50%">
                <stop offset="0%"   stopColor="#8b5cf6" stopOpacity={0.55} />
                <stop offset="100%" stopColor="#6366f1" stopOpacity={0.08} />
              </radialGradient>
            </defs>
            <PolarGrid stroke="rgba(148,163,184,0.12)" />
            <PolarAngleAxis dataKey="tactic"
              tick={({ payload, x, y, textAnchor }) => {
                const entry = radarData.find(d => d.tactic === payload.value)
                const active = (entry?.count || 0) > 0
                return (
                  <text x={x} y={y} textAnchor={textAnchor} fontSize={10}
                    fontWeight={active ? 700 : 400}
                    fill={active ? '#a78bfa' : '#334155'}>
                    {payload.value}
                  </text>
                )
              }}
            />
            <Radar name="Detections" dataKey="count"
              stroke="#8b5cf6" strokeWidth={2}
              fill="url(#radarFill)"
              dot={({ cx, cy, payload }) => payload.count > 0 ? (
                <circle key={`${cx}-${cy}`} cx={cx} cy={cy} r={4}
                  fill="#8b5cf6" stroke="#1e1b4b" strokeWidth={1.5}
                  style={{ filter: 'drop-shadow(0 0 4px #8b5cf6)' }} />
              ) : null}
            />
            <Tooltip content={<MitreTip />} />
          </RadarChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

/* ── Severity trend stacked area ────────────────────────── */
const TREND_LAYERS = [
  { key: 'critical', color: '#ef4444', label: 'Critical' },
  { key: 'high',     color: '#f97316', label: 'High'     },
  { key: 'medium',   color: '#f59e0b', label: 'Medium'   },
  { key: 'low',      color: '#3b82f6', label: 'Low'      },
]

const TrendTip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  const total = payload.reduce((s, p) => s + (p.value || 0), 0)
  return (
    <div style={{ ...TIP, minWidth: 140 }}>
      <p style={{ color: '#94a3b8', marginBottom: 6, fontWeight: 600 }}>{label}</p>
      {[...payload].reverse().map((p) => p.value > 0 && (
        <p key={p.dataKey} style={{ color: p.color, margin: '2px 0', fontWeight: 700 }}>
          {p.name}: <span style={{ color: 'var(--text-primary)' }}>{p.value}</span>
        </p>
      ))}
      {total > 0 && (
        <p style={{ color: '#94a3b8', marginTop: 6, borderTop: '1px solid var(--border-color)',
          paddingTop: 4, fontWeight: 600 }}>
          Total: <span style={{ color: 'var(--text-primary)' }}>{total}</span>
        </p>
      )}
    </div>
  )
}

export function SeverityTrendChart({ data }) {
  const { t } = useLang()
  const hasData = (data || []).some(d =>
    TREND_LAYERS.some(({ key }) => (d[key] || 0) > 0)
  )

  return (
    <div style={CARD}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
          {t('dashboard.attackTimeline')}
        </h3>
        <div className="flex items-center gap-3">
          {TREND_LAYERS.map(({ key, color, label }) => (
            <span key={key} className="flex items-center gap-1.5 text-xs font-semibold"
              style={{ color: '#475569' }}>
              <span className="w-2 h-2 rounded-full" style={{ background: color,
                boxShadow: `0 0 4px ${color}80` }} />
              {label}
            </span>
          ))}
        </div>
      </div>
      {!hasData ? (
        <div className="flex flex-col items-center justify-center gap-3 py-10">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#334155" strokeWidth="1.5">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          <p className="text-sm font-semibold" style={{ color: '#334155' }}>No alert activity in last 24h</p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={230}>
          <AreaChart data={data || []} margin={{ top: 10, right: 8, left: -22, bottom: 0 }}>
            <defs>
              {TREND_LAYERS.map(({ key, color }) => (
                <linearGradient key={key} id={`tg_${key}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={color} stopOpacity={0.45} />
                  <stop offset="95%" stopColor={color} stopOpacity={0.02} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" vertical={false} />
            <XAxis dataKey="hour" tickFormatter={fmtHour}
              tick={{ fontSize: 10, fill: '#334155' }} axisLine={false} tickLine={false}
              interval="preserveStartEnd" />
            <YAxis tick={{ fontSize: 10, fill: '#334155' }} axisLine={false} tickLine={false}
              allowDecimals={false} />
            <Tooltip content={<TrendTip />} />
            {TREND_LAYERS.map(({ key, color, label }) => (
              <Area key={key} type="monotone" dataKey={key}
                stroke={color} strokeWidth={1.8}
                fill={`url(#tg_${key})`} dot={false}
                stackId="1" name={label}
                activeDot={{ r: 4, fill: color, strokeWidth: 0,
                  style: { filter: `drop-shadow(0 0 5px ${color})` } }}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

export { AlertsAreaChart as AlertsLineChart }
