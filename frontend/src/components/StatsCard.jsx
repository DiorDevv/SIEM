import React, { useEffect, useRef, useState } from 'react'

function useCountUp(target, duration = 900) {
  const [value, setValue] = useState(0)
  const prev = useRef(0)
  useEffect(() => {
    const start = prev.current
    const end = Number(target) || 0
    prev.current = end
    if (start === end) { setValue(end); return }
    const startTime = performance.now()
    const tick = (now) => {
      const p = Math.min((now - startTime) / duration, 1)
      const e = 1 - Math.pow(1 - p, 3)
      setValue(Math.round(start + (end - start) * e))
      if (p < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  }, [target, duration])
  return value
}

const palette = {
  blue:   { bg: 'rgba(59,130,246,0.1)',  border: 'rgba(59,130,246,0.25)',  accent: '#3b82f6',  icon: 'rgba(59,130,246,0.2)'  },
  green:  { bg: 'rgba(16,185,129,0.1)',  border: 'rgba(16,185,129,0.25)',  accent: '#10b981',  icon: 'rgba(16,185,129,0.2)'  },
  orange: { bg: 'rgba(249,115,22,0.1)',  border: 'rgba(249,115,22,0.25)',  accent: '#f97316',  icon: 'rgba(249,115,22,0.2)'  },
  red:    { bg: 'rgba(239,68,68,0.1)',   border: 'rgba(239,68,68,0.25)',   accent: '#ef4444',  icon: 'rgba(239,68,68,0.2)'   },
  purple: { bg: 'rgba(139,92,246,0.1)',  border: 'rgba(139,92,246,0.25)',  accent: '#8b5cf6',  icon: 'rgba(139,92,246,0.2)'  },
  indigo: { bg: 'rgba(99,102,241,0.1)',  border: 'rgba(99,102,241,0.25)',  accent: '#6366f1',  icon: 'rgba(99,102,241,0.2)'  },
  gray:   { bg: 'rgba(107,114,128,0.1)', border: 'rgba(107,114,128,0.25)', accent: '#6b7280',  icon: 'rgba(107,114,128,0.2)' },
  cyan:   { bg: 'rgba(6,182,212,0.1)',   border: 'rgba(6,182,212,0.25)',   accent: '#06b6d4',  icon: 'rgba(6,182,212,0.2)'   },
}

export default function StatsCard({ title, value, subtitle, color = 'blue', svgIcon }) {
  const animated = useCountUp(value)
  const c = palette[color] || palette.blue

  return (
    <div
      className="glass-card-hover rounded-2xl p-5 cursor-default"
      style={{ background: c.bg, border: `1px solid ${c.border}` }}
    >
      <div className="flex items-start justify-between mb-4">
        <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>{title}</p>
        {svgIcon && (
          <div
            className="w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: c.icon, color: c.accent }}
          >
            {svgIcon}
          </div>
        )}
      </div>
      <div className="text-3xl font-extrabold mb-1" style={{ color: c.accent }}>
        {typeof value === 'string' ? value : animated.toLocaleString()}
      </div>
      {subtitle && (
        <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{subtitle}</p>
      )}
    </div>
  )
}
