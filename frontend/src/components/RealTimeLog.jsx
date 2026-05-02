import React from 'react'

const LEVEL_COLORS = {
  CRITICAL: '#dc2626',
  ERROR: '#ea580c',
  WARNING: '#ca8a04',
  INFO: '#3B82F6',
  DEBUG: '#6b7280',
}

export default function RealTimeLog({ logs }) {
  if (!logs || logs.length === 0) {
    return (
      <div className="flex items-center justify-center py-8 text-gray-500 text-sm">
        Waiting for live logs...
      </div>
    )
  }

  return (
    <div className="font-mono text-xs space-y-1 max-h-64 overflow-y-auto">
      {logs.map((log, idx) => {
        const color = LEVEL_COLORS[log.level?.toUpperCase()] || '#e2e8f0'
        const ts = log.timestamp
          ? new Date(log.timestamp).toLocaleTimeString()
          : '??:??:??'
        return (
          <div key={idx} className="flex gap-3 py-1 border-b border-white/5">
            <span className="text-gray-500 flex-shrink-0 w-20">{ts}</span>
            <span className="flex-shrink-0 w-16 font-semibold" style={{ color }}>
              [{log.level || 'INFO'}]
            </span>
            <span className="text-gray-400 flex-shrink-0 w-24 truncate">
              {log.agent_id || '—'}
            </span>
            <span className="text-gray-200 truncate">{log.message || '—'}</span>
          </div>
        )
      })}
    </div>
  )
}
