import React from 'react'

const LEVEL_COLORS = {
  CRITICAL: { bg: '#fee2e2', text: '#dc2626' },
  ERROR: { bg: '#ffedd5', text: '#ea580c' },
  WARNING: { bg: '#fef9c3', text: '#ca8a04' },
  INFO: { bg: '#dbeafe', text: '#2563eb' },
  DEBUG: { bg: '#f3f4f6', text: '#6b7280' },
}

function LevelBadge({ level }) {
  const c = LEVEL_COLORS[level?.toUpperCase()] || LEVEL_COLORS.INFO
  return (
    <span
      className="inline-flex text-xs font-semibold px-2 py-0.5 rounded"
      style={{ background: c.bg, color: c.text }}
    >
      {level || 'INFO'}
    </span>
  )
}

export default function LogsTable({ logs, onView, loading }) {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (!logs || logs.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-gray-500">
        <span className="text-4xl mb-3">📋</span>
        <p className="text-base font-medium">No logs found</p>
        <p className="text-sm mt-1">Adjust your filters or wait for new logs.</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
            {['Time', 'Agent', 'Level', 'Source', 'Message'].map((h) => (
              <th
                key={h}
                className="text-left px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {logs.map((log, idx) => (
            <tr
              key={log.id || idx}
              className="border-b hover:bg-white/5 transition-colors cursor-pointer"
              style={{ borderColor: 'var(--border-color)' }}
              onClick={() => onView?.(log)}
            >
              <td className="px-4 py-2 text-gray-400 whitespace-nowrap text-xs font-mono">
                {log.timestamp ? new Date(log.timestamp).toLocaleString() : '—'}
              </td>
              <td className="px-4 py-2 text-gray-300">{log.agent_id || '—'}</td>
              <td className="px-4 py-2">
                <LevelBadge level={log.level} />
              </td>
              <td className="px-4 py-2 text-gray-400">{log.source || '—'}</td>
              <td className="px-4 py-2 text-gray-200 max-w-xl truncate">
                {log.message || '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
