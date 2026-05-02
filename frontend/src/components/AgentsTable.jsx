import React from 'react'

function StatusDot({ status }) {
  const color = status === 'online' ? '#22c55e' : status === 'offline' ? '#ef4444' : '#f59e0b'
  return (
    <span className="inline-flex items-center gap-2">
      <span className="w-2 h-2 rounded-full" style={{ background: color }} />
      <span className="capitalize text-sm" style={{ color }}>
        {status}
      </span>
    </span>
  )
}

export default function AgentsTable({ agents, onDelete, onView, loading }) {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (!agents || agents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-gray-500">
        <span className="text-4xl mb-3">🖥️</span>
        <p className="text-base font-medium">No agents connected</p>
        <p className="text-sm mt-1">Deploy an agent to start monitoring.</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
            {['Hostname', 'IP Address', 'OS', 'Version', 'Status', 'Last Seen', 'Actions'].map((h) => (
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
          {agents.map((agent) => (
            <tr
              key={agent.id}
              className="border-b hover:bg-white/5 transition-colors cursor-pointer"
              style={{ borderColor: 'var(--border-color)' }}
              onClick={() => onView?.(agent)}
            >
              <td className="px-4 py-3 font-medium text-white">{agent.hostname}</td>
              <td className="px-4 py-3 text-gray-300 font-mono">{agent.ip_address}</td>
              <td className="px-4 py-3 text-gray-400">{agent.os || '—'}</td>
              <td className="px-4 py-3 text-gray-400">{agent.agent_version || '—'}</td>
              <td className="px-4 py-3">
                <StatusDot status={agent.status} />
              </td>
              <td className="px-4 py-3 text-gray-400">
                {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : '—'}
              </td>
              <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                <button
                  onClick={() => onDelete?.(agent)}
                  className="text-xs px-2 py-1 rounded text-red-400 hover:bg-red-400/10 transition-colors"
                >
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
