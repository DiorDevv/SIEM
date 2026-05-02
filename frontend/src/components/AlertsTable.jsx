import React from 'react'

const SEVERITY_COLORS = {
  CRITICAL: { bg: '#fee2e2', text: '#dc2626', dot: '#dc2626' },
  HIGH: { bg: '#ffedd5', text: '#ea580c', dot: '#ea580c' },
  MEDIUM: { bg: '#fef9c3', text: '#ca8a04', dot: '#ca8a04' },
  LOW: { bg: '#dbeafe', text: '#2563eb', dot: '#2563eb' },
}

function SeverityBadge({ severity }) {
  const c = SEVERITY_COLORS[severity] || { bg: '#f3f4f6', text: '#374151', dot: '#9ca3af' }
  return (
    <span
      className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full"
      style={{ background: c.bg, color: c.text }}
    >
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: c.dot }} />
      {severity}
    </span>
  )
}

function StatusBadge({ status }) {
  const colors = {
    open: { bg: '#fee2e2', text: '#dc2626' },
    acknowledged: { bg: '#fef9c3', text: '#ca8a04' },
    resolved: { bg: '#dcfce7', text: '#16a34a' },
  }
  const c = colors[status] || { bg: '#f3f4f6', text: '#374151' }
  return (
    <span
      className="inline-flex text-xs font-medium px-2 py-0.5 rounded-full capitalize"
      style={{ background: c.bg, color: c.text }}
    >
      {status}
    </span>
  )
}

export default function AlertsTable({ alerts, onAcknowledge, onResolve, onDelete, onView, loading }) {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (!alerts || alerts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-gray-500">
        <span className="text-4xl mb-3">✅</span>
        <p className="text-base font-medium">No alerts found</p>
        <p className="text-sm mt-1">All clear — no matching alerts.</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
            {['Severity', 'Title', 'Agent', 'Rule', 'Time', 'Status', 'Actions'].map((h) => (
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
          {alerts.map((alert) => (
            <tr
              key={alert.id}
              className="border-b hover:bg-white/5 transition-colors cursor-pointer"
              style={{ borderColor: 'var(--border-color)' }}
              onClick={() => onView?.(alert)}
            >
              <td className="px-4 py-3">
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className="px-4 py-3 font-medium text-white max-w-xs truncate">
                {alert.title}
              </td>
              <td className="px-4 py-3 text-gray-300">{alert.agent_hostname || alert.agent_id}</td>
              <td className="px-4 py-3 text-gray-400">{alert.rule_name || '—'}</td>
              <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
                {alert.created_at ? new Date(alert.created_at).toLocaleString() : '—'}
              </td>
              <td className="px-4 py-3">
                <StatusBadge status={alert.status} />
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                  {alert.status === 'open' && (
                    <button
                      onClick={() => onAcknowledge?.(alert.id)}
                      className="text-xs px-2 py-1 rounded transition-colors text-yellow-400 hover:bg-yellow-400/10"
                    >
                      Ack
                    </button>
                  )}
                  {alert.status !== 'resolved' && (
                    <button
                      onClick={() => onResolve?.(alert.id)}
                      className="text-xs px-2 py-1 rounded transition-colors text-green-400 hover:bg-green-400/10"
                    >
                      Resolve
                    </button>
                  )}
                  <button
                    onClick={() => onDelete?.(alert.id)}
                    className="text-xs px-2 py-1 rounded transition-colors text-red-400 hover:bg-red-400/10"
                  >
                    Del
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export { SeverityBadge, StatusBadge }
