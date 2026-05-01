import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || ''

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true
      const refreshToken = localStorage.getItem('refresh_token')
      if (refreshToken) {
        try {
          const resp = await axios.post(`${API_BASE}/api/auth/refresh`, {
            refresh_token: refreshToken,
          })
          localStorage.setItem('access_token', resp.data.access_token)
          localStorage.setItem('refresh_token', resp.data.refresh_token)
          original.headers.Authorization = `Bearer ${resp.data.access_token}`
          return api(original)
        } catch {
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
          window.location.href = '/login'
        }
      } else {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

// Auth
export const login = (username, password) => {
  const form = new FormData()
  form.append('username', username)
  form.append('password', password)
  return axios.post(`${API_BASE}/api/auth/login`, form)
}
export const logout = () => api.post('/api/auth/logout')
export const getMe = () => api.get('/api/auth/me')
export const changePassword = (data) => api.post('/api/auth/change-password', data)

// Dashboard
export const getDashboardStats = () => api.get('/api/dashboard/stats')
export const getSystemInfo = () => api.get('/api/dashboard/system-info')

// Agents
export const getAgents = (params) => api.get('/api/agents', { params })
export const getAgent = (id) => api.get(`/api/agents/${id}`)
export const deleteAgent = (id) => api.delete(`/api/agents/${id}`)

// Alerts
export const getAlerts       = (params)       => api.get('/api/alerts', { params })
export const getAlert        = (id)           => api.get(`/api/alerts/${id}`)
export const updateAlertStatus = (id, status, note) =>
  api.put(`/api/alerts/${id}/status`, { status, note })
export const assignAlert     = (id, userId)   => api.put(`/api/alerts/${id}/assign`, { user_id: userId })
export const deleteAlert     = (id)           => api.delete(`/api/alerts/${id}`)
export const getAlertNotes   = (id)           => api.get(`/api/alerts/${id}/notes`)
export const addAlertNote    = (id, body)     => api.post(`/api/alerts/${id}/notes`, { body })
export const bulkAlertAction = (data)         => api.post('/api/alerts/bulk-action', data)
export const getAlertStats   = (days = 7)     => api.get('/api/alerts/stats/summary', { params: { days } })
// backward compat
export const acknowledgeAlert = (id) => updateAlertStatus(id, 'acknowledged')
export const resolveAlert     = (id) => updateAlertStatus(id, 'resolved')
export const bulkAcknowledgeAlerts = (ids) =>
  bulkAlertAction({ alert_ids: ids, action: 'acknowledge' })

// Logs
export const getLogs        = (params) => api.get('/api/logs',             { params })
export const getEventTypes  = ()       => api.get('/api/logs/event-types')
export const getLogSources  = ()       => api.get('/api/logs/sources')
export const getLogStats    = (hours)  => api.get('/api/logs/stats',        { params: { hours } })
export const getLogTimeline = (hours)  => api.get('/api/logs/timeline',     { params: { hours } })
export const exportLogsCSV  = (params) => api.get('/api/logs/export/csv',   { params, responseType: 'blob' })

// Rules
export const getRules = () => api.get('/api/rules')
export const createRule = (data) => api.post('/api/rules', data)
export const updateRule = (id, data) => api.put(`/api/rules/${id}`, data)
export const deleteRule = (id) => api.delete(`/api/rules/${id}`)
export const testRule = (id, sampleLogs) => api.post(`/api/rules/${id}/test`, { sample_logs: sampleLogs })

// Active Response
export const getARPolicies       = (params)    => api.get('/api/ar/policies', { params })
export const createARPolicy      = (data)      => api.post('/api/ar/policies', data)
export const updateARPolicy      = (id, data)  => api.put(`/api/ar/policies/${id}`, data)
export const deleteARPolicy      = (id)        => api.delete(`/api/ar/policies/${id}`)
export const cloneARPolicy       = (id)        => api.post(`/api/ar/policies/${id}/clone`)
export const bulkToggleARPolicies= (data)      => api.post('/api/ar/policies/bulk-toggle', data)
export const getARExecutions     = (params)    => api.get('/api/ar/executions', { params })
export const getARExecution      = (id)        => api.get(`/api/ar/executions/${id}`)
export const cancelARExecution   = (id)        => api.delete(`/api/ar/executions/${id}`)
export const retryARExecution    = (id)        => api.post(`/api/ar/executions/${id}/retry`)
export const triggerAR           = (data)      => api.post('/api/ar/trigger', data)
export const getARStats          = ()          => api.get('/api/ar/stats')
export const getARTemplates      = ()          => api.get('/api/ar/templates')

// Vulnerabilities
export const getVulns         = (params)       => api.get('/api/vulns', { params })
export const getVulnSummary   = ()             => api.get('/api/vulns/summary')
export const updateVulnStatus = (id, status)   => api.put(`/api/vulns/${id}/status`, { status })
export const exportVulnsCSV   = (params)       => api.get('/api/reports/vulns/csv', { params, responseType: 'blob' })

// SCA
export const getSCAScans      = (params) => api.get('/api/sca', { params })
export const getLatestSCAScans= ()       => api.get('/api/sca/latest')
export const getSCASummary    = ()       => api.get('/api/sca/summary')
export const exportSCACSV     = (params) => api.get('/api/reports/sca/csv', { params, responseType: 'blob' })

// Users (admin only)
export const getUsers         = ()           => api.get('/api/users')
export const createUser       = (data)       => api.post('/api/users', data)
export const updateUser       = (id, data)   => api.put(`/api/users/${id}`, data)
export const deleteUser       = (id)         => api.delete(`/api/users/${id}`)
export const adminResetPw     = (id, pw)     => api.post(`/api/users/${id}/reset-password`, { new_password: pw })

// Audit Log (admin only)
export const getAuditLogs    = (params) => api.get('/api/audit', { params })
export const getAuditActions = ()       => api.get('/api/audit/actions')
export const exportAuditCSV  = (params) => api.get('/api/audit/csv', { params, responseType: 'blob' })

// 2FA / TOTP
export const totpSetup            = ()           => api.post('/api/auth/totp/setup')
export const totpVerifySetup      = (code)       => api.post('/api/auth/totp/verify-setup', { code })
export const totpLogin            = (temp_token, code) => api.post('/api/auth/totp/login', { temp_token, code })
export const totpDisable          = (password, code) => api.delete('/api/auth/totp/disable', { data: { password, code } })
export const totpRegenerateCodes  = (code)       => api.post('/api/auth/totp/backup-codes/regenerate', { code })
export const totpBackupCodesCount = ()           => api.get('/api/auth/totp/backup-codes/count')

// Health check
export const getSystemHealth    = ()     => api.get('/api/health')

// System Config (admin)
export const getSystemConfig    = ()     => api.get('/api/system/config')
export const updateSystemConfig = (data) => api.put('/api/system/config', data)
export const getAuditdScript    = ()     => `${API_BASE}/api/system/auditd-script`

// Reports / Export
export const exportAlertsCSV  = (params) => api.get('/api/reports/alerts/csv',  { params, responseType: 'blob' })
export const exportAlertsJSON = (params) => api.get('/api/reports/alerts/json', { params, responseType: 'blob' })
export const getReportSummary = (days)   => api.get('/api/reports/summary', { params: { days } })

// Inventory
export const getInventoryAgents     = ()              => api.get('/api/inventory/agents')
export const getInventorySummary    = (agentId)       => api.get(`/api/inventory/${agentId}`)
export const getInventoryPackages   = (agentId, p)    => api.get(`/api/inventory/${agentId}/packages`,  { params: p })
export const getInventoryPorts      = (agentId, p)    => api.get(`/api/inventory/${agentId}/ports`,     { params: p })
export const getInventoryProcesses  = (agentId, p)    => api.get(`/api/inventory/${agentId}/processes`, { params: p })
export const getInventoryInterfaces = (agentId)       => api.get(`/api/inventory/${agentId}/interfaces`)

// Case Management
export const getCaseStats       = ()              => api.get('/api/cases/stats')
export const getCases           = (params)        => api.get('/api/cases', { params })
export const getCase            = (id)            => api.get(`/api/cases/${id}`)
export const createCase         = (data)          => api.post('/api/cases', data)
export const updateCase         = (id, data)      => api.put(`/api/cases/${id}`, data)
export const deleteCaseById     = (id)            => api.delete(`/api/cases/${id}`)
export const changeCaseStatus   = (id, status, note) => api.post(`/api/cases/${id}/status`, { status, note })
export const assignCase         = (id, userId, userName) => api.post(`/api/cases/${id}/assign`, { user_id: userId, user_name: userName })
export const addCaseNote        = (id, data)      => api.post(`/api/cases/${id}/notes`, data)
export const deleteCaseNote     = (caseId, noteId) => api.delete(`/api/cases/${caseId}/notes/${noteId}`)
export const linkCaseAlert      = (caseId, alertId) => api.post(`/api/cases/${caseId}/alerts/${alertId}`)
export const unlinkCaseAlert    = (caseId, alertId) => api.delete(`/api/cases/${caseId}/alerts/${alertId}`)

export default api
