import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

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
export const getAlerts = (params) => api.get('/api/alerts', { params })
export const getAlert = (id) => api.get(`/api/alerts/${id}`)
export const acknowledgeAlert = (id) => api.put(`/api/alerts/${id}/acknowledge`)
export const resolveAlert = (id) => api.put(`/api/alerts/${id}/resolve`)
export const updateAlertStatus = (id, status) => {
  if (status === 'resolved') return resolveAlert(id)
  if (status === 'investigating') return acknowledgeAlert(id)
  return api.put(`/api/alerts/${id}/status`, { status })
}
export const deleteAlert = (id) => api.delete(`/api/alerts/${id}`)
export const bulkAcknowledgeAlerts = (ids) =>
  api.post('/api/alerts/bulk-acknowledge', { alert_ids: ids })

// Logs
export const getLogs = (params) => api.get('/api/logs', { params })
export const getEventTypes = () => api.get('/api/logs/event-types')

// Rules
export const getRules = () => api.get('/api/rules')
export const createRule = (data) => api.post('/api/rules', data)
export const updateRule = (id, data) => api.put(`/api/rules/${id}`, data)
export const deleteRule = (id) => api.delete(`/api/rules/${id}`)

// Active Response
export const getARPolicies   = ()         => api.get('/api/ar/policies')
export const createARPolicy  = (data)     => api.post('/api/ar/policies', data)
export const updateARPolicy  = (id, data) => api.put(`/api/ar/policies/${id}`, data)
export const deleteARPolicy  = (id)       => api.delete(`/api/ar/policies/${id}`)
export const getARExecutions = (params)   => api.get('/api/ar/executions', { params })
export const triggerAR       = (data)     => api.post('/api/ar/trigger', data)

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

// System Config (admin)
export const getSystemConfig    = ()     => api.get('/api/system/config')
export const updateSystemConfig = (data) => api.put('/api/system/config', data)
export const getAuditdScript    = ()     => `${API_BASE}/api/system/auditd-script`

// Reports / Export
export const exportAlertsCSV  = (params) => api.get('/api/reports/alerts/csv',  { params, responseType: 'blob' })
export const exportAlertsJSON = (params) => api.get('/api/reports/alerts/json', { params, responseType: 'blob' })
export const getReportSummary = (days)   => api.get('/api/reports/summary', { params: { days } })

export default api
