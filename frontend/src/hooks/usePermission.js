import { useAuth } from '../context/AuthContext'

const ROLE_LEVELS = { viewer: 0, analyst: 1, admin: 2 }

export function usePermission() {
  const { user } = useAuth()
  const level = ROLE_LEVELS[user?.role] ?? 0

  const can = (minRole) => level >= (ROLE_LEVELS[minRole] ?? 0)

  return {
    can,
    isAdmin:   user?.role === 'admin',
    isAnalyst: level >= ROLE_LEVELS.analyst,
    isViewer:  user?.role === 'viewer',
    role:      user?.role,
  }
}
