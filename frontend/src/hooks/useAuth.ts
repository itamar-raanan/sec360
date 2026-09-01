import { useNavigate, useLocation } from 'react-router-dom'
import { useAuthStore } from '../store/auth'

export function useAuth() {
  const navigate = useNavigate()
  const location = useLocation()
  const { user, isAuthenticated, login, logout, setAuth, restoreSession } = useAuthStore()

  const handleLogin = async (email: string, password: string, totpCode?: string) => {
    const result = await login(email, password, totpCode)
    if (!result.mfa_required) {
      const from = (location.state as { from?: { pathname?: string } })?.from?.pathname || '/dashboard'
      navigate(from, { replace: true })
    }
    return result
  }

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return {
    user,
    isAuthenticated,
    login: handleLogin as (email: string, password: string, totpCode?: string) => Promise<import('../store/auth').LoginResult>,
    logout: handleLogout,
    setAuth,
    restoreSession,
  }
}
