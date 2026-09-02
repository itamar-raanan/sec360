import React, { useEffect } from 'react'
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import Layout from './components/Layout/Layout'
import Login from './pages/Login'
import AcceptInvite from './pages/AcceptInvite'
import Dashboard from './pages/Dashboard'
import Endpoints from './pages/Endpoints'
import Users from './pages/Users'
import Compliance from './pages/Compliance'
import Activity from './pages/Activity'
import Integrations from './pages/Integrations'
import Settings from './pages/Settings'
import Reports from './pages/Reports'
import SsoMfa from './pages/SsoMfa'
import AIInsights from './pages/AIInsights'
import AIChat from './pages/AIChat'
import Investigation from './pages/Investigation'
import DlpUserPolicySearch from './pages/DlpUserPolicySearch'
import { useAuthStore } from './store/auth'

function AdminOnly({ children }: { children: React.ReactNode }) {
  const { user } = useAuthStore()
  if (user?.role !== 'admin') return <Navigate to="/dashboard" replace />
  return <>{children}</>
}

function AnalystOnly({ children }: { children: React.ReactNode }) {
  const { user } = useAuthStore()
  if (!user || user.role === 'viewer') return <Navigate to="/dashboard" replace />
  return <>{children}</>
}

export default function App() {
  const navigate = useNavigate()
  const { restoreSession } = useAuthStore()

  useEffect(() => {
    restoreSession()
    const PUBLIC_PATHS = ['/login', '/accept-invite', '/sso-mfa']
    const onUnauthorized = () => {
      if (!PUBLIC_PATHS.some(p => window.location.pathname.startsWith(p))) {
        navigate('/login', { replace: true })
      }
    }
    window.addEventListener('auth:unauthorized', onUnauthorized)
    return () => window.removeEventListener('auth:unauthorized', onUnauthorized)
  }, [navigate, restoreSession])

  return (
    <Routes>
      {/* Public routes */}
      <Route path="/login" element={<Login />} />
      <Route path="/accept-invite" element={<AcceptInvite />} />
      <Route path="/sso-mfa" element={<SsoMfa />} />

      {/* Authenticated routes */}
      <Route element={<Layout />}>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/endpoints" element={<Endpoints />} />
        <Route path="/users" element={<Users />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/activity" element={<Activity />} />
        <Route path="/investigation" element={<Investigation />} />
        <Route path="/dlp-user-policy-search" element={<AnalystOnly><DlpUserPolicySearch /></AnalystOnly>} />
        <Route path="/ai-insights" element={<AnalystOnly><AIInsights /></AnalystOnly>} />
        <Route path="/ai-chat" element={<AIChat />} />
        <Route path="/reports" element={<AnalystOnly><Reports /></AnalystOnly>} />
        <Route path="/integrations" element={<AdminOnly><Integrations /></AdminOnly>} />
        <Route path="/security" element={<Navigate to="/settings" replace />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}
