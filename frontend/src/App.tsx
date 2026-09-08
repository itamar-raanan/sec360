import React, { Suspense, lazy, useEffect } from 'react'
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import Layout from './components/Layout/Layout'
import { useAuthStore } from './store/auth'
import { useConnectedIntegrations } from './hooks/useConnectedIntegrations'

const Login = lazy(() => import('./pages/Login'))
const AcceptInvite = lazy(() => import('./pages/AcceptInvite'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Endpoints = lazy(() => import('./pages/Endpoints'))
const Users = lazy(() => import('./pages/Users'))
const Compliance = lazy(() => import('./pages/Compliance'))
const Activity = lazy(() => import('./pages/Activity'))
const Integrations = lazy(() => import('./pages/Integrations'))
const Settings = lazy(() => import('./pages/Settings'))
const Reports = lazy(() => import('./pages/Reports'))
const SsoMfa = lazy(() => import('./pages/SsoMfa'))
const DlpUserPolicySearch = lazy(() => import('./pages/DlpUserPolicySearch'))
const ApplicationVulnerabilities = lazy(() => import('./pages/ApplicationVulnerabilities'))
const NotFound = lazy(() => import('./pages/NotFound'))

function RouteLoader() {
  return (
    <div className="flex min-h-[100dvh] items-center justify-center" style={{ background: 'var(--surface-0)' }}>
      <div className="w-full max-w-sm px-8" aria-label="Loading page">
        <div className="shimmer mx-auto h-2 w-20 rounded-full" />
        <div className="shimmer mx-auto mt-4 h-3 w-40 rounded-full opacity-70" />
      </div>
    </div>
  )
}

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

function IntegrationOnly({ integration, children }: { integration: string; children: React.ReactNode }) {
  const { connected, isLoading } = useConnectedIntegrations()
  if (isLoading) return <RouteLoader />
  if (!connected.has(integration)) return <Navigate to="/dashboard" replace />
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
    <Suspense fallback={<RouteLoader />}>
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
        <Route path="/application-vulnerabilities" element={<IntegrationOnly integration="sentinelone"><ApplicationVulnerabilities /></IntegrationOnly>} />
        <Route path="/dlp-user-policy-search" element={<AnalystOnly><IntegrationOnly integration="symantec_dlp"><DlpUserPolicySearch /></IntegrationOnly></AnalystOnly>} />
        <Route path="/reports" element={<AnalystOnly><Reports /></AnalystOnly>} />
        <Route path="/integrations" element={<AdminOnly><Integrations /></AdminOnly>} />
        <Route path="/security" element={<Navigate to="/settings" replace />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<NotFound />} />
    </Routes>
    </Suspense>
  )
}
