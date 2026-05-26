import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || '/api'

export const apiClient = axios.create({
  baseURL: BASE_URL,
  withCredentials: true,  // Send HttpOnly cookies automatically
  headers: { 'Content-Type': 'application/json' },
})

// ── Silent token refresh on 401 ───────────────────────────────────────────────
// When the access token expires the server returns 401. Before giving up we
// attempt one silent refresh using the 7-day refresh token (HttpOnly cookie).
// If that also fails the user is redirected to login.

let _refreshing: Promise<boolean> | null = null

async function tryRefresh(): Promise<boolean> {
  // Deduplicate: if multiple requests 401 simultaneously, only fire one refresh.
  if (_refreshing) return _refreshing

  _refreshing = axios
    .post(`${BASE_URL}/auth/refresh`, {}, { withCredentials: true })
    .then(() => true)
    .catch(() => false)
    .finally(() => { _refreshing = null })

  return _refreshing
}

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config

    // Only intercept 401s that haven't already been retried
    if (error.response?.status === 401 && !original._retried) {
      original._retried = true

      // Skip refresh for auth endpoints themselves to avoid loops
      if (original.url?.includes('/auth/')) {
        window.dispatchEvent(new CustomEvent('auth:unauthorized'))
        return Promise.reject(error)
      }

      const ok = await tryRefresh()
      if (ok) {
        // Retry the original request — new access cookie is now set
        return apiClient(original)
      }

      // Refresh failed → session is truly expired, send to login
      window.dispatchEvent(new CustomEvent('auth:unauthorized'))
    }

    return Promise.reject(error)
  }
)

export default apiClient
