// Minimal fetch wrapper for the Sentinel Chain API.
const BASE = import.meta.env.VITE_API_BASE || '/api'

// Turn a backend error body ({error, message, details} or FastAPI {detail}) into an Error.
function toError(response, data) {
  let message = data?.message || data?.detail || `${response.status} ${response.statusText}`
  if (typeof message !== 'string') message = JSON.stringify(message)
  const error = new Error(message)
  error.status = response.status
  error.data = data
  error.name = data?.error || 'ApiError'
  return error
}

async function request(path, options = {}) {
  const { raw, headers, ...rest } = options
  let response
  try {
    response = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json', ...(headers || {}) },
      ...rest,
    })
  } catch (networkError) {
    const error = new Error(`Network error: ${networkError.message}`)
    error.status = 0
    throw error
  }
  const text = await response.text()
  if (raw) {
    if (!response.ok) {
      let data = null
      try { data = JSON.parse(text) } catch { data = { message: text } }
      throw toError(response, data)
    }
    return text
  }
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = { message: text }
  }
  if (!response.ok) throw toError(response, data)
  return data
}

export const api = {
  get: (path) => request(path),
  getText: (path) => request(path, { raw: true }),
  post: (path, body) => request(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined }),
  delete: (path) => request(path, { method: 'DELETE' }),
}

// Absolute URL for links that open API resources directly (e.g. markdown reports in a new tab).
export function apiUrl(path) {
  return `${BASE}${path}`
}

export default api
