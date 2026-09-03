/**
 * src/api.js
 * API client for jxs FastAPI backend (proxied via Vite at /api/*)
 */

const BASE = '/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  health:       ()           => request('/health'),
  listScopes:   ()           => request('/scopes'),
  createScope:  (data)       => request('/scopes', { method: 'POST', body: JSON.stringify(data) }),
  getGraph:     (scope)      => request(`/scope/${scope}/graph`),
  getFindings:  (scope, params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return request(`/scope/${scope}/findings${qs ? '?' + qs : ''}`)
  },
  getStats:     (scope)      => request(`/scope/${scope}/stats`),
  getJsFile:    (id)         => request(`/js-file/${id}`),
  getJsContent: (id)         => request(`/js-file/${id}/content`),
  triggerExtract:  (scope)   => request(`/extract/${scope}`, { method: 'POST' }),
  triggerTechstack:(scope)   => request(`/techstack/${scope}`, { method: 'POST' }),
  triggerAdvisor:  (scope)   => request(`/advisor/${scope}`, { method: 'POST' }),
  dbStats:      ()           => request('/db/stats'),
}
