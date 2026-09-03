/**
 * src/components/Toolbar.jsx
 * Top toolbar — scope selector, stats, pipeline trigger buttons, filter bar.
 */

import { useState, useEffect } from 'react'
import { RefreshCw, Play, Cpu, Shield, ChevronDown, Filter, Target, Network, Layers, CheckCircle, Bug, Sparkles } from 'lucide-react'
import { api } from '../api'
import './Toolbar.css'

const SEVERITY_OPTIONS = ['all', 'high', 'medium', 'low', 'info']
const TYPE_OPTIONS = [
  'all',
  // DOM sinks
  'dom_sink', 'new_function', 'attr_sink', 'navigation_sink',
  // Discovery
  'sourcemap', 'endpoint', 'endpoint_fetch',
  // Secrets
  'secret_param', 'high_entropy', 'auth_function',
  // PRD 8w — Insecure Storage
  'storage_jwt', 'storage_set', 'storage_get',
]
const REVIEW_STATUS_OPTIONS = ['all', 'unreviewed', 'checked_fp', 'checked_benign', 'confirmed_bug', 'reported']

export default function Toolbar({
  scope,
  onScopeChange,
  onRefresh,
  filters,
  onFiltersChange,
  viewMode,
  onViewModeChange,
  stats,
  loading,
}) {
  const [scopes, setScopes] = useState([])
  const [running, setRunning] = useState(null)
  const [runMsg, setRunMsg] = useState(null)
  const [showFilters, setShowFilters] = useState(false)
  const [reviewSummary, setReviewSummary] = useState(null)

  useEffect(() => {
    api.listScopes()
      .then(data => setScopes(data.scopes || []))
      .catch(console.error)
  }, [])

  // Fetch review summary whenever scope changes
  useEffect(() => {
    if (!scope) { setReviewSummary(null); return }
    fetch(`/api/scope/${scope}/review-summary`)
      .then(r => r.json())
      .then(setReviewSummary)
      .catch(() => setReviewSummary(null))
  }, [scope])

  const runPipeline = async (action, label) => {
    if (!scope || running) return
    setRunning(label)
    setRunMsg(null)
    try {
      let res
      if (action === 'extract')   res = await api.triggerExtract(scope)
      if (action === 'techstack') res = await api.triggerTechstack(scope)
      if (action === 'advisor')   res = await api.triggerAdvisor(scope)
      if (action === 'ai')        res = await api.triggerAiTriage(scope)
      setRunMsg(`✓ ${label}: ${JSON.stringify(res.summary)}`)
      onRefresh()
    } catch (err) {
      setRunMsg(`✗ ${label} failed: ${err.message}`)
    } finally {
      setRunning(null)
    }
  }

  return (
    <header className="toolbar">
      <div className="toolbar-left">
        {/* Logo */}
        <div className="toolbar-logo">
          <span className="logo-text">jxs</span>
          <span className="logo-sub">JS analysis</span>
        </div>

        {/* Scope selector */}
        <div className="scope-selector">
          <Target size={13} className="scope-icon" />
          <select
            className="select"
            value={scope || ''}
            onChange={e => onScopeChange(e.target.value)}
            id="scope-select"
          >
            <option value="">— select scope —</option>
            {scopes.map(s => (
              <option key={s.scope_name} value={s.scope_name}>
                {s.scope_name} ({s.js_file_count} JS files)
              </option>
            ))}
          </select>
        </div>

        {/* View Mode Switcher */}
        <div className="view-mode-switcher">
          <button
            className={`view-mode-btn ${viewMode === 'graph' ? 'active' : ''}`}
            onClick={() => onViewModeChange('graph')}
            title="Visual Flow Graph (n8n node view)"
          >
            <Network size={13} />
            Graph Flow
          </button>
          <button
            className={`view-mode-btn ${viewMode === 'tree' ? 'active' : ''}`}
            onClick={() => onViewModeChange('tree')}
            title="3-Column Data Flow Tree"
          >
            <Layers size={13} />
            Data Flow
          </button>
        </div>

        {/* Stats pills */}
        {stats && scope && (
          <div className="stats-row">
            <span className="stat-pill">
              <span className="stat-value">{stats.js_file_count}</span> JS files
            </span>
            {stats.severity_breakdown?.high > 0 && (
              <span className="stat-pill stat-pill-high">
                <span className="stat-value">{stats.severity_breakdown.high}</span> High
              </span>
            )}
            {stats.severity_breakdown?.medium > 0 && (
              <span className="stat-pill stat-pill-medium">
                <span className="stat-value">{stats.severity_breakdown.medium}</span> Med
              </span>
            )}
            {/* Review summary pills (PRD 8p-1) */}
            {reviewSummary && reviewSummary.breakdown?.unreviewed > 0 && (
              <span className="stat-pill stat-pill-review-unrev" title="Unreviewed findings">
                <span className="stat-value">{reviewSummary.breakdown.unreviewed}</span> unreviewed
              </span>
            )}
            {reviewSummary && reviewSummary.breakdown?.confirmed_bug > 0 && (
              <span className="stat-pill stat-pill-review-bug" title="Confirmed bugs">
                <Bug size={10} />
                <span className="stat-value">{reviewSummary.breakdown.confirmed_bug}</span> confirmed
              </span>
            )}
            {reviewSummary && reviewSummary.breakdown?.reported > 0 && (
              <span className="stat-pill stat-pill-review-reported" title="Reported findings">
                <CheckCircle size={10} />
                <span className="stat-value">{reviewSummary.breakdown.reported}</span> reported
              </span>
            )}
          </div>
        )}
      </div>

      <div className="toolbar-right">
        {/* Run message */}
        {runMsg && (
          <span className="run-msg" title={runMsg}>{runMsg.slice(0, 60)}</span>
        )}

        {/* Filter toggle */}
        <button
          className={`btn btn-ghost ${showFilters ? 'active' : ''}`}
          onClick={() => setShowFilters(f => !f)}
          id="filter-toggle-btn"
        >
          <Filter size={14} />
          Filters
          <ChevronDown size={12} style={{ transform: showFilters ? 'rotate(180deg)' : 'none', transition: '150ms' }} />
        </button>

        {/* Pipeline triggers */}
        <button
          className="btn btn-ghost"
          onClick={() => runPipeline('extract', 'Extract')}
          disabled={!scope || running !== null}
          title="Run extraction pipeline on captured JS files"
          id="run-extract-btn"
        >
          {running === 'Extract' ? <div className="loader" style={{width:14,height:14}} /> : <Play size={14} />}
          Extract
        </button>
        <button
          className="btn btn-ghost"
          onClick={() => runPipeline('techstack', 'Tech')}
          disabled={!scope || running !== null}
          title="Run tech stack detection"
          id="run-tech-btn"
        >
          {running === 'Tech' ? <div className="loader" style={{width:14,height:14}} /> : <Cpu size={14} />}
          Tech
        </button>
        <button
          className="btn btn-ghost"
          onClick={() => runPipeline('advisor', 'Advisor')}
          disabled={!scope || running !== null}
          title="Generate XSS advisories"
          id="run-advisor-btn"
        >
          {running === 'Advisor' ? <div className="loader" style={{width:14,height:14}} /> : <Shield size={14} />}
          Advisor
        </button>
        <button
          className="btn btn-ghost"
          onClick={() => runPipeline('ai', 'AI Triage')}
          disabled={!scope || running !== null}
          title="AI Triage — LLM prioritization hints for unreviewed findings (PRD 8y). Requires JXS_AI_API_KEY on the server."
          id="run-ai-btn"
        >
          {running === 'AI Triage' ? <div className="loader" style={{width:14,height:14}} /> : <Sparkles size={14} />}
          AI Triage
        </button>

        {/* Refresh */}
        <button
          className="btn btn-ghost"
          onClick={onRefresh}
          disabled={loading}
          id="refresh-btn"
        >
          <RefreshCw size={14} style={{ animation: loading ? 'spin 0.7s linear infinite' : 'none' }} />
        </button>
      </div>

      {/* ── Filter bar (collapsible) ───────────────────────────────────── */}
      {showFilters && (
        <div className="filter-bar">
          <div className="filter-group">
            <label className="filter-label">Severity</label>
            <div className="filter-pills">
              {SEVERITY_OPTIONS.map(sev => (
                <button
                  key={sev}
                  className={`filter-pill ${filters.severity === sev ? 'active' : ''} ${sev !== 'all' ? `pill-${sev}` : ''}`}
                  onClick={() => onFiltersChange({ ...filters, severity: sev })}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>
          <div className="filter-group">
            <label className="filter-label">Type</label>
            <select
              className="select filter-select"
              value={filters.type}
              onChange={e => onFiltersChange({ ...filters, type: e.target.value })}
            >
              {TYPE_OPTIONS.map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div className="filter-group">
            <label className="filter-label">Clean JS Files (0 findings)</label>
            <button
              className={`filter-pill ${filters.hide_clean ? 'active' : ''}`}
              onClick={() => onFiltersChange({ ...filters, hide_clean: !filters.hide_clean })}
            >
              {filters.hide_clean ? 'Hidden (Compact)' : 'Show All'}
            </button>
          </div>
          <div className="filter-group">
            <label className="filter-label">Whitelisted</label>
            <button
              className={`filter-pill ${filters.include_whitelisted ? 'active' : ''}`}
              onClick={() => onFiltersChange({ ...filters, include_whitelisted: !filters.include_whitelisted })}
            >
              {filters.include_whitelisted ? 'Show' : 'Hide'}
            </button>
          </div>

          {/* verify_scope_only — show only findings from test_only_hosts */}
          <div className="filter-group">
            <label className="filter-label">Scope Tag</label>
            <button
              className={`filter-pill filter-pill-verify ${filters.verify_scope_only ? 'active' : ''}`}
              onClick={() => onFiltersChange({ ...filters, verify_scope_only: !filters.verify_scope_only })}
              title="Show only findings from test_only_hosts — need scope verification before reporting"
            >
              {filters.verify_scope_only ? '⚠ verify scope' : 'All'}
            </button>
          </div>

          {/* Review status filter (PRD 8p-1) */}
          <div className="filter-group">
            <label className="filter-label">Review</label>
            <div className="filter-pills">
              {REVIEW_STATUS_OPTIONS.map(rv => (
                <button
                  key={rv}
                  className={`filter-pill ${filters.review_status === rv ? 'active' : ''} ${rv !== 'all' ? `pill-review-${rv}` : ''}`}
                  onClick={() => onFiltersChange({ ...filters, review_status: rv })}
                  title={rv === 'all' ? 'Show all review statuses' : rv}
                >
                  {rv === 'unreviewed' ? '⬜' : rv === 'confirmed_bug' ? '🐛' : rv === 'reported' ? '📤' : rv === 'checked_fp' ? '✗ fp' : rv === 'checked_benign' ? '✓ ok' : rv}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </header>
  )
}

