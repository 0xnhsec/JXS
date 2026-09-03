/**
 * src/App.jsx
 * Root application component.
 *
 * Layout:
 *   ┌─────────────────────────────────────────────────┐
 *   │  Toolbar (scope, pipeline buttons, filters)      │
 *   ├────────────────────────────────┬────────────────┤
 *   │  GraphView (React Flow canvas) │ DetailPanel    │
 *   │                                │ (slide-in)     │
 *   └────────────────────────────────┴────────────────┘
 */

import { useState, useEffect } from 'react'
import Toolbar from './components/Toolbar'
import GraphView from './components/GraphView'
import DataFlowTree from './components/DataFlowTree'
import DetailPanel from './components/DetailPanel'
import { useGraph } from './hooks/useGraph'
import { api } from './api'
import './App.css'

const DEFAULT_FILTERS = {
  severity: 'all',
  type: 'all',
  include_whitelisted: false,
  hide_clean: true, // Default to true so 0-finding clean JS files don't stretch the layout
  review_status: 'all', // PRD 8p-1 — filter by review_status
  verify_scope_only: false, // Show only test_only_hosts findings needing scope verification
}

export default function App() {
  const [scope, setScope] = useState(() => localStorage.getItem('jxs_scope') || '')
  const [selectedNode, setSelectedNode] = useState(null)
  const [filters, setFilters] = useState(DEFAULT_FILTERS)
  const [viewMode, setViewMode] = useState('graph') // 'graph' | 'tree'
  const [stats, setStats] = useState(null)

  // Fetch graph data via custom hook
  const { nodes, edges, meta, loading, error, errorType, refetch } = useGraph(scope)

  // Persist scope selection across sessions
  useEffect(() => {
    if (scope) localStorage.setItem('jxs_scope', scope)
  }, [scope])

  // Fetch scope stats whenever scope changes
  useEffect(() => {
    if (!scope) { setStats(null); return }
    api.getStats(scope).then(setStats).catch(() => setStats(null))
  }, [scope])

  // Apply client-side filters to nodes
  const filteredNodes = nodes.filter(node => {
    // Hide clean JS files if filter enabled
    if (filters.hide_clean && node.type === 'jsFile' && node.data.finding_count === 0) {
      return false
    }

    if (filters.severity !== 'all') {
      // For jsFile nodes, filter by worst_severity
      if (node.type === 'jsFile') {
        if (node.data.worst_severity !== filters.severity) return false
      }
      // For finding nodes, filter by their severity
      if (['endpoint', 'domSink', 'sourcemap'].includes(node.type)) {
        if (node.data.severity !== filters.severity) return false
      }
    }
    if (filters.type !== 'all') {
      const typeMap = {
        dom_sink:       'domSink',
        sourcemap:      'sourcemap',
        endpoint:       'endpoint',
        endpoint_fetch: 'endpoint',
      }
      if (['endpoint', 'domSink', 'sourcemap'].includes(node.type)) {
        if (node.type !== (typeMap[filters.type] || filters.type)) return false
      }
    }

    // PRD 8p-1 — filter by review_status (only applies to finding nodes)
    if (filters.review_status !== 'all') {
      if (['endpoint', 'domSink', 'sourcemap', 'highEntropy', 'authFunction'].includes(node.type)) {
        if (node.data.review_status !== filters.review_status) return false
      }
      // jsFile nodes: hide if none of its findings match the review_status
      // (we don't have per-file breakdown here, so only filter finding nodes)
    }

    // verify_scope_only — show only findings from test_only_hosts
    if (filters.verify_scope_only) {
      if (['endpoint', 'domSink', 'sourcemap', 'highEntropy', 'authFunction'].includes(node.type)) {
        if (!node.data.verify_scope) return false
      }
      if (node.type === 'jsFile') {
        // Hide jsFile nodes that have no verify_scope findings
        if (!node.data.verify_scope) return false
      }
    }

    return true
  })

  // Only keep edges where both source and target are in filtered set
  const filteredNodeIds = new Set(filteredNodes.map(n => n.id))
  const filteredEdges = edges.filter(
    e => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target)
  )

  const handleScopeChange = (newScope) => {
    setScope(newScope)
    setSelectedNode(null)
  }

  const handleRefresh = () => {
    refetch()
    if (scope) api.getStats(scope).then(setStats).catch(() => {})
  }

  return (
    <div className="app-layout">
      <Toolbar
        scope={scope}
        onScopeChange={handleScopeChange}
        onRefresh={handleRefresh}
        filters={filters}
        onFiltersChange={setFilters}
        viewMode={viewMode}
        onViewModeChange={setViewMode}
        stats={stats}
        loading={loading}
      />

      <div className="app-body">
        {viewMode === 'graph' ? (
          <GraphView
            scope={scope}
            externalNodes={filteredNodes}
            externalEdges={filteredEdges}
            loading={loading}
            error={error}
            errorType={errorType}
            onNodeSelect={setSelectedNode}
          />
        ) : (
          <DataFlowTree
            nodes={filteredNodes}
            edges={filteredEdges}
            onNodeSelect={setSelectedNode}
            loading={loading}
            error={error}
            errorType={errorType}
          />
        )}

        {selectedNode && (
          <DetailPanel
            node={selectedNode}
            onClose={() => setSelectedNode(null)}
          />
        )}
      </div>
    </div>
  )
}

