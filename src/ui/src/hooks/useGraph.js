/**
 * src/hooks/useGraph.js
 * Custom hook: fetch graph data and apply dagre auto-layout for React Flow.
 */

import { useState, useEffect, useCallback } from 'react'
import dagre from '@dagrejs/dagre'
import { api } from '../api'

// Node size estimates for dagre layout — smaller values = tighter packing.
// These are hints to dagre's algorithm, not the actual rendered card size.
const NODE_SIZES = {
  jsFile:    { width: 200, height: 52 },
  endpoint:  { width: 160, height: 36 },
  domSink:   { width: 180, height: 44 },
  sourcemap: { width: 180, height: 44 },
  techStack: { width: 140, height: 36 },
  default:   { width: 160, height: 40 },
}

export function applyDagreLayout(nodes, edges) {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({
    rankdir: 'LR',     // left-to-right: JS files → findings
    nodesep: 18,       // vertical gap between nodes in same rank
    ranksep: 55,       // horizontal gap between ranks (JS file → finding)
    marginx: 24,
    marginy: 24,
  })

  nodes.forEach((node) => {
    const size = NODE_SIZES[node.type] || NODE_SIZES.default
    g.setNode(node.id, size)
  })
  edges.forEach((edge) => {
    g.setEdge(edge.source, edge.target)
  })

  dagre.layout(g)

  return nodes.map((node) => {
    const pos = g.node(node.id)
    const size = NODE_SIZES[node.type] || NODE_SIZES.default
    return {
      ...node,
      position: {
        x: pos.x - size.width / 2,
        y: pos.y - size.height / 2,
      },
    }
  })
}

export function useGraph(scope) {
  const [nodes, setNodes] = useState([])
  const [edges, setEdges] = useState([])
  const [meta, setMeta] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [errorType, setErrorType] = useState(null) // 'network' | 'empty' | 'unknown'

  const fetchGraph = useCallback(async () => {
    if (!scope) return
    setLoading(true)
    setError(null)
    setErrorType(null)
    try {
      const data = await api.getGraph(scope)
      setNodes(data.nodes)
      setEdges(data.edges)
      setMeta({ total_js_files: data.total_js_files, total_findings: data.total_findings })
    } catch (err) {
      const msg = err.message || ''
      // 'Failed to fetch' = network/CORS/API truly down
      // 'No JS files found' = 404 from API = scope exists but empty
      if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('ERR_CONNECTION')) {
        setErrorType('network')
      } else if (msg.includes('No JS files') || msg.includes('404') || msg.includes('not found')) {
        setErrorType('empty')
      } else {
        setErrorType('unknown')
      }
      setError(msg)
    } finally {
      setLoading(false)
    }
  }, [scope])

  useEffect(() => {
    fetchGraph()
  }, [fetchGraph])

  return { nodes, edges, meta, loading, error, errorType, refetch: fetchGraph, applyDagreLayout }
}

