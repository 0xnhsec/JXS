/**
 * src/components/GraphView.jsx
 * Main React Flow graph canvas with all custom node types.
 */

import { useCallback, useMemo } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'

import JsFileNode from './nodes/JsFileNode'
import { EndpointNode, DomSinkNode, SourcemapNode, TechStackNode } from './nodes/FindingNodes'
import { applyDagreLayout } from '../hooks/useGraph'
import './GraphView.css'

const NODE_TYPES = {
  jsFile:    JsFileNode,
  endpoint:  EndpointNode,
  domSink:   DomSinkNode,
  sourcemap: SourcemapNode,
  techStack: TechStackNode,
}

const MINIMAP_NODE_COLOR = (node) => {
  const colorMap = {
    jsFile:    node.data?.worst_severity === 'high' ? '#ef4444' : '#1e293b',
    endpoint:  '#064e3b',
    domSink:   '#ef4444',
    sourcemap: '#ef4444',
    techStack: '#4c1d95',
  }
  return colorMap[node.type] || '#1e293b'
}

export default function GraphView({ scope, onNodeSelect, externalNodes, externalEdges, loading, error, errorType }) {
  // Dynamically recalculate compact layout for filtered nodes
  const laidOutNodes = useMemo(() => {
    if (!externalNodes || externalNodes.length === 0) return []
    return applyDagreLayout(externalNodes, externalEdges || [])
  }, [externalNodes, externalEdges])


  const onNodeClick = useCallback((_, node) => {
    onNodeSelect?.(node)
  }, [onNodeSelect])

  const onPaneClick = useCallback(() => {
    onNodeSelect?.(null)
  }, [onNodeSelect])

  if (loading) {
    return (
      <div className="graph-placeholder">
        <div className="loader" style={{ width: 32, height: 32 }} />
        <p>Loading graph…</p>
      </div>
    )
  }

  // ── API truly down / network error ────────────────────────────────────────
  if (error && errorType === 'network') {
    return (
      <div className="graph-placeholder">
        <div className="graph-empty-icon" style={{ color: '#ef4444' }}>⚡</div>
        <p className="graph-error">Cannot reach jxs API</p>
        <p className="graph-hint">
          Start the API server:<br />
          <code className="mono">uvicorn src.api.main:app --host 127.0.0.1 --port 8888</code>
        </p>
      </div>
    )
  }

  // ── Unknown API error ──────────────────────────────────────────────────────
  if (error && errorType === 'unknown') {
    return (
      <div className="graph-placeholder">
        <p className="graph-error">⚠ {error}</p>
      </div>
    )
  }

  // ── Scope not yet populated (404 = no JS files captured yet) ──────────────
  if (error && errorType === 'empty') {
    return (
      <div className="graph-placeholder graph-empty-scope">
        <div className="graph-empty-icon">◌</div>
        <p className="graph-empty-title">Scope <code className="mono">{scope}</code> belum ada data</p>
        <p className="graph-hint graph-hint-sub">
          Jalankan scan dulu untuk capture JS files:
        </p>
        <div className="graph-empty-cmds">
          <div className="graph-empty-cmd-block">
            <span className="graph-empty-cmd-label">Option 1 — katana bulk scan (semua host sekaligus)</span>
            <code className="mono">python3 -m src.cli.jxs_cli scan --scope {scope} --katana-all --katana-depth 2</code>
          </div>
          <div className="graph-empty-cmd-block">
            <span className="graph-empty-cmd-label">Option 2 — katana single URL</span>
            <code className="mono">python3 -m src.cli.jxs_cli scan --scope {scope} --katana-url https://target.com</code>
          </div>
          <div className="graph-empty-cmd-block">
            <span className="graph-empty-cmd-label">Option 3 — passive capture via mitmproxy (browse target di Burp)</span>
            <code className="mono">mitmdump -s src/capture/jxs_mitm_addon.py -p 8082 --mode upstream:http://127.0.0.1:8080</code>
          </div>
        </div>
        <p className="graph-hint graph-hint-running">
          Jika scan sedang berjalan, tunggu selesai lalu klik <strong>Refresh</strong> ↻
        </p>
      </div>
    )
  }

  if (!scope) {
    return (
      <div className="graph-placeholder">
        <div className="graph-empty-icon">⬡</div>
        <p className="graph-empty-title">No scope selected</p>
        <p className="graph-hint">Select a scope from the toolbar to visualize its JS graph.</p>
      </div>
    )
  }

  if (!externalNodes || externalNodes.length === 0) {
    return (
      <div className="graph-placeholder">
        <div className="graph-empty-icon">◌</div>
        <p className="graph-empty-title">No data for scope "{scope}"</p>
        <p className="graph-hint">
          All JS files captured but filtered out by current filters.<br />
          Try resetting severity / type filters.
        </p>
      </div>
    )
  }

  return (
    <div className="graph-container">
      <ReactFlow
        nodes={laidOutNodes}
        edges={externalEdges}
        onNodeClick={onNodeClick}
        onPaneClick={onPaneClick}
        nodeTypes={NODE_TYPES}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.1}
        maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
      >

        <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="rgba(255,255,255,0.04)" />
        <Controls showInteractive={false} />
        <MiniMap
          nodeColor={MINIMAP_NODE_COLOR}
          maskColor="rgba(10,11,14,0.7)"
          style={{ bottom: 16, right: 16 }}
        />
      </ReactFlow>

      {/* Node count overlay */}
      <div className="graph-overlay-stats">
        <span>{externalNodes.length} nodes</span>
        <span>{externalEdges.length} edges</span>
      </div>
    </div>
  )
}
