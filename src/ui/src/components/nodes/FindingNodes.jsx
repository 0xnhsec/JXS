/**
 * src/components/nodes/FindingNodes.jsx
 * Endpoint, DomSink, Sourcemap, TechStack node components for React Flow.
 */

import { Handle, Position } from '@xyflow/react'
import { Globe, Zap, Map, Cpu } from 'lucide-react'
import './nodes.css'

/* ── Endpoint Node ────────────────────────────────────────────────────────── */
export function EndpointNode({ data, selected }) {
  return (
    <div className={`jxs-node jxs-node-endpoint ${selected ? 'selected' : ''}`}>
      <Handle type="target" position={Position.Left} className="jxs-handle" />
      <div className="node-header">
        <Globe size={13} className="node-icon-endpoint" />
        <span className="node-title mono truncate" title={data.match_value}>
          {data.match_value}
        </span>
      </div>
      <div className="node-meta">
        <span className={`badge badge-${data.severity}`}>{data.severity}</span>
        {data.is_whitelisted && <span className="node-whitelisted">whitelisted</span>}
      </div>
      <Handle type="source" position={Position.Right} className="jxs-handle" />
    </div>
  )
}

/* ── DOM Sink Node ────────────────────────────────────────────────────────── */
export function DomSinkNode({ data, selected, onClick }) {
  return (
    <div
      className={`jxs-node jxs-node-sink node-sev-high ${selected ? 'selected' : ''}`}
      onClick={onClick}
      style={{ cursor: 'pointer' }}
    >
      <Handle type="target" position={Position.Left} className="jxs-handle" />
      <div className="node-header">
        <Zap size={13} className="node-icon-sink" />
        <span className="node-title mono truncate" title={data.match_value}>
          {data.match_value}
        </span>
      </div>
      <div className="node-meta">
        <span className="badge badge-high">DOM Sink</span>
        {data.is_whitelisted && <span className="node-whitelisted">whitelisted</span>}
      </div>
      {data.snippet && (
        <div className="node-snippet mono">{data.snippet.slice(0, 60)}…</div>
      )}
      <Handle type="source" position={Position.Right} className="jxs-handle" />
    </div>
  )
}

/* ── Sourcemap Node ───────────────────────────────────────────────────────── */
export function SourcemapNode({ data, selected }) {
  const short = (data.match_value || '').split('/').slice(-1)[0] || data.match_value
  return (
    <div className={`jxs-node jxs-node-sourcemap node-sev-high ${selected ? 'selected' : ''}`}>
      <Handle type="target" position={Position.Left} className="jxs-handle" />
      <div className="node-header">
        <Map size={13} className="node-icon-sink" />
        <span className="node-title mono truncate" title={data.match_value}>
          {short}
        </span>
      </div>
      <div className="node-meta">
        <span className="badge badge-high">Sourcemap Leak</span>
      </div>
      <Handle type="source" position={Position.Right} className="jxs-handle" />
    </div>
  )
}

/* ── Tech Stack Node ──────────────────────────────────────────────────────── */
export function TechStackNode({ data, selected }) {
  const pct = Math.round((data.confidence || 0) * 100)
  return (
    <div className={`jxs-node jxs-node-tech ${selected ? 'selected' : ''}`}>
      <Handle type="target" position={Position.Left} className="jxs-handle" />
      <div className="node-header">
        <Cpu size={13} className="node-icon-tech" />
        <span className="node-title">{data.tech_name}</span>
      </div>
      <div className="node-meta">
        <span className="node-confidence">{pct}% confidence</span>
      </div>
      <Handle type="source" position={Position.Right} className="jxs-handle" />
    </div>
  )
}
