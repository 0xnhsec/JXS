/**
 * src/components/nodes/JsFileNode.jsx
 * React Flow custom node — represents a captured JavaScript file.
 *
 * Color coding:
 *   High findings    → red border + glow
 *   Medium findings  → amber border
 *   Low/Info         → default gray border
 *   No findings      → subtle gray
 */

import { Handle, Position } from '@xyflow/react'
import { FileCode2, AlertTriangle, CheckCircle2 } from 'lucide-react'
import './nodes.css'

const SEV_CLASS = {
  high:   'node-sev-high',
  medium: 'node-sev-medium',
  low:    'node-sev-low',
  info:   'node-sev-info',
}

export default function JsFileNode({ data, selected }) {
  const sev = data.worst_severity || 'info'
  const sevClass = SEV_CLASS[sev] || 'node-sev-info'

  // Extract short filename from URL
  const urlParts = (data.url || '').split('/')
  const filename = urlParts[urlParts.length - 1].split('?')[0] || 'unknown.js'
  const host = data.host || ''
  const sizeKb = data.size_bytes ? Math.round(data.size_bytes / 1024) : 0

  return (
    <div className={`jxs-node jxs-node-jsfile ${sevClass} ${selected ? 'selected' : ''}`}>
      <Handle type="target" position={Position.Left} className="jxs-handle" />

      <div className="node-header">
        <FileCode2 size={14} className="node-icon" />
        <span className="node-title truncate" title={data.url}>{filename}</span>
        {data.worst_severity === 'high' && (
          <AlertTriangle size={12} className="node-alert" />
        )}
        {data.finding_count === 0 && (
          <CheckCircle2 size={12} className="node-ok" />
        )}
      </div>

      <div className="node-meta">
        <span className="node-host truncate">{host}</span>
        <span className="node-size">{sizeKb} KB</span>
      </div>

      {data.finding_count > 0 && (
        <div className="node-badge-row">
          <span className={`badge badge-${sev}`}>{data.finding_count} finding{data.finding_count !== 1 ? 's' : ''}</span>
        </div>
      )}

      <Handle type="source" position={Position.Right} className="jxs-handle" />
    </div>
  )
}
