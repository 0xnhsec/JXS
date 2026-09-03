/**
 * src/components/DataFlowTree.jsx
 * Structured 3-column Data Flow View (Host ➔ JS File ➔ Findings).
 * Provides a clean, compact alternative to the React Flow graph canvas.
 */

import { useState, useMemo } from 'react'
import { Globe, FileCode2, Zap, AlertTriangle, ChevronRight, Copy } from 'lucide-react'
import './DataFlowTree.css'

function CopyBtn({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = (e) => {
    e.stopPropagation()
    if (!text) return
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      })
    } else {
      const ta = document.createElement('textarea')
      ta.value = text
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }
  }

  return (
    <button className="btn btn-ghost copy-btn-tree" onClick={handleCopy} title={`Copy: ${text}`}>
      <Copy size={11} />
      {copied ? '✓' : label}
    </button>
  )
}

export default function DataFlowTree({ nodes, edges, onNodeSelect, loading, error }) {
  const [selectedHost, setSelectedHost] = useState(null)
  const [selectedJsId, setSelectedJsId] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')

  // Build hierarchical structure: Hosts ➔ JS Files ➔ Findings
  const treeData = useMemo(() => {
    const jsNodes = nodes.filter(n => n.type === 'jsFile')
    const findingNodesMap = new Map()

    nodes.filter(n => n.type !== 'jsFile').forEach(n => {
      findingNodesMap.set(n.id, n)
    })

    // Map jsFile to its findings via edges
    const jsToFindings = new Map()
    edges.forEach(edge => {
      const targetNode = findingNodesMap.get(edge.target)
      if (targetNode) {
        if (!jsToFindings.has(edge.source)) {
          jsToFindings.set(edge.source, [])
        }
        jsToFindings.get(edge.source).push(targetNode)
      }
    })

    // Group JS files by host
    const hostMap = new Map()
    jsNodes.forEach(jsNode => {
      const host = jsNode.data.host || 'unknown-host'
      if (!hostMap.has(host)) {
        hostMap.set(host, [])
      }
      const findings = jsToFindings.get(jsNode.id) || []
      hostMap.get(host).push({
        node: jsNode,
        findings,
      })
    })

    return hostMap
  }, [nodes, edges])

  const hosts = Array.from(treeData.keys()).sort()

  // Default select first host if not set
  const activeHost = selectedHost || hosts[0] || null
  const activeJsList = activeHost ? treeData.get(activeHost) || [] : []

  // Filter JS list by search query if any
  const filteredJsList = activeJsList.filter(item => {
    if (!searchQuery) return true
    const query = searchQuery.toLowerCase()
    const urlMatch = item.node.data.url?.toLowerCase().includes(query)
    const findingMatch = item.findings.some(f =>
      f.data.match_value?.toLowerCase().includes(query) ||
      f.data.severity?.toLowerCase().includes(query)
    )
    return urlMatch || findingMatch
  })

  // Selected JS file
  const activeJsItem = activeJsList.find(item => item.node.id === selectedJsId) || filteredJsList[0] || null

  if (loading) {
    return (
      <div className="data-flow-placeholder">
        <div className="loader" style={{ width: 32, height: 32 }} />
        <p>Loading data flow structure...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="data-flow-placeholder">
        <p className="graph-error">⚠ {error}</p>
      </div>
    )
  }

  if (nodes.length === 0) {
    return (
      <div className="data-flow-placeholder">
        <p className="graph-empty-title">No matching nodes</p>
        <p className="graph-hint">Adjust filters or select a scope with captured JS files.</p>
      </div>
    )
  }

  return (
    <div className="data-flow-container">
      {/* Search Header */}
      <div className="data-flow-header">
        <input
          type="text"
          className="input search-input"
          placeholder="🔍 Search endpoints, sinks, parameters, or JS filenames..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
        />
        <div className="flow-stats">
          <span>{hosts.length} Hosts</span>
          <span>•</span>
          <span>{nodes.filter(n => n.type === 'jsFile').length} JS Files</span>
          <span>•</span>
          <span>{nodes.filter(n => n.type !== 'jsFile').length} Findings</span>
        </div>
      </div>

      {/* 3-Column Columns View */}
      <div className="data-flow-columns">
        {/* Column 1: Hosts */}
        <div className="flow-column host-column">
          <div className="column-title">
            <Globe size={13} />
            <span>Target Hosts ({hosts.length})</span>
          </div>
          <div className="column-list">
            {hosts.map(host => {
              const count = (treeData.get(host) || []).length
              const highCount = (treeData.get(host) || []).reduce((acc, item) => {
                return acc + item.findings.filter(f => f.data.severity === 'high').length
              }, 0)
              const isActive = host === activeHost

              return (
                <div
                  key={host}
                  className={`flow-item host-item ${isActive ? 'active' : ''}`}
                  onClick={() => {
                    setSelectedHost(host)
                    const firstJs = treeData.get(host)?.[0]?.node?.id
                    setSelectedJsId(firstJs || null)
                  }}
                >
                  <div className="flow-item-row">
                    <span className="host-name truncate" title={host}>{host}</span>
                    <ChevronRight size={12} className="chevron" />
                  </div>
                  <div className="flow-item-meta">
                    <span className="meta-badge">{count} JS files</span>
                    {highCount > 0 && (
                      <span className="badge badge-high">{highCount} High</span>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Column 2: JS Files */}
        <div className="flow-column js-column">
          <div className="column-title">
            <FileCode2 size={13} />
            <span>JS Modules ({filteredJsList.length})</span>
          </div>
          <div className="column-list">
            {filteredJsList.map(({ node, findings }) => {
              const isActive = node.id === (activeJsItem?.node?.id)
              const urlParts = (node.data.url || '').split('/')
              const filename = urlParts[urlParts.length - 1].split('?')[0] || 'file.js'
              const worstSev = node.data.worst_severity || 'info'

              return (
                <div
                  key={node.id}
                  className={`flow-item js-item sev-border-${worstSev} ${isActive ? 'active' : ''}`}
                  onClick={() => {
                    setSelectedJsId(node.id)
                    onNodeSelect?.(node)
                  }}
                >
                  <div className="flow-item-row">
                    <span className="js-filename truncate" title={node.data.url}>{filename}</span>
                    {worstSev === 'high' && <AlertTriangle size={12} className="icon-high" />}
                  </div>
                  <div className="flow-item-meta">
                    <span className={`badge badge-${worstSev}`}>{worstSev}</span>
                    <span className="meta-info">{findings.length} findings</span>
                    <span className="meta-info">{Math.round((node.data.size_bytes || 0) / 1024)} KB</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Column 3: Findings / Sinks & Endpoints */}
        <div className="flow-column finding-column">
          <div className="column-title">
            <Zap size={13} />
            <span>Extracted Findings & Sinks ({activeJsItem?.findings?.length || 0})</span>
          </div>

          <div className="column-list">
            {!activeJsItem || activeJsItem.findings.length === 0 ? (
              <div className="empty-findings">
                <p>✓ No vulnerabilities or endpoints detected in this module.</p>
              </div>
            ) : (
              activeJsItem.findings.map(finding => {
                return (
                  <div
                    key={finding.id}
                    className={`flow-item finding-item finding-sev-${finding.data.severity}`}
                    onClick={() => onNodeSelect?.(finding)}
                  >
                    <div className="finding-header">
                      <span className={`badge badge-${finding.data.severity}`}>
                        {finding.type}
                      </span>
                      <span className="finding-match mono truncate" title={finding.data.match_value}>
                        {finding.data.match_value}
                      </span>
                      <CopyBtn text={finding.data.match_value} label="Copy" />
                    </div>

                    {/* Resolved URL link if present */}
                    {finding.data.resolved_url && (
                      <div className="finding-url-row">
                        <span className="url-label">Source URL:</span>
                        <span className="url-val mono truncate" title={finding.data.resolved_url}>
                          {finding.data.resolved_url}
                        </span>
                        <CopyBtn text={finding.data.resolved_url} label="Copy URL" />
                      </div>
                    )}

                    {finding.data.snippet && (
                      <div className="finding-snippet mono">
                        {finding.data.snippet.slice(0, 150)}
                      </div>
                    )}
                  </div>
                )
              })
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
