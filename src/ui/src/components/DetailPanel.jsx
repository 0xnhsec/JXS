/**
 * src/components/DetailPanel.jsx
 * Slide-in panel on the right — shows detail for selected node.
 * Includes: JS file metadata, findings list, advisories, code snippet viewer.
 */

import { useState, useEffect } from 'react'
import { X, ExternalLink, Copy, ChevronDown, ChevronRight, Shield, AlertTriangle, Info, CheckCircle, ClipboardCheck, ListChecks, Sparkles } from 'lucide-react'
import { api } from '../api'
import './DetailPanel.css'

const SEV_ICON = {
  high:   <AlertTriangle size={13} />,
  medium: <AlertTriangle size={13} />,
  low:    <Info size={13} />,
  info:   <Info size={13} />,
}

function CodeSnippet({ content, maxHeight = 200 }) {
  const [expanded, setExpanded] = useState(false)
  if (!content) return null
  return (
    <div className="code-snippet-wrap">
      <div className="code-snippet-toolbar">
        <CopyBtn text={content} label="Copy snippet" />
        {content.length > 200 && (
          <button className="code-expand-btn btn btn-ghost" onClick={() => setExpanded(e => !e)}>
            {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            {expanded ? 'Collapse' : 'Expand'}
          </button>
        )}
      </div>
      <pre
        className="code-snippet mono"
        style={{ maxHeight: expanded ? 'none' : maxHeight }}
      >
        {content}
      </pre>
    </div>
  )
}

function CopyBtn({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    if (!text) return
    // Primary: Clipboard API (requires HTTPS or localhost)
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text)
        .then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })
        .catch(() => fallbackCopy(text, setCopied))
    } else {
      fallbackCopy(text, setCopied)
    }
  }
  return (
    <button className="btn btn-ghost copy-btn" onClick={handleCopy} title={`Copy: ${text?.slice(0, 60)}`}>
      <Copy size={12} />
      {copied ? '✓ Copied!' : label}
    </button>
  )
}

// Fallback copy using deprecated execCommand (works without HTTPS)
function fallbackCopy(text, setCopied) {
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  ta.focus()
  ta.select()
  try {
    document.execCommand('copy')
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  } catch (e) {
    console.warn('Copy failed:', e)
  }
  document.body.removeChild(ta)
}

// ── Review status config ───────────────────────────────────────────────────
const REVIEW_STATUSES = [
  { value: 'unreviewed',    label: '⬜ Unreviewed',    color: '#6b7280' },
  { value: 'checked_fp',   label: '✗ False positive', color: '#9ca3af' },
  { value: 'checked_benign', label: '✓ Benign',       color: '#6b7280' },
  { value: 'confirmed_bug', label: '🐛 Confirmed bug', color: '#22c55e' },
  { value: 'reported',      label: '📤 Reported',      color: '#3b82f6' },
]

function ReviewWidget({ findingId, initialStatus, initialNote, draftNote, draftSeq }) {
  const [status, setStatus] = useState(initialStatus || 'unreviewed')
  const [note, setNote]     = useState(initialNote || '')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved]   = useState(false)

  // PRD 8y — AI draft note DI-APPEND ke note existing (tidak menimpa),
  // dan yang menekan Save tetap manusia — AI tidak pernah submit sendiri.
  useEffect(() => {
    if (draftSeq && draftNote) {
      setNote(prev => (prev ? `${prev}\n${draftNote}` : draftNote))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draftSeq])

  const save = async () => {
    setSaving(true)
    try {
      await fetch(`/api/findings/${findingId}/review`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ review_status: status, review_note: note || null }),
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (e) {
      console.error('Review save failed:', e)
    } finally {
      setSaving(false)
    }
  }

  const currentColor = REVIEW_STATUSES.find(s => s.value === status)?.color || '#6b7280'

  return (
    <div className="review-widget">
      <div className="review-label">Review status</div>
      <div className="review-controls">
        <select
          className="review-select"
          value={status}
          onChange={e => setStatus(e.target.value)}
          style={{ borderColor: currentColor, color: currentColor }}
        >
          {REVIEW_STATUSES.map(s => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>
        <button
          className="btn btn-ghost review-save-btn"
          onClick={save}
          disabled={saving}
          title="Save review status"
        >
          {saved ? <><CheckCircle size={12} /> Saved!</> : saving ? 'Saving…' : 'Save'}
        </button>
      </div>
      <textarea
        className="review-note mono"
        placeholder="Optional note (e.g. 'innerHTML sink, user-controlled via hash')…"
        value={note}
        onChange={e => setNote(e.target.value)}
        rows={2}
      />
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// PRD 8u — Validation Checklist
// 5 langkah wajib sebelum finding jadi laporan.
// Steps kondisional: step N+1 hanya tampil saat step N di-resolve.
// Step 4 & 5 auto-sync review_status ke API.
// ─────────────────────────────────────────────────────────────────────────────

const CHECKLIST_STEPS = [
  {
    id: 'source',
    label: 'Source check',
    question: 'Apakah nilai yang masuk ke sink berasal dari attacker-controlled input?',
    hint: 'Attacker-controlled: location.search, URLSearchParams, postMessage, form input.\nInternal config/state milik library/framework = BUKAN attacker-controlled.',
    yesLabel: 'Ya — user-controlled input',
    noLabel:  'Tidak — internal config/state → benign',
    noStatus:  'checked_benign',
    noMessage: 'Finding dari internal state library — bukan bug.',
  },
  {
    id: 'accessible',
    label: 'Resource accessible',
    question: 'Buka target_url langsung. Apakah resource accessible dan responnya valid (bukan SPA fallback / soft-404)?',
    hint: 'Soft-404: server balas 200 tapi body = HTML fallback SPA.\nCek: response Content-Type, apakah body sesuai ekspektasi.',
    yesLabel: 'Ya — accessible dan valid',
    noLabel:  'Tidak — 404 / fallback → false positive',
    noStatus:  'checked_fp',
    noMessage: 'Resource tidak accessible — false positive.',
  },
  {
    id: 'reproduce',
    label: 'Manual reproduce',
    question: 'Reproduce manual di browser/Burp Repeater. Berhasil dikonfirmasi?',
    hint: 'Tangkap request-response asli sebagai bukti.\nXSS: screenshot alert(document.domain).\nOpen redirect: screenshot URL bar setelah redirect.',
    yesLabel: 'Ya — berhasil direproduksi',
    noLabel:  'Tidak — tidak bisa direproduksi → false positive',
    noStatus:  'checked_fp',
    noMessage: 'Tidak bisa direproduksi — false positive.',
  },
  {
    id: 'confirmed',
    label: 'Confirmed bug',
    question: 'Tandai sebagai confirmed bug dan jalankan PoC export sebelum mulai laporan.',
    hint: 'jxs export --scope <name> --status confirmed_bug',
    yesLabel:   'Set confirmed_bug ✓',
    autoStatus: 'confirmed_bug',
  },
  {
    id: 'reported',
    label: 'Reported',
    question: 'Sudah submit ke YWH/H1? Tandai sebagai reported.',
    hint: 'Update status supaya tracking tetap akurat.',
    yesLabel:   'Set reported ✓',
    autoStatus: 'reported',
    terminal: true,
  },
]

function inferAnswersFromStatus(status) {
  // Reconstruct approximate checklist state from review_status stored in DB.
  // This prevents the checklist resetting to blank after page reload.
  //
  // DESIGN DECISION — checked_fp ambiguity:
  //   checked_fp bisa muncul dari 2 jalur berbeda:
  //     - Step 2 gagal: resource tidak accessible (SPA fallback / 404)
  //     - Step 3 gagal: manual reproduce tidak berhasil
  //   Karena DB hanya menyimpan status akhir (bukan langkah mana yang trigger),
  //   kita TIDAK bisa infer step mana yang gagal tanpa menyesatkan user.
  //
  //   Solusi: untuk checked_fp, hanya infer step 1 = yes (source = attacker-controlled
  //   terkonfirmasi — karena kalau step 1 = no, hasilnya checked_benign bukan checked_fp).
  //   Biarkan step 2 menjadi active dan tampilkan banner khusus yang menjelaskan ambiguitas.
  //   User di-prompt untuk re-run dari step 2 untuk mengidentifikasi step mana yang failed.
  //
  // All inferred answers are tagged { choice, inferred: true } so the UI can
  // show a subtle hint that these were reconstructed, not interactively entered.
  const Y = { choice: 'yes', inferred: true }
  const N = (outcome) => ({ choice: 'no', inferred: true, outcome })

  switch (status) {
    case 'checked_benign':
      // Step 1 = no: source tidak attacker-controlled → benign. Tidak ambigu.
      return { source: N('checked_benign') }
    case 'checked_fp':
      // Hanya infer step 1 = yes. Step 2 TIDAK di-infer karena ambiguitas:
      // bisa step 2 (accessible=no) atau step 3 (reproduce gagal) yang triggered checked_fp.
      // Flag '_fpAmbiguous' dipakai banner untuk tampilkan pesan khusus.
      return { source: Y, _fpAmbiguous: true }
    case 'confirmed_bug':
      // Steps 1-4 semua yes. Tidak ambigu.
      return { source: Y, accessible: Y, reproduce: Y, confirmed: Y }
    case 'reported':
      // Semua steps yes. Tidak ambigu.
      return { source: Y, accessible: Y, reproduce: Y, confirmed: Y, reported: Y }
    default: // 'unreviewed' atau unknown
      return {}
  }
}

function ValidationChecklist({ findingId, initialStatus, onStatusChange }) {
  const [open, setOpen]       = useState(false)
  const [answers, setAnswers] = useState(() => inferAnswersFromStatus(initialStatus))
  const [syncing, setSyncing] = useState(false)

  // isFpAmbiguous: true ketika status checked_fp tapi tidak bisa infer step mana yang gagal
  const isFpAmbiguous = answers._fpAmbiguous === true
  // isInferred: ada setidaknya satu step yang di-reconstruct dari DB status
  const isInferred    = Object.entries(answers).some(([k, a]) => k !== '_fpAmbiguous' && a?.inferred)

  // Exclude meta-key '_fpAmbiguous' dari step lookups
  const stepAnswers    = Object.fromEntries(Object.entries(answers).filter(([k]) => k !== '_fpAmbiguous'))
  const activeIdx      = CHECKLIST_STEPS.findIndex(s => !stepAnswers[s.id])
  const done           = activeIdx === -1
  const completedCount = Object.keys(stepAnswers).length
  const progress       = Math.round((completedCount / CHECKLIST_STEPS.length) * 100)

  const syncStatus = async (newStatus) => {
    setSyncing(true)
    try {
      await fetch(`/api/findings/${findingId}/review`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ review_status: newStatus }),
      })
      onStatusChange?.(newStatus)
    } catch (e) {
      console.error('Checklist sync failed:', e)
    } finally {
      setSyncing(false)
    }
  }

  const answer = async (step, choice) => {
    // When user answers interactively, clear inferred flag from all subsequent steps too
    setAnswers(prev => ({ ...prev, [step.id]: { choice, inferred: false } }))
    if (choice === 'no'  && step.noStatus)   await syncStatus(step.noStatus)
    if (choice === 'yes' && step.autoStatus) await syncStatus(step.autoStatus)
  }

  // Helper: extract the plain choice string regardless of inferred/non-inferred shape
  // Uses stepAnswers (excludes _fpAmbiguous meta-key)
  const getChoice = (stepId) => {
    const a = stepAnswers[stepId]
    if (!a) return undefined
    return typeof a === 'string' ? a : a.choice
  }

  const collapseLabel = done ? '✅ Selesai'
    : activeIdx === 0 ? 'Belum dimulai'
    : `Step ${activeIdx + 1}/${CHECKLIST_STEPS.length}`

  return (
    <div className="validation-checklist">
      <button
        className="checklist-toggle"
        onClick={() => setOpen(o => !o)}
      >
        <ListChecks size={13} />
        <span className="checklist-toggle-label">Validation Checklist</span>
        <span className="checklist-collapse-status">{collapseLabel}</span>
        <div className="checklist-progress-mini">
          <div className="checklist-progress-mini-fill" style={{ width: `${progress}%` }} />
        </div>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </button>

      {open && (
        <div className="checklist-body">

          {/* FP ambiguous banner — shown when checked_fp but step 2 vs 3 is unknown */}
          {isFpAmbiguous && (
            <div className="checklist-inferred-banner checklist-fp-ambiguous-banner">
              ⚠️ Status <code>checked_fp</code> — finding ini sudah ditandai false positive, tapi tidak bisa diketahui apakah step 2 (resource tidak accessible) atau step 3 (reproduce gagal) yang failed. DB hanya menyimpan status akhir, bukan langkah mana yang trigger.
              <br />Lanjutkan dari step 2 di bawah untuk mengidentifikasi alasan FP, atau klik ↺ Reset untuk re-run dari awal.
            </div>
          )}

          {/* Generic inferred banner — shown when state reconstructed from review_status (not fp-ambiguous) */}
          {isInferred && !isFpAmbiguous && (
            <div className="checklist-inferred-banner">
              ℹ️ State direkonstruksi dari <code>review_status</code> di DB. Klik "↺ Reset" untuk re-run checklist dari awal secara interaktif.
            </div>
          )}

          <div className="checklist-progress-bar">
            <div className="checklist-progress-fill" style={{ width: `${progress}%` }} />
          </div>
          <div className="checklist-progress-label">{completedCount} / {CHECKLIST_STEPS.length} steps</div>

          {CHECKLIST_STEPS.map((step, idx) => {
            const ans      = answers[step.id]
            const choice   = getChoice(step.id)    // 'yes' | 'no' | undefined
            const inferred = ans?.inferred === true
            const isActive = idx === activeIdx
            const isPast   = choice !== undefined

            return (
              <div
                key={step.id}
                className={`checklist-step ${
                  isPast
                    ? (choice === 'yes' ? 'step-yes' : 'step-no') + (inferred ? ' step-inferred' : '')
                    : isActive ? 'step-active' : 'step-future'
                }`}
              >
                <div className="step-header">
                  <span className="step-icon">
                    {isPast ? (choice === 'yes' ? '✅' : '❌') : isActive ? '▶' : '○'}
                  </span>
                  <span className="step-label-text">{idx + 1}. {step.label}</span>
                  {isPast && (choice === 'no' ? step.noStatus : step.autoStatus) && (
                    <span className={`step-outcome outcome-${choice === 'no' ? step.noStatus : step.autoStatus}`}>
                      {(choice === 'no' ? step.noStatus : step.autoStatus)?.replace('_', ' ')}
                    </span>
                  )}
                  {isPast && inferred && (
                    <span className="step-inferred-tag">inferred</span>
                  )}
                </div>

                {isActive && (
                  <div className="step-content">
                    <p className="step-question">{step.question}</p>
                    {step.hint && <pre className="step-hint">{step.hint}</pre>}
                    <div className="step-actions">
                      <button
                        className="btn btn-checklist-yes"
                        onClick={() => answer(step, 'yes')}
                        disabled={syncing}
                      >
                        ✓ {step.yesLabel}
                      </button>
                      {step.noLabel && (
                        <button
                          className="btn btn-checklist-no"
                          onClick={() => answer(step, 'no')}
                          disabled={syncing}
                        >
                          ✗ {step.noLabel}
                        </button>
                      )}
                    </div>
                  </div>
                )}

                {isPast && (
                  <div className="step-past-summary">
                    {choice === 'yes' ? step.yesLabel : step.noLabel}
                    {choice === 'no' && step.noMessage && (
                      <span className="step-no-msg"> — {step.noMessage}</span>
                    )}
                  </div>
                )}
              </div>
            )
          })}

          {done && (
            <div className="checklist-done">
              <ClipboardCheck size={14} />
              <span>Validation selesai — semua langkah terpenuhi!</span>
            </div>
          )}

          <button className="btn btn-ghost checklist-reset" onClick={() => setAnswers({})}>
            ↺ Reset checklist
          </button>
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// PRD 8y — AI Assessment card
// Hint prioritas dari LLM (BUKAN vonis): P1..P5 + kategori + evidence quote
// (sudah terverifikasi substring dari snippet oleh backend) + langkah cek
// manual. Confidence < 0.5 ditandai needs_review (PRD 8y.6).
// ─────────────────────────────────────────────────────────────────────────────

function AIAssessmentCard({ ai, onApplyDraft }) {
  const checks = Array.isArray(ai.recommended_checks) ? ai.recommended_checks : []
  const needsReview = typeof ai.confidence === 'number' && ai.confidence < 0.5
  const draftText = [
    `[AI P${ai.priority} · ${ai.category} · conf ${Math.round((ai.confidence || 0) * 100)}%]`,
    ai.summary,
    ...checks.map(c => `- ${c}`),
  ].filter(Boolean).join('\n')

  return (
    <div className={`ai-assessment-card ai-card-p${ai.priority}`}>
      <div className="ai-card-header">
        <Sparkles size={13} />
        <span className="ai-card-title">AI Assessment</span>
        <span className={`ai-badge ai-p${ai.priority}`}>P{ai.priority}</span>
        <span className="ai-card-category mono">{ai.category}</span>
        {needsReview && (
          <span className="ai-needs-review" title="Confidence < 0.5 — perlu verifikasi ekstra (PRD 8y.6)">
            needs review
          </span>
        )}
      </div>

      <p className="ai-card-summary">{ai.summary}</p>

      {ai.evidence_quote && (
        <>
          <div className="detail-label">Evidence (substring snippet — terverifikasi backend)</div>
          <pre className="ai-evidence mono">{ai.evidence_quote}</pre>
        </>
      )}

      {checks.length > 0 && (
        <>
          <div className="detail-label">Langkah cek manual</div>
          <ol className="ai-checks">
            {checks.map((c, i) => (
              <li key={i} className="ai-check">{c}</li>
            ))}
          </ol>
        </>
      )}

      <div className="ai-card-footer">
        <span className="ai-card-meta">
          conf {Math.round((ai.confidence || 0) * 100)}%{ai.model ? ` · ${ai.model}` : ''}
        </span>
        <button
          className="btn btn-ghost ai-draft-btn"
          onClick={() => onApplyDraft(draftText)}
          title="Isi draft ke note di Review Widget — tetap kamu yang tekan Save"
        >
          <ClipboardCheck size={12} /> Pakai sebagai draft note
        </button>
      </div>
    </div>
  )
}

function FindingRow({ finding }) {
  const [open, setOpen] = useState(false)
  const [aiDraft, setAiDraft] = useState(null) // { text, seq } — PRD 8y draft note

  // Detail /js-file/{id} memberi ai_assessment penuh; daftar /findings
  // memberi field flat (ai_priority/ai_category/ai_confidence) via LEFT JOIN.
  const ai = finding.ai_assessment
    ? finding.ai_assessment
    : finding.ai_priority
      ? { priority: finding.ai_priority, category: finding.ai_category, confidence: finding.ai_confidence }
      : null

  return (
    <div className={`finding-row finding-sev-${finding.severity} ${open ? 'open' : ''}`}>
      <div className="finding-row-header" onClick={() => setOpen(o => !o)}>
        <span className={`badge badge-${finding.severity}`}>
          {SEV_ICON[finding.severity]} {finding.severity}
        </span>
        <span className="finding-type">{finding.type}</span>
        <span className="finding-value mono truncate" title={finding.match_value}>
          {finding.match_value}
        </span>
        {finding.is_whitelisted ? <span className="whitelisted-tag">whitelisted</span> : null}
        {finding.verify_scope === 1 && (
          <span className="verify-scope-tag" title="From test_only_hosts — verify this host is in-scope for the program before reporting">
            ⚠ verify scope
          </span>
        )}
        {/* review badge */}
        {finding.review_status && finding.review_status !== 'unreviewed' && (
          <span className={`review-badge review-${finding.review_status}`}>
            {finding.review_status.replace('_', ' ')}
          </span>
        )}
        {/* AI priority badge (PRD 8y) — hint, bukan verdict */}
        {ai && (
          <span
            className={`ai-badge ai-p${ai.priority}`}
            title={`AI triage: P${ai.priority}${ai.category ? ` · ${ai.category}` : ''}`}
          >
            P{ai.priority}
          </span>
        )}
        {/* source_hint badge (PRD 8z.1) — proximity co-occurrence hint, bukan taint analysis.
            Null untuk non-sink types → no badge. */}
        {finding.source_hint === 'likely_tainted' && (
          <span
            className="source-hint-badge source-hint-badge--tainted"
            title="Source attacker-controlled terdeteksi dalam window ±300 char (co-occurrence, bukan taint analysis — PRD 8z.1)"
          >
            likely tainted
          </span>
        )}
        {finding.source_hint === 'unknown' && (
          <span
            className="source-hint-badge source-hint-badge--unknown"
            title="Tidak ada source attacker-controlled dalam window ±300 char (PRD 8z.1)"
          >
            no source hint
          </span>
        )}
        {/* Stop propagation so copy click doesn't toggle expand */}
        <span onClick={e => e.stopPropagation()} style={{ display: 'flex', alignItems: 'center' }}>
          <CopyBtn text={finding.match_value} label="Copy" />
        </span>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </div>

      {open && (
        <div className="finding-row-detail">
          <div className="detail-meta">
            {finding.line_number && (
              <span className="detail-line">Line {finding.line_number}</span>
            )}
          </div>

          {/* Match value */}
          <div className="detail-label">Match value</div>
          <div className="meta-value-row" style={{ marginBottom: 8 }}>
            <span className="meta-value mono" style={{ wordBreak: 'break-all', fontSize: '0.75rem' }}>
              {finding.match_value}
            </span>
            <CopyBtn text={finding.match_value} label="Copy" />
          </div>

          {/* Source JS file */}
          {finding.resolved_url && (
            <>
              <div className="detail-label">Source JS file</div>
              <div className="meta-value-row" style={{ marginBottom: 6 }}>
                <span className="meta-value mono truncate" title={finding.resolved_url} style={{ fontSize: '0.7rem' }}>
                  {finding.resolved_url}
                </span>
                <CopyBtn text={finding.resolved_url} label="Copy URL" />
              </div>
            </>
          )}

          {/* Target URL (PRD 8p) */}
          {finding.target_url && finding.target_url !== finding.resolved_url && (
            <>
              <div className="detail-label">Target URL
                <span className="detail-label-hint"> (resolved endpoint/resource)</span>
              </div>
              <div className="meta-value-row" style={{ marginBottom: 6 }}>
                <span className="meta-value mono truncate" title={finding.target_url} style={{ fontSize: '0.7rem' }}>
                  {finding.target_url}
                </span>
                <a href={finding.target_url} target="_blank" rel="noreferrer" className="ext-link">
                  <ExternalLink size={11} />
                </a>
                <CopyBtn text={finding.target_url} label="Copy" />
              </div>
            </>
          )}

          {/* Code snippet */}
          {finding.snippet && (
            <>
              <div className="detail-label">Code snippet</div>
              <CodeSnippet content={finding.snippet} />
            </>
          )}

          {/* AI Assessment (PRD 8y) — sebelum ReviewWidget, karena draft-nya
              diteruskan ke widget review; verdict tetap di tangan manusia */}
          {ai && ai.summary && (
            <AIAssessmentCard
              ai={ai}
              onApplyDraft={(text) =>
                setAiDraft(d => ({ text, seq: (d?.seq || 0) + 1 }))
              }
            />
          )}

          {/* Review widget (PRD 8p-1) */}
          <ReviewWidget
            findingId={finding.id}
            initialStatus={finding.review_status}
            initialNote={finding.review_note}
            draftNote={aiDraft?.text}
            draftSeq={aiDraft?.seq}
          />

          {/* Validation Checklist (PRD 8u) */}
          <ValidationChecklist
            findingId={finding.id}
            initialStatus={finding.review_status}
          />

        </div>
      )}
    </div>
  )
}

function AdvisoryCard({ advisory }) {
  const [showPayloads, setShowPayloads] = useState(false)
  const payloads = advisory.sample_payloads || []
  const steps    = advisory.testing_steps   || []

  return (
    <div className="advisory-card">
      <div className="advisory-header">
        <Shield size={13} />
        <span className="advisory-sink mono">{advisory.sink_type}</span>
        {payloads.length > 0 && (
          <button
            className="btn btn-ghost advisory-payload-toggle"
            onClick={() => setShowPayloads(s => !s)}
            title="Toggle manual test payloads"
          >
            {showPayloads ? '▾' : '▸'} {payloads.length} payload{payloads.length !== 1 ? 's' : ''}
          </button>
        )}
      </div>

      {/* Context */}
      {advisory.context && (
        <p className="advisory-context">{advisory.context}</p>
      )}

      <p className="advisory-text">{advisory.advisory_text}</p>

      {/* Code snippet */}
      {advisory.context_snippet && (
        <CodeSnippet content={advisory.context_snippet} maxHeight={120} />
      )}

      {/* Sample payloads (PRD 8s) */}
      {showPayloads && payloads.length > 0 && (
        <div className="advisory-payloads">
          <div className="advisory-payloads-label">
            ⚠ Manual test only — JANGAN auto-fire. Copy, modifikasi, test manual.
          </div>
          {payloads.map((p, i) => (
            <div key={i} className="payload-chip-row">
              <code className="payload-chip mono">{p}</code>
              <CopyBtn text={p} label="Copy" />
            </div>
          ))}
        </div>
      )}

      {/* Testing steps (PRD 8s) */}
      {showPayloads && steps.length > 0 && (
        <ol className="advisory-steps">
          {steps.map((s, i) => (
            <li key={i} className="advisory-step">{s}</li>
          ))}
        </ol>
      )}

      {/* Source ref */}
      {advisory.source_ref && (
        <div className="advisory-source-ref">📖 {advisory.source_ref}</div>
      )}
    </div>
  )
}

export default function DetailPanel({ node, onClose }) {
  const [detail, setDetail] = useState(null)
  const [content, setContent] = useState(null)
  const [loading, setLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('findings')

  useEffect(() => {
    if (!node || node.type !== 'jsFile') {
      setDetail(null)
      setContent(null)
      return
    }
    const id = node.data.id
    setLoading(true)
    Promise.all([api.getJsFile(id), api.getJsContent(id)])
      .then(([det, cnt]) => {
        setDetail(det)
        setContent(cnt)
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [node])

  if (!node) return null

  const isJsFile = node.type === 'jsFile'
  const isFinding = ['domSink', 'sourcemap', 'endpoint'].includes(node.type)

  return (
    <aside className="detail-panel">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="panel-header">
        <div className="panel-title">
          <span className="panel-type-badge">{node.type}</span>
          <span className="panel-name truncate">
            {isJsFile
              ? (node.data.url || '').split('/').slice(-1)[0]
              : node.data.match_value || node.data.tech_name}
          </span>
        </div>
        <button className="btn btn-ghost icon-btn" onClick={onClose} id="panel-close-btn">
          <X size={16} />
        </button>
      </div>

      {/* ── JS File detail ───────────────────────────────────────────────── */}
      {isJsFile && (
        <>
          <div className="panel-meta-grid">
            <div className="meta-item">
              <span className="meta-label">URL</span>
              <div className="meta-value-row">
                <span className="meta-value mono truncate" title={node.data.url}>{node.data.url}</span>
                <a href={node.data.url} target="_blank" rel="noreferrer" className="ext-link">
                  <ExternalLink size={11} />
                </a>
                <CopyBtn text={node.data.url} />
              </div>
            </div>
            <div className="meta-item">
              <span className="meta-label">Host</span>
              <span className="meta-value">{node.data.host}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Size</span>
              <span className="meta-value">{Math.round((node.data.size_bytes || 0) / 1024)} KB</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Status</span>
              <span className={`meta-value status-${node.data.status}`}>{node.data.status}</span>
            </div>
          </div>

          {/* ── Tabs ───────────────────────────────────────────────────── */}
          <div className="panel-tabs">
            {['findings', 'advisories', 'techstack', 'source'].map(tab => (
              <button
                key={tab}
                className={`panel-tab ${activeTab === tab ? 'active' : ''}`}
                onClick={() => setActiveTab(tab)}
                id={`panel-tab-${tab}`}
              >
                {tab}
                {tab === 'findings' && detail && (
                  <span className="tab-count">{detail.findings.length}</span>
                )}
                {tab === 'advisories' && detail && (
                  <span className="tab-count">{detail.advisories.length}</span>
                )}
              </button>
            ))}
          </div>

          {loading && <div className="panel-loading"><div className="loader" /></div>}

          {!loading && detail && (
            <div className="panel-body">
              {activeTab === 'findings' && (
                <div className="findings-list">
                  {detail.findings.length === 0
                    ? <p className="empty-state">No findings for this file.</p>
                    : detail.findings.map(f => <FindingRow key={f.id} finding={f} />)
                  }
                </div>
              )}
              {activeTab === 'advisories' && (
                <div className="advisories-list">
                  {detail.advisories.length === 0
                    ? <p className="empty-state">No advisories. Run XSS Advisor to generate.</p>
                    : detail.advisories.map(a => <AdvisoryCard key={a.id} advisory={a} />)
                  }
                </div>
              )}
              {activeTab === 'techstack' && (
                <div className="tech-list">
                  {detail.tech_stack.length === 0
                    ? <p className="empty-state">No tech stack detected.</p>
                    : detail.tech_stack.map((t, i) => (
                      <div key={i} className="tech-item">
                        <span className="tech-name">{t.tech_name}</span>
                        <span className="tech-confidence">{Math.round(t.confidence * 100)}%</span>
                        {t.evidence && <span className="tech-evidence mono">{t.evidence}</span>}
                      </div>
                    ))
                  }
                </div>
              )}
              {activeTab === 'source' && (
                <div className="source-panel">
                  {content?.content
                    ? <>
                        {content.truncated && (
                          <p className="truncated-warning">⚠ Content truncated at 500 KB for performance</p>
                        )}
                        <CodeSnippet content={content.content} maxHeight={400} />
                      </>
                    : <p className="empty-state">{content?.message || 'No content available.'}</p>
                  }
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* ── Finding node detail ──────────────────────────────────────────── */}
      {isFinding && (
        <div className="panel-body">
          <div className="panel-meta-grid">
            <div className="meta-item">
              <span className="meta-label">Type</span>
              <span className="meta-value">{node.type}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Value</span>
              <div className="meta-value-row">
                <span className="meta-value mono">{node.data.match_value}</span>
                <CopyBtn text={node.data.match_value} />
              </div>
            </div>
            <div className="meta-item">
              <span className="meta-label">Severity</span>
              <span className={`badge badge-${node.data.severity}`}>{node.data.severity}</span>
            </div>
            {node.data.resolved_url && (
              <div className="meta-item">
                <span className="meta-label">Source JS file</span>
                <div className="meta-value-row">
                  <span className="meta-value mono truncate" title={node.data.resolved_url} style={{ fontSize: '0.7rem' }}>
                    {node.data.resolved_url}
                  </span>
                  <a href={node.data.resolved_url} target="_blank" rel="noreferrer" className="ext-link">
                    <ExternalLink size={11} />
                  </a>
                  <CopyBtn text={node.data.resolved_url} label="Copy" />
                </div>
              </div>
            )}
          </div>
          {node.data.snippet && (
            <div className="detail-section">
              <div className="detail-label">Code snippet</div>
              <CodeSnippet content={node.data.snippet} />
            </div>
          )}

          {/* target_url (PRD 8p) */}
          {node.data.target_url && node.data.target_url !== node.data.resolved_url && (
            <div className="detail-section">
              <div className="detail-label">Target URL
                <span className="detail-label-hint"> (resolved resource)</span>
              </div>
              <div className="meta-value-row">
                <span className="meta-value mono truncate" title={node.data.target_url} style={{ fontSize: '0.7rem' }}>
                  {node.data.target_url}
                </span>
                <a href={node.data.target_url} target="_blank" rel="noreferrer" className="ext-link">
                  <ExternalLink size={11} />
                </a>
                <CopyBtn text={node.data.target_url} label="Copy" />
              </div>
            </div>
          )}

          <p className="burp-tip">
            💡 <strong>Verifikasi manual:</strong><br />
            1. Kalau <em>Target URL</em> sudah pernah ter-capture — search nama file-nya di Burp Proxy History (Ctrl+F).<br />
            2. Kalau belum muncul di history — buka <em>Target URL</em> langsung di browser (dengan session aktif jika perlu).
          </p>

          {/* Review widget (PRD 8p-1) */}
          {node.data.id && (
            <ReviewWidget
              findingId={node.data.id}
              initialStatus={node.data.review_status}
              initialNote={node.data.review_note}
            />
          )}
        </div>
      )}

      {/* ── Tech node ───────────────────────────────────────────────────── */}
      {node.type === 'techStack' && (
        <div className="panel-body">
          <div className="panel-meta-grid">
            <div className="meta-item">
              <span className="meta-label">Technology</span>
              <span className="meta-value">{node.data.tech_name}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Confidence</span>
              <span className="meta-value">{Math.round((node.data.confidence || 0) * 100)}%</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Evidence</span>
              <span className="meta-value mono">{node.data.evidence}</span>
            </div>
          </div>
        </div>
      )}
    </aside>
  )
}
