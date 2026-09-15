import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, apiUrl } from '../api/client.js'
import Section from '../components/Section.jsx'
import Table from '../components/Table.jsx'
import StatusBadge from '../components/StatusBadge.jsx'
import Loading from '../components/Loading.jsx'
import ErrorBox from '../components/ErrorBox.jsx'
import KeyValue from '../components/KeyValue.jsx'
import JsonBlock from '../components/JsonBlock.jsx'
import { asList, fixedVersions, fmtDate, fmtPercent, isActive, pkgLabel } from '../utils/format.js'

function FactList({ items, empty = 'None recorded.' }) {
  const list = asList(items)
  if (list.length === 0) return <p className="muted">{empty}</p>
  return (
    <ul className="list">
      {list.map((it, i) => {
        const text = typeof it === 'string' ? it : JSON.stringify(it)
        const isFact = /^FACT:/i.test(text)
        const isInference = /^INFERENCE:/i.test(text)
        return (
          <li key={i} className={isFact ? 'fact' : isInference ? 'inference' : ''}>
            {isFact && <span className="tag fact">FACT</span>}
            {isInference && <span className="tag inference">INFERENCE</span>}
            {text.replace(/^(FACT|INFERENCE):\s*/i, '')}
          </li>
        )
      })}
    </ul>
  )
}

function ReportView({ findingId }) {
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    if (!open || report) return
    setLoading(true)
    api.get(`/findings/${findingId}/report?format=json`).then(setReport).catch(setError).finally(() => setLoading(false))
  }, [open, report, findingId])

  return (
    <Section
      title="Evidence report"
      subtitle="Generated from stored facts, AI reasoning and validation results. Sections keep observed facts separate from inferences."
      actions={
        <>
          <a className="btn" href={apiUrl(`/findings/${findingId}/report?format=markdown`)} target="_blank" rel="noreferrer">Open markdown ↗</a>
          <a className="btn" href={apiUrl(`/findings/${findingId}/report?format=json`)} target="_blank" rel="noreferrer">Open JSON ↗</a>
          <button type="button" className="btn" onClick={() => setOpen((v) => !v)}>{open ? 'Hide report' : 'View report'}</button>
        </>
      }
    >
      {!open && <p className="muted">Click "View report" to render the JSON report here, or open the markdown version in a new tab.</p>}
      {open && loading && <Loading text="Generating report…" />}
      {open && error && <ErrorBox error={error} title="Could not load the report" />}
      {open && report && (
        <div className="report">
          <h3>{report.title || 'Evidence report'}</h3>
          {report.final_recommendation && (
            <div className="alert info">
              <strong>Final recommendation:</strong> <StatusBadge value={report.final_recommendation.decision} />{' '}
              {report.final_recommendation.reason}
            </div>
          )}
          {asList(report.sections).map((s, i) => (
            <div key={i} className="report-section">
              <h4>{s.number ? `${s.number}. ` : ''}{s.title || `Section ${i + 1}`}</h4>
              {asList(s.observed_facts).length > 0 && (<><div className="label">Observed facts</div><FactList items={s.observed_facts} /></>)}
              {asList(s.ai_reasoning).length > 0 && (<><div className="label">AI reasoning (inference)</div><FactList items={s.ai_reasoning} /></>)}
              {asList(s.validation_results).length > 0 && (<><div className="label">Validation results</div><FactList items={s.validation_results} /></>)}
              {asList(s.recommendations).length > 0 && (<><div className="label">Recommendations</div><FactList items={s.recommendations} /></>)}
              {asList(s.notes).length > 0 && (<><div className="label">Notes</div><FactList items={s.notes} /></>)}
            </div>
          ))}
          <JsonBlock title="Raw report JSON" data={report} />
        </div>
      )}
    </Section>
  )
}

export default function Finding() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [finding, setFinding] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [aiBusy, setAiBusy] = useState(false)
  const [aiError, setAiError] = useState(null)
  const [remBusy, setRemBusy] = useState(false)
  const [remError, setRemError] = useState(null)

  function load() {
    setLoading(true)
    setError(null)
    api.get(`/findings/${id}`).then(setFinding).catch(setError).finally(() => setLoading(false))
  }
  useEffect(load, [id])

  // The on-demand AI run is a background job: poll while ai_status is RUNNING.
  useEffect(() => {
    if (!finding || finding.ai_status !== 'RUNNING') return undefined
    const timer = setTimeout(() => api.get(`/findings/${id}`).then(setFinding).catch(setError), 3000)
    return () => clearTimeout(timer)
  }, [finding, id])

  async function runAi() {
    setAiBusy(true)
    setAiError(null)
    try {
      const updated = await api.post(`/findings/${id}/analyze`)  // 202: ai_status becomes RUNNING, polling takes over
      setFinding(updated)
    } catch (e) {
      setAiError(e)
    } finally {
      setAiBusy(false)
    }
  }

  async function remediate() {
    setRemBusy(true)
    setRemError(null)
    try {
      const rem = await api.post(`/findings/${id}/remediate`)
      navigate(`/remediations/${rem.remediation_id}`)
    } catch (e) {
      setRemError(e)
      setRemBusy(false)
    }
  }

  if (loading && !finding) return <Loading text="Loading finding…" />
  if (error && !finding) return <ErrorBox error={error} title="Could not load the finding" onRetry={load} />
  if (!finding) return null

  const dep = finding.dependency || {}
  const vuln = finding.vulnerability || {}
  const usage = finding.usage_evidence && typeof finding.usage_evidence === 'object' ? finding.usage_evidence : {}
  const references = asList(usage.references)
  const ai = finding.ai_results && typeof finding.ai_results === 'object' ? finding.ai_results : null
  const depAnalysis = ai?.dependency_analysis || null
  const impact = ai?.impact || null
  const risk = ai?.risk || null
  const failures = asList(ai?.failures)
  const fixed = fixedVersions(vuln, dep.ecosystem)
  const remediations = asList(finding.remediations)
  const aiRunning = isActive(finding.ai_status)

  return (
    <div>
      <p className="crumbs">
        <Link to="/">Dashboard</Link> › <Link to={`/repositories/${finding.repository?.repository_id ?? dep.repository_id}`}>Repository{finding.repository?.name ? ` ${finding.repository.name}` : ` #${dep.repository_id ?? '?'}`}</Link> › <Link to={`/analyses/${finding.analysis_id}`}>Analysis #{finding.analysis_id}</Link> › Finding #{finding.finding_id}
      </p>
      <div className="page-head">
        <h1>Finding #{finding.finding_id}: <span className="mono">{pkgLabel(dep)}</span> — {vuln.identifier || 'vulnerability'}</h1>
      </div>
      <div className="badges">
        <span>Risk <StatusBadge value={finding.risk_level} fallback="UNKNOWN" /></span>
        <span>Impact <StatusBadge value={finding.impact_level} fallback="UNKNOWN" /></span>
        <span>Severity <StatusBadge value={vuln.severity} fallback="UNKNOWN" /></span>
        <span>AI <StatusBadge value={finding.ai_status} /></span>
        <span className="muted">detected {fmtDate(finding.detected_at)}</span>
      </div>
      {error && <ErrorBox error={error} />}

      <div className="grid-2">
        <Section title="Dependency">
          <KeyValue
            columns={1}
            items={[
              { label: 'Package', value: <span className="mono">{dep.package_name}</span> },
              { label: 'Version', value: <span className="mono">{dep.version || dep.version_spec}</span> },
              { label: 'Spec', value: dep.version_spec ? <span className="mono">{dep.version_spec}</span> : null },
              { label: 'Ecosystem', value: dep.ecosystem },
              { label: 'Scope', value: dep.direct_or_transitive },
              { label: 'Source file', value: dep.source_file ? <span className="mono small">{dep.source_file}</span> : null },
              { label: 'Status', value: <StatusBadge value={dep.vulnerability_status} /> },
              { label: 'Reason', value: dep.status_reason },
              { label: 'Last checked', value: fmtDate(dep.last_checked_at) },
            ]}
          />
        </Section>

        <Section title="Vulnerability">
          <KeyValue
            columns={1}
            items={[
              { label: 'Identifier', value: <span className="mono">{vuln.identifier}</span> },
              { label: 'Aliases', value: asList(vuln.aliases).length ? asList(vuln.aliases).map((a) => <code key={a} className="chip">{a}</code>) : null },
              { label: 'Source', value: vuln.source },
              { label: 'Severity', value: <StatusBadge value={vuln.severity} /> },
              { label: 'CVSS score', value: vuln.cvss_score },
              { label: 'CVSS vector', value: vuln.cvss_vector ? <span className="mono small">{vuln.cvss_vector}</span> : null },
              { label: 'Fixed versions', value: fixed.length ? fixed.map((v) => <code key={v} className="chip ok">{v}</code>) : <span className="muted">no fix listed</span> },
              { label: 'Published', value: fmtDate(vuln.published_at) },
              { label: 'Reference', value: vuln.reference_url ? <a href={vuln.reference_url} target="_blank" rel="noreferrer">{vuln.reference_url}</a> : null },
            ]}
          />
          {vuln.summary && <p><strong>{vuln.summary}</strong></p>}
          {vuln.description && <p className="prewrap small">{vuln.description}</p>}
          {asList(vuln.affected).length > 0 && (
            <>
              <h3>Affected ranges</h3>
              <Table
                compact
                rows={asList(vuln.affected).flatMap((a, i) => (asList(a?.ranges).length ? asList(a.ranges).map((r, j) => ({ ...r, ecosystem: a.ecosystem, package_name: a.package_name, key: `${i}-${j}` })) : [{ ecosystem: a?.ecosystem, package_name: a?.package_name, key: `${i}` }]))}
                rowKey={(r) => r.key}
                columns={[
                  { key: 'ecosystem', label: 'Ecosystem' },
                  { key: 'package_name', label: 'Package' },
                  { key: 'range_type', label: 'Range' },
                  { key: 'introduced', label: 'Introduced', render: (r) => r.introduced ? <span className="mono">{r.introduced}</span> : null },
                  { key: 'fixed', label: 'Fixed', render: (r) => r.fixed ? <span className="mono">{r.fixed}</span> : null },
                  { key: 'last_affected', label: 'Last affected', render: (r) => r.last_affected ? <span className="mono">{r.last_affected}</span> : null },
                ]}
              />
            </>
          )}
          <JsonBlock title="Raw vulnerability JSON" data={vuln} />
        </Section>
      </div>

      <Section title="Evidence — Observed facts" subtitle="Deterministic results of the source-usage scan: files and lines that reference the package, and the components they belong to.">
        <KeyValue
          columns={4}
          items={[
            { label: 'Import names', value: asList(usage.import_names).length ? asList(usage.import_names).map((n) => <code key={n} className="chip">{n}</code>) : null },
            { label: 'Files referencing', value: asList(usage.files).length },
            { label: 'Files scanned', value: usage.scanned_files },
            { label: 'Truncated', value: usage.truncated === undefined ? null : (usage.truncated ? 'yes' : 'no') },
            { label: 'Affected components', value: asList(finding.affected_components).length ? asList(finding.affected_components).map((c) => <code key={c} className="chip">{c}</code>) : <span className="muted">none (no direct import found; transitive and dynamic use are not analysed)</span> },
          ]}
        />
        <Table
          compact
          rows={references}
          rowKey={(r, i) => `${r.file}-${r.line}-${i}`}
          empty="No direct import of this package was found. Use through other packages, dynamic imports and notebooks are not analysed, so this is not evidence that the package is unused."
          columns={[
            { key: 'file', label: 'File', render: (r) => <span className="mono small">{r.file}</span> },
            { key: 'line', label: 'Line' },
            { key: 'kind', label: 'Kind', render: (r) => <StatusBadge value={r.kind} /> },
            { key: 'snippet', label: 'Snippet', render: (r) => <code className="snippet">{r.snippet}</code> },
          ]}
        />
        <JsonBlock title="Raw usage evidence JSON" data={usage} />
      </Section>

      <Section
        title="AI reasoning (inference)"
        subtitle="Produced by the dependency, impact and risk agents (Ollama). Everything here is model output — check it against the observed facts above."
        actions={
          <button type="button" className="btn primary" disabled={aiBusy || aiRunning} onClick={runAi}>
            {aiBusy || aiRunning ? <><span className="spinner light" /> Running agents…</> : (ai ? 'Re-run AI analysis' : 'Run AI analysis')}
          </button>
        }
      >
        {aiError && <ErrorBox error={aiError} title="AI analysis failed" />}
        {aiBusy && <p className="muted">The three agents run synchronously; this can take a minute on a local model.</p>}
        <KeyValue
          columns={4}
          items={[
            { label: 'AI status', value: <StatusBadge value={finding.ai_status} /> },
            { label: 'Model', value: ai?.model },
            { label: 'Result status', value: ai?.status ? <StatusBadge value={ai.status} /> : null },
            { label: 'Error', value: finding.ai_error ? <span className="danger-text">{finding.ai_error}</span> : null },
          ]}
        />
        {aiRunning && <Loading text="AI agents are running…" />}
        {!ai && !aiRunning && <p className="muted">No AI results yet{finding.ai_error ? '' : ' — click "Run AI analysis"'}.</p>}
        {ai && (
          <>
            <h3>Dependency analysis</h3>
            {depAnalysis ? (
              <>
                <p>{depAnalysis.summary || <span className="muted">no summary</span>}</p>
                <div className="label">Usage evidence cited by the agent</div>
                <FactList items={depAnalysis.usage_evidence} />
                <div className="muted small">Confidence: {fmtPercent(depAnalysis.confidence) ?? '—'}</div>
              </>
            ) : <p className="muted">Not available.</p>}

            <h3>Impact {impact?.impact_level && <StatusBadge value={impact.impact_level} />}</h3>
            {impact?.impact_level && finding.impact_level && impact.impact_level !== finding.impact_level && (
              <p className="muted small">
                Stored impact is <strong>{finding.impact_level}</strong>: the AI judged {impact.impact_level}, but Sentinel Chain cannot establish that a vulnerable package has no impact (the usage scan finds direct imports only).
              </p>
            )}
            {impact ? (
              <>
                <div className="grid-2">
                  <div>
                    <div className="label">Facts</div>
                    <FactList items={impact.facts} />
                  </div>
                  <div>
                    <div className="label">Inferences</div>
                    <FactList items={impact.inferences} />
                  </div>
                </div>
                {impact.reasoning && <p className="prewrap">{impact.reasoning}</p>}
                <KeyValue
                  columns={3}
                  items={[
                    { label: 'Affected components', value: asList(impact.affected_components).length ? asList(impact.affected_components).map((c) => <code key={c} className="chip">{c}</code>) : null },
                    { label: 'Dropped components', value: asList(ai.dropped_components).length ? asList(ai.dropped_components).map((c, i) => <code key={i} className="chip warn">{typeof c === 'string' ? c : JSON.stringify(c)}</code>) : <span className="muted">none (all claimed components exist)</span> },
                    { label: 'Confidence', value: fmtPercent(impact.confidence) },
                  ]}
                />
              </>
            ) : <p className="muted">Not available.</p>}

            <h3>Risk {risk?.risk_level && <StatusBadge value={risk.risk_level} />}</h3>
            {risk?.risk_level && finding.risk_level && risk.risk_level !== finding.risk_level && (
              <p className="muted small">
                Stored risk is <strong>{finding.risk_level}</strong> (severity-derived floor): the AI judged {risk.risk_level}. Sentinel Chain never lowers the risk below the severity-derived level because it cannot prove that the vulnerable code is unreachable.
              </p>
            )}
            {risk ? (
              <>
                <div className="label">Factors</div>
                <FactList items={risk.factors} />
                {risk.reasoning && <p className="prewrap">{risk.reasoning}</p>}
                <div className="muted small">Confidence: {fmtPercent(risk.confidence) ?? '—'}</div>
              </>
            ) : <p className="muted">Not available.</p>}

            {failures.length > 0 && (
              <>
                <h3>Agent failures</h3>
                <Table
                  compact
                  rows={failures}
                  columns={[
                    { key: 'agent', label: 'Agent' },
                    { key: 'error', label: 'Error', render: (f) => <span className="danger-text small">{f.error}</span> },
                    { key: 'raw_output', label: 'Raw output', render: (f) => f.raw_output ? <code className="snippet">{String(f.raw_output).slice(0, 300)}</code> : null },
                  ]}
                />
              </>
            )}
          </>
        )}
        {finding.reasoning && (
          <>
            <h3>Combined reasoning</h3>
            <p className="prewrap small">{finding.reasoning}</p>
          </>
        )}
        <JsonBlock title="Raw AI results JSON" data={ai} />
      </Section>

      <Section
        title="Remediation"
        subtitle="The remediation agent picks a fixed version from the deterministic candidates; the change is applied to a temporary copy and validated in Docker."
        actions={
          <button type="button" className="btn primary" disabled={remBusy} onClick={remediate}>
            {remBusy ? <><span className="spinner light" /> Generating…</> : 'Generate remediation'}
          </button>
        }
      >
        {remError && <ErrorBox error={remError} title="Could not generate a remediation" />}
        <Table
          rows={remediations}
          rowKey={(r) => r.remediation_id}
          empty="No remediation generated yet."
          columns={[
            { key: 'remediation_id', label: 'Remediation', render: (r) => <Link to={`/remediations/${r.remediation_id}`}>#{r.remediation_id}</Link> },
            { key: 'status', label: 'Status', render: (r) => <StatusBadge value={r.status} /> },
            { key: 'current_version', label: 'Current', render: (r) => <span className="mono">{r.current_version}</span> },
            { key: 'recommended_version', label: 'Recommended', render: (r) => r.recommended_version ? <span className="mono">{r.recommended_version}</span> : null },
            { key: 'alternative_package', label: 'Alternative', render: (r) => r.alternative_package ? <span className="mono">{r.alternative_package}</span> : null },
            { key: 'confidence_score', label: 'Confidence', render: (r) => fmtPercent(r.confidence_score) },
            { key: 'created_at', label: 'Created', render: (r) => fmtDate(r.created_at) },
            { key: 'error_message', label: 'Error', render: (r) => r.error_message ? <span className="danger-text small">{r.error_message}</span> : null },
          ]}
        />
      </Section>

      <ReportView findingId={id} />

      <p><Link to={`/analyses/${finding.analysis_id}`}>← Back to analysis #{finding.analysis_id}</Link></p>
    </div>
  )
}
