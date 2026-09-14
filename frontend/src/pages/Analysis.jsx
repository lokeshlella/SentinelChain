import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client.js'
import usePolling from '../hooks/usePolling.js'
import Section from '../components/Section.jsx'
import Table from '../components/Table.jsx'
import StatusBadge from '../components/StatusBadge.jsx'
import Loading from '../components/Loading.jsx'
import ErrorBox from '../components/ErrorBox.jsx'
import KeyValue from '../components/KeyValue.jsx'
import JsonBlock from '../components/JsonBlock.jsx'
import StageTracker from '../components/StageTracker.jsx'
import { fmtDate, fmtDuration, isActive, pkgLabel, sortByRisk } from '../utils/format.js'

function Counter({ label, value, tone }) {
  return (
    <div className={`tile ${tone || ''}`}>
      <div className="tile-value">{value ?? '—'}</div>
      <div className="tile-label">{label}</div>
    </div>
  )
}

export default function Analysis() {
  const { id } = useParams()
  const { data: analysis, error, loading, reload } = usePolling(
    () => api.get(`/analyses/${id}`),
    3000,
    (a) => isActive(a?.status),
    [id],
  )

  const [findings, setFindings] = useState(null)
  const [findingsError, setFindingsError] = useState(null)
  const status = analysis?.status

  // Load findings once the analysis is no longer running (and again when its status changes).
  useEffect(() => {
    if (!analysis) return
    if (isActive(status)) {
      setFindings(null)
      return
    }
    api.get(`/analyses/${id}/findings`).then((f) => setFindings(sortByRisk(f))).catch(setFindingsError)
  }, [id, status]) // eslint-disable-line react-hooks/exhaustive-deps

  if (loading && !analysis) return <Loading text="Loading analysis…" />
  if (error && !analysis) return <ErrorBox error={error} title="Could not load the analysis" onRetry={reload} />
  if (!analysis) return null

  const summary = analysis.summary && typeof analysis.summary === 'object' ? analysis.summary : {}
  const deps = summary.dependencies || {}
  const vulns = summary.vulnerabilities || {}
  const usage = summary.usage || {}
  const graph = summary.knowledge_graph || {}
  const ai = summary.ai || {}
  const warnings = [
    ...(Array.isArray(summary.warnings) ? summary.warnings : []),
    ...(Array.isArray(deps.warnings) ? deps.warnings : []),
    ...(Array.isArray(vulns.notes) ? vulns.notes : []),
  ]
  const active = isActive(status)

  return (
    <div>
      <p className="crumbs">
        <Link to="/">Dashboard</Link> › <Link to={`/repositories/${analysis.repository_id}`}>Repository #{analysis.repository_id}{analysis.repository?.name ? ` (${analysis.repository.name})` : ''}</Link> › Analysis #{analysis.analysis_id}
      </p>
      <div className="page-head">
        <h1>Analysis #{analysis.analysis_id}</h1>
        <StatusBadge value={status} />
        {analysis.overall_risk && <span>overall risk <StatusBadge value={analysis.overall_risk} /></span>}
        {active && <Loading inline text="polling every 3 s…" />}
      </div>
      {error && <ErrorBox error={error} title="Refresh failed (still showing the last known state)" />}

      <Section title="Pipeline stages">
        <StageTracker stages={analysis.stages} />
        <KeyValue
          columns={4}
          items={[
            { label: 'Triggered by', value: analysis.triggered_by },
            { label: 'Started', value: fmtDate(analysis.started_at || analysis.created_at) },
            { label: 'Completed', value: fmtDate(analysis.completed_at) },
            { label: 'Duration', value: fmtDuration(analysis.started_at, analysis.completed_at) },
          ]}
        />
        {analysis.error_message && <div className="alert error"><strong>Pipeline error:</strong> {analysis.error_message}</div>}
      </Section>

      <Section title="Summary">
        <div className="tiles">
          <Counter label="Dependencies" value={analysis.dependencies_count ?? deps.total} />
          <Counter label="Vulnerable dependencies" value={vulns.vulnerable} tone={vulns.vulnerable ? 'danger' : ''} />
          <Counter label="Vulnerabilities" value={vulns.vulnerabilities_total} />
          <Counter label="Findings" value={analysis.findings_count ?? summary.findings} />
          <Counter label="Deps with source usage" value={usage.with_source_references} />
          <Counter label="Graph nodes" value={graph.nodes_written} />
          <Counter label="Graph relationships" value={graph.relationships_written} />
          <Counter label="AI analysed" value={ai.analyzed} />
        </div>
        <KeyValue
          columns={3}
          items={[
            { label: 'Language', value: summary.language },
            { label: 'Components', value: summary.components },
            { label: 'Dependency files', value: (summary.dependency_files || []).length ? summary.dependency_files.map((f) => <code key={f} className="chip">{f}</code>) : null },
            { label: 'By ecosystem', value: deps.by_ecosystem ? Object.entries(deps.by_ecosystem).map(([k, v]) => `${k}: ${v}`).join(', ') : null },
            { label: 'Direct / transitive / unknown', value: deps.total !== undefined ? `${deps.direct ?? 0} / ${deps.transitive ?? 0} / ${deps.unknown_scope ?? 0}` : null },
            { label: 'Pinned / unpinned', value: deps.total !== undefined ? `${deps.pinned ?? 0} / ${deps.unpinned ?? 0}` : null },
            { label: 'OSV checked / safe / unknown', value: vulns.checked !== undefined ? `${vulns.checked} / ${vulns.safe ?? 0} / ${vulns.unknown ?? 0}` : null },
            { label: 'OSV provider', value: vulns.provider_available === undefined ? null : <StatusBadge value={vulns.provider_available ? 'OK' : 'UNAVAILABLE'} /> },
            { label: 'Knowledge graph', value: graph.available === undefined ? null : <StatusBadge value={graph.available ? 'OK' : 'UNAVAILABLE'} /> },
            { label: 'AI model', value: ai.model },
            { label: 'AI completed / failed / skipped', value: ai.analyzed !== undefined ? `${ai.completed ?? 0} / ${ai.failed ?? 0} / ${ai.skipped ?? 0}${ai.limit ? ` (limit ${ai.limit})` : ''}` : null },
            { label: 'AI unavailable', value: ai.unavailable },
          ]}
        />
        {graph.error && <div className="alert info">Knowledge graph: {graph.error}</div>}
        <JsonBlock title="Raw summary JSON" data={summary} />
      </Section>

      {warnings.length > 0 && (
        <Section title={`Warnings (${warnings.length})`}>
          <ul className="list">
            {warnings.map((w, i) => <li key={i}>{typeof w === 'string' ? w : JSON.stringify(w)}</li>)}
          </ul>
        </Section>
      )}

      <Section title={`Findings${findings ? ` (${findings.length})` : ''}`} subtitle="Sorted by risk level. Risk is assigned by the AI risk agent; findings without AI results keep the deterministic default.">
        {active && <p className="muted">Findings will appear once the analysis completes.</p>}
        {!active && findingsError && <ErrorBox error={findingsError} title="Could not load findings" />}
        {!active && !findings && !findingsError && <Loading text="Loading findings…" />}
        {findings && (
          <Table
            rows={findings}
            rowKey={(f) => f.finding_id}
            empty="No vulnerable dependencies found."
            columns={[
              { key: 'finding_id', label: 'Finding', render: (f) => <Link to={`/findings/${f.finding_id}`}>#{f.finding_id}</Link> },
              { key: 'package', label: 'Package', render: (f) => <span className="mono">{pkgLabel(f.dependency)}</span> },
              { key: 'ecosystem', label: 'Ecosystem', render: (f) => f.dependency?.ecosystem },
              { key: 'vuln', label: 'Vulnerability', render: (f) => f.vulnerability?.identifier },
              { key: 'severity', label: 'Severity', render: (f) => <StatusBadge value={f.vulnerability?.severity} /> },
              { key: 'cvss', label: 'CVSS', render: (f) => f.vulnerability?.cvss_score },
              { key: 'risk_level', label: 'Risk', render: (f) => <StatusBadge value={f.risk_level} /> },
              { key: 'impact_level', label: 'Impact', render: (f) => f.impact_level ? <StatusBadge value={f.impact_level} /> : null },
              { key: 'components', label: 'Affected components', render: (f) => (f.affected_components || []).length ? f.affected_components.map((c) => <code key={c} className="chip">{c}</code>) : null },
              { key: 'ai_status', label: 'AI', render: (f) => <StatusBadge value={f.ai_status} /> },
            ]}
          />
        )}
      </Section>

      <p><Link to={`/repositories/${analysis.repository_id}`}>← Back to repository</Link></p>
    </div>
  )
}
