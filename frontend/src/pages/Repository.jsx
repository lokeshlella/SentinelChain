import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api/client.js'
import Section from '../components/Section.jsx'
import Table from '../components/Table.jsx'
import StatusBadge from '../components/StatusBadge.jsx'
import Loading from '../components/Loading.jsx'
import ErrorBox from '../components/ErrorBox.jsx'
import KeyValue from '../components/KeyValue.jsx'
import JsonBlock from '../components/JsonBlock.jsx'
import StageTracker from '../components/StageTracker.jsx'
import { fmtDate, fmtDuration, isActive } from '../utils/format.js'

const DEP_STATUSES = ['', 'VULNERABLE', 'SAFE', 'UNKNOWN', 'UNCHECKED']

function GraphView({ repositoryId }) {
  const [graph, setGraph] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    if (!open || graph) return
    setLoading(true)
    api.get(`/repositories/${repositoryId}/graph?limit=500`)
      .then(setGraph)
      .catch(setError)
      .finally(() => setLoading(false))
  }, [open, graph, repositoryId])

  const byType = useMemo(() => {
    const groups = {}
    for (const n of graph?.nodes || []) {
      const t = n?.type || 'Unknown'
      if (!groups[t]) groups[t] = []
      groups[t].push(n)
    }
    return groups
  }, [graph])

  const labelById = useMemo(() => {
    const m = {}
    for (const n of graph?.nodes || []) if (n?.id) m[n.id] = n.label || n.id
    return m
  }, [graph])

  return (
    <Section
      title="Knowledge graph"
      subtitle="Nodes and relationships stored in Neo4j for this repository (Repository → Component / Dependency → Vulnerability)."
      actions={<button type="button" className="btn" onClick={() => setOpen((v) => !v)}>{open ? 'Hide graph' : 'Show graph'}</button>}
    >
      {!open && <p className="muted">Click "Show graph" to load the nodes and edges.</p>}
      {open && loading && <Loading text="Loading graph…" />}
      {open && error && <ErrorBox error={error} title="Could not load the graph" />}
      {open && graph && !graph.available && <div className="alert info">{graph.message || 'Knowledge graph unavailable.'}</div>}
      {open && graph && graph.available && (
        <>
          <KeyValue
            columns={4}
            items={[
              { label: 'Nodes', value: (graph.nodes || []).length },
              { label: 'Edges', value: (graph.edges || []).length },
              { label: 'Components', value: graph.stats?.components },
              { label: 'Dependencies', value: graph.stats?.dependencies },
              { label: 'Vulnerabilities', value: graph.stats?.vulnerabilities },
              { label: 'Truncated', value: graph.truncated ? 'yes' : 'no' },
            ]}
          />
          {Object.keys(byType).map((type) => (
            <div key={type}>
              <h3>{type} nodes ({byType[type].length})</h3>
              <Table
                compact
                rows={byType[type]}
                rowKey={(n) => n.id}
                columns={[
                  { key: 'label', label: 'Label', render: (n) => <span className="mono">{n.label}</span> },
                  { key: 'id', label: 'Node id', render: (n) => <span className="mono small muted">{n.id}</span> },
                  { key: 'props', label: 'Properties', render: (n) => (
                    <span className="small">
                      {Object.entries(n.props || {}).map(([k, v]) => (
                        <span key={k} className="prop"><span className="muted">{k}=</span>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                      ))}
                    </span>
                  ) },
                ]}
              />
            </div>
          ))}
          <h3>Edges ({(graph.edges || []).length})</h3>
          <Table
            compact
            rows={graph.edges}
            rowKey={(e, i) => `${e.source}-${e.type}-${e.target}-${i}`}
            columns={[
              { key: 'source', label: 'Source', render: (e) => <span className="mono">{labelById[e.source] || e.source}</span> },
              { key: 'type', label: 'Relationship', render: (e) => <StatusBadge value={e.type} /> },
              { key: 'target', label: 'Target', render: (e) => <span className="mono">{labelById[e.target] || e.target}</span> },
            ]}
          />
          <JsonBlock title="Raw graph JSON" data={graph} />
        </>
      )}
    </Section>
  )
}

export default function Repository() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [repo, setRepo] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const [deps, setDeps] = useState(null)
  const [depsError, setDepsError] = useState(null)
  const [depsStatus, setDepsStatus] = useState('')

  const [runAi, setRunAi] = useState(true)
  const [refresh, setRefresh] = useState(false)
  const [analyzeBusy, setAnalyzeBusy] = useState(false)
  const [analyzeError, setAnalyzeError] = useState(null)
  const [deleteBusy, setDeleteBusy] = useState(false)

  function load() {
    setLoading(true)
    setError(null)
    api.get(`/repositories/${id}`).then(setRepo).catch(setError).finally(() => setLoading(false))
  }

  useEffect(load, [id])

  // Ingestion (clone / copy + profile) runs in the background: keep polling while PENDING.
  useEffect(() => {
    if (!repo || repo.status !== 'PENDING') return undefined
    const timer = setTimeout(() => api.get(`/repositories/${id}`).then(setRepo).catch(setError), 3000)
    return () => clearTimeout(timer)
  }, [repo, id])

  const [ingestBusy, setIngestBusy] = useState(false)
  async function reingest() {
    setIngestBusy(true)
    setError(null)
    try {
      setRepo(await api.post(`/repositories/${id}/ingest`))
    } catch (e) {
      setError(e)
    } finally {
      setIngestBusy(false)
    }
  }
  const ingesting = repo?.status === 'PENDING'
  const ingestFailed = repo?.status === 'FAILED'

  useEffect(() => {
    setDeps(null)
    setDepsError(null)
    const q = depsStatus ? `?status=${encodeURIComponent(depsStatus)}` : ''
    api.get(`/repositories/${id}/dependencies${q}`).then((d) => setDeps(Array.isArray(d) ? d : [])).catch(setDepsError)
  }, [id, depsStatus])

  async function analyze() {
    setAnalyzeBusy(true)
    setAnalyzeError(null)
    try {
      const analysis = await api.post(`/repositories/${id}/analyze`, { run_ai: runAi, refresh })
      navigate(`/analyses/${analysis.analysis_id}`)
    } catch (e) {
      // 409: an analysis is already running — offer the link
      setAnalyzeError(e)
      setAnalyzeBusy(false)
    }
  }

  async function remove() {
    if (!window.confirm(`Delete repository #${id} and all of its analyses? This cannot be undone.`)) return
    setDeleteBusy(true)
    try {
      await api.delete(`/repositories/${id}`)
      navigate('/')
    } catch (e) {
      setError(e)
      setDeleteBusy(false)
    }
  }

  if (loading && !repo) return <Loading text="Loading repository…" />
  if (error && !repo) return <ErrorBox error={error} title="Could not load the repository" onRetry={load} />
  if (!repo) return null

  const latest = repo.latest_analysis
  const analyses = Array.isArray(repo.analyses) ? repo.analyses : []
  const components = Array.isArray(repo.components) ? repo.components : []
  const profile = repo.profile && typeof repo.profile === 'object' ? repo.profile : {}
  const hints = profile.hints && typeof profile.hints === 'object' ? profile.hints : {}
  const runningAnalysisId = analyzeError?.data?.details?.analysis_id

  return (
    <div>
      <p className="crumbs"><Link to="/">Dashboard</Link> › Repository #{repo.repository_id}</p>
      <div className="page-head">
        <h1>{repo.name || `Repository #${repo.repository_id}`}</h1>
        <div className="badges">
          {repo.status && repo.status !== 'READY' && <StatusBadge value={repo.status === 'PENDING' ? 'INGESTING' : repo.status} />}
          {latest?.overall_risk && <StatusBadge value={latest.overall_risk} />}
        </div>
      </div>
      {error && <ErrorBox error={error} />}
      {ingesting && (
        <div className="alert info"><span className="spinner" />Ingesting the repository (clone / copy and structure profile) in the background… this page refreshes automatically.</div>
      )}
      {ingestFailed && (
        <div className="alert error">
          Ingestion failed: {repo.error_message || 'unknown error'}{' '}
          <button type="button" className="btn" disabled={ingestBusy} onClick={reingest}>{ingestBusy ? 'Retrying…' : 'Retry ingestion'}</button>
        </div>
      )}

      <Section
        title="Details"
        actions={<button type="button" className="btn danger" disabled={deleteBusy} onClick={remove}>{deleteBusy ? 'Deleting…' : 'Delete repository'}</button>}
      >
        <KeyValue
          columns={3}
          items={[
            { label: 'Source', value: <span className="mono small">{repo.source_url}</span> },
            { label: 'Type', value: repo.source_type },
            { label: 'Branch', value: repo.branch },
            { label: 'Language', value: repo.language },
            { label: 'Commit', value: repo.commit_sha ? <span className="mono small">{repo.commit_sha}</span> : null },
            { label: 'Local path', value: repo.local_path ? <span className="mono small">{repo.local_path}</span> : null },
            { label: 'Dependencies', value: repo.dependencies_count },
            { label: 'Vulnerable', value: <span className={repo.vulnerable_count ? 'danger-text' : ''}>{repo.vulnerable_count ?? 0}</span> },
            { label: 'Registered', value: fmtDate(repo.created_at) },
            { label: 'Latest analysis', value: latest ? (
              <span><Link to={`/analyses/${latest.analysis_id}`}>#{latest.analysis_id}</Link> <StatusBadge value={latest.status} /></span>
            ) : 'not analysed yet' },
          ]}
        />
        {latest?.stages && (
          <div className="mt">
            <StageTracker stages={latest.stages} />
          </div>
        )}
      </Section>

      <Section title="Analyze" subtitle="Runs extraction → OSV → source usage → knowledge graph → AI agents in the background.">
        <div className="form-row align-end">
          <label className="check">
            <input type="checkbox" checked={runAi} onChange={(e) => setRunAi(e.target.checked)} disabled={analyzeBusy} />
            Run AI agents (Ollama)
          </label>
          <label className="check">
            <input type="checkbox" checked={refresh} onChange={(e) => setRefresh(e.target.checked)} disabled={analyzeBusy} />
            Refresh working copy (re-clone / re-copy)
          </label>
          <button type="button" className="btn primary" disabled={analyzeBusy || ingesting} onClick={analyze} title={ingesting ? 'Wait for ingestion to finish' : undefined}>
            {analyzeBusy ? 'Starting…' : ingesting ? 'Ingesting…' : 'Analyze'}
          </button>
        </div>
        {analyzeError && (
          <div>
            <ErrorBox error={analyzeError} title="Could not start the analysis" />
            {runningAnalysisId && (
              <p><Link to={`/analyses/${runningAnalysisId}`}>Open the running analysis #{runningAnalysisId}</Link></p>
            )}
          </div>
        )}
      </Section>

      <Section title="Profile" subtitle="Deterministic facts detected when the repository was ingested.">
        <KeyValue
          columns={3}
          items={[
            { label: 'Project name', value: profile.name },
            { label: 'Total files', value: profile.total_files },
            { label: 'Languages', value: profile.languages ? Object.entries(profile.languages).map(([k, v]) => `${k} (${v})`).join(', ') : null },
            { label: 'Dependency files', value: (profile.dependency_files || []).length ? profile.dependency_files.map((f) => <code key={f} className="chip">{f}</code>) : null },
            { label: 'Source dirs', value: (profile.source_dirs || []).length ? profile.source_dirs.map((f) => <code key={f} className="chip">{f}</code>) : null },
            { label: 'Test dirs', value: (profile.test_dirs || []).length ? profile.test_dirs.map((f) => <code key={f} className="chip">{f}</code>) : null },
          ]}
        />
        {Object.keys(hints).length > 0 && (
          <>
            <h3>Hints</h3>
            <KeyValue
              columns={3}
              items={Object.entries(hints).map(([k, v]) => ({
                label: k,
                value: typeof v === 'boolean' ? <StatusBadge value={v ? 'OK' : 'UNAVAILABLE'} fallback="—" /> : (typeof v === 'object' ? JSON.stringify(v) : String(v)),
              }))}
            />
          </>
        )}
        <h3>Components ({components.length})</h3>
        <Table
          compact
          rows={components}
          rowKey={(c) => c.component_id}
          empty="No components detected."
          columns={[
            { key: 'name', label: 'Name', render: (c) => <span className="mono">{c.name}</span> },
            { key: 'path', label: 'Path', render: (c) => <span className="mono small">{c.path}</span> },
            { key: 'component_type', label: 'Type' },
            { key: 'file_count', label: 'Files' },
            { key: 'description', label: 'Description' },
          ]}
        />
        <JsonBlock title="Raw profile JSON" data={profile} />
      </Section>

      <Section title={`Analyses (${analyses.length})`}>
        <Table
          rows={analyses}
          rowKey={(a) => a.analysis_id}
          empty="No analyses yet — click Analyze above."
          columns={[
            { key: 'analysis_id', label: 'Analysis', render: (a) => <Link to={`/analyses/${a.analysis_id}`}>#{a.analysis_id}</Link> },
            { key: 'status', label: 'Status', render: (a) => <StatusBadge value={a.status} /> },
            { key: 'overall_risk', label: 'Overall risk', render: (a) => a.overall_risk ? <StatusBadge value={a.overall_risk} /> : null },
            { key: 'dependencies_count', label: 'Dependencies' },
            { key: 'findings_count', label: 'Findings' },
            { key: 'triggered_by', label: 'Triggered by' },
            { key: 'started_at', label: 'Started', render: (a) => fmtDate(a.started_at || a.created_at) },
            { key: 'duration', label: 'Duration', render: (a) => isActive(a.status) ? <span className="muted">running…</span> : fmtDuration(a.started_at, a.completed_at) },
            { key: 'error_message', label: 'Error', render: (a) => a.error_message ? <span className="danger-text small">{a.error_message}</span> : null },
          ]}
        />
      </Section>

      <Section
        title="Dependencies"
        subtitle="From the latest completed analysis. Vulnerability status comes from OSV."
        actions={
          <label className="field inline">
            <span>Status</span>
            <select value={depsStatus} onChange={(e) => setDepsStatus(e.target.value)}>
              {DEP_STATUSES.map((s) => <option key={s} value={s}>{s || 'All'}</option>)}
            </select>
          </label>
        }
      >
        {depsError && <ErrorBox error={depsError} title="Could not load dependencies" />}
        {!deps && !depsError && <Loading text="Loading dependencies…" />}
        {deps && (
          <Table
            rows={deps}
            rowKey={(d) => d.dependency_id}
            empty={depsStatus ? `No ${depsStatus} dependencies.` : 'No dependencies recorded yet (run an analysis).'}
            columns={[
              { key: 'package_name', label: 'Package', render: (d) => <span className="mono">{d.package_name}</span> },
              { key: 'version', label: 'Version', render: (d) => <span className="mono">{d.version || d.version_spec || '—'}</span> },
              { key: 'ecosystem', label: 'Ecosystem' },
              { key: 'direct_or_transitive', label: 'Scope' },
              { key: 'source_file', label: 'Source file', render: (d) => <span className="mono small">{d.source_file}</span> },
              { key: 'vulnerability_status', label: 'Status', render: (d) => <StatusBadge value={d.vulnerability_status} /> },
              { key: 'status_reason', label: 'Reason', render: (d) => d.status_reason ? <span className="small">{d.status_reason}</span> : null },
            ]}
          />
        )}
      </Section>

      <GraphView repositoryId={id} />
    </div>
  )
}
