import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import Section from '../components/Section.jsx'
import Table from '../components/Table.jsx'
import StatusBadge from '../components/StatusBadge.jsx'
import Loading from '../components/Loading.jsx'
import ErrorBox from '../components/ErrorBox.jsx'
import { fmtDate, pkgLabel } from '../utils/format.js'

const RISK_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']

function Tile({ label, value, tone, to }) {
  const body = (
    <div className={`tile ${tone || ''}`}>
      <div className="tile-value">{value ?? '—'}</div>
      <div className="tile-label">{label}</div>
    </div>
  )
  return to ? <Link to={to} className="tile-link">{body}</Link> : body
}

function AddRepositoryForm({ onCreated }) {
  const [sourceUrl, setSourceUrl] = useState('')
  const [branch, setBranch] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function submit(e) {
    e.preventDefault()
    if (!sourceUrl.trim()) {
      setError('Enter a GitHub URL or a local directory path.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const payload = { source_url: sourceUrl.trim() }
      if (branch.trim()) payload.branch = branch.trim()
      const repo = await api.post('/repositories', payload)
      onCreated(repo)
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="form-row" onSubmit={submit}>
      <label className="field grow">
        <span>Repository URL or local path</span>
        <input
          type="text"
          value={sourceUrl}
          onChange={(e) => setSourceUrl(e.target.value)}
          placeholder="https://github.com/owner/repo or /path/to/project"
          disabled={busy}
        />
      </label>
      <label className="field">
        <span>Branch (optional)</span>
        <input type="text" value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="main" disabled={busy} />
      </label>
      <div className="field">
        <span>&nbsp;</span>
        <button type="submit" className="btn primary" disabled={busy}>
          {busy ? 'Registering…' : 'Add repository'}
        </button>
      </div>
      <div className="form-note muted">Source type (github / local) is detected automatically. Registration clones or copies the repository.</div>
      {error && <div className="form-error"><ErrorBox error={error} /></div>}
    </form>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [repos, setRepos] = useState(null)

  function load() {
    setLoading(true)
    setError(null)
    Promise.all([api.get('/dashboard'), api.get('/repositories')])
      .then(([dash, list]) => {
        setData(dash)
        setRepos(Array.isArray(list) ? list : [])
      })
      .catch(setError)
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  const byRisk = data?.findings_by_risk || {}

  return (
    <div>
      <h1>Dashboard</h1>

      <Section title="Add repository" subtitle="Register a GitHub repository or a local project, then start an analysis from its page.">
        <AddRepositoryForm onCreated={(repo) => navigate(`/repositories/${repo.repository_id}`)} />
      </Section>

      {error && <ErrorBox error={error} title="Could not load the dashboard" onRetry={load} />}
      {loading && !data && <Loading />}

      {data && (
        <>
          <div className="tiles">
            <Tile label="Repositories" value={data.repositories} />
            <Tile label="Analyses" value={data.analyses} />
            <Tile label="Dependencies" value={data.dependencies} />
            <Tile label="Vulnerable dependencies" value={data.vulnerable_dependencies} tone={data.vulnerable_dependencies ? 'danger' : 'ok'} />
            <Tile label="Findings" value={data.findings} />
            <Tile label="Remediations" value={data.remediations} />
            <Tile label="Validations" value={data.validations} />
            <Tile label="Pull requests" value={data.pull_requests} to="/pull-requests" />
          </div>

          <Section title="Findings by risk level">
            <div className="tiles small">
              {RISK_LEVELS.map((level) => (
                <div key={level} className={`tile risk-${level.toLowerCase()}`}>
                  <div className="tile-value">{byRisk[level] ?? 0}</div>
                  <div className="tile-label"><StatusBadge value={level} /></div>
                </div>
              ))}
              {Object.keys(byRisk)
                .filter((k) => !RISK_LEVELS.includes(k))
                .map((k) => (
                  <div key={k} className="tile">
                    <div className="tile-value">{byRisk[k]}</div>
                    <div className="tile-label"><StatusBadge value={k} /></div>
                  </div>
                ))}
            </div>
          </Section>

          <Section title="Repositories">
            <Table
              rows={repos || data.recent_repositories}
              rowKey={(r) => r.repository_id}
              empty="No repositories yet — add one above."
              columns={[
                { key: 'name', label: 'Name', render: (r) => (
                  <span>
                    <Link to={`/repositories/${r.repository_id}`}>{r.name || `#${r.repository_id}`}</Link>
                    {r.status && r.status !== 'READY' && <> <StatusBadge value={r.status === 'PENDING' ? 'INGESTING' : r.status} /></>}
                  </span>
                ) },
                { key: 'source_url', label: 'Source', render: (r) => <span className="mono small">{r.source_url}</span> },
                { key: 'source_type', label: 'Type' },
                { key: 'language', label: 'Language' },
                { key: 'dependencies_count', label: 'Dependencies' },
                { key: 'vulnerable_count', label: 'Vulnerable', render: (r) => <span className={r.vulnerable_count ? 'danger-text' : ''}>{r.vulnerable_count ?? 0}</span> },
                { key: 'latest', label: 'Latest analysis', render: (r) => r.latest_analysis ? (
                  <Link to={`/analyses/${r.latest_analysis.analysis_id}`}>
                    #{r.latest_analysis.analysis_id} <StatusBadge value={r.latest_analysis.status} />
                  </Link>
                ) : <span className="muted">not analysed</span> },
                { key: 'risk', label: 'Risk', render: (r) => r.latest_analysis?.overall_risk ? <StatusBadge value={r.latest_analysis.overall_risk} /> : null },
              ]}
            />
          </Section>

          <Section title="Recent analyses">
            <Table
              rows={data.recent_analyses}
              rowKey={(a) => a.analysis_id}
              empty="No analyses yet."
              columns={[
                { key: 'analysis_id', label: 'Analysis', render: (a) => <Link to={`/analyses/${a.analysis_id}`}>#{a.analysis_id}</Link> },
                { key: 'repository_id', label: 'Repository', render: (a) => <Link to={`/repositories/${a.repository_id}`}>#{a.repository_id}</Link> },
                { key: 'status', label: 'Status', render: (a) => <StatusBadge value={a.status} /> },
                { key: 'overall_risk', label: 'Overall risk', render: (a) => a.overall_risk ? <StatusBadge value={a.overall_risk} /> : null },
                { key: 'dependencies_count', label: 'Dependencies' },
                { key: 'findings_count', label: 'Findings' },
                { key: 'created_at', label: 'Started', render: (a) => fmtDate(a.started_at || a.created_at) },
                { key: 'error_message', label: 'Error', render: (a) => a.error_message ? <span className="danger-text small">{a.error_message}</span> : null },
              ]}
            />
          </Section>

          <Section title="High-risk findings" subtitle="CRITICAL and HIGH risk findings across all analyses.">
            <Table
              rows={data.high_risk_findings}
              rowKey={(f) => f.finding_id}
              empty="No high-risk findings."
              columns={[
                { key: 'finding_id', label: 'Finding', render: (f) => <Link to={`/findings/${f.finding_id}`}>#{f.finding_id}</Link> },
                { key: 'package', label: 'Package', render: (f) => <span className="mono">{pkgLabel(f.dependency)}</span> },
                { key: 'ecosystem', label: 'Ecosystem', render: (f) => f.dependency?.ecosystem },
                { key: 'vuln', label: 'Vulnerability', render: (f) => f.vulnerability?.identifier },
                { key: 'severity', label: 'Severity', render: (f) => <StatusBadge value={f.vulnerability?.severity} /> },
                { key: 'risk_level', label: 'Risk', render: (f) => <StatusBadge value={f.risk_level} /> },
                { key: 'impact_level', label: 'Impact', render: (f) => f.impact_level ? <StatusBadge value={f.impact_level} /> : null },
                { key: 'ai_status', label: 'AI', render: (f) => <StatusBadge value={f.ai_status} /> },
                { key: 'analysis_id', label: 'Analysis', render: (f) => <Link to={`/analyses/${f.analysis_id}`}>#{f.analysis_id}</Link> },
              ]}
            />
          </Section>
        </>
      )}
    </div>
  )
}
