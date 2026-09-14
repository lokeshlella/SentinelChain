import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client.js'
import Section from '../components/Section.jsx'
import StatusBadge from '../components/StatusBadge.jsx'
import Loading from '../components/Loading.jsx'
import ErrorBox from '../components/ErrorBox.jsx'
import KeyValue from '../components/KeyValue.jsx'
import JsonBlock from '../components/JsonBlock.jsx'
import { fmtDate } from '../utils/format.js'

export default function PullRequest() {
  const { id } = useParams()
  const [pr, setPr] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  function load() {
    setLoading(true)
    setError(null)
    api.get(`/pull-requests/${id}`).then(setPr).catch(setError).finally(() => setLoading(false))
  }
  useEffect(load, [id])

  if (loading && !pr) return <Loading text="Loading pull request…" />
  if (error && !pr) return <ErrorBox error={error} title="Could not load the pull request" onRetry={load} />
  if (!pr) return null

  const status = String(pr.review_status || '').toUpperCase()
  const manual = status === 'UNAVAILABLE' || status === 'FAILED'

  return (
    <div>
      <p className="crumbs">
        <Link to="/">Dashboard</Link> › <Link to="/pull-requests">Pull requests</Link> › <Link to={`/remediations/${pr.remediation_id}`}>Remediation #{pr.remediation_id}</Link> › PR #{pr.pr_id}
      </p>
      <div className="page-head">
        <h1>{pr.title || `Pull request #${pr.pr_id}`}</h1>
        <StatusBadge value={pr.review_status} />
      </div>
      {error && <ErrorBox error={error} />}
      {pr.error_message && <div className="alert error"><strong>Error:</strong> {pr.error_message}</div>}

      <Section
        title="Details"
        actions={pr.pr_url ? <a className="btn primary" href={pr.pr_url} target="_blank" rel="noreferrer">Open on GitHub ↗</a> : null}
      >
        <KeyValue
          columns={3}
          items={[
            { label: 'Review status', value: <StatusBadge value={pr.review_status} /> },
            { label: 'GitHub URL', value: pr.pr_url ? <a href={pr.pr_url} target="_blank" rel="noreferrer">{pr.pr_url}</a> : <span className="muted">not created on GitHub</span> },
            { label: 'PR number', value: pr.pr_number },
            { label: 'Branch', value: pr.branch_name ? <span className="mono">{pr.branch_name}</span> : null },
            { label: 'Remediation', value: <Link to={`/remediations/${pr.remediation_id}`}>#{pr.remediation_id}</Link> },
            { label: 'Created', value: fmtDate(pr.created_at) },
            { label: 'Reviewed', value: fmtDate(pr.reviewed_at) },
          ]}
        />
        {status === 'DRAFT' && <div className="alert info">Draft pull request — a human reviewer must review and merge it; Sentinel Chain never merges automatically.</div>}
      </Section>

      {manual && (
        <Section title="Manual instructions" subtitle={status === 'UNAVAILABLE' ? 'GitHub credentials are not configured (or the repository is local), so the pull request could not be opened automatically.' : 'The pull request could not be created. Apply the change manually with the steps below.'}>
          {pr.instructions ? <pre className="pre prewrap">{pr.instructions}</pre> : <p className="muted">No instructions recorded.</p>}
        </Section>
      )}

      <Section title="Pull request body" subtitle="Markdown as it appears on GitHub (rendered here as preformatted text).">
        {pr.body ? <pre className="pre prewrap markdown">{pr.body}</pre> : <p className="muted">No body.</p>}
      </Section>

      <Section title="Evidence" subtitle="Snapshot of the finding, remediation and validation the PR was created from.">
        {pr.evidence ? <JsonBlock title="Evidence JSON" data={pr.evidence} open /> : <p className="muted">No evidence attached.</p>}
      </Section>

      <p><Link to={`/remediations/${pr.remediation_id}`}>← Back to remediation #{pr.remediation_id}</Link></p>
    </div>
  )
}
