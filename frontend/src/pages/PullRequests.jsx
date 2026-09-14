import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import Section from '../components/Section.jsx'
import Table from '../components/Table.jsx'
import StatusBadge from '../components/StatusBadge.jsx'
import Loading from '../components/Loading.jsx'
import ErrorBox from '../components/ErrorBox.jsx'
import { fmtDate } from '../utils/format.js'

export default function PullRequests() {
  const [rows, setRows] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  function load() {
    setLoading(true)
    setError(null)
    api.get('/pull-requests').then((d) => setRows(Array.isArray(d) ? d : (d?.items || []))).catch(setError).finally(() => setLoading(false))
  }
  useEffect(load, [])

  return (
    <div>
      <h1>Pull requests</h1>
      <Section subtitle="Draft pull requests created from validated remediations. Sentinel Chain never merges automatically.">
        {error && <ErrorBox error={error} title="Could not load pull requests" onRetry={load} />}
        {loading && !rows && <Loading />}
        {rows && (
          <Table
            rows={rows}
            rowKey={(p) => p.pr_id}
            empty="No pull requests yet. Generate a remediation from a finding, validate it, then create a draft PR."
            columns={[
              { key: 'pr_id', label: 'PR', render: (p) => <Link to={`/pull-requests/${p.pr_id}`}>#{p.pr_id}</Link> },
              { key: 'title', label: 'Title', render: (p) => <Link to={`/pull-requests/${p.pr_id}`}>{p.title || `Pull request #${p.pr_id}`}</Link> },
              { key: 'review_status', label: 'Status', render: (p) => <StatusBadge value={p.review_status} /> },
              { key: 'remediation_id', label: 'Remediation', render: (p) => <Link to={`/remediations/${p.remediation_id}`}>#{p.remediation_id}</Link> },
              { key: 'branch_name', label: 'Branch', render: (p) => p.branch_name ? <span className="mono small">{p.branch_name}</span> : null },
              { key: 'pr_url', label: 'GitHub', render: (p) => p.pr_url ? <a href={p.pr_url} target="_blank" rel="noreferrer">{p.pr_number ? `#${p.pr_number}` : 'open'} ↗</a> : null },
              { key: 'created_at', label: 'Created', render: (p) => fmtDate(p.created_at) },
              { key: 'error_message', label: 'Error', render: (p) => p.error_message ? <span className="danger-text small">{p.error_message}</span> : null },
            ]}
          />
        )}
      </Section>
    </div>
  )
}
