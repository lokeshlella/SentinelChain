import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api/client.js'
import usePolling from '../hooks/usePolling.js'
import Section from '../components/Section.jsx'
import Table from '../components/Table.jsx'
import StatusBadge from '../components/StatusBadge.jsx'
import Loading from '../components/Loading.jsx'
import ErrorBox from '../components/ErrorBox.jsx'
import KeyValue from '../components/KeyValue.jsx'
import JsonBlock from '../components/JsonBlock.jsx'
import DiffView from '../components/DiffView.jsx'
import { asList, fmtDate, fmtPercent, isActive, pkgLabel } from '../utils/format.js'

// candidates may be {versions: [...]} / {fixed_versions: [...]} / a list — normalise to rows.
function candidateRows(candidates) {
  if (!candidates) return []
  if (Array.isArray(candidates)) return candidates.map((c) => (typeof c === 'object' && c ? c : { version: String(c) }))
  if (typeof candidates !== 'object') return []
  for (const key of ['candidates', 'versions', 'fixed_versions', 'options']) {
    if (Array.isArray(candidates[key])) return candidates[key].map((c) => (typeof c === 'object' && c ? c : { version: String(c) }))
  }
  return []
}

function candidateColumns(rows) {
  const keys = []
  for (const r of rows) for (const k of Object.keys(r || {})) if (!keys.includes(k)) keys.push(k)
  const preferred = ['version', 'package', 'package_name', 'source', 'reason', 'fixes', 'fixes_all', 'is_latest', 'released_at', 'notes']
  keys.sort((a, b) => {
    const ia = preferred.indexOf(a), ib = preferred.indexOf(b)
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib)
  })
  return keys.map((k) => ({
    key: k,
    label: k.replace(/_/g, ' '),
    render: (r) => {
      const v = r[k]
      if (v === null || v === undefined) return null
      if (typeof v === 'boolean') return v ? 'yes' : 'no'
      if (Array.isArray(v)) return v.map((x, i) => <code key={i} className="chip">{typeof x === 'string' ? x : JSON.stringify(x)}</code>)
      if (typeof v === 'object') return <code className="snippet">{JSON.stringify(v)}</code>
      return String(v)
    },
  }))
}

export default function Remediation() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { data: rem, error, loading, reload } = usePolling(
    () => api.get(`/remediations/${id}`),
    3000,
    (r) => isActive(r?.status),
    [id],
  )
  const [validateBusy, setValidateBusy] = useState(false)
  const [validateError, setValidateError] = useState(null)
  const [prBusy, setPrBusy] = useState(false)
  const [prError, setPrError] = useState(null)
  const [force, setForce] = useState(false)

  useEffect(() => { setValidateError(null); setPrError(null) }, [id])

  async function validate() {
    setValidateBusy(true)
    setValidateError(null)
    try {
      const v = await api.post(`/remediations/${id}/validate`)
      navigate(`/validations/${v.validation_id}`)
    } catch (e) {
      setValidateError(e)
      setValidateBusy(false)
    }
  }

  async function createPr() {
    setPrBusy(true)
    setPrError(null)
    try {
      const pr = await api.post(`/remediations/${id}/pull-request`, { force })
      navigate(`/pull-requests/${pr.pr_id}`)
    } catch (e) {
      // 502 = GitHub refused, but the PR record (with the error and manual instructions) exists:
      // show it instead of a bare error.
      if (e?.data?.pr_id) {
        navigate(`/pull-requests/${e.data.pr_id}`)
        return
      }
      setPrError(e)
      setPrBusy(false)
    }
  }

  if (loading && !rem) return <Loading text="Loading remediation…" />
  if (error && !rem) return <ErrorBox error={error} title="Could not load the remediation" onRetry={reload} />
  if (!rem) return null

  const finding = rem.finding || {}
  const dep = finding.dependency || {}
  const change = rem.proposed_change && typeof rem.proposed_change === 'object' ? rem.proposed_change : null
  const candidates = rem.candidates && typeof rem.candidates === 'object' ? rem.candidates : null
  const candRows = candidateRows(candidates)
  const candMeta = candidates && !Array.isArray(candidates)
    ? Object.entries(candidates).filter(([, v]) => !Array.isArray(v) || v.every((x) => typeof x !== 'object'))
    : []
  const validations = asList(rem.validations)
  const pullRequests = asList(rem.pull_requests)
  const latestValidation = validations.length ? validations[validations.length - 1] : null
  const validationFailed = latestValidation && String(latestValidation.overall_result || '').toUpperCase() === 'FAIL'
  const validationPassed = latestValidation && String(latestValidation.overall_result || '').toUpperCase() === 'PASS'
  const status = String(rem.status || '').toUpperCase()
  const canValidate = !!change && status !== 'FAILED' && !isActive(status)
  const ai = rem.ai_result && typeof rem.ai_result === 'object' ? rem.ai_result : null

  return (
    <div>
      <p className="crumbs">
        <Link to="/">Dashboard</Link>
        {finding.analysis_id ? <> › <Link to={`/analyses/${finding.analysis_id}`}>Analysis #{finding.analysis_id}</Link></> : null}
        {' '}› <Link to={`/findings/${rem.finding_id}`}>Finding #{rem.finding_id}</Link> › Remediation #{rem.remediation_id}
      </p>
      <div className="page-head">
        <h1>Remediation #{rem.remediation_id}{dep.package_name ? <>: <span className="mono">{pkgLabel(dep)}</span></> : null}</h1>
        <StatusBadge value={rem.status} />
        {isActive(status) && <Loading inline text="polling…" />}
      </div>
      {error && <ErrorBox error={error} title="Refresh failed (showing the last known state)" />}
      {rem.error_message && <div className="alert error"><strong>Remediation error:</strong> {rem.error_message}</div>}
      {status === 'PENDING' && (
        <div className="alert info"><span className="spinner" />Computing candidate versions (OSV + registry) and asking the local LLM for a recommendation in the background… this page refreshes automatically.</div>
      )}

      <Section title="Recommendation" subtitle="The recommended version must be one of the deterministic candidates below; the agent only chooses among them.">
        <div className="upgrade">
          <span className="mono big">{rem.current_version || dep.version || '?'}</span>
          <span className="arrow">→</span>
          <span className="mono big ok-text">{rem.recommended_version || (rem.alternative_package ? `switch to ${rem.alternative_package}` : 'no version recommended')}</span>
        </div>
        <KeyValue
          columns={3}
          items={[
            { label: 'Package', value: dep.package_name ? <span className="mono">{dep.package_name}</span> : null },
            { label: 'Ecosystem', value: dep.ecosystem },
            { label: 'Vulnerability', value: finding.vulnerability?.identifier ? <span>{finding.vulnerability.identifier} <StatusBadge value={finding.vulnerability.severity} /></span> : null },
            { label: 'Alternative package', value: rem.alternative_package ? <span className="mono">{rem.alternative_package}</span> : null },
            { label: 'Confidence', value: fmtPercent(rem.confidence_score) },
            { label: 'Created', value: fmtDate(rem.created_at) },
          ]}
        />
        {rem.recommendation && <p className="prewrap">{rem.recommendation}</p>}
      </Section>

      <Section title="Candidates — Observed facts" subtitle="Fixed versions from OSV and registry metadata; computed deterministically before the agent runs.">
        {candRows.length > 0 ? (
          <Table compact rows={candRows} rowKey={(r, i) => `${r.version || i}-${i}`} columns={candidateColumns(candRows)} />
        ) : <p className="muted">No candidate table available.</p>}
        {candMeta.length > 0 && (
          <KeyValue
            columns={3}
            items={candMeta.map(([k, v]) => ({
              label: k.replace(/_/g, ' '),
              value: Array.isArray(v) ? (v.length ? v.map((x, i) => <code key={i} className="chip">{String(x)}</code>) : null)
                : (typeof v === 'boolean' ? (v ? 'yes' : 'no') : (typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v))),
            }))}
          />
        )}
        <JsonBlock title="Raw candidates JSON" data={candidates} />
      </Section>

      <Section title="AI result (inference)" subtitle="Structured output of the remediation agent.">
        {ai ? (
          <>
            <KeyValue
              columns={3}
              items={[
                { label: 'Recommended version', value: ai.recommended_version ? <span className="mono">{ai.recommended_version}</span> : null },
                { label: 'Alternative package', value: ai.alternative_package ? <span className="mono">{ai.alternative_package}</span> : null },
                { label: 'Confidence', value: fmtPercent(ai.confidence) },
                { label: 'Model', value: ai.model },
                { label: 'Status', value: ai.status ? <StatusBadge value={ai.status} /> : null },
              ]}
            />
            {ai.reasoning && <p className="prewrap">{ai.reasoning}</p>}
            {ai.compatibility_notes && <p className="prewrap small"><strong>Compatibility notes:</strong> {ai.compatibility_notes}</p>}
            {ai.error && <div className="alert error">{String(ai.error)}</div>}
          </>
        ) : <p className="muted">No AI result stored (the recommendation may have been derived deterministically).</p>}
        <JsonBlock title="Raw AI result JSON" data={ai} open={!ai || (!ai.reasoning && !ai.recommended_version)} />
      </Section>

      <Section title="Proposed change" subtitle="Applied to a temporary working copy only; the original repository is never modified.">
        {change ? (
          <>
            <KeyValue
              columns={3}
              items={[
                { label: 'File', value: change.file ? <span className="mono">{change.file}</span> : null },
                { label: 'Line', value: change.line_number },
                { label: 'Workspace', value: change.workspace_path ? <span className="mono small">{change.workspace_path}</span> : null },
              ]}
            />
            {(change.before || change.after) && (
              <div className="grid-2">
                <div><div className="label">Before</div><pre className="pre small">{String(change.before ?? '')}</pre></div>
                <div><div className="label">After</div><pre className="pre small">{String(change.after ?? '')}</pre></div>
              </div>
            )}
            <div className="label">Diff</div>
            <DiffView diff={change.diff} before={change.diff ? null : change.before} after={change.diff ? null : change.after} />
            {change.notes && <p className="prewrap small"><strong>Notes:</strong> {typeof change.notes === 'string' ? change.notes : JSON.stringify(change.notes)}</p>}
            <JsonBlock title="Raw proposed change JSON" data={change} />
          </>
        ) : <p className="muted">No change proposed{rem.error_message ? ` — ${rem.error_message}` : ''}.</p>}
      </Section>

      <Section
        title={`Validations (${validations.length})`}
        subtitle="Each validation installs the patched dependencies in a Docker sandbox, runs the project's tests and re-checks OSV."
        actions={
          <button type="button" className="btn primary" disabled={!canValidate || validateBusy} onClick={validate} title={canValidate ? '' : 'A proposed change is required before validating'}>
            {validateBusy ? <><span className="spinner light" /> Starting…</> : 'Validate in Docker sandbox'}
          </button>
        }
      >
        {validateError && <ErrorBox error={validateError} title="Could not start the validation" />}
        <Table
          rows={validations}
          rowKey={(v) => v.validation_id}
          empty="Not validated yet."
          columns={[
            { key: 'validation_id', label: 'Validation', render: (v) => <Link to={`/validations/${v.validation_id}`}>#{v.validation_id}</Link> },
            { key: 'status', label: 'Status', render: (v) => <StatusBadge value={v.status} /> },
            { key: 'build_status', label: 'Build', render: (v) => <StatusBadge value={v.build_status} /> },
            { key: 'test_status', label: 'Tests', render: (v) => <StatusBadge value={v.test_status} /> },
            { key: 'security_scan_status', label: 'Security', render: (v) => <StatusBadge value={v.security_scan_status} /> },
            { key: 'overall_result', label: 'Overall', render: (v) => <StatusBadge value={v.overall_result} /> },
            { key: 'validated_at', label: 'Validated', render: (v) => fmtDate(v.validated_at || v.created_at) },
            { key: 'error_message', label: 'Error', render: (v) => v.error_message ? <span className="danger-text small">{v.error_message}</span> : null },
          ]}
        />
      </Section>

      <Section
        title={`Pull requests (${pullRequests.length})`}
        subtitle="Creates a branch with the validated change and opens a DRAFT pull request on GitHub (never merged automatically). Without credentials the PR is recorded as UNAVAILABLE with manual instructions."
        actions={
          <>
            {(validationFailed || !validationPassed) && (
              <label className="check" title="Create the PR even though the validation did not pass">
                <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} disabled={prBusy} />
                force (skip validation gate)
              </label>
            )}
            <button type="button" className="btn primary" disabled={prBusy || !change} onClick={createPr}>
              {prBusy ? <><span className="spinner light" /> Creating…</> : 'Create draft pull request'}
            </button>
          </>
        }
      >
        {validationFailed && <div className="alert error">The latest validation failed. Tick "force" to create the pull request anyway.</div>}
        {!latestValidation && change && <div className="alert info">No validation has been run yet. The backend may refuse to open a PR without a passing validation unless "force" is ticked.</div>}
        {prError && <ErrorBox error={prError} title="Could not create the pull request" />}
        <Table
          rows={pullRequests}
          rowKey={(p) => p.pr_id}
          empty="No pull request yet."
          columns={[
            { key: 'pr_id', label: 'PR', render: (p) => <Link to={`/pull-requests/${p.pr_id}`}>#{p.pr_id}</Link> },
            { key: 'title', label: 'Title' },
            { key: 'review_status', label: 'Status', render: (p) => <StatusBadge value={p.review_status} /> },
            { key: 'branch_name', label: 'Branch', render: (p) => p.branch_name ? <span className="mono small">{p.branch_name}</span> : null },
            { key: 'pr_url', label: 'GitHub', render: (p) => p.pr_url ? <a href={p.pr_url} target="_blank" rel="noreferrer">{p.pr_number ? `#${p.pr_number}` : 'open'} ↗</a> : null },
            { key: 'created_at', label: 'Created', render: (p) => fmtDate(p.created_at) },
            { key: 'error_message', label: 'Error', render: (p) => p.error_message ? <span className="danger-text small">{p.error_message}</span> : null },
          ]}
        />
      </Section>

      <p><Link to={`/findings/${rem.finding_id}`}>← Back to finding #{rem.finding_id}</Link></p>
    </div>
  )
}
