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
import { asList, fmtDate, fmtDuration, fmtSeconds, isActive } from '../utils/format.js'

function Logs({ validation }) {
  const [open, setOpen] = useState(false)
  const [text, setText] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const inline = typeof validation?.logs === 'string' && validation.logs.length > 0

  useEffect(() => {
    if (!open || inline || text !== null) return
    setLoading(true)
    api.getText(`/validations/${validation.validation_id}/logs`)
      .then((t) => setText(t || ''))
      .catch(setError)
      .finally(() => setLoading(false))
  }, [open, inline, text, validation?.validation_id])

  // When polling refreshes the validation with inline logs, prefer them.
  const body = inline ? validation.logs : text

  return (
    <div>
      <button type="button" className="linklike" onClick={() => setOpen((v) => !v)}>
        {open ? '▾' : '▸'} Full sandbox logs{validation?.logs_path ? <span className="muted small"> ({validation.logs_path})</span> : null}
      </button>
      {open && loading && <Loading text="Loading logs…" />}
      {open && error && <ErrorBox error={error} title="Could not load logs" />}
      {open && body !== null && body !== undefined && (
        <pre className="pre logs">{body.length ? body : '(empty log)'}</pre>
      )}
    </div>
  )
}

export default function Validation() {
  const { id } = useParams()
  const { data: v, error, loading, reload } = usePolling(
    () => api.get(`/validations/${id}`),
    3000,
    (val) => isActive(val?.status),
    [id],
  )

  if (loading && !v) return <Loading text="Loading validation…" />
  if (error && !v) return <ErrorBox error={error} title="Could not load the validation" onRetry={reload} />
  if (!v) return null

  const details = v.details && typeof v.details === 'object' ? v.details : {}
  const steps = asList(details.steps)
  const warnings = asList(details.warnings)
  const scan = details.security_scan && typeof details.security_scan === 'object' ? details.security_scan : null
  const active = isActive(v.status)
  const extraDetailKeys = Object.keys(details).filter((k) => !['image', 'steps', 'warnings', 'security_scan'].includes(k))

  return (
    <div>
      <p className="crumbs">
        <Link to="/">Dashboard</Link> › <Link to={`/remediations/${v.remediation_id}`}>Remediation #{v.remediation_id}</Link> › Validation #{v.validation_id}
      </p>
      <div className="page-head">
        <h1>Validation #{v.validation_id}</h1>
        <StatusBadge value={v.status} />
        {active && <Loading inline text="running in the sandbox — polling every 3 s…" />}
      </div>
      {error && <ErrorBox error={error} title="Refresh failed (showing the last known state)" />}
      {v.error_message && <div className="alert error"><strong>Validation error:</strong> {v.error_message}</div>}

      <Section title="Results">
        <div className="tiles">
          <div className="tile"><div className="tile-value"><StatusBadge value={v.build_status} /></div><div className="tile-label">Build / install</div></div>
          <div className="tile"><div className="tile-value"><StatusBadge value={v.test_status} /></div><div className="tile-label">Tests</div></div>
          <div className="tile"><div className="tile-value"><StatusBadge value={v.security_scan_status} /></div><div className="tile-label">Security scan</div></div>
          <div className="tile"><div className="tile-value"><StatusBadge value={v.overall_result} /></div><div className="tile-label">Overall</div></div>
        </div>
        <KeyValue
          columns={4}
          items={[
            { label: 'Docker image', value: details.image ? <span className="mono">{details.image}</span> : null },
            { label: 'Created', value: fmtDate(v.created_at) },
            { label: 'Validated', value: fmtDate(v.validated_at) },
            { label: 'Duration', value: fmtDuration(v.created_at, v.validated_at) },
            { label: 'Timed out', value: details.timed_out === undefined ? null : (details.timed_out ? 'yes' : 'no') },
            { label: 'Container', value: details.container_id ? <span className="mono small">{details.container_id}</span> : null },
          ]}
        />
      </Section>

      <Section title={`Steps (${steps.length})`}>
        {active && steps.length === 0 && <p className="muted">Steps appear once the sandbox reports back.</p>}
        <Table
          compact
          rows={steps}
          rowKey={(s, i) => `${s.name || 'step'}-${i}`}
          empty={active ? 'Waiting for the sandbox…' : 'No steps recorded.'}
          columns={[
            { key: 'name', label: 'Step' },
            { key: 'status', label: 'Status', render: (s) => <StatusBadge value={s.status} /> },
            { key: 'command', label: 'Command', render: (s) => s.command ? <code className="snippet">{s.command}</code> : null },
            { key: 'exit_code', label: 'Exit code', render: (s) => s.exit_code === null || s.exit_code === undefined ? null : String(s.exit_code) },
            { key: 'duration_seconds', label: 'Duration', render: (s) => fmtSeconds(s.duration_seconds ?? s.duration) },
            { key: 'note', label: 'Note', render: (s) => s.note ? <span className="small">{s.note}</span> : null },
          ]}
        />
        {steps.some((s) => s.output_tail) && (
          <>
            <h3>Output tails</h3>
            {steps.filter((s) => s.output_tail).map((s, i) => (
              <div key={i}>
                <div className="label">{s.name}</div>
                <pre className="pre small">{s.output_tail}</pre>
              </div>
            ))}
          </>
        )}
      </Section>

      {warnings.length > 0 && (
        <Section title={`Warnings (${warnings.length})`}>
          <ul className="list">
            {warnings.map((w, i) => <li key={i}>{typeof w === 'string' ? w : JSON.stringify(w)}</li>)}
          </ul>
        </Section>
      )}

      <Section title="Security scan" subtitle="Re-checks the patched dependency set against OSV.">
        {scan ? (
          <>
            <KeyValue
              columns={4}
              items={Object.entries(scan)
                .filter(([, val]) => typeof val !== 'object' || val === null)
                .map(([k, val]) => ({
                  label: k.replace(/_/g, ' '),
                  value: typeof val === 'boolean' ? (val ? 'yes' : 'no') : (val === null ? null : /status|result/i.test(k) ? <StatusBadge value={val} /> : String(val)),
                }))}
            />
            {Object.entries(scan).filter(([, val]) => Array.isArray(val)).map(([k, list]) => (
              <div key={k}>
                <h3>{k.replace(/_/g, ' ')} ({list.length})</h3>
                {list.length === 0 ? <p className="muted">none</p> : (
                  list.every((x) => typeof x === 'object' && x !== null) ? (
                    <Table
                      compact
                      rows={list}
                      columns={Object.keys(list[0]).map((col) => ({
                        key: col,
                        label: col.replace(/_/g, ' '),
                        render: (r) => {
                          const val = r[col]
                          if (val === null || val === undefined) return null
                          if (typeof val === 'object') return <code className="snippet">{JSON.stringify(val)}</code>
                          return /status|severity|result/i.test(col) ? <StatusBadge value={val} /> : String(val)
                        },
                      }))}
                    />
                  ) : (
                    <ul className="list">{list.map((x, i) => <li key={i}>{typeof x === 'string' ? x : JSON.stringify(x)}</li>)}</ul>
                  )
                )}
              </div>
            ))}
            <JsonBlock title="Raw security scan JSON" data={scan} />
          </>
        ) : <p className="muted">{active ? 'Not run yet.' : 'No security scan details recorded.'}</p>}
      </Section>

      <Section title="Logs">
        <Logs validation={v} />
        {extraDetailKeys.length > 0 && (
          <JsonBlock title="Other details" data={Object.fromEntries(extraDetailKeys.map((k) => [k, details[k]]))} />
        )}
        <JsonBlock title="Raw validation JSON" data={{ ...v, logs: v.logs ? `(${v.logs.length} chars)` : v.logs }} />
      </Section>

      <p><Link to={`/remediations/${v.remediation_id}`}>← Back to remediation #{v.remediation_id}</Link></p>
    </div>
  )
}
