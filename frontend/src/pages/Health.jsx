import { useEffect, useState } from 'react'
import { api } from '../api/client.js'
import Section from '../components/Section.jsx'
import Table from '../components/Table.jsx'
import StatusBadge from '../components/StatusBadge.jsx'
import Loading from '../components/Loading.jsx'
import ErrorBox from '../components/ErrorBox.jsx'
import { asList } from '../utils/format.js'

export default function Health() {
  const [health, setHealth] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  function load() {
    setLoading(true)
    setError(null)
    api.get('/health').then(setHealth).catch(setError).finally(() => setLoading(false))
  }
  useEffect(load, [])

  return (
    <div>
      <h1>System health</h1>
      {error && <ErrorBox error={error} title="Backend unreachable" onRetry={load} />}
      {loading && !health && <Loading text="Checking services…" />}
      {health && (
        <Section
          title={`${health.app || 'Sentinel Chain'} v${health.version || '?'}`}
          subtitle={`environment: ${health.environment || '?'}`}
          actions={<><StatusBadge value={health.status === 'ok' ? 'OK' : 'PARTIAL'} /> <button type="button" className="btn" onClick={load}>Re-check</button></>}
        >
          <p className="muted small">PostgreSQL is mandatory. Neo4j, Ollama, Docker and GitHub are optional — when one is down the matching pipeline stage is reported as UNAVAILABLE instead of failing the analysis.</p>
          <Table
            rows={asList(health.services)}
            rowKey={(s) => s.name}
            columns={[
              { key: 'name', label: 'Service' },
              { key: 'ok', label: 'Status', render: (s) => <StatusBadge value={s.ok ? 'OK' : 'UNAVAILABLE'} /> },
              { key: 'detail', label: 'Detail', render: (s) => <span className="muted">{s.detail}</span> },
            ]}
          />
        </Section>
      )}
    </div>
  )
}
