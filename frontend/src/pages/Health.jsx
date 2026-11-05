import { useEffect, useState } from 'react'
import { api } from '../api/client.js'
import Section from '../components/Section.jsx'
import Table from '../components/Table.jsx'
import StatusBadge from '../components/StatusBadge.jsx'
import Loading from '../components/Loading.jsx'
import ErrorBox from '../components/ErrorBox.jsx'
import { asList } from '../utils/format.js'

const SERVICE_NAMES = { postgresql: 'PostgreSQL', neo4j: 'Neo4j', osv: 'OSV.dev', ollama: 'Ollama', docker: 'Docker', github: 'GitHub' }

// "a, b and c"
function joinNames(names) {
  return names.length <= 1 ? names.join('') : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`
}

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
          <p className="muted small">
            PostgreSQL is mandatory. {joinNames(asList(health.services).map((s) => s.name).filter((n) => n !== 'postgresql').map((n) => SERVICE_NAMES[n] || n))} {asList(health.services).length > 2 ? 'are' : 'is'} optional — when one is down the matching pipeline stage is reported as UNAVAILABLE instead of failing the analysis (without OSV.dev, dependencies are UNKNOWN, never SAFE).
          </p>
          <Table
            rows={asList(health.services)}
            rowKey={(s) => s.name}
            columns={[
              { key: 'name', label: 'Service', render: (s) => SERVICE_NAMES[s.name] || s.name },
              { key: 'ok', label: 'Status', render: (s) => <StatusBadge value={s.ok ? 'OK' : 'UNAVAILABLE'} /> },
              { key: 'detail', label: 'Detail', render: (s) => <span className="muted">{s.detail}</span> },
            ]}
          />
        </Section>
      )}
    </div>
  )
}
