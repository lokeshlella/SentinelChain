import StatusBadge from './StatusBadge.jsx'

const ORDER = ['repository', 'dependencies', 'vulnerabilities', 'usage', 'knowledge_graph', 'ai']
const LABELS = {
  repository: 'Repository',
  dependencies: 'Dependencies',
  vulnerabilities: 'Vulnerabilities',
  usage: 'Source usage',
  knowledge_graph: 'Knowledge graph',
  ai: 'AI agents',
}

// Renders analysis.stages ({name: status}) as a horizontal list of stage → badge.
export default function StageTracker({ stages }) {
  const map = stages && typeof stages === 'object' ? stages : {}
  const keys = [...ORDER.filter((k) => k in map), ...Object.keys(map).filter((k) => !ORDER.includes(k))]
  if (keys.length === 0) return <p className="muted">No stage information yet.</p>
  return (
    <ol className="stages">
      {keys.map((k, i) => (
        <li key={k} className="stage">
          <span className="stage-index">{i + 1}</span>
          <span className="stage-name">{LABELS[k] || k}</span>
          <StatusBadge value={map[k]} fallback="PENDING" />
        </li>
      ))}
    </ol>
  )
}
