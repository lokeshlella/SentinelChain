// Renders a unified diff (or a before/after pair) in a <pre> with +/- line colouring.
function classify(line) {
  if (line.startsWith('+++') || line.startsWith('---')) return 'diff-meta'
  if (line.startsWith('@@')) return 'diff-hunk'
  if (line.startsWith('+')) return 'diff-add'
  if (line.startsWith('-')) return 'diff-del'
  return 'diff-ctx'
}

export default function DiffView({ diff, before, after }) {
  let text = diff
  if (!text && (before || after)) {
    // Build a minimal diff when the backend only provides before/after text.
    const b = String(before ?? '').split('\n')
    const a = String(after ?? '').split('\n')
    const lines = ['--- before', '+++ after']
    const max = Math.max(b.length, a.length)
    for (let i = 0; i < max; i += 1) {
      if (b[i] === a[i]) lines.push(` ${b[i] ?? ''}`)
      else {
        if (i < b.length) lines.push(`-${b[i]}`)
        if (i < a.length) lines.push(`+${a[i]}`)
      }
    }
    text = lines.join('\n')
  }
  if (!text) return <p className="muted">No diff available.</p>
  return (
    <pre className="pre diff">
      {String(text).split('\n').map((line, i) => (
        <div key={i} className={`diff-line ${classify(line)}`}>{line === '' ? ' ' : line}</div>
      ))}
    </pre>
  )
}
