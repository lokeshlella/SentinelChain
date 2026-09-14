export default function Loading({ text = 'Loading…', inline = false }) {
  if (inline) return <span className="muted"><span className="spinner" /> {text}</span>
  return (
    <p className="muted loading">
      <span className="spinner" /> {text}
    </p>
  )
}
