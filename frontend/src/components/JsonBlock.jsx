import { useState } from 'react'

// Collapsible <pre> for JSON (or plain text when `text` is given).
export default function JsonBlock({ title = 'Raw JSON', data, text, open = false, maxHeight = 420 }) {
  const [isOpen, setOpen] = useState(open)
  let body = text
  if (body === undefined) {
    try {
      body = data === undefined ? 'undefined' : JSON.stringify(data, null, 2)
    } catch {
      body = String(data)
    }
  }
  if (body === null || body === undefined) body = ''
  return (
    <div className="jsonblock">
      <button type="button" className="linklike" onClick={() => setOpen((v) => !v)}>
        {isOpen ? '▾' : '▸'} {title}
      </button>
      {isOpen && (
        <pre className="pre" style={{ maxHeight }}>
          {body}
        </pre>
      )}
    </div>
  )
}
