// Renders an Error (from the API client), a string, or nothing.
export default function ErrorBox({ error, title, onRetry }) {
  if (!error) return null
  const message = typeof error === 'string' ? error : error.message || 'Unknown error'
  const status = typeof error === 'object' && error.status ? ` (HTTP ${error.status})` : ''
  const details = typeof error === 'object' && error.data?.details && Object.keys(error.data.details).length > 0
    ? JSON.stringify(error.data.details)
    : null
  return (
    <div className="alert error" role="alert">
      <strong>{title || (typeof error === 'object' && error.name) || 'Error'}{status}:</strong> {message}
      {details && <div className="small">{details}</div>}
      {onRetry && (
        <div>
          <button type="button" className="btn small" onClick={onRetry}>Retry</button>
        </div>
      )}
    </div>
  )
}
