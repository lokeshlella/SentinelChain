// Maps any status / severity / risk / result string to a coloured badge.
const CLASS_BY_VALUE = {
  // success
  PASS: 'ok', OK: 'ok', COMPLETED: 'ok', SAFE: 'ok', VALIDATED: 'ok', MERGED: 'ok', PR_CREATED: 'ok', NONE: 'ok',
  // in progress / not decided
  PENDING: 'neutral', RUNNING: 'neutral', INGESTING: 'neutral', READY: 'ok', UNKNOWN: 'neutral', SKIPPED: 'neutral', UNCHECKED: 'neutral',
  VALIDATING: 'neutral', PROPOSED: 'info', CLOSED: 'neutral',
  // needs attention
  PARTIAL: 'warn', UNAVAILABLE: 'warn', MEDIUM: 'warn', VALIDATION_FAILED: 'warn',
  // bad
  FAIL: 'danger', FAILED: 'danger', VULNERABLE: 'danger', HIGH: 'danger',
  CRITICAL: 'critical',
  // informational
  LOW: 'info', DRAFT: 'info', OPEN: 'info',
}

export function badgeClass(value) {
  if (value === null || value === undefined || value === '') return 'neutral'
  return CLASS_BY_VALUE[String(value).toUpperCase()] || 'neutral'
}

export default function StatusBadge({ value, fallback = '—', title }) {
  const text = value === null || value === undefined || value === '' ? fallback : String(value)
  return (
    <span className={`badge ${badgeClass(value)}`} title={title}>
      {text}
    </span>
  )
}
