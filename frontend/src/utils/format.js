// Small formatting helpers shared by the pages. All of them tolerate null / undefined.

export function fmtDate(value) {
  if (!value) return null
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return String(value)
  return d.toLocaleString()
}

export function fmtDuration(start, end) {
  if (!start) return null
  const a = new Date(start).getTime()
  const b = end ? new Date(end).getTime() : Date.now()
  if (Number.isNaN(a) || Number.isNaN(b)) return null
  const s = Math.max(0, Math.round((b - a) / 1000))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  return `${m}m ${s % 60}s`
}

export function fmtSeconds(value) {
  if (value === null || value === undefined || value === '') return null
  const n = Number(value)
  if (Number.isNaN(n)) return String(value)
  return n < 10 ? `${n.toFixed(2)}s` : `${Math.round(n)}s`
}

export function fmtPercent(value) {
  if (value === null || value === undefined || value === '') return null
  const n = Number(value)
  if (Number.isNaN(n)) return String(value)
  return `${Math.round(n * 100)}%`
}

export function pkgLabel(dep) {
  if (!dep) return '—'
  return `${dep.package_name || '?'}@${dep.version || dep.version_spec || '?'}`
}

const RISK_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4, UNKNOWN: 5 }

export function riskRank(level) {
  if (!level) return 6
  const r = RISK_ORDER[String(level).toUpperCase()]
  return r === undefined ? 6 : r
}

export function sortByRisk(findings) {
  return [...(findings || [])].sort((a, b) => {
    const d = riskRank(a?.risk_level) - riskRank(b?.risk_level)
    if (d !== 0) return d
    const s = riskRank(a?.vulnerability?.severity) - riskRank(b?.vulnerability?.severity)
    if (s !== 0) return s
    return (b?.finding_id || 0) - (a?.finding_id || 0)
  })
}

// Fixed versions from VulnerabilityDetail.affected (OSV "affected" entries normalised by the backend).
export function fixedVersions(vulnerability, ecosystem) {
  const affected = Array.isArray(vulnerability?.affected) ? vulnerability.affected : []
  const out = new Set()
  for (const entry of affected) {
    if (!entry || typeof entry !== 'object') continue
    if (ecosystem && entry.ecosystem && String(entry.ecosystem).toLowerCase() !== String(ecosystem).toLowerCase()) continue
    // Only ecosystem/semver fixes are versions; GIT ranges carry commit hashes.
    for (const v of entry.fixed_versions || []) if (v) out.add(String(v))
    for (const r of entry.ranges || []) {
      if (r?.fixed && String(r.range_type || '').toUpperCase() !== 'GIT') out.add(String(r.fixed))
    }
  }
  return [...out]
}

export function asList(value) {
  if (Array.isArray(value)) return value
  if (value === null || value === undefined || value === '') return []
  return [value]
}

export function isActive(status) {
  const s = String(status || '').toUpperCase()
  return s === 'PENDING' || s === 'RUNNING' || s === 'VALIDATING'
}
