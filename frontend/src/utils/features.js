// Which product features the backend build exposes (GET /api/features, set by SENTINEL_PHASE).
// Phase 1 is the deterministic analysis — repositories, dependencies, OSV, source usage and the
// knowledge graph — and is always on. Phase-2 features are on only when the backend says so.

export const PHASE_2_FEATURES = ['ai', 'remediation', 'validation', 'reports', 'pull_requests']

// Until the backend answers — or when it cannot (down, or an older build without the endpoint) —
// every Phase-2 feature stays hidden: a Phase-1 review must never show a Phase-2 control.
export const UNKNOWN_BUILD = Object.freeze({
  phase: null,
  loaded: false,
  features: Object.freeze(Object.fromEntries(PHASE_2_FEATURES.map((name) => [name, false]))),
})

export function normaliseFeatures(data) {
  const raw = data && typeof data === 'object' && data.features && typeof data.features === 'object' ? data.features : {}
  const features = {}
  for (const name of PHASE_2_FEATURES) features[name] = raw[name] === true // anything but an explicit true is off
  const phase = Number(data?.phase)
  return { phase: phase === 1 || phase === 2 ? phase : null, loaded: true, features }
}

// Short names for the pipeline stages a build runs, in order (the Analyze section's description).
export function pipelineDescription(features) {
  const steps = ['extraction', 'OSV', 'source usage', 'knowledge graph']
  if (features?.ai) steps.push('AI agents')
  return steps.join(' → ')
}
