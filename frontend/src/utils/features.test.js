// Phase gating must fail closed: a Phase-1 review may never show a Phase-2 control.
import assert from 'node:assert/strict'
import test from 'node:test'

import { PHASE_2_FEATURES, UNKNOWN_BUILD, normaliseFeatures, pipelineDescription } from './features.js'

const allOff = Object.fromEntries(PHASE_2_FEATURES.map((n) => [n, false]))

test('before the backend answers, every Phase-2 feature is hidden', () => {
  assert.equal(UNKNOWN_BUILD.loaded, false)
  assert.equal(UNKNOWN_BUILD.phase, null)
  assert.deepEqual({ ...UNKNOWN_BUILD.features }, allOff)
})

test('a Phase-1 build keeps every Phase-2 feature off', () => {
  const build = normaliseFeatures({
    phase: 1,
    features: { repositories: true, knowledge_graph: true, ai: false, remediation: false, validation: false, reports: false, pull_requests: false },
  })
  assert.equal(build.phase, 1)
  assert.equal(build.loaded, true)
  assert.deepEqual(build.features, allOff)
})

test('the complete product turns every Phase-2 feature on', () => {
  const build = normaliseFeatures({ phase: 2, features: Object.fromEntries(PHASE_2_FEATURES.map((n) => [n, true])) })
  assert.equal(build.phase, 2)
  assert.ok(PHASE_2_FEATURES.every((n) => build.features[n] === true))
})

test('a single extra feature is honoured on its own', () => {
  const build = normaliseFeatures({ phase: 1, features: { ai: true } })
  assert.equal(build.features.ai, true)
  assert.equal(build.features.remediation, false)
})

test('anything but an explicit true is off', () => {
  for (const value of ['true', 1, 'yes', null, undefined, {}]) {
    assert.equal(normaliseFeatures({ phase: 2, features: { ai: value } }).features.ai, false, JSON.stringify(value))
  }
  for (const input of [null, undefined, 'nope', [], { phase: 'two' }, { features: 'all' }]) {
    const build = normaliseFeatures(input)
    assert.deepEqual(build.features, allOff, JSON.stringify(input))
    assert.equal(build.phase, null)
  }
})

test('the Analyze description lists only the stages the build runs', () => {
  assert.equal(pipelineDescription(allOff), 'extraction → OSV → source usage → knowledge graph')
  assert.equal(pipelineDescription({ ...allOff, ai: true }), 'extraction → OSV → source usage → knowledge graph → AI agents')
  assert.equal(pipelineDescription(undefined), 'extraction → OSV → source usage → knowledge graph')
})
