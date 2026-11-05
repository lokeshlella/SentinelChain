// Pure-helper tests. No test framework is installed for the frontend: these run on Node's own
// runner, `npm test` in frontend/ (node --test), and need no node_modules.
import assert from 'node:assert/strict'
import test from 'node:test'

import { aiSummary } from './format.js'

// The shape the backend writes since audit F-19 (taken from a real analysis run).
const CURRENT = {
  attempted: 5, completed: 5, failed: 0, unavailable: 0, skipped_by_limit: 8,
  limit: 5, model: 'llama3.2:3b', note: '8 finding(s) not analysed: per-run limit of 5 reached',
}

test('reads the current F-19 counter keys', () => {
  const ai = aiSummary(CURRENT)
  assert.deepEqual(
    { attempted: ai.attempted, completed: ai.completed, failed: ai.failed, unavailable: ai.unavailable, skipped: ai.skipped },
    { attempted: 5, completed: 5, failed: 0, unavailable: 0, skipped: 8 },
  )
  assert.equal(ai.limit, 5)
  assert.equal(ai.model, 'llama3.2:3b')
  assert.equal(ai.note, CURRENT.note)
  assert.equal(ai.hasCounters, true)
})

test('zero counters are kept, not dropped as missing', () => {
  const ai = aiSummary({ attempted: 0, completed: 0, failed: 0, unavailable: 0, skipped_by_limit: 0, note: 'no findings' })
  assert.equal(ai.completed, 0)
  assert.equal(ai.skipped, 0)
  assert.equal(ai.hasCounters, true) // so the breakdown row renders "0 / 0 / 0" rather than "—"
  assert.equal(ai.note, 'no findings')
})

test('falls back to the pre-F-19 keys on older rows', () => {
  const ai = aiSummary({ analyzed: 3, failed: 1, skipped: 2, model: 'llama3.2:3b' })
  assert.equal(ai.attempted, 3)
  assert.equal(ai.completed, 3) // older rows had no separate completed count
  assert.equal(ai.failed, 1)
  assert.equal(ai.skipped, 2)
  assert.equal(ai.hasCounters, true)
})

test('current keys win over a stale duplicate', () => {
  const ai = aiSummary({ ...CURRENT, analyzed: 99, skipped: 99 })
  assert.equal(ai.attempted, 5)
  assert.equal(ai.skipped, 8)
})

test('a missing or malformed summary reports no counters', () => {
  for (const input of [undefined, null, {}, 'nope', { model: 'llama3.2:3b' }]) {
    const ai = aiSummary(input)
    assert.equal(ai.hasCounters, false, `input: ${JSON.stringify(input)}`)
    assert.equal(ai.attempted, undefined)
    assert.equal(ai.note, null)
  }
})
