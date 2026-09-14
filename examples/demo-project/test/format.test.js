'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { formatTemperature, groupNotesByFirstWord, recentNoteTexts } = require('../src/widget/format');

test('formatTemperature renders one decimal with unit', () => {
  assert.equal(formatTemperature(18.44), '18.4 °C');
  assert.equal(formatTemperature(-3), '-3.0 °C');
  assert.equal(formatTemperature(0), '0.0 °C');
});

test('formatTemperature falls back to n/a for non-numbers', () => {
  assert.equal(formatTemperature(null), 'n/a');
  assert.equal(formatTemperature(undefined), 'n/a');
  assert.equal(formatTemperature(NaN), 'n/a');
  assert.equal(formatTemperature('12'), 'n/a');
});

test('groupNotesByFirstWord groups case-insensitively and keeps order', () => {
  const notes = [
    { id: 1, text: 'Rain expected tonight' },
    { id: 2, text: 'sun tomorrow' },
    { id: 3, text: 'rain again on Friday' },
    { id: 4, text: '   ' },
  ];
  const groups = groupNotesByFirstWord(notes);
  assert.deepEqual(Object.keys(groups).sort(), ['other', 'rain', 'sun']);
  assert.deepEqual(groups.rain.map((n) => n.id), [1, 3]);
  assert.deepEqual(groups.other.map((n) => n.id), [4]);
});

test('recentNoteTexts returns newest first, limited and truncated', () => {
  const notes = [
    { id: 1, text: 'oldest' },
    { id: 2, text: 'a rather long note that should be shortened for the widget' },
    { id: 3, text: 'newest' },
  ];
  assert.deepEqual(recentNoteTexts(notes, 2, 20), ['newest', 'a rather long not...']);
  assert.deepEqual(recentNoteTexts([], 5), []);
});
