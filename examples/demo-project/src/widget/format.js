'use strict';

// Formatting helpers for the weather-notes widget.
// lodash is the deliberately vulnerable dependency of the JavaScript part of
// this demo project (see README.md). Only harmless helpers are used.
const _ = require('lodash');

/**
 * Format a temperature in degrees Celsius with one decimal, or "n/a".
 * @param {number|null|undefined} value
 * @returns {string}
 */
function formatTemperature(value) {
  if (!_.isFinite(value)) {
    return 'n/a';
  }
  return `${_.round(value, 1).toFixed(1)} °C`;
}

/**
 * Group notes by the first word of their text (lower-cased), preserving
 * insertion order inside each group. Notes without words go to "other".
 * @param {{id: number, text: string}[]} notes
 * @returns {Object<string, {id: number, text: string}[]>}
 */
function groupNotesByFirstWord(notes) {
  return _.groupBy(notes, (note) => _.toLower(_.head(_.words(note.text)) || 'other'));
}

/**
 * Return the texts of the most recent `limit` notes, newest first, trimmed to
 * `maxLength` characters with an ellipsis.
 * @param {{id: number, text: string}[]} notes
 * @param {number} limit
 * @param {number} maxLength
 * @returns {string[]}
 */
function recentNoteTexts(notes, limit = 3, maxLength = 40) {
  return _.chain(notes)
    .orderBy(['id'], ['desc'])
    .take(limit)
    .map((note) => _.truncate(note.text, { length: maxLength }))
    .value();
}

module.exports = { formatTemperature, groupNotesByFirstWord, recentNoteTexts };
