"""In-memory notes API.

Notes live in a process-local dictionary owned by the Flask application
(``app.extensions["note_store"]``): good enough for a demo, and it keeps the
project free of databases and extra dependencies.
"""

from __future__ import annotations

from itertools import count
from typing import Any

from flask import Blueprint, abort, current_app, jsonify, request

MAX_TEXT_LENGTH = 500


class NoteStore:
    """Minimal store keyed by an auto-incrementing integer id."""

    def __init__(self) -> None:
        self._notes: dict[int, dict[str, Any]] = {}
        self._ids = count(start=1)

    def all(self) -> list[dict[str, Any]]:
        return [self._notes[key] for key in sorted(self._notes)]

    def get(self, note_id: int) -> dict[str, Any] | None:
        return self._notes.get(note_id)

    def add(self, text: str) -> dict[str, Any]:
        note = {"id": next(self._ids), "text": text}
        self._notes[note["id"]] = note
        return note

    def delete(self, note_id: int) -> bool:
        return self._notes.pop(note_id, None) is not None


def get_store() -> NoteStore:
    """Return the note store of the current application."""
    return current_app.extensions["note_store"]


notes_bp = Blueprint("notes", __name__, url_prefix="/api/notes")


def _validated_text(payload: Any) -> str:
    """Return the trimmed note text from a JSON body, or abort with 400."""
    if not isinstance(payload, dict):
        abort(400, description="JSON object expected")
    text = payload.get("text")
    if not isinstance(text, str) or not text.strip():
        abort(400, description="'text' must be a non-empty string")
    if len(text) > MAX_TEXT_LENGTH:
        abort(400, description=f"'text' longer than {MAX_TEXT_LENGTH} characters")
    return text.strip()


@notes_bp.get("")
def list_notes():
    return jsonify(get_store().all())


@notes_bp.post("")
def create_note():
    text = _validated_text(request.get_json(silent=True))
    note = get_store().add(text)
    return jsonify(note), 201


@notes_bp.get("/<int:note_id>")
def get_note(note_id: int):
    note = get_store().get(note_id)
    if note is None:
        abort(404, description="note not found")
    return jsonify(note)


@notes_bp.delete("/<int:note_id>")
def delete_note(note_id: int):
    if not get_store().delete(note_id):
        abort(404, description="note not found")
    return "", 204
