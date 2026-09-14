"""Markdown rendering helpers for the evidence report.

The report template hands every section dictionary to :func:`render_value`, which
turns JSON-like data into plain CommonMark: nested bullet lists for dicts and
lists, fenced code blocks for unified diffs, source snippets and multi-line text,
inline text for everything else. No HTML is ever emitted, so the output renders
the same on GitHub, in the dashboard and in any Markdown viewer.
"""

from __future__ import annotations

import re
from typing import Any

INDENT = "  "
NONE_TEXT = "n/a"
EMPTY_TEXT = "(none)"

#: Keys whose string value is a unified diff (rendered as a ```diff block).
DIFF_KEYS: frozenset[str] = frozenset({"diff"})
#: Keys carrying a source snippet (rendered as a fenced block under the item).
SNIPPET_KEY = "snippet"

#: Inline scalar lists stay on one bullet line while they are short.
INLINE_ITEM_MAX_LENGTH = 60
INLINE_TOTAL_MAX_LENGTH = 120

_FENCE_RUN_RE = re.compile(r"`{3,}")
_LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".vue": "vue",
    ".json": "json",
    ".toml": "toml",
    ".txt": "text",
}


def is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def scalar_text(value: Any) -> str:
    """Single-line text for a scalar (``None`` → ``n/a``, booleans lower-case)."""
    if value is None:
        return NONE_TEXT
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def escape_table_cell(text: str) -> str:
    """Make a value safe inside a Markdown pipe table cell."""
    return " ".join(str(text).split()).replace("|", "\\|")


def language_for_file(path: str | None) -> str:
    """Fence language for a snippet taken from ``path`` (``text`` when unknown)."""
    if not path:
        return "text"
    dot = path.rfind(".")
    return _LANGUAGE_BY_SUFFIX.get(path[dot:].lower(), "text") if dot >= 0 else "text"


def fenced_block(text: str, language: str = "text", depth: int = 0) -> str:
    """A fenced code block indented so it stays inside the bullet at ``depth``.

    The fence is longer than any backtick run inside the text, so the block can
    never be terminated early by its own content.
    """
    longest = max((len(run) for run in _FENCE_RUN_RE.findall(text)), default=0)
    fence = "`" * max(3, longest + 1)
    pad = INDENT * depth
    body = text.rstrip("\n").splitlines() or [""]
    lines = [f"{pad}{fence}{language}", *(f"{pad}{line}" if line else pad.rstrip() for line in body), f"{pad}{fence}"]
    return "\n".join(lines)


def render_value(value: Any, depth: int = 0) -> str:
    """Render a JSON-like value as Markdown bullets (dicts / lists) or plain text."""
    if isinstance(value, dict):
        if not value:
            return f"{INDENT * depth}- {EMPTY_TEXT}"
        return "\n".join(_render_entry(str(key), item, depth) for key, item in value.items())
    if isinstance(value, list):
        if not value:
            return f"{INDENT * depth}- {EMPTY_TEXT}"
        return _render_list(value, depth)
    if isinstance(value, str) and "\n" in value:
        return fenced_block(value, "text", depth)
    return f"{INDENT * depth}{scalar_text(value)}"


# ------------------------------------------------------------------ internals


def _render_entry(key: str, value: Any, depth: int) -> str:
    pad = INDENT * depth
    label = f"{pad}- **{key}**"
    if key in DIFF_KEYS and isinstance(value, str) and value.strip():
        return f"{label}:\n{fenced_block(value, 'diff', depth + 1)}"
    if isinstance(value, str) and "\n" in value:
        return f"{label}:\n{fenced_block(value, 'text', depth + 1)}"
    if is_scalar(value):
        return f"{label}: {scalar_text(value)}"
    if isinstance(value, dict):
        if not value:
            return f"{label}: {EMPTY_TEXT}"
        return f"{label}:\n{render_value(value, depth + 1)}"
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        if not items:
            return f"{label}: {EMPTY_TEXT}"
        if _inline_ok(items):
            return f"{label}: " + ", ".join(scalar_text(item) for item in items)
        return f"{label}:\n{_render_list(items, depth + 1)}"
    return f"{label}: {scalar_text(value)}"


def _inline_ok(items: list[Any]) -> bool:
    if not all(is_scalar(item) for item in items):
        return False
    texts = [scalar_text(item) for item in items]
    if any("\n" in text or "," in text or len(text) > INLINE_ITEM_MAX_LENGTH for text in texts):
        return False
    return sum(len(text) for text in texts) + 2 * (len(texts) - 1) <= INLINE_TOTAL_MAX_LENGTH


def _render_list(items: list[Any], depth: int) -> str:
    return "\n".join(_render_item(item, depth) for item in items)


def _render_item(item: Any, depth: int) -> str:
    pad = INDENT * depth
    if isinstance(item, dict):
        if SNIPPET_KEY in item:
            return _render_snippet_item(item, depth)
        return _render_dict_item(item, depth)
    if isinstance(item, (list, tuple)):
        return f"{pad}-\n{_render_list(list(item), depth + 1)}" if item else f"{pad}- {EMPTY_TEXT}"
    if isinstance(item, str) and "\n" in item:
        return f"{pad}-\n{fenced_block(item, 'text', depth + 1)}"
    return f"{pad}- {scalar_text(item)}"


def _render_snippet_item(item: dict, depth: int) -> str:
    """``- `file:line` (kind)`` followed by the snippet in a fenced block."""
    pad = INDENT * depth
    location = str(item.get("file") or "")
    if item.get("line") not in (None, ""):
        location = f"{location}:{item['line']}"
    kind = item.get("kind")
    head = f"{pad}- `{location}`" if location else f"{pad}-"
    if kind:
        head += f" ({kind})"
    snippet = item.get(SNIPPET_KEY)
    if snippet in (None, ""):
        return head
    return f"{head}\n{fenced_block(str(snippet), language_for_file(item.get('file')), depth + 1)}"


def _render_dict_item(item: dict, depth: int) -> str:
    """A list item that is a dict: scalars on the bullet line, complex values nested below."""
    pad = INDENT * depth
    if not item:
        return f"{pad}- {EMPTY_TEXT}"
    simple = {k: v for k, v in item.items() if is_scalar(v) and not (isinstance(v, str) and "\n" in v)}
    complex_ = {k: v for k, v in item.items() if k not in simple}
    head = ", ".join(f"{key}: {scalar_text(value)}" for key, value in simple.items())
    lines = [f"{pad}- {head}" if head else f"{pad}-"]
    for key, value in complex_.items():
        lines.append(_render_entry(str(key), value, depth + 1))
    return "\n".join(lines)
