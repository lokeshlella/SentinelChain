"""Helpers shared by the dependency extractors (file discovery, path handling)."""

from __future__ import annotations

import codecs

import os
from collections.abc import Callable, Iterator
from pathlib import Path

# Directories that never hold the project's own dependency manifests.
IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        "__pycache__",
        "site-packages",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".eggs",
    }
)


def relative_posix(path: Path, root: Path) -> str:
    """Return ``path`` relative to ``root`` with POSIX separators."""
    return path.relative_to(root).as_posix()


def is_ignored_path(relative_parts: tuple[str, ...]) -> bool:
    """True when any component of a relative path is an ignored directory."""
    return any(part in IGNORED_DIRS for part in relative_parts)


def is_within(path: Path, root: Path) -> bool:
    """True when ``path`` (symlinks followed) stays inside ``root``; ``root`` must be resolved."""
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):  # missing target, permission problem or symlink loop
        return False
    return resolved.is_relative_to(root)


def is_repository_file(path: Path, root: Path) -> bool:
    """A regular file that belongs to the repository (``root`` must be resolved).

    Symlinks are followed only when their target stays inside ``root``: a hostile
    repository can ship ``requirements.txt -> /etc/passwd`` and the extractors would
    otherwise echo host data into warnings and analysis results.
    """
    return path.is_file() and (not path.is_symlink() or is_within(path, root))


def walk_files(
    root: Path,
    *,
    max_depth: int,
    predicate: Callable[[Path], bool],
) -> Iterator[Path]:
    """Yield files under ``root`` (sorted, deterministic) whose directory depth is ``<= max_depth``.

    Ignored directories are pruned so their contents are never visited, the walk never
    descends deeper than needed, symlinked directories are not followed and symlinked
    files are yielded only when they resolve inside ``root`` (see ``is_repository_file``).
    """
    root = root.resolve()
    for current, dirnames, filenames in os.walk(root):
        current_path = Path(current)
        depth = len(current_path.relative_to(root).parts)
        # Prune: do not descend into ignored directories or beyond the depth limit.
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS) if depth < max_depth else []
        for filename in sorted(filenames):
            candidate = current_path / filename
            if is_repository_file(candidate, root) and predicate(candidate):
                yield candidate


def truncate_text(text: str, limit: int = 120) -> str:
    """Shorten raw file content quoted in warnings so one garbage line cannot bloat the summary."""
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


def read_text_file(path: Path) -> str:
    """Read a text file tolerantly, honouring UTF-8/16/32 byte-order marks like pip does.

    ``pip freeze > requirements.txt`` under PowerShell 5 writes UTF-16 LE with a
    BOM; pip installs such files without complaint, so we must parse them too.
    Undecodable bytes are replaced rather than raising.
    """
    data = path.read_bytes()
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            return data[len(bom):].decode(encoding, errors="replace")
    return data.decode("utf-8", errors="replace")
