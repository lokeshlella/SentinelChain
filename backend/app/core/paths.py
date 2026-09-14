"""Workspace-relative path storage (audit finding F-10).

Rows must not be tied to one backend instance's filesystem layout: the host
backend keeps its workspace under ``./workspace`` while the Compose backend
uses ``/workspace``. Paths are therefore stored *relative to the workspace*
and resolved against the running instance's ``REPOSITORY_WORKSPACE`` when
used. Absolute values written by earlier versions still resolve as-is.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from app.core.config import Settings, get_settings


def to_workspace_relative(path: Path | str, settings: Settings | None = None) -> str:
    """POSIX path relative to the workspace when ``path`` lies inside it, else the absolute path."""
    settings = settings or get_settings()
    candidate = Path(path)
    try:
        resolved = candidate.resolve()
        root = settings.workspace_path.resolve()
        if resolved == root:
            return "."
        if resolved.is_relative_to(root):
            return resolved.relative_to(root).as_posix()
    except OSError:
        pass
    return str(candidate)


def resolve_workspace_path(stored: str | Path | None, settings: Settings | None = None) -> Path | None:
    """The concrete path for a stored value: absolute values as-is, relative ones under the workspace."""
    if stored is None or str(stored).strip() == "":
        return None
    settings = settings or get_settings()
    value = str(stored)
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    relative = PurePosixPath(value)
    if any(part == ".." for part in relative.parts):
        raise ValueError(f"Stored workspace path escapes the workspace: {value!r}")
    return settings.workspace_path / Path(*relative.parts) if relative.parts and value != "." else settings.workspace_path


__all__ = ["to_workspace_relative", "resolve_workspace_path"]
