"""Temporary working copies for remediations (never the original repository)."""

from __future__ import annotations

import shutil
from pathlib import Path

from app.core.exceptions import RepositoryError
from app.core.logging import get_stage_logger
from app.services.repository.git_safety import harden_git_dir
from app.services.repository.ignore import copytree_ignore

log = get_stage_logger("Remediation")


def create_working_copy(source: Path | str, destination: Path | str) -> Path:
    """Copy ``source`` into ``destination`` (replaced if present), keeping ``.git``.

    Build artefacts and virtual environments are skipped (same ignore list as
    repository ingestion) so the copy stays small and the sandbox only sees
    source files and dependency manifests.
    """
    src, dest = Path(source), Path(destination)
    if not src.is_dir():
        raise RepositoryError(f"Working copy source does not exist: {src}")
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dest, symlinks=True, ignore=copytree_ignore([dest]))
    for note in harden_git_dir(dest):
        log.info("Working copy %s: %s", dest, note)
    log.info("Working copy created at %s", dest)
    return dest


def remove_workspace(path: Path | str | None) -> None:
    """Delete a working copy; missing paths and permission problems are logged, not raised."""
    if not path:
        return
    target = Path(path)
    if not target.exists():
        return
    try:
        shutil.rmtree(target)
        log.info("Working copy removed: %s", target)
    except OSError as exc:
        log.warning("Could not remove working copy %s: %s", target, exc)
