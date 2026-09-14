"""Audit F-10: stored paths are workspace-relative and resolve against the running instance."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.paths import resolve_workspace_path, to_workspace_relative


def test_round_trip_inside_and_outside_the_workspace(tmp_path):
    settings = Settings(_env_file=None, repository_workspace=str(tmp_path / "ws"))
    inside = settings.workspace_path / "remediations" / "7"
    inside.mkdir(parents=True)
    assert to_workspace_relative(inside, settings) == "remediations/7"
    assert resolve_workspace_path("remediations/7", settings) == inside
    assert to_workspace_relative(settings.workspace_path, settings) == "."
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    assert to_workspace_relative(outside, settings) == str(outside)  # kept absolute
    assert resolve_workspace_path(str(outside), settings) == outside  # legacy absolute values still resolve
    assert resolve_workspace_path(None, settings) is None and resolve_workspace_path("", settings) is None


def test_rows_written_by_one_instance_resolve_on_another(tmp_path):
    """The host backend stores 'repos/3'; the Compose backend (different workspace) resolves it under /workspace."""
    host = Settings(_env_file=None, repository_workspace=str(tmp_path / "host-ws"))
    container = Settings(_env_file=None, repository_workspace=str(tmp_path / "container-ws"))
    stored = to_workspace_relative(host.workspace_path / "repos" / "3", host)
    assert stored == "repos/3"
    assert resolve_workspace_path(stored, container) == container.workspace_path / "repos" / "3"


def test_relative_values_cannot_escape_the_workspace(tmp_path):
    settings = Settings(_env_file=None, repository_workspace=str(tmp_path / "ws"))
    with pytest.raises(ValueError):
        resolve_workspace_path("../../etc/passwd", settings)
    with pytest.raises(ValueError):
        resolve_workspace_path("repos/../../x", settings)
