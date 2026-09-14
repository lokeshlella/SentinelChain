"""Directory ignore rules shared by the repository walk and working-copy creation.

The same list is used when a local repository is copied into the workspace
(``shutil.copytree(ignore=...)``) and when the analyser walks a tree, so the
profile always describes what actually ended up in the working copy.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

#: Directories that never carry project information worth copying or analysing.
IGNORED_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        "__pycache__",
        ".pytest_cache",
        ".tox",
        ".mypy_cache",
    }
)

#: Hidden directories that the analyser still looks into (CI / workflow configuration).
ANALYZED_HIDDEN_DIRS: frozenset[str] = frozenset({".github"})


def is_ignored_dir(name: str) -> bool:
    """True for directories that are neither copied nor analysed (``node_modules``, ...)."""
    return name in IGNORED_DIR_NAMES


def should_analyze_dir(name: str) -> bool:
    """True when the analyser should descend into a directory called ``name``.

    Ignored directories and hidden directories (``.git``, ``.idea``, ``.vscode``, ...)
    are skipped; ``.github`` is the deliberate exception.
    """
    if name in IGNORED_DIR_NAMES:
        return False
    if name.startswith(".") and name not in ANALYZED_HIDDEN_DIRS:
        return False
    return True


def copytree_ignore(skip_paths: Iterable[Path] = ()) -> Callable[[str, list[str]], set[str]]:
    """Build an ``ignore`` callable for :func:`shutil.copytree`.

    * directories named in :data:`IGNORED_DIR_NAMES` are skipped (files with such a
      name are kept);
    * ``.git`` is deliberately **kept** so the copy remains a git repository, but
      ``.git/hooks`` is never copied (hooks are repository-controlled executables);
    * any absolute path listed in ``skip_paths`` is skipped (used to keep the
      Sentinel Chain workspace out of a copy of its own parent directory).
    """
    skip = {Path(p).resolve() for p in skip_paths}

    def _ignore(directory: str, names: list[str]) -> set[str]:
        base = Path(directory)
        ignored: set[str] = set()
        for name in names:
            candidate = base / name
            if name in IGNORED_DIR_NAMES and candidate.is_dir():
                ignored.add(name)
            elif name == "hooks" and base.name == ".git":
                ignored.add(name)
            elif skip and candidate.is_dir():
                try:
                    if candidate in skip or candidate.resolve() in skip:
                        ignored.add(name)
                except OSError:
                    continue
        return ignored

    return _ignore
