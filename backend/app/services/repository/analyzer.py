"""Basic repository analysis: project name, language, dependency files, structure.

Deliberately simple (no static analysis): one walk over the tree, extension
based language counts, well-known directory names for the component types.
The analyser never raises because of an unreadable file — it records what it
could observe.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import tomllib
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from app.core.logging import get_stage_logger
from app.models.enums import ComponentType
from app.services.repository.ignore import should_analyze_dir

logger = get_stage_logger("Repository")

LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".sh": "Shell",
    ".bash": "Shell",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
}
#: Languages that make a directory a *source* component and decide the dominant language.
PROGRAMMING_LANGUAGES: frozenset[str] = frozenset(
    {"Python", "JavaScript", "TypeScript", "Java", "Go", "Rust", "Ruby", "PHP", "C#"}
)

TEST_DIR_NAMES: frozenset[str] = frozenset({"tests", "test", "__tests__", "spec", "specs", "testing"})
DOC_DIR_NAMES: frozenset[str] = frozenset({"docs", "doc", "documentation"})
CONFIG_DIR_NAMES: frozenset[str] = frozenset(
    {".github", "config", "configs", "ci", "deploy", "deployment", "docker", "k8s", "infra", "requirements"}
)
SCRIPT_DIR_NAMES: frozenset[str] = frozenset({"scripts", "script", "bin", "tools"})
#: Layout directories whose children are listed as source dirs too (``src/mypkg``).
SOURCE_LAYOUT_DIRS: frozenset[str] = frozenset({"src", "app", "lib", "packages"})

DEPENDENCY_FILE_NAMES: frozenset[str] = frozenset(
    {
        "package.json",
        "package-lock.json",
        "pyproject.toml",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "setup.py",
        "setup.cfg",
        "yarn.lock",
        "pnpm-lock.yaml",
    }
)
MAX_DEPENDENCY_FILE_DEPTH = 3  # directories between the root and the file
MAX_TEST_DIR_DEPTH = 2
NPM_PLACEHOLDER_TEST_SCRIPT = 'echo "Error: no test specified" && exit 1'

_TEST_FILE_PATTERNS: tuple[str, ...] = (
    "test_*.py",
    "*_test.py",
    "conftest.py",
    "*.test.js",
    "*.test.jsx",
    "*.test.ts",
    "*.test.tsx",
    "*.test.mjs",
    "*.test.cjs",
    "*.spec.js",
    "*.spec.jsx",
    "*.spec.ts",
    "*.spec.tsx",
    "*.spec.mjs",
    "*.spec.cjs",
)
_PYTHON_TEST_FILE_PATTERNS: tuple[str, ...] = ("test_*.py", "*_test.py")
_DOCKERFILE_PATTERNS: tuple[str, ...] = ("dockerfile", "dockerfile.*", "*.dockerfile")
_MAX_TEXT_FILE_BYTES = 2_000_000


# ---------------------------------------------------------------------- results


@dataclass
class ComponentInfo:
    """A logical part of the application (top-level directory or the root)."""

    name: str
    path: str  # POSIX path relative to the repository root ("." for the root)
    component_type: str  # enums.ComponentType value
    description: str
    file_count: int


@dataclass
class RepositoryProfile:
    """Structure summary stored as ``Repository.profile`` (see ``to_dict``)."""

    name: str
    language: str | None = None
    languages: dict[str, int] = field(default_factory=dict)
    dependency_files: list[str] = field(default_factory=list)
    source_dirs: list[str] = field(default_factory=list)
    test_dirs: list[str] = field(default_factory=list)
    components: list[ComponentInfo] = field(default_factory=list)
    total_files: int = 0
    hints: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "RepositoryProfile":
        """Rebuild a profile from the JSON column (tolerates missing keys)."""
        data = dict(data or {})
        data.setdefault("name", "")
        components = [ComponentInfo(**c) for c in data.pop("components", []) or []]
        known = {f for f in cls.__dataclass_fields__ if f != "components"}
        return cls(components=components, **{k: v for k, v in data.items() if k in known})

    @property
    def component_paths(self) -> list[str]:
        return [component.path for component in self.components]


# ---------------------------------------------------------------------- walking


@dataclass(frozen=True)
class _FileEntry:
    parts: tuple[str, ...]  # path components relative to the root (last = file name)

    @property
    def name(self) -> str:
        return self.parts[-1]

    @property
    def depth(self) -> int:
        """Number of directories between the root and the file."""
        return len(self.parts) - 1

    @property
    def rel_path(self) -> str:
        return "/".join(self.parts)

    @property
    def language(self) -> str | None:
        return LANGUAGE_EXTENSIONS.get(PurePosixPath(self.name).suffix.lower())

    @property
    def is_test(self) -> bool:
        return _matches_any(self.name, _TEST_FILE_PATTERNS)


@dataclass
class _DirStats:
    """Aggregated counts for one directory subtree."""

    files: int = 0
    programming: int = 0
    tests: int = 0
    languages: Counter = field(default_factory=Counter)

    def add(self, entry: _FileEntry) -> None:
        self.files += 1
        language = entry.language
        if language:
            self.languages[language] += 1
            if language in PROGRAMMING_LANGUAGES:
                self.programming += 1
        if entry.is_test:
            self.tests += 1

    @property
    def mostly_tests(self) -> bool:
        return self.tests > 0 and self.tests * 2 > self.programming


def _matches_any(name: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _dominant_language(languages: Counter) -> str | None:
    """Dominant programming language, falling back to markup/shell when none exists."""
    for pool in (PROGRAMMING_LANGUAGES, None):
        candidates = [(count, name) for name, count in languages.items() if pool is None or name in pool]
        if candidates:
            candidates.sort(key=lambda item: (-item[0], item[1]))
            return candidates[0][1]
    return None


def _walk(root: Path) -> list[_FileEntry]:
    """List every file below ``root`` (skipping ignored / hidden dirs, never following symlinked dirs)."""
    entries: list[_FileEntry] = []
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _err: None, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if should_analyze_dir(name))
        try:
            rel_parts = Path(dirpath).relative_to(root).parts
        except ValueError:
            continue
        for filename in sorted(filenames):
            entries.append(_FileEntry(parts=(*rel_parts, filename)))
    return entries


# ---------------------------------------------------------------------- analyser


class RepositoryAnalyzer:
    """Builds a :class:`RepositoryProfile` from a working copy on disk."""

    def analyze(self, local_path: Path | str, *, default_name: str | None = None) -> RepositoryProfile:
        """Profile the tree at ``local_path``.

        ``default_name`` is used when no manifest provides a project name (the
        service passes the repository name, since workspace copies live in
        directories named after the repository id).
        """
        root = Path(local_path)
        fallback = default_name or root.name or "repository"
        if not root.is_dir():
            logger.warning("Cannot analyse %s: not a directory", root)
            return RepositoryProfile(name=fallback)

        entries = _walk(root)
        top_stats, nested_stats, root_stats = self._aggregate(entries)
        languages = Counter()
        for entry in entries:
            if entry.language:
                languages[entry.language] += 1

        dependency_files = self._dependency_files(entries)
        test_dirs = self._test_dirs(top_stats, nested_stats)
        components = self._components(top_stats, root_stats, set(test_dirs))
        source_dirs = self._source_dirs(components, nested_stats, set(test_dirs))
        hints = self._hints(root, entries, test_dirs)
        language = _dominant_language(languages) or self._language_from_dependency_files(dependency_files)
        name = self._project_name(root, language, fallback)

        profile = RepositoryProfile(
            name=name,
            language=language,
            languages=dict(sorted(languages.items(), key=lambda item: (-item[1], item[0]))),
            dependency_files=dependency_files,
            source_dirs=source_dirs,
            test_dirs=test_dirs,
            components=components,
            total_files=len(entries),
            hints=hints,
        )
        logger.info(
            "Analysed %s: %d files, language=%s, %d components, %d dependency files, %d test dirs",
            name, profile.total_files, language or "unknown", len(components), len(dependency_files), len(test_dirs),
        )
        return profile

    # ---------------------------------------------------------------- aggregation

    @staticmethod
    def _aggregate(
        entries: list[_FileEntry],
    ) -> tuple[dict[str, _DirStats], dict[tuple[str, ...], _DirStats], _DirStats]:
        """Per top-level dir, per depth-2 dir and root-level file statistics."""
        top: dict[str, _DirStats] = defaultdict(_DirStats)
        nested: dict[tuple[str, ...], _DirStats] = defaultdict(_DirStats)
        root_files = _DirStats()
        for entry in entries:
            if entry.depth == 0:
                root_files.add(entry)
                continue
            top[entry.parts[0]].add(entry)
            if entry.depth >= 2:
                nested[entry.parts[:2]].add(entry)
        return dict(top), dict(nested), root_files

    # ---------------------------------------------------------------- dependency files

    @staticmethod
    def _is_dependency_file(entry: _FileEntry) -> bool:
        if entry.depth > MAX_DEPENDENCY_FILE_DEPTH:
            return False
        name = entry.name
        if name in DEPENDENCY_FILE_NAMES:
            return True
        if fnmatch.fnmatchcase(name, "requirements*.txt"):
            return True
        return entry.depth >= 1 and entry.parts[-2] == "requirements" and name.endswith(".txt")

    def _dependency_files(self, entries: list[_FileEntry]) -> list[str]:
        return sorted(entry.rel_path for entry in entries if self._is_dependency_file(entry))

    @staticmethod
    def _language_from_dependency_files(dependency_files: list[str]) -> str | None:
        names = {PurePosixPath(path).name for path in dependency_files}
        if any(name.startswith("requirements") or name in {"pyproject.toml", "Pipfile", "setup.py"} for name in names):
            return "Python"
        if "package.json" in names:
            return "JavaScript"
        return None

    # ---------------------------------------------------------------- structure

    @staticmethod
    def _is_test_dir(name: str, stats: _DirStats) -> bool:
        return name in TEST_DIR_NAMES or stats.mostly_tests

    def _test_dirs(self, top: dict[str, _DirStats], nested: dict[tuple[str, ...], _DirStats]) -> list[str]:
        """Outermost directories (depth <= 2) that are test suites."""
        found: list[str] = [name for name, stats in top.items() if self._is_test_dir(name, stats)]
        for parts, stats in nested.items():
            if parts[0] in found:
                continue  # already covered by the parent
            if self._is_test_dir(parts[-1], stats):
                found.append("/".join(parts))
        return sorted(found)

    @staticmethod
    def _component_type(name: str, stats: _DirStats, is_test: bool) -> ComponentType:
        if is_test:
            return ComponentType.TESTS
        if name in DOC_DIR_NAMES:
            return ComponentType.DOCS
        if name in CONFIG_DIR_NAMES:
            return ComponentType.CONFIG
        if name in SCRIPT_DIR_NAMES:
            return ComponentType.SCRIPTS
        if stats.languages:
            return ComponentType.SOURCE
        return ComponentType.OTHER

    @staticmethod
    def _describe(component_type: ComponentType, stats: _DirStats, *, root: bool = False) -> str:
        kind = {
            ComponentType.SOURCE: "source",
            ComponentType.TESTS: "test",
            ComponentType.DOCS: "documentation",
            ComponentType.CONFIG: "configuration",
            ComponentType.SCRIPTS: "scripts",
            ComponentType.OTHER: "other",
        }[component_type]
        language = _dominant_language(stats.languages)
        words: list[str] = []
        if language and component_type in (ComponentType.SOURCE, ComponentType.TESTS):
            words.append(language)
        words.append(kind)
        words.append("files in the repository root" if root else "directory")
        text = " ".join(words)
        text = text[0].upper() + text[1:]
        plural = "file" if stats.files == 1 else "files"
        return f"{text} ({stats.files} {plural})"

    def _components(
        self, top: dict[str, _DirStats], root_stats: _DirStats, test_dirs: set[str]
    ) -> list[ComponentInfo]:
        components: list[ComponentInfo] = []
        if root_stats.languages:  # the root holds source files itself
            root_type = ComponentType.TESTS if root_stats.mostly_tests else ComponentType.SOURCE
            components.append(
                ComponentInfo(
                    name=".",
                    path=".",
                    component_type=root_type.value,
                    description=self._describe(root_type, root_stats, root=True),
                    file_count=root_stats.files,
                )
            )
        for name in sorted(top):
            stats = top[name]
            if stats.files == 0:
                continue
            component_type = self._component_type(name, stats, name in test_dirs)
            components.append(
                ComponentInfo(
                    name=name,
                    path=name,
                    component_type=component_type.value,
                    description=self._describe(component_type, stats),
                    file_count=stats.files,
                )
            )
        return components

    @staticmethod
    def _source_dirs(
        components: list[ComponentInfo], nested: dict[tuple[str, ...], _DirStats], test_dirs: set[str]
    ) -> list[str]:
        """Top-level source components plus ``src/<pkg>``-style children with source files."""
        dirs = [c.path for c in components if c.component_type == ComponentType.SOURCE.value and c.path != "."]
        for parts, stats in sorted(nested.items()):
            if parts[0] in SOURCE_LAYOUT_DIRS and parts[0] in dirs and stats.programming and "/".join(parts) not in test_dirs:
                if parts[1] not in TEST_DIR_NAMES:
                    dirs.append("/".join(parts))
        return sorted(dirs)

    # ---------------------------------------------------------------- hints & name

    def _hints(self, root: Path, entries: list[_FileEntry], test_dirs: list[str]) -> dict[str, Any]:
        root_names = {entry.name for entry in entries if entry.depth == 0}
        return {
            "has_pytest": self._has_pytest(root, entries, test_dirs),
            "has_tests_dir": bool(test_dirs),
            "npm_test_script": self._npm_test_script(root),
            "has_dockerfile": any(_matches_any(name.lower(), _DOCKERFILE_PATTERNS) for name in root_names),
            "readme_present": any(name.lower().startswith("readme") for name in root_names),
        }

    def _has_pytest(self, root: Path, entries: list[_FileEntry], test_dirs: list[str]) -> bool:
        root_names = {entry.name for entry in entries if entry.depth == 0}
        if "pytest.ini" in root_names:
            return True
        if any(entry.name == "conftest.py" and entry.depth <= MAX_TEST_DIR_DEPTH for entry in entries):
            return True
        if "[tool.pytest" in (_read_text(root / "pyproject.toml") or ""):
            return True
        if "[tool:pytest]" in (_read_text(root / "setup.cfg") or ""):
            return True
        if re.search(r"^\[pytest\]", _read_text(root / "tox.ini") or "", re.MULTILINE):
            return True
        test_dir_set = set(test_dirs)
        for entry in entries:
            if _matches_any(entry.name, _PYTHON_TEST_FILE_PATTERNS) and self._inside_any(entry, test_dir_set):
                return True
        return any(
            re.match(r"^\s*pytest\b", line, re.IGNORECASE)
            for entry in entries
            if fnmatch.fnmatchcase(entry.name, "requirements*.txt") and entry.depth <= MAX_DEPENDENCY_FILE_DEPTH
            for line in (_read_text(root / entry.rel_path) or "").splitlines()
        )

    @staticmethod
    def _inside_any(entry: _FileEntry, dirs: set[str]) -> bool:
        directory = "/".join(entry.parts[:-1])
        return any(directory == d or directory.startswith(d + "/") for d in dirs)

    @staticmethod
    def _npm_test_script(root: Path) -> str | None:
        data = _read_json(root / "package.json")
        scripts = data.get("scripts") if isinstance(data, dict) else None
        script = scripts.get("test") if isinstance(scripts, dict) else None
        if not isinstance(script, str) or not script.strip():
            return None
        normalised = " ".join(script.split())
        if normalised == NPM_PLACEHOLDER_TEST_SCRIPT or "no test specified" in normalised:
            return None
        return script.strip()

    @staticmethod
    def _project_name(root: Path, language: str | None, fallback: str) -> str:
        """Manifest name matching the dominant language, else any manifest, else ``fallback``."""
        python_name = _pyproject_name(root / "pyproject.toml")
        npm_name = _package_json_name(root / "package.json")
        ordered = (npm_name, python_name) if language in {"JavaScript", "TypeScript"} else (python_name, npm_name)
        for candidate in ordered:
            if candidate:
                return candidate
        return fallback


# ---------------------------------------------------------------------- safe readers


def _read_text(path: Path) -> str | None:
    """Read a small text file; None when missing, unreadable, binary or too large."""
    try:
        if not path.is_file() or path.stat().st_size > _MAX_TEXT_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def _read_json(path: Path) -> Any:
    text = _read_text(path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _package_json_name(path: Path) -> str | None:
    data = _read_json(path)
    name = data.get("name") if isinstance(data, dict) else None
    return name.strip() if isinstance(name, str) and name.strip() else None


def _pyproject_name(path: Path) -> str | None:
    text = _read_text(path)
    if text is None:
        return None
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return None
    for section in (data.get("project"), (data.get("tool") or {}).get("poetry")):
        if isinstance(section, dict):
            name = section.get("name")
            if isinstance(name, str) and name.strip():
                return name.strip()
    return None
