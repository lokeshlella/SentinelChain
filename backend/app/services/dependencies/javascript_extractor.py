"""JavaScript (npm) dependency extraction from ``package.json`` and ``package-lock.json``.

* ``package.json`` (root, ``workspaces`` members and other manifests at depth <= 2,
  plus every workspace the lock file names explicitly, whatever its depth) gives the
  DIRECT dependencies with their raw specifier.
* ``package-lock.json`` (lockfileVersion 1, 2 and 3; ``npm-shrinkwrap.json`` has the
  same format) gives the installed versions, the TRANSITIVE dependencies and the
  parent -> child relations, resolved with Node's ``node_modules`` lookup rules.

Workspace patterns are matched against the manifests found by the (depth-limited,
symlink-safe) directory walk instead of being handed to ``Path.glob``: a hostile or
malformed pattern (``.``, ``""``, ``/abs``, ``../x``, ``**``) can therefore neither
crash detection nor reach outside the repository.

``yarn.lock`` / ``pnpm-lock.yaml`` are detected but not parsed in V1 (warning).
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_stage_logger
from app.core.versions import is_valid_version
from app.models.enums import DependencyScope, Ecosystem
from app.services.dependencies.base import (
    DependencyExtractor,
    ExtractedDependency,
    ExtractedRelation,
    ExtractionResult,
)
from app.services.dependencies.common import (
    is_ignored_path,
    is_repository_file,
    is_within,
    read_text_file,
    relative_posix,
    walk_files,
)

log = get_stage_logger("Dependencies")

MANIFEST = "package.json"
LOCK_FILES = ("package-lock.json", "npm-shrinkwrap.json")
UNSUPPORTED_LOCK_FILES = ("yarn.lock", "pnpm-lock.yaml")
MAX_DEPTH = 2

# Section name -> dev flag. Order matters: the first section that declares a package wins.
DEPENDENCY_SECTIONS: tuple[tuple[str, bool], ...] = (
    ("dependencies", False),
    ("devDependencies", True),
    ("optionalDependencies", False),
    ("peerDependencies", False),
)

_EXACT_SPEC_RE = re.compile(
    r"^\s*=?\s*v?(?P<version>(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\s*$"
)
_UNRESOLVABLE_PREFIXES = (
    "file:", "link:", "workspace:", "npm:", "git+", "git:", "github:", "gitlab:", "bitbucket:",
    "gist:", "http://", "https://", "ssh://", "portal:", "patch:",
)
# GitHub shorthand "owner/repo" or "owner/repo#ref" (no protocol, no range operators).
_GITHUB_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9][\w.-]*/[\w.-]+(#.*)?$")
_GIT_RESOLVED_RE = re.compile(r"^(git\+|git:|github:|gitlab:|bitbucket:|ssh://)")


def exact_version(spec: str) -> str | None:
    """``1.2.3`` / ``=1.2.3`` / ``v1.2.3`` → ``1.2.3``; anything else (ranges, tags) → None."""
    match = _EXACT_SPEC_RE.match(spec or "")
    return match.group("version") if match else None


def unresolvable_kind(spec: str) -> str | None:
    """Name of the non-registry specifier kind (``file:``, ``git+``, ...) or None for registry specs."""
    text = (spec or "").strip()
    for prefix in _UNRESOLVABLE_PREFIXES:
        if text.lower().startswith(prefix):
            return prefix
    if _GITHUB_SHORTHAND_RE.match(text):
        return "github shorthand"
    return None


def split_lock_key(key: str) -> tuple[str, str]:
    """``node_modules/a/node_modules/@s/b`` → (``node_modules/a``, ``@s/b``)."""
    marker = "node_modules/"
    index = key.rfind(marker)
    if index == -1:
        return "", key
    return key[:index].rstrip("/"), key[index + len(marker):]


def resolve_lock_key(base_key: str, dependency: str, packages: dict[str, Any]) -> str | None:
    """Node resolution: look for ``<base>/node_modules/<dep>`` walking up the tree to the root."""
    base = base_key
    while True:
        candidate = f"{base}/node_modules/{dependency}" if base else f"node_modules/{dependency}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        index = base.rfind("/node_modules/")
        base = base[:index] if index != -1 else ""


def workspace_pattern_segments(pattern: str) -> list[str] | None:
    """Normalise a ``workspaces`` glob into path segments; None when it cannot name a member.

    ``./packages/*/`` → ``["packages", "*"]``; ``.``/``""``/``./`` → ``[]`` (the root
    itself); absolute patterns and patterns climbing out of the repository (``../x``)
    → None.
    """
    if not isinstance(pattern, str):
        return None
    text = pattern.strip()
    if text.startswith(("/", "\\")):
        return None
    segments = [segment for segment in text.replace("\\", "/").split("/") if segment not in ("", ".")]
    if ".." in segments:
        return None
    return segments


def matches_workspace_pattern(segments: list[str], directory: str) -> bool:
    """Anchored glob match of a POSIX directory (``""`` = root) against pattern segments.

    ``*``, ``?`` and ``[...]`` match within one path component (like ``Path.glob``),
    ``**`` matches any number of components (like minimatch, which npm uses).
    """
    return _match_segments(segments, directory.split("/") if directory else [])


def _match_segments(pattern: list[str], parts: list[str]) -> bool:
    if not pattern:
        return not parts
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        return any(_match_segments(rest, parts[index:]) for index in range(len(parts) + 1))
    if not parts or not fnmatch.fnmatchcase(parts[0], head):
        return False
    return _match_segments(rest, parts[1:])


def is_workspace_key(key: str) -> bool:
    """Lock ``packages`` keys that denote a workspace directory rather than an installed package."""
    return bool(key) and "node_modules/" not in key


@dataclass
class _Manifest:
    path: Path
    relative: str  # POSIX path of package.json relative to the repository root
    directory: str  # POSIX directory relative to the repository root ("" for root)
    data: dict[str, Any]
    from_lock: bool = False  # synthesised from a lock's workspace entry (no readable package.json)


@dataclass
class _Lock:
    path: Path
    relative: str
    directory: str
    packages: dict[str, dict[str, Any]]  # normalised lockfileVersion 2/3 style map
    version: int
    # lock key -> identity (package_name, version) of the emitted dependency (None = not emitted).
    # Keys claimed by a manifest's direct dependency are registered here before the
    # transitive pass so they are never reported twice.
    identities: dict[str, tuple[str, str | None] | None] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class JavaScriptDependencyExtractor(DependencyExtractor):
    """Extracts npm dependencies from package.json (+ package-lock.json when present)."""

    ecosystem = Ecosystem.NPM

    # ---------------------------------------------------------------- detection
    def detect(self, repo_path: Path) -> list[Path]:
        repo_path = Path(repo_path).resolve()
        if not repo_path.is_dir():
            return []
        manifests = self._discover_manifests(repo_path)
        return manifests + self._locks_for(manifests, repo_path)

    def _discover_manifests(self, repo_path: Path) -> list[Path]:
        """Root manifest first, then ``workspaces`` members, other manifests at depth <= 2,
        then workspaces the lock files name explicitly (any depth)."""
        candidates = list(walk_files(repo_path, max_depth=MAX_DEPTH, predicate=lambda p: p.name == MANIFEST))
        manifests: list[Path] = []
        root_manifest = repo_path / MANIFEST
        if root_manifest in candidates:
            manifests.append(root_manifest)
            for member in self._workspace_manifests(repo_path, root_manifest, candidates):
                if member not in manifests:
                    manifests.append(member)
        for candidate in candidates:
            if candidate not in manifests:
                manifests.append(candidate)
        for lock_path in self._locks_for(manifests, repo_path):
            for member in self._lock_workspace_manifests(lock_path, repo_path):
                if member not in manifests:
                    manifests.append(member)
        return manifests

    def _workspace_manifests(self, repo_path: Path, root_manifest: Path, candidates: list[Path]) -> list[Path]:
        """Candidates whose directory matches a ``workspaces`` pattern (and no ``!`` exclusion)."""
        try:
            data = json.loads(read_text_file(root_manifest))
        except (OSError, ValueError, RecursionError):
            return []
        patterns = data.get("workspaces") if isinstance(data, dict) else None
        if isinstance(patterns, dict):
            patterns = patterns.get("packages")
        if not isinstance(patterns, list):
            return []
        included: list[list[str]] = []
        excluded: list[list[str]] = []
        for pattern in patterns:
            negated = isinstance(pattern, str) and pattern.startswith("!")
            segments = workspace_pattern_segments(pattern[1:] if negated else pattern)
            if segments is None or (not segments and not negated):
                continue  # unusable pattern, or the root itself (already listed)
            (excluded if negated else included).append(segments)
        members: list[Path] = []
        for segments in included:
            for candidate in candidates:
                directory = relative_posix(candidate.parent, repo_path) if candidate.parent != repo_path else ""
                if not directory or candidate in members:
                    continue
                if matches_workspace_pattern(segments, directory) and not any(
                    matches_workspace_pattern(exclusion, directory) for exclusion in excluded
                ):
                    members.append(candidate)
        return members

    def _locks_for(self, manifests: list[Path], repo_path: Path) -> list[Path]:
        locks: list[Path] = []
        for manifest in manifests:
            lock = self._lock_for(manifest.parent, repo_path)
            if lock is not None and lock not in locks:
                locks.append(lock)
        return locks

    @staticmethod
    def _lock_workspace_manifests(lock_path: Path, repo_path: Path) -> list[Path]:
        """Manifests of the workspaces a v2/v3 lock records (``packages/<dir>`` keys), when readable.

        The lock names these directories explicitly, so their manifests are used even
        beyond ``MAX_DEPTH``: their dependencies are DIRECT and must not be mistaken for
        transitive ones. Keys are untrusted: those leaving the repository (lexically or
        through a symlinked directory) or entering ignored directories are skipped.
        """
        try:
            data = json.loads(read_text_file(lock_path))
        except (OSError, ValueError, RecursionError):
            return []
        packages = data.get("packages") if isinstance(data, dict) else None
        if not isinstance(packages, dict):
            return []
        members: list[Path] = []
        for key in sorted(packages):
            if not isinstance(key, str) or not is_workspace_key(key):
                continue
            segments = workspace_pattern_segments(key)
            if not segments or is_ignored_path(tuple(segments)):
                continue
            manifest = lock_path.parent.joinpath(*segments) / MANIFEST
            if manifest.is_file() and is_within(manifest, repo_path) and manifest not in members:
                members.append(manifest)
        return members

    def _lock_for(self, directory: Path, repo_path: Path, result: ExtractionResult | None = None) -> Path | None:
        """The lock file that governs a manifest: adjacent first, else the nearest ancestor's.

        An ancestor lock only governs a nested manifest when it declares that
        directory as a workspace (a ``packages/<dir>`` key in a v2/v3 lock or a
        matching ``workspaces`` pattern of the root manifest). Any other nested
        manifest (an example project, a vendored tool, ...) is lock-less: npm
        would resolve it independently, so adopting the root lock's versions
        would fabricate versions that were never installed for it.
        """
        current = directory
        while True:
            for name in LOCK_FILES:
                candidate = current / name
                if not is_repository_file(candidate, repo_path):
                    continue
                if current == directory or self._is_workspace_of(candidate, directory, repo_path):
                    return candidate
                if result is not None:
                    result.warnings.append(
                        f"{relative_posix(directory / MANIFEST, repo_path)}: not a workspace of "
                        f"{relative_posix(candidate, repo_path)}; versions are taken from exact specs only"
                    )
                return None
            if current == repo_path or repo_path not in current.parents:
                return None
            current = current.parent

    def _is_workspace_of(self, lock_path: Path, directory: Path, repo_path: Path) -> bool:
        manifest = directory / MANIFEST
        if manifest in self._lock_workspace_manifests(lock_path, repo_path):
            return True
        root_manifest = lock_path.parent / MANIFEST
        if not root_manifest.is_file():
            return False
        return manifest in self._workspace_manifests(repo_path, root_manifest, [manifest])

    # --------------------------------------------------------------- extraction
    def extract(self, repo_path: Path) -> ExtractionResult:
        repo_path = Path(repo_path).resolve()
        result = ExtractionResult()
        manifests: list[_Manifest] = []
        for manifest_path in self._discover_manifests(repo_path):
            manifest = self._load_manifest(manifest_path, repo_path, result)
            if manifest is not None:
                manifests.append(manifest)
        locks: dict[Path, _Lock | None] = {}
        groups: dict[Path | None, list[_Manifest]] = {}
        for manifest in manifests:
            lock_path = self._lock_for(manifest.path.parent, repo_path, result)
            if lock_path is not None and lock_path not in locks:
                locks[lock_path] = self._load_lock(lock_path, repo_path, result)
            groups.setdefault(lock_path, []).append(manifest)
            self._warn_unsupported_locks(manifest.path.parent, repo_path, result)

        for lock_path, group in groups.items():
            lock = locks.get(lock_path) if lock_path else None
            if lock is not None:
                group = group + self._lock_only_workspaces(lock, manifests, result)
            direct_identities: set[tuple[str, str | None]] = set()
            lock_emitted: set[tuple[str, str | None]] = set()  # shared by every lock-sourced workspace
            for manifest in group:
                direct_identities |= self._extract_direct(
                    manifest, lock, result, emitted=lock_emitted if manifest.from_lock else None
                )
            if lock is not None:
                self._extract_transitive(lock, direct_identities, result)
                self._extract_relations(lock, result)
                result.warnings.extend(lock.warnings)
        return result

    @staticmethod
    def _lock_only_workspaces(lock: _Lock, manifests: list[_Manifest], result: ExtractionResult) -> list[_Manifest]:
        """Workspaces the lock records whose ``package.json`` could not be read.

        Their declared dependencies are still direct (the lock's workspace entry proves
        it), so they are extracted from that entry with ``source_file`` = the lock and a
        warning, instead of being misreported as transitive. ``manifests`` are all the
        manifests that were loaded (a workspace with its own lock is still known).
        """
        known = {manifest.directory for manifest in manifests}
        synthetic: list[_Manifest] = []
        for key in sorted(lock.packages):
            if not is_workspace_key(key):
                continue
            segments = workspace_pattern_segments(key)
            directory = "/".join(([lock.directory] if lock.directory else []) + (segments if segments else [key]))
            entry = lock.packages[key]
            if directory in known or not any(isinstance(entry.get(section), dict) for section, _ in DEPENDENCY_SECTIONS):
                continue
            result.warnings.append(
                f"{lock.relative}: workspace '{key}' has no readable {MANIFEST}; "
                "its declared dependencies are reported from the lock file"
            )
            synthetic.append(
                _Manifest(path=lock.path, relative=lock.relative, directory=directory, data=entry, from_lock=True)
            )
        return synthetic

    # ----------------------------------------------------------------- loading
    def _load_manifest(self, path: Path, repo_path: Path, result: ExtractionResult) -> _Manifest | None:
        relative = relative_posix(path, repo_path)
        data = self._load_json(path, relative, result)
        if data is None:
            return None
        result.files.append(relative)
        directory = relative_posix(path.parent, repo_path) if path.parent != repo_path else ""
        return _Manifest(path=path, relative=relative, directory=directory, data=data)

    def _load_lock(self, path: Path, repo_path: Path, result: ExtractionResult) -> _Lock | None:
        relative = relative_posix(path, repo_path)
        data = self._load_json(path, relative, result)
        if data is None:
            return None
        directory = relative_posix(path.parent, repo_path) if path.parent != repo_path else ""
        version = data.get("lockfileVersion")
        if isinstance(data.get("packages"), dict):
            packages = {k: v for k, v in data["packages"].items() if isinstance(v, dict)}
            version = int(version) if isinstance(version, int) else 2
        elif isinstance(data.get("dependencies"), dict):
            packages = _flatten_v1_tree(data["dependencies"], "")
            version = 1
        else:
            result.warnings.append(f"{relative}: unrecognised lock file format (no 'packages' or 'dependencies'); skipped")
            return None
        result.files.append(relative)
        log.info("%s: lockfileVersion %s with %d entries", relative, version, len(packages))
        return _Lock(path=path, relative=relative, directory=directory, packages=packages, version=version)

    @staticmethod
    def _load_json(path: Path, relative: str, result: ExtractionResult) -> dict[str, Any] | None:
        try:
            data = json.loads(read_text_file(path))
        except OSError as exc:
            result.warnings.append(f"{relative}: cannot read file ({exc})")
            return None
        except (ValueError, RecursionError) as exc:
            result.warnings.append(f"{relative}: malformed JSON ({exc.__class__.__name__}: {str(exc)[:120]}); file skipped")
            return None
        if not isinstance(data, dict):
            result.warnings.append(f"{relative}: expected a JSON object; file skipped")
            return None
        return data

    @staticmethod
    def _warn_unsupported_locks(directory: Path, repo_path: Path, result: ExtractionResult) -> None:
        for name in UNSUPPORTED_LOCK_FILES:
            candidate = directory / name
            if candidate.is_file():
                relative = relative_posix(candidate, repo_path)
                message = f"{relative}: yarn/pnpm lock files are not parsed in V1; transitive dependencies are unavailable"
                if message not in result.warnings:
                    result.warnings.append(message)

    # ------------------------------------------------------------ direct deps
    def _extract_direct(
        self,
        manifest: _Manifest,
        lock: _Lock | None,
        result: ExtractionResult,
        emitted: set[tuple[str, str | None]] | None = None,
    ) -> set[tuple[str, str | None]]:
        """Emit the manifest's declared dependencies once each; returns their identities.

        ``emitted`` (identities already reported under the same ``source_file``) lets the
        lock-sourced workspaces share one source file without duplicate rows.
        """
        identities: set[tuple[str, str | None]] = set()
        seen: set[str] = set()
        base_key = _relative_dir(manifest.directory, lock.directory) if lock else ""
        for section, dev in DEPENDENCY_SECTIONS:
            entries = manifest.data.get(section)
            if entries is None:
                continue
            if not isinstance(entries, dict):
                result.warnings.append(f"{manifest.relative}: '{section}' is not an object; section skipped")
                continue
            for name, spec in entries.items():
                if not isinstance(name, str) or not name or name in seen:
                    continue
                seen.add(name)
                spec_text = spec if isinstance(spec, str) else json.dumps(spec)
                version = self._direct_version(manifest, name, spec_text, base_key, lock, result)
                identities.add((name, version))
                if emitted is not None:
                    if (name, version) in emitted:
                        continue
                    emitted.add((name, version))
                result.dependencies.append(
                    ExtractedDependency(
                        package_name=name,
                        ecosystem=Ecosystem.NPM,
                        source_file=manifest.relative,
                        version=version,
                        version_spec=spec_text.strip() or None,
                        scope=DependencyScope.DIRECT,
                        dev=dev,
                    )
                )
        log.info("%s: %d direct dependencies", manifest.relative, len(seen))
        return identities

    def _direct_version(
        self, manifest: _Manifest, name: str, spec: str, base_key: str, lock: _Lock | None, result: ExtractionResult
    ) -> str | None:
        """Concrete version of a declared dependency: exact spec, else the lock, else None."""
        kind = unresolvable_kind(spec)
        exact = None if kind else exact_version(spec)
        lock_key = resolve_lock_key(base_key, name, lock.packages) if lock else None
        entry, note = self._lock_entry_for_direct(lock, lock_key, name)
        if kind:
            result.warnings.append(
                f"{manifest.relative}: '{name}' uses a {kind} specifier ({spec!r}); version cannot be determined"
            )
            version = None
        elif exact:
            version = exact
        else:
            version = _entry_version(entry) if entry else None
            if lock and version is None:
                reason = note or f"not found in {lock.relative}"
                result.warnings.append(f"{manifest.relative}: '{name}' ({spec}) {reason}; version unresolved")
        if lock and lock_key and entry is not None:
            lock.identities[lock_key] = (name, version)  # claimed: not a transitive dependency
            installed = _entry_version(entry)
            if exact and installed not in (None, exact):
                result.warnings.append(
                    f"{manifest.relative}: '{name}' pins {exact} but {lock.relative} installs {installed}"
                )
        return version

    @staticmethod
    def _lock_entry_for_direct(
        lock: _Lock | None, lock_key: str | None, name: str
    ) -> tuple[dict[str, Any] | None, str | None]:
        """The lock entry that IS the declared package, or (None, reason) for links / aliases."""
        if lock is None or not lock_key:
            return None, None
        entry = lock.packages[lock_key]
        if entry.get("link"):
            return None, f"is a linked local package ({entry.get('resolved')!r})"
        real_name = entry.get("name")
        if isinstance(real_name, str) and real_name != name:
            return None, f"is an alias of '{real_name}'"
        return entry, None

    # -------------------------------------------------------- transitive deps
    def _extract_transitive(
        self, lock: _Lock, direct_identities: set[tuple[str, str | None]], result: ExtractionResult
    ) -> None:
        """Every installed package not claimed by a manifest becomes a TRANSITIVE dependency."""
        emitted: dict[tuple[str, str | None], ExtractedDependency] = {}
        count = 0
        for key, entry in lock.packages.items():
            if key in lock.identities:
                continue  # claimed by a manifest's direct dependency
            if key == "" or "node_modules/" not in key or entry.get("link"):
                lock.identities[key] = None  # root project, workspace package or symlink
                continue
            name = entry.get("name") if isinstance(entry.get("name"), str) else split_lock_key(key)[1]
            version = _entry_version(entry)
            if version is None:
                lock.warnings.append(
                    f"{lock.relative}: '{key}' has no valid version ({entry.get('version')!r}); version unknown"
                )
            elif isinstance(entry.get("resolved"), str) and _GIT_RESOLVED_RE.match(entry["resolved"]):
                lock.warnings.append(
                    f"{lock.relative}: '{name}@{version}' is installed from git ({entry['resolved']}); "
                    "the version may not match a registry release"
                )
            identity = (name, version)
            lock.identities[key] = identity
            if identity in direct_identities:
                continue  # same package/version already reported as a direct dependency
            dev = bool(entry.get("dev"))
            if identity in emitted:
                emitted[identity].dev = emitted[identity].dev and dev
                continue
            dependency = ExtractedDependency(
                package_name=name,
                ecosystem=Ecosystem.NPM,
                source_file=lock.relative,
                version=version,
                version_spec=None,
                scope=DependencyScope.TRANSITIVE,
                dev=dev,
            )
            emitted[identity] = dependency
            result.dependencies.append(dependency)
            count += 1
        log.info("%s: %d transitive dependencies", lock.relative, count)

    # ---------------------------------------------------------------- relations
    def _extract_relations(self, lock: _Lock, result: ExtractionResult) -> None:
        seen: set[tuple[tuple[str, str | None], tuple[str, str | None]]] = set()
        unresolved = 0
        for key, entry in lock.packages.items():
            parent = lock.identities.get(key)
            if parent is None:
                continue
            for section in ("dependencies", "optionalDependencies", "peerDependencies"):
                declared = entry.get(section)
                if not isinstance(declared, dict):
                    continue
                for child_name in declared:
                    child_key = resolve_lock_key(key, child_name, lock.packages)
                    child = lock.identities.get(child_key) if child_key else None
                    if child is None:
                        unresolved += 1
                        continue
                    edge = (parent, child)
                    if edge in seen or parent == child:
                        continue
                    seen.add(edge)
                    result.relations.append(
                        ExtractedRelation(
                            parent_name=parent[0],
                            parent_version=parent[1],
                            child_name=child[0],
                            child_version=child[1],
                            ecosystem=Ecosystem.NPM,
                        )
                    )
        log.info("%s: %d relations (%d declared dependencies not installed)", lock.relative, len(seen), unresolved)


def _flatten_v1_tree(tree: dict[str, Any], prefix: str) -> dict[str, dict[str, Any]]:
    """Convert a lockfileVersion 1 nested ``dependencies`` tree into a v2/v3-style ``packages`` map."""
    packages: dict[str, dict[str, Any]] = {}
    for name, entry in tree.items():
        if not isinstance(entry, dict):
            continue
        key = f"{prefix}/node_modules/{name}" if prefix else f"node_modules/{name}"
        normalised: dict[str, Any] = {"version": entry.get("version")}
        for flag in ("dev", "optional", "resolved"):
            if flag in entry:
                normalised[flag] = entry[flag]
        if isinstance(entry.get("requires"), dict):
            normalised["dependencies"] = entry["requires"]
        packages[key] = normalised
        if isinstance(entry.get("dependencies"), dict):
            packages.update(_flatten_v1_tree(entry["dependencies"], key))
    return packages


def _entry_version(entry: dict[str, Any]) -> str | None:
    """The installed version of a lock entry when it is a real semver (git/file specs are not)."""
    version = entry.get("version")
    if isinstance(version, str) and is_valid_version(version, "npm") and not unresolvable_kind(version):
        return version.strip()
    return None


def _relative_dir(manifest_dir: str, lock_dir: str) -> str:
    """Manifest directory expressed relative to the lock's directory (the lock's key namespace)."""
    if not lock_dir:
        return manifest_dir
    if manifest_dir == lock_dir:
        return ""
    return manifest_dir[len(lock_dir) + 1:] if manifest_dir.startswith(lock_dir + "/") else manifest_dir


__all__ = [
    "JavaScriptDependencyExtractor",
    "exact_version",
    "unresolvable_kind",
    "split_lock_key",
    "resolve_lock_key",
    "workspace_pattern_segments",
    "matches_workspace_pattern",
    "is_workspace_key",
    "MAX_DEPTH",
]
