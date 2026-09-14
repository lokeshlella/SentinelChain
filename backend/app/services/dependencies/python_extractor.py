"""Python (PyPI) dependency extraction from ``requirements.txt``-style files.

Lines are parsed with :class:`packaging.requirements.Requirement` (PEP 508)
after the pip-specific pre-processing pip itself applies: line continuations,
comments, per-requirement options (``--hash=...``) and global options
(``-r``, ``-c``, ``-e``, ``--index-url`` ...).

``requirements.txt`` cannot tell direct from transitive dependencies, so every
dependency is reported with ``DependencyScope.UNKNOWN`` (never pretend).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from app.core.logging import get_stage_logger
from app.models.enums import DependencyScope, Ecosystem
from app.services.dependencies.base import DependencyExtractor, ExtractedDependency, ExtractionResult
from app.services.dependencies.common import read_text_file, relative_posix, truncate_text, walk_files

log = get_stage_logger("Dependencies")

MAX_DEPTH = 3

# A "#" starts a comment when it is at the start of the line or preceded by whitespace
# (so URL fragments such as "...#egg=name" survive).
_COMMENT_RE = re.compile(r"(^|\s)#.*$")
# Per-requirement options (pip only allows them after the requirement, separated by whitespace).
_PER_REQUIREMENT_OPTION_RE = re.compile(r"\s--[a-zA-Z][\w-]*(=\S*|\s+\S+)?")
_EGG_FRAGMENT_RE = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
_URL_LIKE_RE = re.compile(r"^(git\+|hg\+|svn\+|bzr\+|https?://|ssh://|file:|\.{1,2}/|/)")

# Options that reference other files: recorded as warnings, never followed recursively.
_INCLUDE_OPTIONS = {"-r": "requirement", "--requirement": "requirement", "-c": "constraint", "--constraint": "constraint"}
_EDITABLE_OPTIONS = {"-e", "--editable"}
# A file is development-only when a token of its name contains one of these markers ...
_DEV_FILE_MARKERS = ("dev", "test")
# ... except for ordinary words that merely happen to contain "test" (requirements-latest.txt).
_NOT_DEV_TOKENS = frozenset({"latest", "greatest", "fastest", "attest", "contest", "detest", "protest"})


@dataclass
class _LogicalLine:
    """A requirement line after joining continuations; ``number`` is its first physical line."""

    number: int
    text: str


def is_requirements_file(path: Path) -> bool:
    """``requirements.txt``, ``requirements-*.txt``, ``requirements_*.txt`` or ``requirements/*.txt``."""
    name = path.name.lower()
    if not name.endswith(".txt"):
        return False
    if name == "requirements.txt" or name.startswith(("requirements-", "requirements_")):
        return True
    return path.parent.name.lower() == "requirements"


def is_dev_requirements_file(relative_file: str) -> bool:
    """Development-only when a token of the file name contains ``dev`` or ``test`` (contract §4.2).

    Tokens are the pieces of the file stem split on ``-``, ``_`` and ``.``: ``dev``,
    ``devel``, ``development``, ``test``, ``tests``, ``testing``, ``pytest`` and
    ``unittest`` all qualify, while ``requirements-latest.txt`` is not a test file.
    """
    stem = Path(relative_file).name.lower()
    if stem.endswith(".txt"):
        stem = stem[:-4]
    tokens = [token for token in re.split(r"[-_.]+", stem) if token]
    return any(
        token not in _NOT_DEV_TOKENS and any(marker in token for marker in _DEV_FILE_MARKERS)
        for token in tokens
    )


def logical_lines(text: str) -> list[_LogicalLine]:
    """Join backslash continuations (as pip does) and strip comments / blank lines."""
    result: list[_LogicalLine] = []
    buffer: list[str] = []
    start = 0
    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not buffer:
            start = index
        if line.endswith("\\") and not line.lstrip().startswith("#"):
            buffer.append(line[:-1])
            continue
        buffer.append(line)
        joined = _COMMENT_RE.sub("", "".join(buffer)).strip()
        buffer = []
        if joined:
            result.append(_LogicalLine(number=start, text=joined))
    if buffer:  # trailing continuation at end of file
        joined = _COMMENT_RE.sub("", "".join(buffer)).strip()
        if joined:
            result.append(_LogicalLine(number=start, text=joined))
    return result


def pinned_version(requirement: Requirement) -> str | None:
    """The concrete version when the specifier pins exactly one (``==x`` or ``===x``).

    Wildcards (``==1.0.*``) and contradictory pins are not concrete.
    """
    pins = {spec.version for spec in requirement.specifier if spec.operator in ("==", "===")}
    pins = {pin for pin in pins if not pin.endswith(".*")}
    if len(pins) == 1:
        return pins.pop()
    return None


class PythonDependencyExtractor(DependencyExtractor):
    """Extracts PyPI dependencies from requirements files (depth <= 3, ignored dirs skipped)."""

    ecosystem = Ecosystem.PYPI

    def detect(self, repo_path: Path) -> list[Path]:
        repo_path = Path(repo_path).resolve()
        if not repo_path.is_dir():
            return []
        return list(walk_files(repo_path, max_depth=MAX_DEPTH, predicate=is_requirements_file))

    def extract(self, repo_path: Path) -> ExtractionResult:
        repo_path = Path(repo_path).resolve()
        result = ExtractionResult()
        files = self.detect(repo_path)
        detected = {relative_posix(f, repo_path) for f in files}
        for file_path in files:
            relative = relative_posix(file_path, repo_path)
            try:
                text = read_text_file(file_path)
            except OSError as exc:
                result.warnings.append(f"{relative}: cannot read file ({exc})")
                continue
            result.files.append(relative)
            before = len(result.dependencies)
            self._parse_file(text, relative, detected, result)
            log.info("%s: %d requirements parsed", relative, len(result.dependencies) - before)
        return result

    # ------------------------------------------------------------------ parsing
    def _parse_file(self, text: str, relative: str, detected: set[str], result: ExtractionResult) -> None:
        dev = is_dev_requirements_file(relative)
        for line in logical_lines(text):
            if line.text.startswith("-"):
                self._handle_option(line, relative, detected, result)
                continue
            dependency = self._parse_requirement_line(line, relative, dev, result)
            if dependency is not None:
                result.dependencies.append(dependency)

    def _handle_option(self, line: _LogicalLine, relative: str, detected: set[str], result: ExtractionResult) -> None:
        tokens = line.text.split(maxsplit=1)
        option, argument = tokens[0], (tokens[1].strip() if len(tokens) > 1 else "")
        if "=" in option and option.startswith("--"):
            option, argument = option.split("=", 1)
        elif len(option) > 2 and option[0] == "-" and option[1] != "-" and not argument:
            # pip also accepts attached short-option arguments: -rfile.txt, -cconstraints.txt, -e.
            option, argument = option[:2], option[2:]
        if option in _INCLUDE_OPTIONS:
            kind = _INCLUDE_OPTIONS[option]
            target = _resolve_include(relative, argument)
            note = "it is parsed separately" if target in detected else "the file is not parsed"
            result.warnings.append(
                f"{relative}:{line.number}: {kind} include '{option} {argument}' is not followed ({note})"
            )
        elif option in _EDITABLE_OPTIONS:
            result.warnings.append(
                f"{relative}:{line.number}: editable requirement '{line.text}' skipped "
                "(local/VCS installs have no registry version)"
            )
        else:
            log.debug("%s:%d: ignoring pip option %r", relative, line.number, line.text)

    def _parse_requirement_line(
        self, line: _LogicalLine, relative: str, dev: bool, result: ExtractionResult
    ) -> ExtractedDependency | None:
        text = _PER_REQUIREMENT_OPTION_RE.sub("", line.text).strip()
        if _URL_LIKE_RE.match(text):
            return self._url_requirement(text, line, relative, dev, result)
        try:
            requirement = Requirement(text)
        except InvalidRequirement as exc:
            reason = str(exc).splitlines()[0]
            result.warnings.append(
                f"{relative}:{line.number}: cannot parse {truncate_text(line.text)!r} ({reason})"
            )
            return None
        name = requirement.name
        raw_spec = text[len(name):].strip() if text.lower().startswith(name.lower()) else text
        version: str | None = None
        if requirement.url:
            result.warnings.append(
                f"{relative}:{line.number}: '{name}' is installed from a URL ({requirement.url}); "
                "version cannot be determined"
            )
        else:
            version = pinned_version(requirement)
        return ExtractedDependency(
            package_name=name,
            ecosystem=Ecosystem.PYPI,
            source_file=relative,
            version=version,
            version_spec=raw_spec or None,
            scope=DependencyScope.UNKNOWN,
            dev=dev,
            line_number=line.number,
        )

    @staticmethod
    def _url_requirement(
        text: str, line: _LogicalLine, relative: str, dev: bool, result: ExtractionResult
    ) -> ExtractedDependency | None:
        """Bare URL / path requirements: only usable when they carry an ``#egg=name`` fragment."""
        match = _EGG_FRAGMENT_RE.search(text)
        if not match:
            result.warnings.append(
                f"{relative}:{line.number}: URL/path requirement {truncate_text(text)!r} skipped (no package name)"
            )
            return None
        name = match.group(1)
        result.warnings.append(
            f"{relative}:{line.number}: '{name}' is installed from a URL ({text}); version cannot be determined"
        )
        return ExtractedDependency(
            package_name=name,
            ecosystem=Ecosystem.PYPI,
            source_file=relative,
            version=None,
            version_spec=text,
            scope=DependencyScope.UNKNOWN,
            dev=dev,
            line_number=line.number,
        )


def _resolve_include(relative_file: str, argument: str) -> str:
    """Path of an included requirements file relative to the repository root (POSIX)."""
    base = Path(relative_file).parent
    parts = (base / argument).as_posix().split("/")
    stack: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if stack:
                stack.pop()
            continue
        stack.append(part)
    return "/".join(stack)


__all__ = [
    "PythonDependencyExtractor",
    "is_requirements_file",
    "is_dev_requirements_file",
    "logical_lines",
    "pinned_version",
    "MAX_DEPTH",
]
