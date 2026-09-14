"""Application-aware usage analysis: where is a dependency referenced in the repository?

The analyser scans the repository's own source files for import statements of a
package (Python ``import``/``from`` lines, JavaScript ``require``/``import``
forms) and flags lines in dependency manifests that declare the package. Every hit is
recorded as a :class:`UsageReference` (file, line, snippet, kind) so downstream
stages — the LLM agents, the knowledge graph and the evidence report — only ever
receive *observed facts*.

The scan is deliberately simple (regular expressions, no AST): V1 needs an honest,
fast, deterministic answer to "which files and components reference package X?",
not a full static analysis.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.core.exceptions import RepositoryError
from app.core.logging import get_stage_logger
from app.core.versions import normalize_package_name
from app.models.enums import Ecosystem
from app.services.agents.schemas import UsageContext, UsageReferenceContext

logger = get_stage_logger("Usage")

# --------------------------------------------------------------------------- constants

REFERENCE_KIND_IMPORT = "import"
REFERENCE_KIND_CONFIG = "config"

#: Directories that never contain the application's own source (same list as the
#: repository analyser, plus a few tool caches).
IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git", "node_modules", ".venv", "venv", "env", "dist", "build", "__pycache__",
        ".pytest_cache", ".mypy_cache", ".tox", "site-packages", "coverage", ".next", ".cache",
        ".ruff_cache", ".eggs", ".idea", ".vscode", ".svn", ".hg",
    }
)

#: Files larger than this are skipped (generated bundles, vendored blobs, ...). The
#: reader never consumes more than this many bytes + 1 from any file, whatever
#: ``stat`` reported.
MAX_FILE_SIZE_BYTES = 1024 * 1024

#: Snippets are single source lines, truncated so evidence stays compact.
SNIPPET_MAX_LENGTH = 200

#: Line terminators: CRLF, CR or LF only — the line numbers editors and ``git blame``
#: show. (``str.splitlines`` would also break on form feeds, U+2028 and friends.)
_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")

PYTHON_SOURCE_SUFFIXES: frozenset[str] = frozenset({".py"})
JS_SOURCE_SUFFIXES: frozenset[str] = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"})

#: Python manifests whose dependency declarations are quoted requirement strings or
#: ``name = spec`` keys (TOML / INI / ``setup()`` keyword arguments) rather than one
#: PEP 508 requirement per line. Only dependency-bearing lines are matched — see
#: ``_PythonMatcher.manifest_lines``.
PYTHON_TOKEN_MANIFESTS: frozenset[str] = frozenset({"pyproject.toml", "setup.cfg", "setup.py", "Pipfile"})

#: TOML tables / INI sections whose entries are dependency declarations:
#: ``[project.optional-dependencies]``, ``[dependency-groups]``, ``[tool.poetry.dependencies]``,
#: ``[tool.poetry.group.dev.dependencies]``, ``[tool.poetry.extras]``, ``[tool.pdm.dev-dependencies]``,
#: ``[tool.flit.metadata.requires-extra]``, ``[options.extras_require]`` and the Pipfile
#: ``[packages]`` / ``[dev-packages]`` tables.
_DEPENDENCY_SECTION_RE = re.compile(r"require|depend|extras|^(?:dev-)?packages$", re.IGNORECASE)

#: Keys / keyword arguments whose value lists dependencies: ``dependencies``,
#: ``dev-dependencies``, ``install_requires``, ``extras_require``, ``setup_requires``,
#: ``tests_require``, ``requires`` (build-system), ``deps`` / ``REQUIREMENTS`` variables.
_DEPENDENCY_KEY_RE = re.compile(r"require|depend|deps", re.IGNORECASE)

#: ``key =`` (TOML key or Python keyword argument / assignment) anywhere in a line;
#: ``==`` and other comparison operators never count.
_KEY_ASSIGNMENT_RE = re.compile(r"""(?<![\w"'.\-])(?P<key>[A-Za-z_][\w.\-]*)\s*=(?!=)""")

#: ``[table]`` / ``[[array.of.tables]]`` / ``[section]`` header.
_SECTION_HEADER_RE = re.compile(r"^\s*\[\[?\s*(?P<name>[^\]]*?)\s*\]\]?")

#: ``key = value`` / ``key: value`` at the start of an INI line (setup.cfg).
_INI_KEY_RE = re.compile(r"^(?P<key>[A-Za-z_][\w.\-]*)\s*[=:]\s*(?P<value>.*)$")


def split_lines(text: str) -> list[str]:
    """Split on CRLF / CR / LF only, so index + 1 is the line number an editor shows."""
    return _LINE_BREAK_RE.split(text)


#: Curated PyPI distribution name (PEP 503 normalised) -> import name, for the common
#: packages whose import name cannot be derived from the distribution name.
PYTHON_IMPORT_NAMES: dict[str, str] = {
    "pyyaml": "yaml",
    "pillow": "PIL",
    "beautifulsoup4": "bs4",
    "scikit-learn": "sklearn",
    "scikit-image": "skimage",
    "python-dateutil": "dateutil",
    "python-dotenv": "dotenv",
    "python-slugify": "slugify",
    "python-magic": "magic",
    "python-ldap": "ldap",
    "python-memcached": "memcache",
    "python-gnupg": "gnupg",
    "python-docx": "docx",
    "python-pptx": "pptx",
    "python-json-logger": "pythonjsonlogger",
    "python-telegram-bot": "telegram",
    "python-decouple": "decouple",
    "psycopg2-binary": "psycopg2",
    "opencv-python": "cv2",
    "opencv-python-headless": "cv2",
    "opencv-contrib-python": "cv2",
    "attrs": "attr",
    "pyjwt": "jwt",
    "markupsafe": "markupsafe",
    "msgpack-python": "msgpack",
    "protobuf": "google.protobuf",
    "python-jose": "jose",
    "djangorestframework": "rest_framework",
    "djangorestframework-simplejwt": "rest_framework_simplejwt",
    "django-cors-headers": "corsheaders",
    "django-filter": "django_filters",
    "django-debug-toolbar": "debug_toolbar",
    "django-environ": "environ",
    "django-storages": "storages",
    "flask-sqlalchemy": "flask_sqlalchemy",
    "flask-cors": "flask_cors",
    "flask-login": "flask_login",
    "flask-migrate": "flask_migrate",
    "flask-wtf": "flask_wtf",
    "gitpython": "git",
    "pygithub": "github",
    "pymongo": "pymongo",
    "mysqlclient": "MySQLdb",
    "setuptools": "setuptools",
    "typing-extensions": "typing_extensions",
    "importlib-metadata": "importlib_metadata",
    "importlib-resources": "importlib_resources",
    "python-multipart": "multipart",
    "pydantic-settings": "pydantic_settings",
    "uvicorn": "uvicorn",
    "jinja2": "jinja2",
    "pycryptodome": "Crypto",
    "pycryptodomex": "Cryptodome",
    "pycrypto": "Crypto",
    "pyopenssl": "OpenSSL",
    "pysocks": "socks",
    "websocket-client": "websocket",
    "google-api-python-client": "googleapiclient",
    "google-auth": "google.auth",
    "google-cloud-storage": "google.cloud.storage",
    "pyzmq": "zmq",
    "pynacl": "nacl",
    "pyserial": "serial",
    "pyusb": "usb",
    "pywin32": "win32api",
    "grpcio": "grpc",
    "ipython": "IPython",
    "apache-airflow": "airflow",
    "azure-storage-blob": "azure.storage.blob",
    "pyqt5": "PyQt5",
    "pyside2": "PySide2",
    "sentry-sdk": "sentry_sdk",
    "charset-normalizer": "charset_normalizer",
    "requests-oauthlib": "requests_oauthlib",
    "factory-boy": "factory",
    "vcrpy": "vcr",
    "kafka-python": "kafka",
    "confluent-kafka": "confluent_kafka",
    "cassandra-driver": "cassandra",
    "prometheus-client": "prometheus_client",
    "opentelemetry-api": "opentelemetry",
    "dataclasses-json": "dataclasses_json",
    "hydra-core": "hydra",
    "pypdf2": "PyPDF2",
    "pdfminer-six": "pdfminer",
    "discord-py": "discord",
    "slack-sdk": "slack_sdk",
    "slackclient": "slack",
    "tortoise-orm": "tortoise",
    "wxpython": "wx",
    "pyinstaller": "PyInstaller",
    "cython": "Cython",
    "ruamel-yaml": "ruamel.yaml",
    "zope-interface": "zope.interface",
    "backports-zoneinfo": "backports.zoneinfo",
    "line-profiler": "line_profiler",
    "memory-profiler": "memory_profiler",
    "setuptools-scm": "setuptools_scm",
    "dj-database-url": "dj_database_url",
    "drf-yasg": "drf_yasg",
    "aws-xray-sdk": "aws_xray_sdk",
}


# --------------------------------------------------------------------------- data


@dataclass
class UsageReference:
    """One observed line that references the dependency."""

    file: str  # POSIX path relative to the repository root
    line: int  # 1-based line number
    snippet: str  # the stripped source line (truncated)
    kind: str = REFERENCE_KIND_IMPORT  # "import" (source code) | "config" (dependency manifest)

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "snippet": self.snippet, "kind": self.kind}

    @classmethod
    def from_dict(cls, data: dict) -> "UsageReference":
        return cls(
            file=str(data.get("file", "")),
            line=int(data.get("line", 0) or 0),
            snippet=str(data.get("snippet", "")),
            kind=str(data.get("kind", REFERENCE_KIND_IMPORT) or REFERENCE_KIND_IMPORT),
        )


@dataclass
class UsageEvidence:
    """Everything the analyser observed about one package in one repository.

    * ``references`` — import references first (sorted by file, then line), followed by
      config references (same order); capped at ``max_references``.
    * ``files`` / ``components`` — derived from *import* references only: they answer
      "which parts of the application code use this package?". Manifest lines are
      reported as references but do not make a component a user of the package.
      ``files`` is sorted and capped at ``max_reported_files``; ``total_files`` is the
      number of importing files actually observed (``components`` always covers all of
      them — it is bounded by the component list, not by the file count).
    * ``import_names`` — the import names actually observed; when nothing was found,
      the names the analyser searched for (so the reader knows what was looked up).
    * ``truncated`` — a cap (files scanned, references, files reported) was hit or part
      of the tree could not be read; evidence is partial.
    """

    package_name: str
    ecosystem: str
    import_names: list[str] = field(default_factory=list)
    references: list[UsageReference] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    components: list[str] = field(default_factory=list)
    truncated: bool = False
    scanned_files: int = 0
    total_files: int = 0

    def __post_init__(self) -> None:
        if self.total_files < len(self.files):
            self.total_files = len(self.files)

    @property
    def import_references(self) -> list[UsageReference]:
        return [r for r in self.references if r.kind == REFERENCE_KIND_IMPORT]

    @property
    def config_references(self) -> list[UsageReference]:
        return [r for r in self.references if r.kind == REFERENCE_KIND_CONFIG]

    @property
    def is_used(self) -> bool:
        """True when at least one source file imports the package."""
        return bool(self.files)

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "import_names": list(self.import_names),
            "references": [r.to_dict() for r in self.references],
            "files": list(self.files),
            "components": list(self.components),
            "truncated": self.truncated,
            "scanned_files": self.scanned_files,
            "total_files": self.total_files,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "UsageEvidence":
        """Rebuild evidence from its stored JSON form (tolerates missing keys)."""
        files = [str(f) for f in data.get("files", []) or []]
        return cls(
            package_name=str(data.get("package_name", "")),
            ecosystem=str(data.get("ecosystem", "")),
            import_names=[str(n) for n in data.get("import_names", []) or []],
            references=[UsageReference.from_dict(r) for r in data.get("references", []) or []],
            files=files,
            components=[str(c) for c in data.get("components", []) or []],
            truncated=bool(data.get("truncated", False)),
            scanned_files=int(data.get("scanned_files", 0) or 0),
            total_files=int(data.get("total_files", len(files)) or 0),
        )

    def to_context(self) -> UsageContext:
        """The FACT-only view handed to the AI agents."""
        return UsageContext(
            import_names=list(self.import_names),
            references=[UsageReferenceContext(file=r.file, line=r.line, snippet=r.snippet) for r in self.references],
            files=list(self.files),
            components=list(self.components),
            truncated=self.truncated,
        )


# --------------------------------------------------------------------------- helpers


def normalise_ecosystem(ecosystem: str | Ecosystem) -> Ecosystem | None:
    """Map ``"PyPI"``/``"pypi"``/``Ecosystem.PYPI`` (and npm) to the enum; None when unsupported."""
    value = str(ecosystem).strip().lower()
    if value == Ecosystem.PYPI.value.lower():
        return Ecosystem.PYPI
    if value == Ecosystem.NPM.value.lower():
        return Ecosystem.NPM
    return None


def python_import_candidates(package_name: str) -> list[str]:
    """Import names to look for, most likely first.

    A curated mapping wins outright; otherwise heuristics derive candidates from the
    distribution name (``-``/``.`` → ``_``, lower-case; ``python-``/``py-`` prefix and
    ``-python`` suffix stripped; dotted namespace kept when the name contains a dot).
    """
    key = normalize_package_name(package_name, Ecosystem.PYPI.value)
    mapped = PYTHON_IMPORT_NAMES.get(key)
    if mapped:
        return [mapped]

    cleaned = package_name.strip().lower()
    base = re.sub(r"[-.\s]+", "_", cleaned).strip("_")
    candidates: list[str] = []

    def add(name: str) -> None:
        if name and name not in candidates:
            candidates.append(name)

    add(base)
    stripped = base
    if stripped.startswith("python_"):
        stripped = stripped[len("python_"):]
    elif stripped.startswith("py_"):
        stripped = stripped[len("py_"):]
    if stripped.endswith("_python"):
        stripped = stripped[: -len("_python")]
    add(stripped.strip("_"))
    if "." in cleaned:  # namespace packages: zope.interface -> import zope.interface
        add(re.sub(r"[-\s]+", "_", cleaned).strip("_."))
    return candidates or [base]


def _python_name_variants(package_name: str, candidates: Sequence[str]) -> list[str]:
    """Case variants tried by the matcher (matching itself stays case-sensitive)."""
    variants: list[str] = []

    def add(name: str) -> None:
        if name and name not in variants:
            variants.append(name)

    for candidate in candidates:
        add(candidate)
        add(candidate.lower())
        add(candidate.capitalize())
    original = re.sub(r"[-.\s]+", "_", package_name.strip()).strip("_")
    add(original)
    return variants


def _alternation(names: Sequence[str]) -> str:
    """Regex alternation of escaped names, longest first."""
    return "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))


def map_components(file: str, component_paths: Sequence[object] | None) -> list[str]:
    """Component paths (from ``component_paths``) that contain ``file``.

    A component matches when it is the file's directory or one of its ancestors.
    ``"."`` only ever matches top-level files, and top-level files map to ``"."``
    even when no component list contains it. When no component list is available
    at all, the file's top-level directory is used so evidence is never lost.
    """
    parent = PurePosixPath(file).parent.as_posix()
    if parent in ("", "."):
        return ["."]

    normalised = [_normalise_component(c) for c in (component_paths or [])]
    matches = {
        comp for comp in normalised
        if comp not in ("", ".") and (parent == comp or parent.startswith(comp + "/"))
    }
    if matches:
        return sorted(matches)
    if not any(c not in ("", ".") for c in normalised):
        return [parent.split("/", 1)[0]]
    return []


def _normalise_component(path: object) -> str:
    # Accept plain paths as well as objects carrying a ``.path`` (e.g. Component rows).
    value = str(getattr(path, "path", path)).strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    value = value.strip("/")
    return value or "."


# --------------------------------------------------------------------------- matchers


class _PythonMatcher:
    """Matches Python imports of a package plus requirement/pyproject manifest lines."""

    source_suffixes = PYTHON_SOURCE_SUFFIXES

    def __init__(self, package_name: str):
        self.package_name = package_name.strip()
        self.normalized = normalize_package_name(self.package_name, Ecosystem.PYPI.value)
        self.candidates = python_import_candidates(self.package_name)
        names = _alternation(_python_name_variants(self.package_name, self.candidates))
        # import X | import X.y | import X as z | import os, X
        self._import_re = re.compile(rf"^\s*import\s+(?:[\w.]+(?:\s+as\s+\w+)?\s*,\s*)*(?P<name>{names})\b")
        # from X import ... | from X.y import ...
        self._from_re = re.compile(rf"^\s*from\s+(?P<name>{names})\b[\w.]*\s+import\b")
        # __import__("X") | importlib.import_module("X.y")
        self._dynamic_re = re.compile(rf"""(?:__import__|import_module)\(\s*['"](?P<name>{names})\b""")
        # requirement lines: name, optional extras/specifier/marker
        self._requirement_re = re.compile(r"^\s*(?:-e\s+)?(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
        # The distribution name as it may be spelled in a manifest (PEP 503: -, _ and .
        # are interchangeable, case-insensitive); never a longer name sharing the prefix.
        token = "[-_.]+".join(re.escape(part) for part in self.normalized.split("-"))
        bounded = rf"(?<![A-Za-z0-9._-]){token}(?![A-Za-z0-9._-])"
        # A quoted PEP 508 requirement whose name is the package: "requests",
        # 'requests[security]>=2', "requests ; python_version<'3'", "requests @ https://…".
        self._quoted_requirement_re = re.compile(
            rf"""(?P<q>["'])\s*{bounded}\s*(?:\[[^\]]*\]\s*)?(?:[<>=!~;@(]|(?P=q))""", re.IGNORECASE
        )
        # A `name = spec` entry in a dependency table (Poetry, Pipfile, pixi): requests = "^2"
        self._key_entry_re = re.compile(rf"""^\s*(?P<q>["']?){bounded}(?P=q)\s*=(?!=)""", re.IGNORECASE)

    @staticmethod
    def is_comment(stripped_line: str) -> bool:
        return stripped_line.startswith("#")

    @staticmethod
    def is_manifest(rel_path: PurePosixPath) -> bool:
        name = rel_path.name
        lower = name.lower()
        if lower.endswith(".txt") and (
            lower.startswith("requirements") or lower.startswith("constraints") or rel_path.parent.name == "requirements"
        ):
            return True
        return name in PYTHON_TOKEN_MANIFESTS

    def match_import(self, stripped_line: str) -> str | None:
        """Return the matched top-level import name, or None."""
        for pattern in (self._import_re, self._from_re, self._dynamic_re):
            match = pattern.search(stripped_line)
            if match:
                return match.group("name")
        return None

    def manifest_lines(self, rel_path: PurePosixPath, lines: Sequence[str]) -> set[int]:
        """1-based numbers of the lines in a manifest that *declare* the package.

        Requirement/constraint files are one PEP 508 line each. For pyproject.toml,
        Pipfile, setup.cfg and setup.py only dependency-bearing context counts — a
        quoted requirement or ``name = spec`` entry inside a dependency table or under
        a dependency key (``dependencies``, ``install_requires``, ...). Descriptions,
        keywords, mypy/isort tool settings and the like never match.
        """
        name = rel_path.name
        if name == "setup.cfg":
            return self._ini_manifest_lines(lines)
        if name == "setup.py":
            return self._python_manifest_lines(lines)
        if name in PYTHON_TOKEN_MANIFESTS:  # pyproject.toml, Pipfile
            return self._toml_manifest_lines(lines)
        return {number for number, line in enumerate(lines, start=1) if self._is_requirement(line)}

    def _is_requirement(self, text: str) -> bool:
        match = self._requirement_re.match(text)
        return bool(match) and normalize_package_name(match.group("name"), Ecosystem.PYPI.value) == self.normalized

    def _quoted_in_dependency_context(self, raw: str, carried_key: str | None, in_section: bool) -> bool:
        """Does ``raw`` hold a quoted requirement for the package under a dependency key?

        Every ``key =`` on the line before the string is considered (so the inline
        table ``optional-dependencies = {x = ["pkg"]}`` works); when the line has none,
        the last key seen on a previous line applies (multi-line arrays).
        """
        keys = [(m.start(), m.group("key")) for m in _KEY_ASSIGNMENT_RE.finditer(raw)]
        for match in self._quoted_requirement_re.finditer(raw):
            if in_section:
                return True
            before = [key for position, key in keys if position < match.start()] or ([carried_key] if carried_key else [])
            if any(_DEPENDENCY_KEY_RE.search(key) for key in before):
                return True
        return False

    @staticmethod
    def _last_key(raw: str, carried_key: str | None) -> str | None:
        keys = _KEY_ASSIGNMENT_RE.findall(raw)
        return keys[-1] if keys else carried_key

    def _toml_manifest_lines(self, lines: Sequence[str]) -> set[int]:
        hits: set[int] = set()
        section = ""
        carried: str | None = None
        for number, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            header = _SECTION_HEADER_RE.match(stripped)
            if header:
                section = header.group("name").strip("\"' ")
                carried = None
                continue
            in_section = bool(_DEPENDENCY_SECTION_RE.search(section))
            if (in_section and self._key_entry_re.match(stripped)) or self._quoted_in_dependency_context(
                raw, carried, in_section
            ):
                hits.add(number)
            carried = self._last_key(raw, carried)
        return hits

    def _python_manifest_lines(self, lines: Sequence[str]) -> set[int]:
        hits: set[int] = set()
        carried: str | None = None
        for number, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if self._quoted_in_dependency_context(raw, carried, in_section=False):
                hits.add(number)
            carried = self._last_key(raw, carried)
        return hits

    def _ini_manifest_lines(self, lines: Sequence[str]) -> set[int]:
        hits: set[int] = set()
        section = ""
        key: str | None = None
        for number, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            header = _SECTION_HEADER_RE.match(stripped)
            if header:
                section = header.group("name")
                key = None
                continue
            if raw[0].isspace():  # continuation line of the current key
                value = stripped
            else:
                entry = _INI_KEY_RE.match(stripped)
                key = entry.group("key") if entry else None
                value = entry.group("value") if entry else ""
            if not value or not (_DEPENDENCY_SECTION_RE.search(section) or (key and _DEPENDENCY_KEY_RE.search(key))):
                continue
            if any(self._is_requirement(segment) for segment in value.split(";")):
                hits.add(number)
        return hits


class _JavaScriptMatcher:
    """Matches CommonJS / ESM imports of an npm package plus package.json lines."""

    source_suffixes = JS_SOURCE_SUFFIXES

    def __init__(self, package_name: str):
        self.package_name = package_name.strip()
        self.candidates = [self.package_name]
        pkg = re.escape(self.package_name)
        # require('pkg') | require.resolve('pkg') | import('pkg') | ... from 'pkg' | import 'pkg'
        # The specifier must be exactly the package or a sub-path of it (pkg/x) — never a
        # package that merely shares the prefix (lodash-es, lodash.get).
        self._import_re = re.compile(
            rf"""(?:\brequire(?:\.resolve)?\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|\bimport\s+)"""
            rf"""(?P<q>['"`])(?P<spec>{pkg}(?:/[^'"`\s]*)?)(?P=q)"""
        )
        self._manifest_re = re.compile(rf'^\s*"{pkg}"\s*:')

    @staticmethod
    def is_comment(stripped_line: str) -> bool:
        return stripped_line.startswith(("//", "/*", "*"))

    @staticmethod
    def is_manifest(rel_path: PurePosixPath) -> bool:
        return rel_path.name == "package.json"

    def match_import(self, stripped_line: str) -> str | None:
        match = self._import_re.search(stripped_line)
        return match.group("spec") if match else None

    def manifest_lines(self, rel_path: PurePosixPath, lines: Sequence[str]) -> set[int]:
        """1-based numbers of the ``"pkg": "<spec>"`` lines in package.json."""
        return {number for number, line in enumerate(lines, start=1) if self._manifest_re.match(line.strip())}


# --------------------------------------------------------------------------- analyser


class SourceUsageAnalyzer:
    """Finds where a package is imported / declared inside a repository working copy.

    ``max_files`` caps how many eligible files (source + manifests) are read,
    ``max_references`` caps how many references are returned and
    ``max_reported_files`` caps the ``files`` list (``total_files`` keeps the real
    count); hitting any cap sets ``UsageEvidence.truncated``.

    Only regular files are read: symbolic links (to files or directories), FIFOs,
    devices and sockets are skipped, so the scan never leaves the working copy and
    never blocks — a git checkout can legitimately contain a symlink to ``/dev/urandom``.
    """

    def __init__(self, max_files: int = 5000, max_references: int = 100, max_reported_files: int = 200):
        if max_files < 1 or max_references < 1 or max_reported_files < 1:
            raise ValueError("max_files, max_references and max_reported_files must be positive")
        self.max_files = max_files
        self.max_references = max_references
        self.max_reported_files = max_reported_files

    # -- public API ----------------------------------------------------------------

    def find_usage(
        self,
        repo_path: Path | str,
        package_name: str,
        ecosystem: str | Ecosystem,
        component_paths: Sequence[object] | None = None,
    ) -> UsageEvidence:
        """Scan ``repo_path`` for references to ``package_name``.

        ``component_paths`` are the repository's component paths (strings, or objects
        with a ``.path`` attribute such as Component rows).

        Raises :class:`RepositoryError` when ``repo_path`` is not a readable directory
        and ``ValueError`` for an empty package name (surrounding whitespace is
        stripped). Unsupported ecosystems return empty evidence (logged) instead of
        failing. Sub-directories that cannot be listed are skipped with a warning and
        mark the evidence ``truncated``.
        """
        package_name = str(package_name).strip()
        if not package_name:
            raise ValueError("package_name must not be empty")
        root = Path(repo_path)
        if not root.is_dir():
            raise RepositoryError(
                f"Cannot analyse usage of {package_name}: repository path does not exist or is not a directory: {root}"
            )
        try:
            with os.scandir(root):
                pass
        except OSError as exc:
            raise RepositoryError(
                f"Cannot analyse usage of {package_name}: repository path is not readable: {root} ({exc.strerror or exc})"
            ) from exc
        eco = normalise_ecosystem(ecosystem)
        if eco is None:
            logger.warning("Usage analysis not supported for ecosystem %r (package %s)", str(ecosystem), package_name)
            return UsageEvidence(package_name=package_name, ecosystem=str(ecosystem))

        matcher = _PythonMatcher(package_name) if eco is Ecosystem.PYPI else _JavaScriptMatcher(package_name)
        import_refs: list[UsageReference] = []
        config_refs: list[UsageReference] = []
        observed: set[str] = set()
        scanned = 0
        truncated = False

        def on_walk_error(exc: OSError) -> None:
            nonlocal truncated
            truncated = True
            logger.warning(
                "Cannot list %s while scanning for %s (%s); usage evidence is partial",
                exc.filename or root,
                package_name,
                exc.strerror or exc,
            )

        for abs_path, rel_path in self._iter_files(root, on_walk_error):
            is_source = rel_path.suffix in matcher.source_suffixes
            is_manifest = matcher.is_manifest(rel_path)
            if not (is_source or is_manifest):
                continue
            if scanned >= self.max_files:
                truncated = True
                logger.warning(
                    "File cap reached (%d) while scanning for %s; usage evidence is partial", self.max_files, package_name
                )
                break
            lines = self._read_lines(abs_path)
            if lines is None:
                continue
            scanned += 1
            self._scan_lines(matcher, rel_path.as_posix(), lines, is_source, is_manifest, import_refs, config_refs, observed)

        import_refs.sort(key=lambda r: (r.file, r.line))
        config_refs.sort(key=lambda r: (r.file, r.line))
        references = import_refs + config_refs
        if len(references) > self.max_references:
            references = references[: self.max_references]
            truncated = True

        all_files = sorted({r.file for r in import_refs})
        components: set[str] = set()
        for file in all_files:
            components.update(map_components(file, component_paths))
        files = all_files
        if len(all_files) > self.max_reported_files:
            files = all_files[: self.max_reported_files]
            truncated = True
            logger.warning(
                "%d files import %s; reporting the first %d", len(all_files), package_name, self.max_reported_files
            )

        evidence = UsageEvidence(
            package_name=package_name,
            ecosystem=eco.value,
            import_names=sorted(observed) if observed else list(matcher.candidates),
            references=references,
            files=files,
            components=sorted(components),
            truncated=truncated,
            scanned_files=scanned,
            total_files=len(all_files),
        )
        logger.info(
            "%s (%s): %d import reference(s) in %d file(s), %d config reference(s), components=%s, scanned %d files%s",
            package_name,
            eco.value,
            len(import_refs),
            len(all_files),
            len(config_refs),
            evidence.components or "[]",
            scanned,
            " (truncated)" if truncated else "",
        )
        return evidence

    # -- internals -----------------------------------------------------------------

    @staticmethod
    def _iter_files(
        root: Path, on_error: Callable[[OSError], None] | None = None
    ) -> Iterator[tuple[Path, PurePosixPath]]:
        """Deterministic walk (sorted names) that prunes ignored directories.

        Symlinked directories are never followed; directories that cannot be listed
        are reported to ``on_error`` and skipped.
        """
        for dirpath, dirnames, filenames in os.walk(root, onerror=on_error, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
            for filename in sorted(filenames):
                abs_path = Path(dirpath) / filename
                yield abs_path, PurePosixPath(abs_path.relative_to(root).as_posix())

    @staticmethod
    def _read_lines(path: Path) -> list[str] | None:
        """Lines of a regular text file; None when it is not a regular file, too large or unreadable.

        Symlinks are not followed (a link may point anywhere, including outside the
        working copy or at a device / FIFO whose ``st_size`` is 0) and at most
        ``MAX_FILE_SIZE_BYTES + 1`` bytes are ever read, whatever ``lstat`` reported.
        """
        try:
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                logger.debug("Skipping %s: symbolic link", path)
                return None
            if not stat.S_ISREG(st.st_mode):
                logger.debug("Skipping %s: not a regular file", path)
                return None
            if st.st_size > MAX_FILE_SIZE_BYTES:
                logger.debug("Skipping %s: larger than %d bytes", path, MAX_FILE_SIZE_BYTES)
                return None
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            fd = os.open(path, flags)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):  # replaced between lstat and open
                    logger.debug("Skipping %s: not a regular file", path)
                    return None
                with os.fdopen(fd, "rb") as handle:
                    fd = -1  # owned by the handle now
                    data = handle.read(MAX_FILE_SIZE_BYTES + 1)
            finally:
                if fd >= 0:
                    os.close(fd)
            if len(data) > MAX_FILE_SIZE_BYTES:
                logger.debug("Skipping %s: larger than %d bytes", path, MAX_FILE_SIZE_BYTES)
                return None
            return split_lines(data.decode("utf-8-sig", errors="ignore"))
        except OSError as exc:
            logger.debug("Skipping %s: %s", path, exc)
            return None

    @staticmethod
    def _scan_lines(
        matcher: _PythonMatcher | _JavaScriptMatcher,
        rel_file: str,
        lines: list[str],
        is_source: bool,
        is_manifest: bool,
        import_refs: list[UsageReference],
        config_refs: list[UsageReference],
        observed: set[str],
    ) -> None:
        config_hits = matcher.manifest_lines(PurePosixPath(rel_file), lines) if is_manifest else set()
        for number, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or matcher.is_comment(stripped):
                continue
            snippet = stripped[:SNIPPET_MAX_LENGTH]
            if is_source:
                name = matcher.match_import(stripped)
                if name:
                    import_refs.append(UsageReference(rel_file, number, snippet, REFERENCE_KIND_IMPORT))
                    observed.add(name)
                    continue
            if number in config_hits:
                config_refs.append(UsageReference(rel_file, number, snippet, REFERENCE_KIND_CONFIG))
