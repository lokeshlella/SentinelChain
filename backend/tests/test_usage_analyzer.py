"""Unit tests for app.services.analysis.usage (synthetic repositories in tmp_path)."""

from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path

import pytest

from app.core.exceptions import RepositoryError
from app.models.enums import Ecosystem
from app.services.agents.schemas import UsageContext
from app.services.analysis import usage as usage_module
from app.services.analysis.usage import (
    MAX_FILE_SIZE_BYTES,
    REFERENCE_KIND_CONFIG,
    REFERENCE_KIND_IMPORT,
    SourceUsageAnalyzer,
    UsageEvidence,
    UsageReference,
    map_components,
    python_import_candidates,
    split_lines,
)

not_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="permission bits are not enforced for root"
)
posix_only = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX special files")


def _refs(evidence: UsageEvidence) -> list[tuple[str, int, str]]:
    return [(r.file, r.line, r.kind) for r in evidence.references]


def _write(root: Path, relative: str, content: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- fixtures


@pytest.fixture
def python_repo(tmp_path: Path) -> Path:
    root = tmp_path / "pyrepo"
    _write(root, "requirements.txt", "requests==2.19.0\npyyaml>=5.1\n# flask==1.0\nrequests-toolbelt==1.0\n")
    _write(root, "requirements-dev.txt", "pytest\nRequests[security]>=2.19  # extras + comment\n")
    _write(
        root,
        "src/app/auth/service.py",
        '"""Auth service."""\n'
        "import os\n"
        "import requests\n"
        "from yaml import safe_load\n"
        "# import requests  <- commented out, must not match\n"
        "\n"
        "def login():\n"
        "    return requests.get('https://example')\n",
    )
    _write(root, "src/app/__init__.py", "")
    _write(
        root,
        "src/app/util.py",
        "import requests_toolbelt\n"
        "from requests.adapters import HTTPAdapter\n"
        "import json, requests as rq\n"
        "from .requests import local_thing\n",
    )
    _write(root, "tests/test_x.py", "import requests\n\n\ndef test_x():\n    assert requests\n")
    _write(root, "manage.py", "import requests\n")
    # Must be ignored: dependency installs and caches.
    _write(root, "node_modules/requests_shim/index.py", "import requests\n")
    _write(root, ".venv/lib/site.py", "import requests\n")
    _write(root, "build/lib/app.py", "import requests\n")
    # Must be skipped: larger than the 1 MB cap.
    _write(root, "src/generated.py", "import requests\n" + ("x = 1\n" * (MAX_FILE_SIZE_BYTES // 6 + 1)))
    assert (root / "src/generated.py").stat().st_size > MAX_FILE_SIZE_BYTES
    # Not a Python file: never scanned.
    _write(root, "README.md", "import requests\n")
    return root


@pytest.fixture
def js_repo(tmp_path: Path) -> Path:
    root = tmp_path / "jsrepo"
    _write(
        root,
        "package.json",
        json.dumps(
            {
                "name": "demo",
                "dependencies": {"lodash": "^4.17.15", "lodash-es": "^4.17.0", "@scope/pkg": "1.0.0"},
                "devDependencies": {"jest": "^29"},
            },
            indent=2,
        )
        + "\n",
    )
    _write(
        root,
        "src/index.js",
        "const _ = require('lodash');\n"
        'const get = require("lodash/get");\n'
        "// const again = require('lodash');\n"
        "import('lodash').then((m) => m);\n",
    )
    _write(
        root,
        "src/other.js",
        "import { map } from 'lodash-es';\n"
        "import get from 'lodash.get';\n"
        "import foo from 'lodashx';\n",
    )
    _write(
        root,
        "src/scoped.ts",
        "import { a } from '@scope/pkg';\n"
        "import b from '@scope/pkg/sub/path';\n"
        "import c from '@scope/pkg-extra';\n"
        'export * from "@scope/pkg";\n'
        "import '@scope/pkg/styles.css';\n",
    )
    _write(root, "components/Widget.vue", "<script>\nimport _ from 'lodash'\nexport default {}\n</script>\n")
    _write(root, "node_modules/lodash/index.js", "module.exports = require('lodash/core');\n")
    _write(root, "dist/bundle.js", "require('lodash');\n")
    return root


# --------------------------------------------------------------------------- Python


def test_python_usage_references_files_and_components(python_repo: Path):
    evidence = SourceUsageAnalyzer().find_usage(python_repo, "requests", "PyPI", ["src", "tests"])

    assert evidence.package_name == "requests"
    assert evidence.ecosystem == "PyPI"
    assert evidence.import_names == ["requests"]
    # src/generated.py is larger than the cap: it may import the package, so the evidence is partial (audit V2-03)
    assert evidence.truncated is True
    assert evidence.skipped_files == ["src/generated.py"] and evidence.skipped_files_total == 1

    imports = [(r.file, r.line, r.snippet) for r in evidence.import_references]
    assert imports == [
        ("manage.py", 1, "import requests"),
        ("src/app/auth/service.py", 3, "import requests"),
        ("src/app/util.py", 2, "from requests.adapters import HTTPAdapter"),
        ("src/app/util.py", 3, "import json, requests as rq"),
        ("tests/test_x.py", 1, "import requests"),
    ]
    configs = [(r.file, r.line, r.snippet) for r in evidence.config_references]
    assert configs == [
        ("requirements-dev.txt", 2, "Requests[security]>=2.19  # extras + comment"),
        ("requirements.txt", 1, "requests==2.19.0"),
    ]
    # import references first, then config references
    assert [r.kind for r in evidence.references] == [REFERENCE_KIND_IMPORT] * 5 + [REFERENCE_KIND_CONFIG] * 2

    assert evidence.files == ["manage.py", "src/app/auth/service.py", "src/app/util.py", "tests/test_x.py"]
    # top-level manage.py maps to "." even though "." was not in the component list
    assert evidence.components == [".", "src", "tests"]
    # 5 python files outside ignored dirs + 2 requirement files; generated.py (>1 MB) is skipped
    assert evidence.scanned_files == 7


def test_python_mapping_resolves_pyyaml_to_yaml(python_repo: Path):
    evidence = SourceUsageAnalyzer().find_usage(python_repo, "PyYAML", Ecosystem.PYPI, ["src", "tests"])

    assert evidence.import_names == ["yaml"]
    assert [(r.file, r.line, r.snippet, r.kind) for r in evidence.references] == [
        ("src/app/auth/service.py", 4, "from yaml import safe_load", REFERENCE_KIND_IMPORT),
        ("requirements.txt", 2, "pyyaml>=5.1", REFERENCE_KIND_CONFIG),
    ]
    assert evidence.files == ["src/app/auth/service.py"]
    assert evidence.components == ["src"]


def test_python_commented_requirement_and_missing_imports_yield_no_references(python_repo: Path):
    evidence = SourceUsageAnalyzer().find_usage(python_repo, "flask", "PyPI", ["src", "tests"])

    assert evidence.references == []
    assert evidence.files == []
    assert evidence.components == []
    assert evidence.import_names == ["flask"]  # what was searched for
    assert evidence.is_used is False
    assert evidence.truncated is True  # src/generated.py was not scanned: "no import" is not a complete answer
    assert evidence.skipped_files == ["src/generated.py"]


def test_python_prefix_sharing_package_does_not_match(python_repo: Path):
    evidence = SourceUsageAnalyzer().find_usage(python_repo, "requests-toolbelt", "PyPI", ["src"])

    assert [(r.file, r.line, r.kind) for r in evidence.references] == [
        ("src/app/util.py", 1, REFERENCE_KIND_IMPORT),
        ("requirements.txt", 4, REFERENCE_KIND_CONFIG),
    ]
    assert evidence.import_names == ["requests_toolbelt"]


def test_truncation_by_max_references_keeps_imports_first(python_repo: Path):
    evidence = SourceUsageAnalyzer(max_references=1).find_usage(python_repo, "requests", "PyPI", ["src", "tests"])

    assert evidence.truncated is True
    assert [(r.file, r.line, r.kind) for r in evidence.references] == [("manage.py", 1, REFERENCE_KIND_IMPORT)]
    # files/components still describe every importing file found during the scan
    assert evidence.files == ["manage.py", "src/app/auth/service.py", "src/app/util.py", "tests/test_x.py"]
    assert evidence.components == [".", "src", "tests"]


def test_truncation_by_max_files(python_repo: Path):
    evidence = SourceUsageAnalyzer(max_files=2).find_usage(python_repo, "requests", "PyPI", ["src", "tests"])

    assert evidence.truncated is True
    assert evidence.scanned_files == 2
    # walk order is sorted: manage.py, requirements-dev.txt come first
    assert [(r.file, r.line, r.kind) for r in evidence.references] == [
        ("manage.py", 1, REFERENCE_KIND_IMPORT),
        ("requirements-dev.txt", 2, REFERENCE_KIND_CONFIG),
    ]


def test_analyzer_rejects_non_positive_caps():
    with pytest.raises(ValueError):
        SourceUsageAnalyzer(max_files=0)
    with pytest.raises(ValueError):
        SourceUsageAnalyzer(max_references=0)
    with pytest.raises(ValueError):
        SourceUsageAnalyzer(max_reported_files=0)


def test_reported_files_are_capped_but_components_and_total_are_not(tmp_path: Path):
    root = tmp_path / "repo"
    for index in range(12):
        _write(root, f"pkg{index % 3}/m{index:02d}.py", "import requests\n")

    evidence = SourceUsageAnalyzer(max_references=100, max_reported_files=5).find_usage(
        root, "requests", "PyPI", ["pkg0", "pkg1", "pkg2"]
    )

    assert evidence.truncated is True
    assert len(evidence.references) == 12  # references have their own cap
    assert evidence.files == ["pkg0/m00.py", "pkg0/m03.py", "pkg0/m06.py", "pkg0/m09.py", "pkg1/m01.py"]
    assert evidence.total_files == 12
    assert evidence.components == ["pkg0", "pkg1", "pkg2"]  # derived from every importing file
    assert evidence.is_used is True
    assert len(evidence.to_context().files) == 5
    assert evidence.to_dict()["total_files"] == 12

    uncapped = SourceUsageAnalyzer().find_usage(root, "requests", "PyPI", ["pkg0", "pkg1", "pkg2"])
    assert uncapped.truncated is False
    assert len(uncapped.files) == uncapped.total_files == 12


def test_python_case_variants_and_dotted_import_names(tmp_path: Path):
    root = tmp_path / "repo"
    _write(root, "a.py", "import Cython\n")
    _write(root, "b.py", "import google.protobuf\nfrom google.protobuf import message\nimport google\n")

    cython = SourceUsageAnalyzer().find_usage(root, "cython", "PyPI", ["."])
    assert [(r.file, r.line) for r in cython.references] == [("a.py", 1)]
    assert cython.import_names == ["Cython"]  # observed spelling wins over the candidate list

    protobuf = SourceUsageAnalyzer().find_usage(root, "protobuf", "PyPI", ["."])
    assert [(r.file, r.line) for r in protobuf.references] == [("b.py", 1), ("b.py", 2)]
    assert protobuf.import_names == ["google.protobuf"]


def test_python_manifests_in_requirements_dir_and_pyproject(tmp_path: Path):
    root = tmp_path / "repo"
    _write(root, "requirements/base.txt", "Django>=4\npython-dateutil==2.8.2\n")
    _write(root, "pyproject.toml", '[project]\ndependencies = ["python_dateutil>=2.8", "requests"]\n')
    _write(root, "setup.py", "from setuptools import setup\nsetup(install_requires=['python.dateutil'])\n")
    _write(root, "src/app.py", "from dateutil import parser\n")

    evidence = SourceUsageAnalyzer().find_usage(root, "python-dateutil", "PyPI", ["src"])

    assert [(r.file, r.line, r.kind) for r in evidence.references] == [
        ("src/app.py", 1, REFERENCE_KIND_IMPORT),
        ("pyproject.toml", 2, REFERENCE_KIND_CONFIG),
        ("requirements/base.txt", 2, REFERENCE_KIND_CONFIG),
        ("setup.py", 2, REFERENCE_KIND_CONFIG),
    ]
    assert evidence.import_names == ["dateutil"]
    assert evidence.files == ["src/app.py"]
    assert evidence.components == ["src"]

    setuptools = SourceUsageAnalyzer().find_usage(root, "setuptools", "PyPI", ["src"])
    # setup.py is scanned as source (import) and as a manifest; the import wins for line 1
    assert [(r.file, r.line, r.kind) for r in setuptools.references] == [("setup.py", 1, REFERENCE_KIND_IMPORT)]


@pytest.mark.parametrize(
    ("package", "expected"),
    [
        ("PyYAML", ["yaml"]),
        ("pillow", ["PIL"]),
        ("beautifulsoup4", ["bs4"]),
        ("scikit-learn", ["sklearn"]),
        ("python-dateutil", ["dateutil"]),
        ("Python-Dotenv", ["dotenv"]),
        ("psycopg2_binary", ["psycopg2"]),
        ("opencv-python", ["cv2"]),
        ("attrs", ["attr"]),
        ("PyJWT", ["jwt"]),
        ("protobuf", ["google.protobuf"]),
        ("GitPython", ["git"]),
        ("mysqlclient", ["MySQLdb"]),
        ("requests", ["requests"]),
        ("Flask-Login", ["flask_login"]),
        ("python-slugify", ["slugify"]),  # curated
        ("python-foobar", ["python_foobar", "foobar"]),  # heuristic: strip python- prefix
        ("py-cpuinfo", ["py_cpuinfo", "cpuinfo"]),  # heuristic: strip py- prefix
        ("foo-python", ["foo_python", "foo"]),  # heuristic: strip -python suffix
        ("zope.interface", ["zope.interface"]),
        ("some.namespace-pkg", ["some_namespace_pkg", "some.namespace_pkg"]),
    ],
)
def test_python_import_candidates(package: str, expected: list[str]):
    assert python_import_candidates(package) == expected


# --------------------------------------------------------------------------- JavaScript


def test_js_usage_matches_require_import_subpaths_but_not_prefix_sharing_packages(js_repo: Path):
    evidence = SourceUsageAnalyzer().find_usage(js_repo, "lodash", "npm", ["src", "components"])

    assert evidence.ecosystem == "npm"
    assert [(r.file, r.line, r.snippet, r.kind) for r in evidence.references] == [
        ("components/Widget.vue", 2, "import _ from 'lodash'", REFERENCE_KIND_IMPORT),
        ("src/index.js", 1, "const _ = require('lodash');", REFERENCE_KIND_IMPORT),
        ("src/index.js", 2, 'const get = require("lodash/get");', REFERENCE_KIND_IMPORT),
        ("src/index.js", 4, "import('lodash').then((m) => m);", REFERENCE_KIND_IMPORT),
        ("package.json", 4, '"lodash": "^4.17.15",', REFERENCE_KIND_CONFIG),
    ]
    assert evidence.files == ["components/Widget.vue", "src/index.js"]
    assert evidence.components == ["components", "src"]
    assert evidence.import_names == ["lodash", "lodash/get"]
    assert evidence.truncated is False
    # index.js, other.js, scoped.ts, Widget.vue, package.json (node_modules/ and dist/ ignored)
    assert evidence.scanned_files == 5


def test_js_lodash_es_is_a_distinct_package(js_repo: Path):
    evidence = SourceUsageAnalyzer().find_usage(js_repo, "lodash-es", "npm", ["src"])

    assert [(r.file, r.line, r.kind) for r in evidence.references] == [
        ("src/other.js", 1, REFERENCE_KIND_IMPORT),
        ("package.json", 5, REFERENCE_KIND_CONFIG),
    ]
    assert evidence.files == ["src/other.js"]


def test_js_scoped_package_and_subpaths(js_repo: Path):
    evidence = SourceUsageAnalyzer().find_usage(js_repo, "@scope/pkg", "npm", ["src"])

    assert [(r.file, r.line, r.kind) for r in evidence.references] == [
        ("src/scoped.ts", 1, REFERENCE_KIND_IMPORT),
        ("src/scoped.ts", 2, REFERENCE_KIND_IMPORT),
        ("src/scoped.ts", 4, REFERENCE_KIND_IMPORT),
        ("src/scoped.ts", 5, REFERENCE_KIND_IMPORT),
        ("package.json", 6, REFERENCE_KIND_CONFIG),
    ]
    assert evidence.import_names == ["@scope/pkg", "@scope/pkg/styles.css", "@scope/pkg/sub/path"]
    assert evidence.components == ["src"]


def test_js_dev_dependency_only_in_manifest(js_repo: Path):
    evidence = SourceUsageAnalyzer().find_usage(js_repo, "jest", "npm", ["src"])

    assert [(r.file, r.line, r.kind) for r in evidence.references] == [("package.json", 9, REFERENCE_KIND_CONFIG)]
    assert evidence.files == []
    assert evidence.components == []
    assert evidence.import_names == ["jest"]


def test_js_comment_lines_are_skipped(tmp_path: Path):
    root = tmp_path / "repo"
    _write(root, "a.js", "/* import x from 'left-pad' */\n * import y from 'left-pad'\n// require('left-pad')\nrequire('left-pad')\n")

    evidence = SourceUsageAnalyzer().find_usage(root, "left-pad", "npm", ["."])
    assert [(r.file, r.line) for r in evidence.references] == [("a.js", 4)]


# --------------------------------------------------------------------------- general


def test_results_are_deterministic(js_repo: Path, python_repo: Path):
    analyzer = SourceUsageAnalyzer()
    assert analyzer.find_usage(js_repo, "lodash", "npm", ["src"]).to_dict() == analyzer.find_usage(
        js_repo, "lodash", "npm", ["src"]
    ).to_dict()
    assert analyzer.find_usage(python_repo, "requests", "PyPI", ["src"]).to_dict() == analyzer.find_usage(
        python_repo, "requests", "PyPI", ["src"]
    ).to_dict()


def test_missing_repository_path_raises_clear_error(tmp_path: Path):
    with pytest.raises(RepositoryError) as excinfo:
        SourceUsageAnalyzer().find_usage(tmp_path / "does-not-exist", "requests", "PyPI", [])
    assert "does not exist" in str(excinfo.value)
    assert "requests" in str(excinfo.value)


def test_empty_package_name_is_rejected(python_repo: Path):
    with pytest.raises(ValueError):
        SourceUsageAnalyzer().find_usage(python_repo, "   ", "PyPI", [])


def test_component_paths_accept_objects_with_path_attribute(python_repo: Path):
    class FakeComponent:
        def __init__(self, path: str):
            self.path = path

    evidence = SourceUsageAnalyzer().find_usage(
        python_repo, "requests", "PyPI", [FakeComponent("src"), FakeComponent("tests"), FakeComponent(".")]
    )
    assert evidence.components == [".", "src", "tests"]


def test_unsupported_ecosystem_returns_empty_evidence(python_repo: Path):
    evidence = SourceUsageAnalyzer().find_usage(python_repo, "serde", "crates.io", ["src"])

    assert evidence == UsageEvidence(package_name="serde", ecosystem="crates.io")
    assert evidence.references == [] and evidence.import_names == []


def test_undecodable_and_unreadable_files(tmp_path: Path):
    root = tmp_path / "repo"
    _write(root, "ok.py", "import requests\n")
    (root / "binary.py").write_bytes(b"\xff\xfe\x00garbage\nimport requests\n")
    (root / "broken.py").symlink_to(root / "missing-target.py")  # symlink (dangling) -> skipped, never raises

    evidence = SourceUsageAnalyzer().find_usage(root, "requests", "PyPI", ["."])

    # undecodable bytes are dropped (errors="ignore") and the remaining lines are still matched
    assert [(r.file, r.line) for r in evidence.references] == [("binary.py", 2), ("ok.py", 1)]
    assert evidence.scanned_files == 2


# --------------------------------------------------------------------------- file safety


def test_symlinked_files_are_never_followed(tmp_path: Path):
    """Symlinks can point anywhere (git stores their targets verbatim): never read them."""
    root = tmp_path / "repo"
    outside = tmp_path / "secret.py"
    outside.write_text("import requests  # SECRET TOKEN=abc123\n", encoding="utf-8")
    _write(root, "ok.py", "import requests\n")
    (root / "link.py").symlink_to(outside)
    (root / "requirements.txt").symlink_to(tmp_path / "outside-requirements.txt")
    (tmp_path / "outside-requirements.txt").write_text("requests==2.0\n", encoding="utf-8")
    _write(tmp_path / "elsewhere", "vendored.py", "import requests\n")
    (root / "linked-dir").symlink_to(tmp_path / "elsewhere", target_is_directory=True)

    evidence = SourceUsageAnalyzer().find_usage(root, "requests", "PyPI", ["."])

    assert _refs(evidence) == [("ok.py", 1, REFERENCE_KIND_IMPORT)]
    assert evidence.scanned_files == 1
    assert not any("SECRET" in r.snippet for r in evidence.references)


@posix_only
def test_special_files_are_skipped_without_blocking(tmp_path: Path):
    """A FIFO (or a symlink to a device / FIFO) has st_size 0, so the size cap alone
    would not save us: opening it for reading blocks forever. The scan must return."""
    root = tmp_path / "repo"
    _write(root, "ok.py", "import requests\n")
    os.mkfifo(root / "pipe.py")  # a FIFO named like a source file
    (root / "linked-pipe.py").symlink_to(root / "pipe.py")
    for device in ("/dev/urandom", "/dev/zero", "/dev/null"):
        if Path(device).exists():
            (root / f"dev-{Path(device).name}.py").symlink_to(device)
    assert not stat.S_ISREG(os.lstat(root / "pipe.py").st_mode)

    result: dict[str, UsageEvidence] = {}
    worker = threading.Thread(
        target=lambda: result.update(evidence=SourceUsageAnalyzer().find_usage(root, "requests", "PyPI", ["."])),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=15)

    assert not worker.is_alive(), "find_usage blocked on a special file"
    assert _refs(result["evidence"]) == [("ok.py", 1, REFERENCE_KIND_IMPORT)]
    assert result["evidence"].scanned_files == 1


def test_read_is_bounded_even_when_stat_size_is_wrong(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The reader never consumes more than MAX_FILE_SIZE_BYTES + 1 bytes, whatever lstat says."""
    root = tmp_path / "repo"
    _write(root, "ok.py", "import requests\n")
    big = _write(root, "big.py", "import requests\n" + ("x = 1\n" * (MAX_FILE_SIZE_BYTES // 6 + 1)))
    assert big.stat().st_size > MAX_FILE_SIZE_BYTES
    real_lstat = os.lstat
    seen: list[int] = []

    def lying_lstat(path, *args, **kwargs):
        st = real_lstat(path, *args, **kwargs)
        if Path(path).name != "big.py":
            return st
        seen.append(st.st_size)
        # same mode/inode/... but st_size = 0, like a device node or a file still being written
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, st.st_gid, 0, st.st_atime, st.st_mtime, st.st_ctime))

    real_fdopen = os.fdopen
    reads: list[int] = []

    class CountingHandle:
        def __init__(self, handle):
            self._handle = handle

        def read(self, size=-1):
            reads.append(size)
            return self._handle.read(size)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return self._handle.__exit__(*exc)

    monkeypatch.setattr(usage_module.os, "lstat", lying_lstat)
    monkeypatch.setattr(usage_module.os, "fdopen", lambda fd, *a, **kw: CountingHandle(real_fdopen(fd, *a, **kw)))

    evidence = SourceUsageAnalyzer().find_usage(root, "requests", "PyPI", ["."])

    assert seen and seen[0] > MAX_FILE_SIZE_BYTES  # the size really was lied about
    assert all(size == MAX_FILE_SIZE_BYTES + 1 for size in reads)  # every read was bounded
    assert _refs(evidence) == [("ok.py", 1, REFERENCE_KIND_IMPORT)]  # oversized content was discarded
    assert evidence.scanned_files == 1


@not_root
def test_unreadable_repository_root_raises(tmp_path: Path):
    root = tmp_path / "repo"
    _write(root, "a.py", "import requests\n")
    os.chmod(root, 0)
    try:
        with pytest.raises(RepositoryError) as excinfo:
            SourceUsageAnalyzer().find_usage(root, "requests", "PyPI", ["."])
    finally:
        os.chmod(root, 0o755)
    assert "not readable" in str(excinfo.value)
    assert "requests" in str(excinfo.value)


@not_root
def test_unreadable_subdirectory_marks_evidence_truncated(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    root = tmp_path / "repo"
    _write(root, "a.py", "import requests\n")
    _write(root, "locked/b.py", "import requests\n")
    os.chmod(root / "locked", 0)
    try:
        with caplog.at_level("WARNING", logger="sentinel.usage"):
            evidence = SourceUsageAnalyzer().find_usage(root, "requests", "PyPI", ["."])
    finally:
        os.chmod(root / "locked", 0o755)

    assert _refs(evidence) == [("a.py", 1, REFERENCE_KIND_IMPORT)]
    assert evidence.truncated is True  # the reader knows the evidence is partial
    assert any("locked" in record.getMessage() and "partial" in record.getMessage() for record in caplog.records)


# --------------------------------------------------------------------------- line numbers


def test_line_numbers_count_newlines_only(tmp_path: Path):
    """Form feeds, U+2028/U+2029, NEL and friends are not line breaks for editors or git blame."""
    root = tmp_path / "repo"
    _write(root, "a.py", "x = 1\n\x0c\nimport requests\n")
    _write(root, "b.py", 'x = "a\u2028b"\ny = "c\x85d\x1ce"\nimport requests\n')
    _write(root, "crlf.py", "x = 1\r\nimport requests\r\n")
    _write(root, "cr.py", "x = 1\rimport requests\r")
    _write(root, "c.js", 'const s = "a\u2028b";\nconst _ = require("lodash");\n')

    py = SourceUsageAnalyzer().find_usage(root, "requests", "PyPI", ["."])
    assert [(r.file, r.line) for r in py.references] == [("a.py", 3), ("b.py", 3), ("cr.py", 2), ("crlf.py", 2)]
    js = SourceUsageAnalyzer().find_usage(root, "lodash", "npm", ["."])
    assert [(r.file, r.line) for r in js.references] == [("c.js", 2)]

    text = (root / "b.py").read_text(encoding="utf-8")
    assert len(split_lines(text)) == 4  # 3 lines + the empty tail after the final newline
    assert len(text.splitlines()) == 6  # what str.splitlines (the old implementation) counted


def test_utf8_bom_does_not_hide_the_first_line(tmp_path: Path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src/a.py").write_bytes(b"\xef\xbb\xbfimport requests\n")

    evidence = SourceUsageAnalyzer().find_usage(root, "requests", "PyPI", ["src"])
    assert _refs(evidence) == [("src/a.py", 1, REFERENCE_KIND_IMPORT)]


# --------------------------------------------------------------------------- package name


def test_package_name_whitespace_is_stripped(tmp_path: Path):
    root = tmp_path / "repo"
    _write(root, "requirements.txt", "requests==2.19.0\npyyaml==5.1\n")
    _write(root, "src/a.py", "import requests\nimport yaml\n")
    analyzer = SourceUsageAnalyzer()

    clean = analyzer.find_usage(root, "requests", "PyPI", ["src"])
    padded = analyzer.find_usage(root, " requests\t", "PyPI", ["src"])
    assert padded.to_dict() == clean.to_dict()
    assert padded.package_name == "requests"
    assert _refs(padded) == [("src/a.py", 1, REFERENCE_KIND_IMPORT), ("requirements.txt", 1, REFERENCE_KIND_CONFIG)]

    mapped = analyzer.find_usage(root, " pyyaml ", "PyPI", ["src"])
    assert mapped.import_names == ["yaml"]  # the curated mapping still applies
    assert _refs(mapped) == [("src/a.py", 2, REFERENCE_KIND_IMPORT), ("requirements.txt", 2, REFERENCE_KIND_CONFIG)]

    with pytest.raises(ValueError):
        analyzer.find_usage(root, " \t\n", "PyPI", ["src"])


# --------------------------------------------------------------------------- manifest precision


PYPROJECT = """[build-system]
requires = ["setuptools>=61", "wheel"]

[project]
name = "myapp"
description = "A thin requests wrapper"
keywords = ["requests", "http"]
dependencies = [
    "httpx",
    "Requests[security] >= 2.19 ; python_version < '3.12'",
]
requires-python = ">=3.9"

[project.optional-dependencies]
dev = ["pytest", "requests-mock"]
security = ["requests[security]"]

[dependency-groups]
lint = ["ruff", "requests"]

[tool.poetry.dependencies]
python = "^3.9"
requests = {version = "^2.19", extras = ["security"]}
"pyyaml" = "*"

[tool.poetry.group.dev.dependencies]
requests-mock = "^1.0"

[tool.mypy]
module = "requests.*"

[[tool.mypy.overrides]]
module = ["requests", "yaml"]
ignore_missing_imports = true

[tool.isort]
known_third_party = ["requests"]

[tool.uv]
dev-dependencies = ["requests>=2"]

[tool.hatch.envs.default]
dependencies = [
  "requests",
]

[tool.setuptools.packages.find]
include = ["requests*"]
"""


def test_pyproject_only_dependency_declarations_count(tmp_path: Path):
    root = tmp_path / "repo"
    _write(root, "pyproject.toml", PYPROJECT)
    analyzer = SourceUsageAnalyzer()

    requests = analyzer.find_usage(root, "requests", "PyPI", ["."])
    assert [r.line for r in requests.references] == [10, 16, 19, 23, 40, 44]
    assert all(r.kind == REFERENCE_KIND_CONFIG for r in requests.references)
    assert requests.files == [] and requests.components == []  # manifests never make a component a user

    assert [r.line for r in analyzer.find_usage(root, "PyYAML", "PyPI", ["."]).references] == [24]
    assert [r.line for r in analyzer.find_usage(root, "setuptools", "PyPI", ["."]).references] == [2]
    assert [r.line for r in analyzer.find_usage(root, "requests_mock", "PyPI", ["."]).references] == [15, 27]
    assert analyzer.find_usage(root, "yaml", "PyPI", ["."]).references == []  # only in a mypy override
    assert analyzer.find_usage(root, "httpx", "PyPI", ["."]).references[0].line == 9


def test_pyproject_description_only_mention_is_not_a_declaration(tmp_path: Path):
    root = tmp_path / "repo"
    _write(root, "pyproject.toml", '[project]\nname = "myapp"\ndescription = "A thin requests wrapper"\ndependencies = ["httpx"]\n')

    evidence = SourceUsageAnalyzer().find_usage(root, "requests", "PyPI", ["."])
    assert evidence.references == []
    assert evidence.is_used is False


def test_pipfile_declarations(tmp_path: Path):
    root = tmp_path / "repo"
    _write(
        root,
        "Pipfile",
        '[[source]]\nurl = "https://pypi.org/simple"\nname = "pypi"\n\n'
        '[packages]\nrequests = "*"\n"Flask-Login" = {version = ">=0.6"}\n\n'
        '[dev-packages]\npytest = "*"\n',
    )
    analyzer = SourceUsageAnalyzer()
    assert [r.line for r in analyzer.find_usage(root, "requests", "PyPI", ["."]).references] == [6]
    assert [r.line for r in analyzer.find_usage(root, "flask_login", "PyPI", ["."]).references] == [7]
    assert [r.line for r in analyzer.find_usage(root, "pytest", "PyPI", ["."]).references] == [10]
    assert analyzer.find_usage(root, "pypi", "PyPI", ["."]).references == []  # the [[source]] name


def test_setup_cfg_declarations(tmp_path: Path):
    root = tmp_path / "repo"
    _write(
        root,
        "setup.cfg",
        "[metadata]\n"
        "name = myapp\n"
        "description = A thin requests wrapper\n"
        "keywords = requests, http\n"
        "    requests is great\n"
        "\n"
        "[options]\n"
        "packages = find:\n"
        "install_requires =\n"
        '    requests>=2.19  ; python_version<"3.12"\n'
        "    pyyaml\n"
        "python_requires = >=3.9\n"
        "setup_requires = setuptools_scm; requests\n"
        "\n"
        "[options.extras_require]\n"
        "dev =\n"
        "    pytest\n"
        "    requests-mock\n"
        "security = requests[security]\n"
        "\n"
        "[mypy-requests.*]\n"
        "ignore_missing_imports = True\n",
    )
    analyzer = SourceUsageAnalyzer()
    assert [r.line for r in analyzer.find_usage(root, "requests", "PyPI", ["."]).references] == [10, 13, 19]
    assert [r.line for r in analyzer.find_usage(root, "pyyaml", "PyPI", ["."]).references] == [11]
    assert [r.line for r in analyzer.find_usage(root, "setuptools-scm", "PyPI", ["."]).references] == [13]
    assert [r.line for r in analyzer.find_usage(root, "requests-mock", "PyPI", ["."]).references] == [18]
    assert analyzer.find_usage(root, "myapp", "PyPI", ["."]).references == []


def test_setup_py_declarations(tmp_path: Path):
    root = tmp_path / "repo"
    _write(
        root,
        "setup.py",
        "from setuptools import setup\n"
        "\n"
        "REQUIREMENTS = [\n"
        '    "requests>=2.19",\n'
        "]\n"
        'x = "requests"\n'
        "setup(\n"
        '    name="myapp",\n'
        '    description="requests wrapper",\n'
        '    long_description="requests is a library",\n'
        '    keywords=["requests", "http"],\n'
        "    install_requires=REQUIREMENTS,\n"
        "    extras_require={\n"
        '        "security": ["requests[security]"],\n'
        '        "dev": ["pytest"],\n'
        "    },\n"
        "    setup_requires=['pyyaml'],\n"
        '    python_requires=">=3.9",\n'
        '    packages=["requests_shim"],\n'
        ")\n",
    )
    analyzer = SourceUsageAnalyzer()
    requests = analyzer.find_usage(root, "requests", "PyPI", ["."])
    assert [(r.line, r.kind) for r in requests.references] == [(4, REFERENCE_KIND_CONFIG), (14, REFERENCE_KIND_CONFIG)]
    assert [r.line for r in analyzer.find_usage(root, "pyyaml", "PyPI", ["."]).references] == [17]
    assert [r.line for r in analyzer.find_usage(root, "pytest", "PyPI", ["."]).references] == [15]
    # setup.py is also source: the import of setuptools is reported as an import, not config
    assert [(r.line, r.kind) for r in analyzer.find_usage(root, "setuptools", "PyPI", ["."]).references] == [
        (1, REFERENCE_KIND_IMPORT)
    ]


def test_component_mapping_rules():
    assert map_components("src/app/auth/service.py", ["src", "tests", "."]) == ["src"]
    assert map_components("src/app/auth/service.py", ["src", "src/app", "src/app/auth", "src/apple"]) == [
        "src", "src/app", "src/app/auth"
    ]
    assert map_components("manage.py", ["src"]) == ["."]  # top-level files always map to "."
    assert map_components("manage.py", ["src", "."]) == ["."]
    assert map_components("lib/x.py", ["src", "."]) == []  # "." never matches nested files
    assert map_components("lib/x.py", []) == ["lib"]  # no component list -> top-level dir
    assert map_components("lib/x.py", None) == ["lib"]
    assert map_components("src/x.py", ["./src/", "src/app"]) == ["src"]


def test_evidence_serialisation_and_context():
    evidence = UsageEvidence(
        package_name="lodash",
        ecosystem="npm",
        import_names=["lodash"],
        references=[
            UsageReference("src/index.js", 1, "require('lodash')", REFERENCE_KIND_IMPORT),
            UsageReference("package.json", 4, '"lodash": "^4"', REFERENCE_KIND_CONFIG),
        ],
        files=["src/index.js"],
        components=["src"],
        truncated=True,
        scanned_files=2,
    )

    data = evidence.to_dict()
    assert data == {
        "package_name": "lodash",
        "ecosystem": "npm",
        "import_names": ["lodash"],
        "references": [
            {"file": "src/index.js", "line": 1, "snippet": "require('lodash')", "kind": "import"},
            {"file": "package.json", "line": 4, "snippet": '"lodash": "^4"', "kind": "config"},
        ],
        "files": ["src/index.js"],
        "components": ["src"],
        "truncated": True,
        "scanned_files": 2,
        "total_files": 1,
        "skipped_files": [],
        "skipped_files_total": 0,
        "analysis_depth": "direct-import-scan",
    }
    assert json.loads(json.dumps(data)) == data  # JSON-serialisable for the findings table
    assert UsageEvidence.from_dict(data) == evidence
    assert UsageEvidence.from_dict({"package_name": "x", "references": [{"file": "a.py", "line": 3, "snippet": "s"}]}).references == [
        UsageReference("a.py", 3, "s", REFERENCE_KIND_IMPORT)
    ]
    # evidence stored before total_files existed: the count falls back to the file list
    legacy = UsageEvidence.from_dict({"package_name": "x", "files": ["a.py", "b.py"]})
    assert legacy.total_files == 2
    assert UsageEvidence(package_name="x", ecosystem="PyPI", files=["a.py"], total_files=7).total_files == 7

    context = evidence.to_context()
    assert isinstance(context, UsageContext)
    assert context.import_names == ["lodash"]
    assert [(r.file, r.line, r.snippet) for r in context.references] == [
        ("src/index.js", 1, "require('lodash')"),
        ("package.json", 4, '"lodash": "^4"'),
    ]
    assert context.files == ["src/index.js"]
    assert context.components == ["src"]
    assert context.truncated is True
