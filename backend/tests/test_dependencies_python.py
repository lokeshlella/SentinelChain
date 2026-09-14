"""PythonDependencyExtractor: requirements.txt discovery and PEP 508 parsing edge cases."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from app.models.enums import DependencyScope, Ecosystem
from app.services.dependencies.python_extractor import (
    PythonDependencyExtractor,
    is_dev_requirements_file,
    is_requirements_file,
    logical_lines,
    pinned_version,
)

FIXTURES = Path(__file__).parent / "fixtures" / "dependencies"
PYTHON_PROJECT = FIXTURES / "python_project"


@pytest.fixture
def extractor() -> PythonDependencyExtractor:
    return PythonDependencyExtractor()


@pytest.fixture
def result(extractor):
    return extractor.extract(PYTHON_PROJECT)


def by_name(result, name: str, source_file: str = "requirements.txt"):
    matches = [d for d in result.dependencies if d.package_name == name and d.source_file == source_file]
    assert len(matches) == 1, f"expected exactly one {name!r} in {source_file}, got {matches}"
    return matches[0]


def symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):  # pragma: no cover - Windows without symlink privilege
        pytest.skip("symlinks are not supported on this platform")


# ------------------------------------------------------------------ discovery
def test_detects_requirement_files_up_to_depth_three(extractor):
    relative = sorted(p.relative_to(PYTHON_PROJECT).as_posix() for p in extractor.detect(PYTHON_PROJECT))
    assert relative == [
        "requirements-dev.txt",
        "requirements.txt",
        "requirements/base.txt",
        "requirements/test.txt",
        "services/api/requirements.txt",
    ]
    # constraints.txt is not a requirements file; a/b/c/d/requirements.txt is deeper than 3.
    assert "constraints.txt" not in relative
    assert "a/b/c/d/requirements.txt" not in relative


def test_detect_skips_ignored_directories(extractor, tmp_path):
    shutil.copytree(PYTHON_PROJECT, tmp_path / "repo")
    repo = tmp_path / "repo"
    for ignored in (".venv/lib", "node_modules/pkg", "build", "site-packages/x", ".git"):
        (repo / ignored).mkdir(parents=True)
        (repo / ignored / "requirements.txt").write_text("ignored==1.0\n")
    found = {p.relative_to(repo).as_posix() for p in extractor.detect(repo)}
    assert not any(part in path for path in found for part in (".venv", "node_modules", "build", "site-packages", ".git"))
    assert "requirements.txt" in found


def test_detect_on_missing_directory_returns_nothing(extractor, tmp_path):
    assert extractor.detect(tmp_path / "does-not-exist") == []


def test_symlink_escaping_the_repository_is_never_read(extractor, tmp_path):
    secret = tmp_path / "outside" / "secret.txt"
    secret.parent.mkdir()
    secret.write_text("db_password: hunter2\nroot:*:0:0:System Administrator:/var/root:/bin/sh\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    symlink(secret, repo / "requirements.txt")  # absolute target outside the repository
    symlink(Path("..") / "outside" / "secret.txt", repo / "requirements-dev.txt")  # relative escape
    assert extractor.detect(repo) == []
    result = extractor.extract(repo)
    assert result.files == [] and result.dependencies == [] and result.warnings == []


def test_symlink_inside_the_repository_is_followed(extractor, tmp_path):
    (tmp_path / "reqs").mkdir()
    (tmp_path / "reqs" / "prod.txt").write_text("flask==3.0.3\n")
    symlink(Path("reqs") / "prod.txt", tmp_path / "requirements.txt")
    assert [p.name for p in extractor.detect(tmp_path)] == ["requirements.txt"]
    result = extractor.extract(tmp_path)
    assert [(d.package_name, d.version, d.source_file) for d in result.dependencies] == [("flask", "3.0.3", "requirements.txt")]


def test_broken_symlink_is_skipped(extractor, tmp_path):
    symlink(tmp_path / "missing.txt", tmp_path / "requirements.txt")
    assert extractor.detect(tmp_path) == []


@pytest.mark.parametrize(
    "path, expected",
    [
        ("requirements.txt", True),
        ("Requirements.TXT", True),
        ("requirements-dev.txt", True),
        ("requirements_prod.txt", True),
        ("requirements/base.txt", True),
        ("requirements.in", False),
        ("constraints.txt", False),
        ("dev-requirements.txt", False),
        ("docs/requirements.md", False),
    ],
)
def test_is_requirements_file(path, expected):
    assert is_requirements_file(Path(path)) is expected


@pytest.mark.parametrize(
    "path, expected",
    [
        ("requirements.txt", False),
        ("requirements-dev.txt", True),
        ("requirements_test.txt", True),
        ("requirements/dev.txt", True),
        ("requirements/testing.txt", True),
        ("requirements-development.txt", True),
        ("requirements/devel.txt", True),
        ("requirements-pytest.txt", True),  # contract: the name contains "test"
        ("requirements-unittest.txt", True),
        ("requirements-e2e-tests.txt", True),
        ("requirements.test.txt", True),
        ("requirements-latest.txt", False),  # "latest" contains "test" but is not a test file
        ("requirements-greatest.txt", False),
        ("requirements/prod.txt", False),
        ("requirements-prod-2024.txt", False),
        ("tests/requirements.txt", False),  # only the file name counts
    ],
)
def test_is_dev_requirements_file(path, expected):
    assert is_dev_requirements_file(path) is expected


# -------------------------------------------------------------------- parsing
def test_all_files_are_reported_and_every_dependency_has_unknown_scope(result):
    assert result.files == [
        "requirements-dev.txt",
        "requirements.txt",
        "requirements/base.txt",
        "requirements/test.txt",
        "services/api/requirements.txt",
    ]
    assert {d.ecosystem for d in result.dependencies} == {Ecosystem.PYPI}
    assert {d.scope for d in result.dependencies} == {DependencyScope.UNKNOWN}


def test_exact_pin(result):
    dep = by_name(result, "requests")
    assert (dep.version, dep.version_spec, dep.line_number, dep.dev) == ("2.25.1", "==2.25.1", 8, False)
    assert dep.is_pinned


def test_range_keeps_raw_spec_and_no_version(result):
    dep = by_name(result, "Django")  # name kept exactly as written
    assert dep.version is None
    assert dep.version_spec == ">=3.2,<4"
    assert not dep.is_pinned


def test_extras_and_environment_marker(result):
    dep = by_name(result, "foo")
    assert dep.version == "1.0"
    assert dep.version_spec == '[extra]==1.0 ; python_version<"3.9"'


def test_url_requirement_has_no_version_and_a_warning(result):
    dep = by_name(result, "pkg")
    assert dep.version is None
    assert dep.version_spec == "@ https://example.com/pkg-1.0.tar.gz"
    assert any(w.startswith("requirements.txt:11:") and "'pkg'" in w and "URL" in w for w in result.warnings)


def test_inline_comment_is_stripped(result):
    dep = by_name(result, "pkg2")
    assert (dep.version, dep.version_spec) == ("1.0", "==1.0")


def test_arbitrary_equality_is_treated_as_pinned(result):
    dep = by_name(result, "pkg3")
    assert dep.version == "1.0"
    assert dep.version_spec == "=== 1.0"


def test_line_continuation_and_hash_options(result):
    dep = by_name(result, "multi")
    assert (dep.version, dep.version_spec, dep.line_number) == ("2.0", "==2.0", 14)


def test_unpinned_forms(result):
    assert by_name(result, "loose").version is None
    assert by_name(result, "loose").version_spec is None
    assert by_name(result, "tilde").version is None
    assert by_name(result, "tilde").version_spec == "~= 1.4"
    wildcard = by_name(result, "wildcard")
    assert wildcard.version is None  # ==1.0.* is not a concrete version
    assert wildcard.version_spec == "== 1.0.*"


def test_vcs_url_with_egg_fragment_yields_named_dependency_without_version(result):
    dep = by_name(result, "tool")
    assert dep.version is None
    assert dep.version_spec == "git+https://github.com/example/tool.git#egg=tool"
    assert any("requirements.txt:20:" in w and "'tool'" in w for w in result.warnings)


def test_bare_url_without_name_is_skipped_with_warning(result):
    assert not any(d.package_name.startswith("https://") for d in result.dependencies)
    assert any(w.startswith("requirements.txt:21:") and "no package name" in w for w in result.warnings)


def test_invalid_line_produces_warning_with_file_and_line_and_does_not_raise(result):
    assert any(w.startswith("requirements.txt:22: cannot parse 'this is not a requirement'") for w in result.warnings)


def test_option_lines_are_recorded_as_warnings_not_dependencies(result):
    names = {d.package_name for d in result.dependencies}
    assert not names & {"-r", "-c", "-e", "--index-url", "."}
    assert any(
        w.startswith("requirements.txt:4:") and "-r requirements/base.txt" in w and "parsed separately" in w
        for w in result.warnings
    )
    assert any(w.startswith("requirements.txt:5:") and "-c constraints.txt" in w and "not parsed" in w for w in result.warnings)
    assert any(w.startswith("requirements.txt:6:") and "editable" in w for w in result.warnings)
    # --index-url / --extra-index-url are silently ignored (no warning).
    assert not any("index-url" in w for w in result.warnings)


def test_names_are_kept_as_written_so_the_service_can_normalise(result):
    written = [d.package_name for d in result.dependencies if d.package_name.lower() == "sqlalchemy"]
    assert written == ["SQLAlchemy", "sqlalchemy"]


def test_dev_flag_follows_file_name(result):
    assert by_name(result, "pytest", "requirements-dev.txt").dev is True
    assert by_name(result, "black", "requirements-dev.txt").dev is True
    assert by_name(result, "coverage", "requirements/test.txt").dev is True
    assert by_name(result, "httpx", "requirements/base.txt").dev is False
    assert by_name(result, "flask", "services/api/requirements.txt").dev is False


def test_total_counts(result):
    assert len(result.dependencies) == 18
    assert len(result.relations) == 0  # requirements files carry no relation information
    assert len(result.warnings) == 7


# ------------------------------------------------------------- helper units
def test_logical_lines_join_continuations_and_strip_comments():
    text = "# leading comment\n\na==1 \\\n  --hash=sha256:x  # trailing\nb>=2 # c\n  \nc @ https://h/p#egg=c\nlast \\"
    lines = logical_lines(text)
    assert [(line.number, line.text) for line in lines] == [
        (3, "a==1   --hash=sha256:x"),
        (5, "b>=2"),
        (7, "c @ https://h/p#egg=c"),  # "#egg" is not a comment (no whitespace before "#")
        (8, "last"),
    ]


@pytest.mark.parametrize(
    "requirement, expected",
    [
        ("a==1.0", "1.0"),
        ("a===1.0.post1", "1.0.post1"),
        ("a>=1,==2", "2"),
        ("a==1.0.*", None),
        ("a==1.0,==2.0", None),  # contradictory pins are not a concrete version
        ("a>=1.0", None),
        ("a", None),
    ],
)
def test_pinned_version(requirement, expected):
    assert pinned_version(Requirement(requirement)) == expected


def test_undecodable_bytes_do_not_break_parsing(extractor, tmp_path):
    (tmp_path / "requirements.txt").write_bytes(b"\xef\xbb\xbfrequests==2.31.0\n\xff\xfe garbage line\n")
    result = extractor.extract(tmp_path)
    assert [(d.package_name, d.version) for d in result.dependencies] == [("requests", "2.31.0")]
    assert len(result.warnings) == 1 and result.warnings[0].startswith("requirements.txt:2:")


def test_unparseable_line_is_truncated_in_the_warning(extractor, tmp_path):
    garbage = "x" * 500 + " not a requirement"
    (tmp_path / "requirements.txt").write_text(f"{garbage}\nhttps://example.com/{'y' * 500}\n")
    result = extractor.extract(tmp_path)
    assert result.dependencies == []
    assert len(result.warnings) == 2
    assert all(len(w) < 250 for w in result.warnings)
    assert result.warnings[0].startswith("requirements.txt:1: cannot parse 'xxxx") and "\u2026" in result.warnings[0]
    assert result.warnings[1].startswith("requirements.txt:2: URL/path requirement 'https://example.com/yyy")


def test_empty_requirements_file(extractor, tmp_path):
    (tmp_path / "requirements.txt").write_text("# nothing here\n\n")
    result = extractor.extract(tmp_path)
    assert result.files == ["requirements.txt"]
    assert result.dependencies == [] and result.warnings == []


def test_attached_short_option_arguments_are_recognised(tmp_path):
    """pip accepts -rfile.txt / -e. spellings; they must yield the same include warnings."""
    from app.services.dependencies.python_extractor import PythonDependencyExtractor

    (tmp_path / "requirements.txt").write_text("-rrequirements/extra.txt\n-e.\nrequests==2.25.1\n")
    result = PythonDependencyExtractor().extract(tmp_path)
    assert [d.package_name for d in result.dependencies] == ["requests"]
    assert any("requirements/extra.txt" in w and "not followed" in w for w in result.warnings)
    assert any("editable" in w for w in result.warnings)


def test_utf16_requirements_file_is_parsed_like_pip_does(tmp_path):
    """PowerShell's `pip freeze > requirements.txt` writes UTF-16 LE with a BOM."""
    from app.services.dependencies.python_extractor import PythonDependencyExtractor

    (tmp_path / "requirements.txt").write_bytes("requests==2.25.1\r\nDjango==3.2.0\r\n".encode("utf-16"))
    result = PythonDependencyExtractor().extract(tmp_path)
    assert {(d.package_name, d.version) for d in result.dependencies} == {("requests", "2.25.1"), ("Django", "3.2.0")}
    assert result.warnings == []
