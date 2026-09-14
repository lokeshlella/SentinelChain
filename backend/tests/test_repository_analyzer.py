"""RepositoryAnalyzer on synthetic trees: languages, dependency files, components, hints."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from app.models.enums import ComponentType
from app.services.repository.analyzer import ComponentInfo, RepositoryAnalyzer, RepositoryProfile


def write(path: Path, content: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


@pytest.fixture
def python_project(tmp_path: Path) -> Path:
    root = tmp_path / "demo-service"
    write(root / "README.md", "# demo\n")
    write(root / "Dockerfile", "FROM python:3.12-slim\n")
    write(root / "manage.py", "import django\n")
    write(root / "requirements.txt", "flask==2.0.0\npytest\n")
    write(root / "requirements-dev.txt", "black\n")
    write(root / "requirements" / "prod.txt", "gunicorn\n")
    write(root / "pyproject.toml", '[project]\nname = "demo-service"\n\n[tool.pytest.ini_options]\ntestpaths = ["tests"]\n')
    write(root / "package.json", json.dumps({"name": "demo-frontend", "scripts": {"test": "jest --ci"}}))
    write(root / "app" / "__init__.py")
    write(root / "app" / "main.py", "from flask import Flask\n")
    write(root / "app" / "auth" / "service.py", "import jwt\n")
    write(root / "app" / "templates" / "index.html", "<html></html>")
    write(root / "app" / "static" / "style.css", "body {}")
    write(root / "tests" / "conftest.py")
    write(root / "tests" / "test_main.py", "def test_x(): pass\n")
    write(root / "tests" / "fixtures" / "data.json", "{}")
    write(root / "docs" / "index.md", "# docs\n")
    write(root / "scripts" / "deploy.sh", "#!/bin/sh\n")
    write(root / "scripts" / "migrate.py", "print('migrate')\n")
    write(root / ".github" / "workflows" / "ci.yml", "on: push\n")
    write(root / "data" / "seed.csv", "a,b\n")
    # noise that must be ignored
    write(root / ".venv" / "lib" / "site.py", "# venv\n")
    write(root / "node_modules" / "left-pad" / "index.js", "// dep\n")
    write(root / "node_modules" / "left-pad" / "package.json", "{}")
    write(root / ".idea" / "workspace.xml", "<xml/>")
    write(root / "__pycache__" / "x.cpython-312.pyc", "")
    write(root / "build" / "lib" / "app.py", "# built\n")
    write(root / "a" / "b" / "c" / "requirements.txt", "depth-3 ok\n")
    write(root / "a" / "b" / "c" / "d" / "requirements.txt", "depth-4 too deep\n")
    return root


def test_python_project_profile(python_project: Path):
    profile = RepositoryAnalyzer().analyze(python_project)

    assert profile.name == "demo-service", "pyproject name wins for a Python project"
    assert profile.language == "Python"
    assert profile.languages["Python"] == 7
    assert profile.languages["HTML"] == 1 and profile.languages["CSS"] == 1 and profile.languages["Shell"] == 1
    assert profile.total_files == 23  # everything except .venv, node_modules, .idea, __pycache__, build

    assert profile.dependency_files == [
        "a/b/c/requirements.txt",
        "package.json",
        "pyproject.toml",
        "requirements-dev.txt",
        "requirements.txt",
        "requirements/prod.txt",
    ]
    assert profile.source_dirs == ["app", "app/auth"]
    assert profile.test_dirs == ["tests"]

    by_path = {component.path: component for component in profile.components}
    assert set(by_path) == {".", ".github", "a", "app", "data", "docs", "requirements", "scripts", "tests"}
    assert by_path["."].component_type == ComponentType.SOURCE and by_path["."].name == "."
    assert by_path["."].file_count == 7  # README, Dockerfile, manage.py, 2 requirements, pyproject, package.json
    assert by_path["."].description == "Python source files in the repository root (7 files)"
    assert by_path["app"].component_type == ComponentType.SOURCE
    assert by_path["app"].description == "Python source directory (5 files)"
    assert by_path["app"].file_count == 5
    assert by_path["tests"].component_type == ComponentType.TESTS
    assert by_path["tests"].description == "Python test directory (3 files)"
    assert by_path["docs"].component_type == ComponentType.DOCS
    assert by_path["docs"].description == "Documentation directory (1 file)"
    assert by_path["scripts"].component_type == ComponentType.SCRIPTS
    assert by_path[".github"].component_type == ComponentType.CONFIG
    assert by_path["requirements"].component_type == ComponentType.CONFIG
    assert by_path["data"].component_type == ComponentType.OTHER
    assert by_path["a"].component_type == ComponentType.OTHER, "only manifests, no source files"

    assert profile.hints == {
        "has_pytest": True,
        "has_tests_dir": True,
        "npm_test_script": "jest --ci",
        "has_dockerfile": True,
        "readme_present": True,
    }


def test_profile_roundtrip_and_component_paths(python_project: Path):
    profile = RepositoryAnalyzer().analyze(python_project)
    data = profile.to_dict()
    assert isinstance(data["components"][0], dict)
    json.dumps(data)  # must be JSON serialisable for the Repository.profile column
    restored = RepositoryProfile.from_dict(data)
    assert restored == profile
    assert restored.component_paths == [component.path for component in profile.components]
    assert RepositoryProfile.from_dict({"name": "x", "unknown_key": 1}).name == "x"
    assert RepositoryProfile.from_dict(None).name == ""  # tolerant: never raises


def test_npm_placeholder_test_script_is_ignored(tmp_path: Path):
    root = tmp_path / "web"
    write(root / "package.json", json.dumps({"name": "web", "scripts": {"test": 'echo "Error: no test specified" && exit 1'}}))
    write(root / "src" / "index.js", "const x = require('lodash');\n")
    write(root / "src" / "index.test.js", "test('x', () => {});\n")
    profile = RepositoryAnalyzer().analyze(root)
    assert profile.hints["npm_test_script"] is None
    assert profile.hints["has_pytest"] is False
    assert profile.language == "JavaScript"
    assert profile.name == "web"


def test_javascript_project_with_nested_tests_and_src_layout(tmp_path: Path):
    root = tmp_path / "ts-app"
    write(root / "package.json", json.dumps({"name": "@acme/ts-app", "scripts": {"test": "vitest run"}}))
    write(root / "package-lock.json", "{}")
    write(root / "src" / "core" / "index.ts", "export {};\n")
    write(root / "src" / "core" / "util.ts", "export {};\n")
    write(root / "src" / "ui" / "App.tsx", "export {};\n")
    write(root / "src" / "__tests__" / "app.test.ts", "test('a', () => {});\n")
    write(root / "checks" / "one.spec.ts", "")
    write(root / "checks" / "two.spec.ts", "")
    write(root / "checks" / "helper.ts", "")
    write(root / "e2e" / "helper.ts", "")
    write(root / "e2e" / "login.spec.ts", "")
    write(root / "e2e" / "logout.spec.ts", "")
    write(root / "e2e" / "util.ts", "")
    write(root / "flows" / "a.spec.ts", "")
    write(root / "flows" / "b.spec.ts", "")
    write(root / "flows" / "c.spec.ts", "")
    write(root / "flows" / "helper.ts", "")
    write(root / "flows" / "util.ts", "")
    profile = RepositoryAnalyzer().analyze(root)

    assert profile.language == "TypeScript"
    assert profile.name == "@acme/ts-app"
    assert profile.dependency_files == ["package-lock.json", "package.json"]
    assert profile.test_dirs == ["checks", "flows", "src/__tests__"]
    assert profile.source_dirs == ["e2e", "src", "src/core", "src/ui"]
    by_path = {component.path: component for component in profile.components}
    assert by_path["checks"].component_type == ComponentType.TESTS, "2 of 3 files are tests -> tests"
    assert by_path["flows"].component_type == ComponentType.TESTS, "3 of 5 files are tests -> tests"
    assert by_path["e2e"].component_type == ComponentType.SOURCE, "2 of 4 is not a majority -> source"
    assert by_path["src"].component_type == ComponentType.SOURCE
    assert "." not in by_path, "root has no source files, only manifests"
    assert profile.hints["npm_test_script"] == "vitest run"
    assert profile.hints["has_tests_dir"] is True


def test_dominant_language_prefers_programming_languages(tmp_path: Path):
    root = tmp_path / "site"
    for i in range(5):
        write(root / "pages" / f"page{i}.html", "<p/>")
    write(root / "static" / "a.css", "")
    write(root / "static" / "b.css", "")
    write(root / "server.py", "print()")
    profile = RepositoryAnalyzer().analyze(root)
    assert profile.language == "Python", "one Python file outranks five HTML files"
    assert profile.languages == {"HTML": 5, "CSS": 2, "Python": 1}


def test_language_falls_back_to_dependency_files(tmp_path: Path):
    root = tmp_path / "manifest-only"
    write(root / "requirements.txt", "requests==2.25.1\n")
    profile = RepositoryAnalyzer().analyze(root)
    assert profile.language == "Python"
    assert profile.components == []
    assert profile.hints["has_pytest"] is False

    root2 = tmp_path / "npm-only"
    write(root2 / "package.json", "{}")
    assert RepositoryAnalyzer().analyze(root2).language == "JavaScript"


def test_pytest_detection_variants(tmp_path: Path):
    analyzer = RepositoryAnalyzer()

    ini = tmp_path / "ini"
    write(ini / "pytest.ini", "[pytest]\n")
    assert analyzer.analyze(ini).hints["has_pytest"] is True

    cfg = tmp_path / "cfg"
    write(cfg / "setup.cfg", "[tool:pytest]\naddopts = -q\n")
    assert analyzer.analyze(cfg).hints["has_pytest"] is True

    tox = tmp_path / "tox"
    write(tox / "tox.ini", "[tox]\nenvlist = py\n\n[pytest]\naddopts = -q\n")
    assert analyzer.analyze(tox).hints["has_pytest"] is True

    tests_only = tmp_path / "tests-only"
    write(tests_only / "tests" / "test_a.py", "")
    assert analyzer.analyze(tests_only).hints["has_pytest"] is True

    req = tmp_path / "req"
    write(req / "requirements-dev.txt", "# dev deps\nPytest>=7\n")
    assert analyzer.analyze(req).hints["has_pytest"] is True

    none = tmp_path / "none"
    write(none / "src" / "main.py", "")
    write(none / "tests" / "readme.txt", "no python tests here")
    profile = analyzer.analyze(none)
    assert profile.hints["has_pytest"] is False
    assert profile.hints["has_tests_dir"] is True


def test_root_with_mostly_test_files_is_a_test_component(tmp_path: Path):
    root = tmp_path / "flat-tests"
    write(root / "test_one.py", "")
    write(root / "test_two.py", "")
    write(root / "helper.py", "")
    profile = RepositoryAnalyzer().analyze(root)
    assert profile.components == [
        ComponentInfo(".", ".", ComponentType.TESTS.value, "Python test files in the repository root (3 files)", 3)
    ]
    assert profile.test_dirs == []
    assert profile.hints["has_pytest"] is False, "root is not a test dir; nothing tells us pytest is used"


def test_unreadable_and_malformed_manifests_never_raise(tmp_path: Path):
    root = tmp_path / "broken"
    write(root / "package.json", "{not json")
    write(root / "pyproject.toml", "= this is not toml [")
    write(root / "app.py", "")
    profile = RepositoryAnalyzer().analyze(root)
    assert profile.name == "broken"
    assert profile.hints["npm_test_script"] is None

    if os.geteuid() != 0:
        locked = tmp_path / "locked"
        write(locked / "package.json", json.dumps({"name": "hidden", "scripts": {"test": "jest"}}))
        write(locked / "index.js", "")
        (locked / "package.json").chmod(0)
        try:
            profile = RepositoryAnalyzer().analyze(locked)
        finally:
            (locked / "package.json").chmod(0o644)
        assert profile.name == "locked"
        assert profile.hints["npm_test_script"] is None
        assert "package.json" in profile.dependency_files


def test_unreadable_directory_is_skipped(tmp_path: Path):
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    root = tmp_path / "proj"
    write(root / "src" / "main.py", "")
    write(root / "private" / "x.py", "")
    (root / "private").chmod(0)
    try:
        profile = RepositoryAnalyzer().analyze(root)
    finally:
        (root / "private").chmod(0o755)
    assert "src" in profile.source_dirs
    assert profile.total_files == 1


def test_empty_and_missing_paths(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    profile = RepositoryAnalyzer().analyze(empty)
    assert profile == RepositoryProfile(
        name="empty",
        language=None,
        languages={},
        dependency_files=[],
        source_dirs=[],
        test_dirs=[],
        components=[],
        total_files=0,
        hints={
            "has_pytest": False,
            "has_tests_dir": False,
            "npm_test_script": None,
            "has_dockerfile": False,
            "readme_present": False,
        },
    )
    missing = RepositoryAnalyzer().analyze(tmp_path / "missing")
    assert missing.name == "missing" and missing.total_files == 0


def test_symlinked_directories_are_not_followed(tmp_path: Path):
    root = tmp_path / "linked"
    write(root / "src" / "main.py", "")
    outside = tmp_path / "outside"
    write(outside / "huge.py", "")
    os.symlink(outside, root / "link-to-outside")
    profile = RepositoryAnalyzer().analyze(root)
    assert profile.total_files == 1
    assert [component.path for component in profile.components] == ["src"]
