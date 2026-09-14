"""JavaScriptDependencyExtractor: package.json specifiers, lock files v1/v3, workspaces, Node resolution."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from app.models.enums import DependencyScope, Ecosystem
from app.services.dependencies.javascript_extractor import (
    JavaScriptDependencyExtractor,
    exact_version,
    is_workspace_key,
    matches_workspace_pattern,
    resolve_lock_key,
    split_lock_key,
    unresolvable_kind,
    workspace_pattern_segments,
)

FIXTURES = Path(__file__).parent / "fixtures" / "dependencies"
JS_PROJECT = FIXTURES / "js_project"
JS_V1_PROJECT = FIXTURES / "js_v1_project"
JS_WORKSPACES = FIXTURES / "js_workspaces"


@pytest.fixture
def extractor() -> JavaScriptDependencyExtractor:
    return JavaScriptDependencyExtractor()


@pytest.fixture
def v3(extractor):
    return extractor.extract(JS_PROJECT)


def deps(result, source_file: str):
    return [d for d in result.dependencies if d.source_file == source_file]


def one(result, name: str, source_file: str, version: str | None = "any"):
    matches = [
        d for d in result.dependencies
        if d.package_name == name and d.source_file == source_file and (version == "any" or d.version == version)
    ]
    assert len(matches) == 1, f"expected exactly one {name!r} ({version}) in {source_file}, got {matches}"
    return matches[0]


def edges(result) -> set[tuple[str, str | None, str, str | None]]:
    return {(r.parent_name, r.parent_version, r.child_name, r.child_version) for r in result.relations}


def symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):  # pragma: no cover - Windows without symlink privilege
        pytest.skip("symlinks are not supported on this platform")


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def workspace_repo_with_deep_member(tmp_path: Path) -> Path:
    """The js_workspaces fixture plus a lock entry for the depth-3 workspace ``packages/deep/nested``."""
    repo = tmp_path / "repo"
    shutil.copytree(JS_WORKSPACES, repo)
    root = json.loads((repo / "package.json").read_text())
    root["workspaces"] = ["packages/*", "packages/deep/*"]
    write_json(repo / "package.json", root)
    lock = json.loads((repo / "package-lock.json").read_text())
    lock["packages"]["packages/deep/nested"] = {"name": "too-deep", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}}
    lock["packages"]["node_modules/too-deep"] = {"resolved": "packages/deep/nested", "link": True}
    lock["packages"]["node_modules/left-pad"] = {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
    write_json(repo / "package-lock.json", lock)
    return repo


# ------------------------------------------------------------- pure helpers
@pytest.mark.parametrize(
    "spec, expected",
    [
        ("1.2.3", "1.2.3"),
        ("=1.2.3", "1.2.3"),
        ("v1.2.3", "1.2.3"),
        (" 1.2.3 ", "1.2.3"),
        ("1.2.3-beta.1", "1.2.3-beta.1"),
        ("^1.2.3", None),
        ("~1.2.3", None),
        (">=1.2.3 <2", None),
        ("1.2", None),  # npm reads "1.2" as a range (>=1.2.0 <1.3.0)
        ("1.x", None),
        ("*", None),
        ("", None),
        ("latest", None),
        ("^1 || ^2", None),
    ],
)
def test_exact_version(spec, expected):
    assert exact_version(spec) == expected


@pytest.mark.parametrize(
    "spec, expected",
    [
        ("file:../lib", "file:"),
        ("link:../lib", "link:"),
        ("workspace:*", "workspace:"),
        ("npm:string-width@^4.2.0", "npm:"),
        ("git+https://github.com/a/b.git", "git+"),
        ("github:a/b#v1", "github:"),
        ("owner/repo", "github shorthand"),
        ("owner/repo#semver:^1", "github shorthand"),
        ("https://example.com/pkg.tgz", "https://"),
        ("^1.0.0", None),
        ("1.0.0", None),
        (">=1 <2", None),
        ("latest", None),
    ],
)
def test_unresolvable_kind(spec, expected):
    assert unresolvable_kind(spec) == expected


@pytest.mark.parametrize(
    "pattern, expected",
    [
        ("packages/*", ["packages", "*"]),
        ("./packages/*/", ["packages", "*"]),
        ("packages//app", ["packages", "app"]),
        (".", []),
        ("", []),
        ("./", []),
        ("  ", []),
        ("/abs", None),
        ("../x", None),
        ("packages/../x", None),
        (None, None),
        (42, None),
    ],
)
def test_workspace_pattern_segments(pattern, expected):
    assert workspace_pattern_segments(pattern) == expected


@pytest.mark.parametrize(
    "pattern, directory, expected",
    [
        ("packages/*", "packages/app", True),
        ("packages/*", "packages/deep/nested", False),  # "*" never crosses a "/"
        ("packages/*", "x/packages/app", False),  # anchored at the root
        ("packages/**", "packages", True),
        ("packages/**", "packages/deep/nested", True),
        ("**/*", "tools/cli", True),
        ("**", "", True),
        ("packages/app", "packages/app", True),
        ("packages/app", "", False),
        ("packages/[al]*", "packages/lib", True),
        ("packages/?pp", "packages/app", True),
    ],
)
def test_matches_workspace_pattern(pattern, directory, expected):
    assert matches_workspace_pattern(workspace_pattern_segments(pattern), directory) is expected


def test_is_workspace_key():
    assert is_workspace_key("packages/app")
    assert is_workspace_key("packages/deep/nested")
    assert not is_workspace_key("")
    assert not is_workspace_key("node_modules/ms")
    assert not is_workspace_key("packages/app/node_modules/ms")


def test_split_lock_key_handles_scopes_and_nesting():
    assert split_lock_key("node_modules/ms") == ("", "ms")
    assert split_lock_key("node_modules/@babel/core") == ("", "@babel/core")
    assert split_lock_key("node_modules/a/node_modules/@s/b") == ("node_modules/a", "@s/b")
    assert split_lock_key("packages/app/node_modules/x") == ("packages/app", "x")


def test_resolve_lock_key_walks_up_like_node():
    packages = {
        "": {},
        "node_modules/ms": {},
        "node_modules/a": {},
        "node_modules/a/node_modules/b": {},
        "node_modules/a/node_modules/b/node_modules/ms": {},
        "packages/app": {},
        "packages/app/node_modules/x": {},
    }
    assert resolve_lock_key("node_modules/a/node_modules/b", "ms", packages) == "node_modules/a/node_modules/b/node_modules/ms"
    assert resolve_lock_key("node_modules/a", "ms", packages) == "node_modules/ms"
    assert resolve_lock_key("node_modules/a/node_modules/b", "a", packages) == "node_modules/a"
    assert resolve_lock_key("", "ms", packages) == "node_modules/ms"
    assert resolve_lock_key("packages/app", "x", packages) == "packages/app/node_modules/x"
    assert resolve_lock_key("packages/app", "ms", packages) == "node_modules/ms"
    assert resolve_lock_key("node_modules/a", "nope", packages) is None


# ---------------------------------------------------------------- detection
def test_detect_lists_manifest_and_lock(extractor):
    found = [p.relative_to(JS_PROJECT).as_posix() for p in extractor.detect(JS_PROJECT)]
    assert found == ["package.json", "package-lock.json"]


def test_detect_workspaces_and_nested_manifests_within_depth(extractor):
    found = [p.relative_to(JS_WORKSPACES).as_posix() for p in extractor.detect(JS_WORKSPACES)]
    assert found == [
        "package.json",
        "packages/app/package.json",
        "packages/lib/package.json",
        "tools/cli/package.json",
        "package-lock.json",
    ]
    assert "packages/deep/nested/package.json" not in found  # depth 3


def test_detect_skips_node_modules(extractor, tmp_path):
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {}}')
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "package.json").write_text('{"name": "dep"}')
    assert [p.name for p in extractor.detect(tmp_path)] == ["package.json"]


@pytest.mark.parametrize(
    "workspaces",
    [
        [".", "packages/*"],
        ["/abs"],
        [""],
        ["./"],
        ["../x"],
        ["**/*"],
        ["packages/**"],
        ["!packages/*"],
        [None, 42, {"packages": ["x"]}],
        "packages/*",
        {"packages": ["packages/*", "."]},
        {"nohoist": ["**"]},
    ],
)
def test_detect_survives_any_workspaces_value(extractor, tmp_path, workspaces):
    write_json(tmp_path / "package.json", {"name": "r", "workspaces": workspaces, "dependencies": {"a": "1.0.0"}})
    write_json(tmp_path / "packages" / "x" / "package.json", {"dependencies": {"b": "2.0.0"}})
    found = [p.relative_to(tmp_path.resolve()).as_posix() for p in extractor.detect(tmp_path)]
    assert found == ["package.json", "packages/x/package.json"]
    result = extractor.extract(tmp_path)
    assert {(d.package_name, d.version, d.source_file) for d in result.dependencies} == {
        ("a", "1.0.0", "package.json"),
        ("b", "2.0.0", "packages/x/package.json"),
    }
    assert result.warnings == []


def test_workspace_patterns_order_members_first_and_honour_negations(extractor):
    found = [p.relative_to(JS_WORKSPACES).as_posix() for p in extractor.detect(JS_WORKSPACES)]
    assert found[:3] == ["package.json", "packages/app/package.json", "packages/lib/package.json"]
    # "!" exclusions only change the order: excluded members are still found by the walk.
    assert matches_workspace_pattern(workspace_pattern_segments("packages/*"), "packages/lib")


def test_workspace_pattern_cannot_reach_outside_the_repository(extractor, tmp_path):
    write_json(tmp_path / "outside" / "package.json", {"dependencies": {"evil": "1.0.0"}})
    repo = tmp_path / "repo"
    write_json(repo / "package.json", {"workspaces": ["../outside", "../*"], "dependencies": {"a": "1.0.0"}})
    assert [p.name for p in extractor.detect(repo)] == ["package.json"]
    result = extractor.extract(repo)
    assert result.files == ["package.json"]
    assert [d.package_name for d in result.dependencies] == ["a"]


def test_symlinked_lock_outside_the_repository_is_ignored(extractor, tmp_path):
    outside = tmp_path / "outside" / "package-lock.json"
    write_json(outside, {"lockfileVersion": 3, "packages": {"": {}, "node_modules/leaked": {"version": "9.9.9"}}})
    repo = tmp_path / "repo"
    write_json(repo / "package.json", {"dependencies": {"a": "^1.0.0"}})
    symlink(outside, repo / "package-lock.json")
    assert [p.name for p in extractor.detect(repo)] == ["package.json"]
    result = extractor.extract(repo)
    assert result.files == ["package.json"]
    assert [(d.package_name, d.version) for d in result.dependencies] == [("a", None)]
    assert not any("leaked" in w for w in result.warnings)


def test_symlinked_manifest_inside_the_repository_is_followed(extractor, tmp_path):
    write_json(tmp_path / "config" / "real-package.json", {"dependencies": {"a": "1.0.0"}})
    symlink(Path("config") / "real-package.json", tmp_path / "package.json")
    result = extractor.extract(tmp_path)
    assert result.files == ["package.json"]
    assert [(d.package_name, d.version) for d in result.dependencies] == [("a", "1.0.0")]


# ----------------------------------------------------- lockfileVersion 3
def test_v3_files_and_counts(v3):
    assert v3.files == ["package.json", "package-lock.json"]
    assert len(deps(v3, "package.json")) == 12
    assert len(deps(v3, "package-lock.json")) == 9
    assert {d.ecosystem for d in v3.dependencies} == {Ecosystem.NPM}


def test_v3_direct_dependencies_are_emitted_once_with_lock_resolved_versions(v3):
    direct = deps(v3, "package.json")
    assert {d.scope for d in direct} == {DependencyScope.DIRECT}
    assert len({d.package_name for d in direct}) == len(direct)
    debug = one(v3, "debug", "package.json")
    assert (debug.version, debug.version_spec, debug.dev) == ("2.6.9", "^2.6.9", False)
    send = one(v3, "send", "package.json")
    assert (send.version, send.version_spec) == ("0.18.0", "~0.18.0")
    react = one(v3, "react", "package.json")  # peerDependencies
    assert (react.version, react.version_spec, react.dev) == ("18.2.0", ">=16", False)
    fsevents = one(v3, "fsevents", "package.json")  # optionalDependencies
    assert (fsevents.version, fsevents.dev) == ("2.3.2", False)


def test_v3_exact_specifiers_win_over_the_lock(v3):
    assert one(v3, "lodash", "package.json").version == "4.17.21"
    assert one(v3, "left-pad", "package.json").version == "1.3.0"
    mocha = one(v3, "mocha", "package.json")
    assert (mocha.version, mocha.version_spec, mocha.dev) == ("10.2.0", "v10.2.0", True)
    etag = one(v3, "etag", "package.json")
    assert etag.version == "1.8.0"  # the declared pin, with a warning about the lock disagreeing
    assert any("'etag' pins 1.8.0 but package-lock.json installs 1.8.1" in w for w in v3.warnings)
    # The lock entry for etag belongs to the direct dependency: no extra transitive row.
    assert not [d for d in deps(v3, "package-lock.json") if d.package_name == "etag"]


def test_v3_non_registry_specifiers_have_no_version_and_a_warning(v3):
    for name, kind in (("local-lib", "file:"), ("my-fork", "github:"), ("aliased-ms", "npm:")):
        dep = one(v3, name, "package.json")
        assert dep.version is None and dep.scope == DependencyScope.DIRECT
        assert any(f"'{name}' uses a {kind} specifier" in w for w in v3.warnings), name


def test_v3_direct_dependency_missing_from_lock(v3):
    dep = one(v3, "missing-from-lock", "package.json")
    assert (dep.version, dep.version_spec) == (None, "^1.0.0")
    assert any("'missing-from-lock' (^1.0.0) not found in package-lock.json" in w for w in v3.warnings)


def test_v3_nested_duplicates_are_distinct_transitive_dependencies(v3):
    ms_versions = sorted(d.version for d in deps(v3, "package-lock.json") if d.package_name == "ms")
    assert ms_versions == ["2.0.0", "2.1.2", "2.1.3"]
    # ms@2.1.3 is installed three times (send/, mocha/, and via the alias) but reported once.
    assert one(v3, "ms", "package-lock.json", "2.1.3").dev is False  # send's copy is not dev-only
    assert one(v3, "ms", "package-lock.json", "2.1.2").dev is True  # only reachable through mocha
    assert one(v3, "debug", "package-lock.json", "4.3.4").dev is True
    transitive = deps(v3, "package-lock.json")
    assert {d.scope for d in transitive} == {DependencyScope.TRANSITIVE}
    assert all(d.version_spec is None for d in transitive)
    assert {d.package_name for d in transitive} == {
        "ms", "escape-html", "fresh", "mime", "debug", "loose-envify", "js-tokens",
    }


def test_v3_root_links_and_workspace_entries_are_not_dependencies(v3):
    names = {d.package_name for d in v3.dependencies}
    assert "sentinel-fixture-app" not in names
    assert not [d for d in deps(v3, "package-lock.json") if d.package_name == "local-lib"]


def test_v3_alias_entry_is_reported_under_its_real_name(v3):
    assert not [d for d in deps(v3, "package-lock.json") if d.package_name == "aliased-ms"]
    assert one(v3, "ms", "package-lock.json", "2.1.3")


def test_v3_relations_follow_node_resolution(v3):
    assert edges(v3) == {
        ("debug", "2.6.9", "ms", "2.0.0"),
        ("send", "0.18.0", "debug", "2.6.9"),
        ("send", "0.18.0", "escape-html", "1.0.3"),
        ("send", "0.18.0", "etag", "1.8.0"),
        ("send", "0.18.0", "fresh", "0.5.2"),
        ("send", "0.18.0", "mime", "1.6.0"),
        ("send", "0.18.0", "ms", "2.1.3"),  # send/node_modules/ms, not the top-level 2.0.0
        ("mocha", "10.2.0", "debug", "4.3.4"),  # mocha/node_modules/debug
        ("mocha", "10.2.0", "ms", "2.1.3"),  # mocha/node_modules/ms
        ("debug", "4.3.4", "ms", "2.1.2"),  # mocha/node_modules/debug/node_modules/ms
        ("my-fork", None, "ms", "2.0.0"),  # unresolved direct dep still gets its edges
        ("react", "18.2.0", "loose-envify", "1.4.0"),
        ("loose-envify", "1.4.0", "js-tokens", "4.0.0"),
    }
    assert all(r.ecosystem == Ecosystem.NPM and r.relation_type == "depends_on" for r in v3.relations)
    # No root -> direct edges (Repository USES covers them).
    assert not any(r.parent_name == "sentinel-fixture-app" for r in v3.relations)


def test_v3_yarn_lock_presence_is_reported(v3):
    assert sum("yarn.lock" in w and "not parsed in V1" in w for w in v3.warnings) == 1


def test_v3_warning_count(v3):
    assert len(v3.warnings) == 6


# ----------------------------------------------------- lockfileVersion 1
def test_v1_lock_tree(extractor):
    result = extractor.extract(JS_V1_PROJECT)
    assert result.files == ["package.json", "package-lock.json"]
    direct = {d.package_name: d for d in deps(result, "package.json")}
    assert set(direct) == {"debug", "send", "git-dep", "ms"}
    assert (direct["debug"].version, direct["debug"].version_spec) == ("2.6.9", "^2.6.9")
    assert direct["send"].version == "0.18.0"
    assert (direct["ms"].version, direct["ms"].dev) == ("2.1.3", True)
    assert direct["git-dep"].version is None
    assert any("'git-dep' uses a github: specifier" in w for w in result.warnings)
    transitive = {(d.package_name, d.version) for d in deps(result, "package-lock.json")}
    assert transitive == {("ms", "2.0.0"), ("mime", "1.6.0")}
    assert edges(result) == {
        ("debug", "2.6.9", "ms", "2.0.0"),  # nested under debug
        ("send", "0.18.0", "debug", "2.6.9"),
        ("send", "0.18.0", "mime", "1.6.0"),
        ("send", "0.18.0", "ms", "2.1.3"),  # top-level ms
        ("git-dep", None, "mime", "1.6.0"),
    }


# ----------------------------------------------------------- workspaces
def test_workspaces_resolve_through_the_root_lock(extractor):
    result = extractor.extract(JS_WORKSPACES)
    assert result.files == [
        "package.json",
        "packages/app/package.json",
        "packages/lib/package.json",
        "tools/cli/package.json",
        "package-lock.json",
    ]
    ts = one(result, "typescript", "package.json")
    assert (ts.version, ts.version_spec, ts.dev) == ("5.4.5", "~5.4.0", True)
    app_lib = one(result, "@mono/lib", "packages/app/package.json")
    assert app_lib.version is None
    assert any("'@mono/lib' uses a workspace: specifier" in w for w in result.warnings)
    assert one(result, "lodash", "packages/app/package.json").version == "4.17.21"
    assert one(result, "ms", "packages/app/package.json").version == "2.1.3"  # hoisted
    assert one(result, "ms", "packages/lib/package.json").version == "2.0.0"  # packages/lib/node_modules/ms
    assert one(result, "lodash", "packages/lib/package.json").version_spec == ">=4"  # peer, hoisted
    # tools/cli is NOT a workspace member: the root lock does not govern it, so its
    # range spec stays unresolved and the extractor says why.
    chalk = one(result, "chalk", "tools/cli/package.json")
    assert chalk.version is None and chalk.version_spec == "^5.3.0"
    assert any("tools/cli/package.json: not a workspace of package-lock.json" in w for w in result.warnings)
    # Every installed package is claimed by a manifest -> no transitive rows, no relations.
    assert deps(result, "package-lock.json") == []
    assert result.relations == []
    assert not any(d.package_name in ("@mono/app", "too-deep", "left-pad") for d in result.dependencies)
    assert any("pnpm-lock.yaml" in w and "not parsed in V1" in w for w in result.warnings)


def test_lock_declared_workspace_beyond_max_depth_is_direct(extractor, tmp_path):
    repo = workspace_repo_with_deep_member(tmp_path)
    found = [p.relative_to(repo.resolve()).as_posix() for p in extractor.detect(repo)]
    assert found == [
        "package.json",
        "packages/app/package.json",
        "packages/lib/package.json",
        "tools/cli/package.json",
        "packages/deep/nested/package.json",  # depth 3, but the lock names it as a workspace
        "package-lock.json",
    ]
    result = extractor.extract(repo)
    assert "packages/deep/nested/package.json" in result.files
    left_pad = one(result, "left-pad", "packages/deep/nested/package.json")
    assert (left_pad.version, left_pad.version_spec, left_pad.scope, left_pad.dev) == (
        "1.3.0", "1.3.0", DependencyScope.DIRECT, False,
    )
    # The lock entry belongs to that direct dependency: never reported as transitive.
    assert not [d for d in deps(result, "package-lock.json") if d.package_name == "left-pad"]
    assert not any(d.package_name == "too-deep" for d in result.dependencies)
    assert not any("workspace 'packages/deep/nested'" in w for w in result.warnings)


def test_lock_declared_workspace_without_manifest_is_reported_from_the_lock(extractor, tmp_path):
    repo = workspace_repo_with_deep_member(tmp_path)
    shutil.rmtree(repo / "packages" / "deep")  # stale lock: the workspace is gone
    assert "packages/deep/nested/package.json" not in [p.name for p in extractor.detect(repo)]
    result = extractor.extract(repo)
    assert "packages/deep/nested/package.json" not in result.files
    left_pad = one(result, "left-pad", "package-lock.json")
    assert (left_pad.version, left_pad.version_spec, left_pad.scope) == ("1.3.0", "1.3.0", DependencyScope.DIRECT)
    assert sum(
        "workspace 'packages/deep/nested' has no readable package.json" in w and "reported from the lock" in w
        for w in result.warnings
    ) == 1


def test_lock_workspace_key_spelling_does_not_duplicate_a_loaded_manifest(extractor, tmp_path):
    write_json(tmp_path / "package.json", {"workspaces": ["packages/*"]})
    write_json(tmp_path / "packages" / "app" / "package.json", {"dependencies": {"b": "2.0.0"}})
    write_json(tmp_path / "package-lock.json", {
        "lockfileVersion": 3,
        "packages": {
            "": {},
            "./packages/app/": {"dependencies": {"b": "2.0.0"}},
            "node_modules/b": {"version": "2.0.0"},
            "packages/empty": {"name": "empty", "version": "1.0.0"},  # declares nothing: no warning
        },
    })
    result = extractor.extract(tmp_path)
    assert [(d.package_name, d.scope, d.source_file) for d in result.dependencies] == [
        ("b", DependencyScope.DIRECT, "packages/app/package.json"),
    ]
    assert result.warnings == []


def test_workspace_with_its_own_lock_is_not_reported_again_by_the_root_lock(extractor, tmp_path):
    write_json(tmp_path / "package.json", {"workspaces": ["packages/*"]})
    write_json(tmp_path / "package-lock.json", {
        "lockfileVersion": 3,
        "packages": {"": {}, "packages/app": {"dependencies": {"b": "2.0.0"}}, "node_modules/b": {"version": "2.0.0"}},
    })
    write_json(tmp_path / "packages" / "app" / "package.json", {"dependencies": {"b": "^2.0.0"}})
    write_json(tmp_path / "packages" / "app" / "package-lock.json", {
        "lockfileVersion": 3, "packages": {"": {}, "node_modules/b": {"version": "2.0.1"}},
    })
    result = extractor.extract(tmp_path)
    assert {(d.package_name, d.version, d.scope, d.source_file) for d in result.dependencies} == {
        ("b", "2.0.1", DependencyScope.DIRECT, "packages/app/package.json"),
        ("b", "2.0.0", DependencyScope.TRANSITIVE, "package-lock.json"),  # installed at the root, unclaimed
    }
    assert not any("has no readable package.json" in w for w in result.warnings)


def test_lock_workspace_reached_through_an_escaping_symlink_is_not_read(extractor, tmp_path):
    write_json(tmp_path / "outside" / "nested" / "package.json", {"dependencies": {"evil": "1.0.0"}, "devDependencies": {"leaked": "1.0.0"}})
    repo = tmp_path / "repo"
    write_json(repo / "package.json", {"workspaces": ["packages/*"], "dependencies": {"a": "1.0.0"}})
    (repo / "packages").mkdir()
    symlink(tmp_path / "outside", repo / "packages" / "deep")
    write_json(repo / "package-lock.json", {
        "lockfileVersion": 3,
        "packages": {
            "": {},
            "packages/deep/nested": {"dependencies": {"evil": "1.0.0"}},
            "../outside/nested": {"dependencies": {"evil": "1.0.0"}},
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/evil": {"version": "1.0.0"},
        },
    })
    assert [p.name for p in extractor.detect(repo)] == ["package.json", "package-lock.json"]
    result = extractor.extract(repo)
    assert result.files == ["package.json", "package-lock.json"]
    assert not any(d.package_name == "leaked" for d in result.dependencies)  # host manifest never parsed
    evil = one(result, "evil", "package-lock.json")
    assert evil.scope == DependencyScope.DIRECT  # the lock itself says the workspace declares it
    assert any("workspace 'packages/deep/nested' has no readable package.json" in w for w in result.warnings)


# ----------------------------------------------------------- failure modes
def test_manifest_without_lock(extractor, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4.18.2", "lodash": "4.17.21"},
        "devDependencies": {"jest": "29.7.0"},
    }))
    result = extractor.extract(tmp_path)
    assert result.files == ["package.json"]
    by = {d.package_name: d for d in result.dependencies}
    assert by["express"].version is None and by["express"].version_spec == "^4.18.2"
    assert by["lodash"].version == "4.17.21"
    assert by["jest"].version == "29.7.0" and by["jest"].dev is True
    assert result.relations == [] and result.warnings == []


def test_malformed_lock_is_skipped_with_warning(extractor, tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"debug": "^4.3.4"}}')
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {')
    result = extractor.extract(tmp_path)
    assert result.files == ["package.json"]
    assert [(d.package_name, d.version) for d in result.dependencies] == [("debug", None)]
    assert len(result.warnings) == 1
    assert result.warnings[0].startswith("package-lock.json: malformed JSON")


def test_malformed_manifest_is_skipped_with_warning(extractor, tmp_path):
    (tmp_path / "package.json").write_text("not json at all")
    result = extractor.extract(tmp_path)
    assert result.files == [] and result.dependencies == []
    assert result.warnings and result.warnings[0].startswith("package.json: malformed JSON")


def test_manifest_that_is_not_an_object(extractor, tmp_path):
    (tmp_path / "package.json").write_text("[1, 2, 3]")
    result = extractor.extract(tmp_path)
    assert result.dependencies == []
    assert any("expected a JSON object" in w for w in result.warnings)


def test_dependency_section_that_is_not_an_object(extractor, tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": ["debug"], "devDependencies": {"jest": "29.7.0"}}')
    result = extractor.extract(tmp_path)
    assert [d.package_name for d in result.dependencies] == ["jest"]
    assert any("'dependencies' is not an object" in w for w in result.warnings)


def test_lock_without_packages_or_dependencies(extractor, tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"debug": "4.3.4"}}')
    (tmp_path / "package-lock.json").write_text('{"name": "x", "lockfileVersion": 3}')
    result = extractor.extract(tmp_path)
    assert result.files == ["package.json"]
    assert any("unrecognised lock file format" in w for w in result.warnings)
    assert one(result, "debug", "package.json").version == "4.3.4"


def test_same_package_in_two_sections_is_reported_once(extractor, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "devDependencies": {"react": "18.2.0"},
        "peerDependencies": {"react": ">=16"},
    }))
    result = extractor.extract(tmp_path)
    assert [(d.package_name, d.version, d.dev) for d in result.dependencies] == [("react", "18.2.0", True)]


def test_lock_entry_without_valid_version_is_reported_unknown(extractor, tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "^1.0.0"}}')
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "*"}},
            "node_modules/b": {"version": "git+ssh://git@github.com/x/b.git#abc"},
        },
    }))
    result = extractor.extract(tmp_path)
    assert one(result, "a", "package.json").version == "1.0.0"
    b = one(result, "b", "package-lock.json")
    assert b.version is None
    assert any("node_modules/b" in w and "no valid version" in w for w in result.warnings)
    assert edges(result) == {("a", "1.0.0", "b", None)}


def test_git_installed_transitive_is_flagged(extractor, tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}')
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 2,
        "packages": {
            "": {"dependencies": {"a": "1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "github:x/b"}},
            "node_modules/b": {"version": "2.0.0", "resolved": "git+ssh://git@github.com/x/b.git#abc"},
        },
        "dependencies": {"a": {"version": "1.0.0"}},  # v2 keeps a legacy tree; must be ignored
    }))
    result = extractor.extract(tmp_path)
    assert one(result, "b", "package-lock.json").version == "2.0.0"
    assert any("'b@2.0.0' is installed from git" in w for w in result.warnings)
    assert len(result.dependencies) == 2


def test_nested_manifest_outside_workspaces_is_not_governed_by_root_lock(tmp_path):
    """examples/demo/package.json is not a workspace: the root lock's versions must not be adopted."""
    import json

    from app.services.dependencies.javascript_extractor import JavaScriptDependencyExtractor

    (tmp_path / "package.json").write_text(json.dumps({"name": "root", "dependencies": {"lodash": "^4.17.21"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "root", "lockfileVersion": 3, "packages": {
            "": {"dependencies": {"lodash": "^4.17.21"}},
            "node_modules/lodash": {"version": "4.17.21"},
        },
    }))
    demo = tmp_path / "examples" / "demo"
    demo.mkdir(parents=True)
    (demo / "package.json").write_text(json.dumps({"name": "demo", "dependencies": {"lodash": "^3.10.0", "left-pad": "1.3.0"}}))
    result = JavaScriptDependencyExtractor().extract(tmp_path)
    by_file = {(d.source_file, d.package_name): d for d in result.dependencies}
    assert by_file[("package.json", "lodash")].version == "4.17.21"
    nested = by_file[("examples/demo/package.json", "lodash")]
    assert nested.version is None and nested.version_spec == "^3.10.0"
    assert by_file[("examples/demo/package.json", "left-pad")].version == "1.3.0"  # exact spec still resolves
    assert any("not a workspace of package-lock.json" in w for w in result.warnings)


def test_nested_workspace_member_is_still_governed_by_root_lock(tmp_path):
    import json

    from app.services.dependencies.javascript_extractor import JavaScriptDependencyExtractor

    (tmp_path / "package.json").write_text(json.dumps({"name": "root", "workspaces": ["packages/*"]}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "root", "lockfileVersion": 3, "packages": {
            "": {"workspaces": ["packages/*"]},
            "packages/app": {"name": "app", "dependencies": {"lodash": "^4.17.21"}},
            "node_modules/app": {"resolved": "packages/app", "link": True},
            "node_modules/lodash": {"version": "4.17.21"},
        },
    }))
    app_dir = tmp_path / "packages" / "app"
    app_dir.mkdir(parents=True)
    (app_dir / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"lodash": "^4.17.21"}}))
    result = JavaScriptDependencyExtractor().extract(tmp_path)
    member = next(d for d in result.dependencies if d.source_file == "packages/app/package.json" and d.package_name == "lodash")
    assert member.version == "4.17.21"
    assert not any("not a workspace" in w for w in result.warnings)


def test_deeply_nested_json_is_reported_as_malformed_not_raised(tmp_path):
    from app.services.dependencies.javascript_extractor import JavaScriptDependencyExtractor

    (tmp_path / "package.json").write_text('{"name":"x","workspaces":["packages/*"],"dependencies":{"a":"1.0.0"},"junk":' + "[" * 100000 + "]" * 100000 + "}")
    extractor = JavaScriptDependencyExtractor()
    assert extractor.detect(tmp_path)  # the file exists and is detected
    result = extractor.extract(tmp_path)
    assert result.dependencies == []
    assert any("malformed JSON" in w for w in result.warnings)


def test_negated_workspace_patterns_exclude_members(tmp_path):
    import json

    from app.services.dependencies.javascript_extractor import JavaScriptDependencyExtractor

    (tmp_path / "package.json").write_text(json.dumps({"name": "root", "workspaces": ["packages/*", "!packages/lib"]}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "root", "lockfileVersion": 3,
        "packages": {"": {}, "packages/app": {"dependencies": {"ms": "^2.0.0"}}, "node_modules/ms": {"version": "2.1.3"}},
    }))
    for member in ("app", "lib"):
        d = tmp_path / "packages" / member
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": member, "dependencies": {"ms": "^2.0.0"}}))
    result = JavaScriptDependencyExtractor().extract(tmp_path)
    app_ms = next(d for d in result.dependencies if d.source_file == "packages/app/package.json")
    lib_ms = next(d for d in result.dependencies if d.source_file == "packages/lib/package.json")
    assert app_ms.version == "2.1.3"  # member: governed by the root lock
    assert lib_ms.version is None  # excluded by "!packages/lib": lock-less
