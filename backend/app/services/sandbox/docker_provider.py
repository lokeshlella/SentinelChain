"""Docker sandbox provider: installs the proposed dependency state and runs the tests in a container.

How a validation run works
--------------------------
1. The image is chosen by ecosystem (``settings.docker_python_image`` / ``docker_node_image``).
   **The first validation on a machine pulls the image** (``docker pull``), which can take a
   few minutes; later runs reuse the cached image.
2. A container is created with a hardened configuration (no capabilities, no privilege
   escalation, memory / CPU / pid limits, bridge network so package registries are
   reachable) and **no host mounts**: the working copy is streamed in with ``put_archive``.
3. A generated POSIX ``sh`` script runs the install and the tests. It prints step markers
   (``::step build start <epoch>`` / ``::step build end <exit> <epoch>``) around every step
   and always exits 0, so the outcome is read from the markers, never from the container's
   own exit code.
4. The provider waits ``request.timeout_seconds``; on timeout the container is killed and
   every step that did not finish is reported as UNKNOWN (never PASS).
5. Logs are collected (last 2 MB kept), ``package-lock.json`` is copied back for npm
   projects and the container is always removed.

Infrastructure problems (daemon unreachable, image cannot be pulled, ...) raise
:class:`SandboxError`; build / test failures are reported through :class:`StepResult`.
"""

from __future__ import annotations

import io
import json
import os
import re
import shlex
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from app.core.config import Settings, get_settings
from app.core.logging import get_stage_logger
from app.models.enums import CheckResult, Ecosystem
from app.services.sandbox.base import SandboxError, SandboxProvider, SandboxRequest, SandboxResult, StepResult

log = get_stage_logger("Sandbox")

#: Directories never copied into the sandbox (build outputs, caches, virtualenvs, VCS metadata).
SANDBOX_IGNORED_DIRS: frozenset[str] = frozenset(
    {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".pytest_cache", ".tox", ".mypy_cache"}
)
CONTAINER_WORKDIR = "/workspace"
MAX_LOG_BYTES = 2 * 1024 * 1024  # keep the tail of the combined log
MAX_WORKSPACE_BYTES = 256 * 1024 * 1024  # refuse to stream absurdly large working copies
OUTPUT_TAIL_LINES = 40
OUTPUT_TAIL_CHARS = 4000
NPM_PLACEHOLDER_TEST_SCRIPT = 'echo "Error: no test specified" && exit 1'
LOCK_FILE = "package-lock.json"
STEP_NAMES = ("build", "tests")

_MARKER_RE = re.compile(r"^::step (?P<step>build|tests) (?P<event>start|end|skipped)(?: (?P<rest>.*))?$")
_NUMBER_RE = re.compile(r"^-?\d+(?:\.\d+)?$")

SANDBOX_ENVIRONMENT = {
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "npm_config_update_notifier": "false",
    "CI": "1",
}

PYTHON_INSTALL_CMD = "python -m pip install --no-cache-dir -r {file}"
PYTHON_PYTEST_INSTALL_CMD = "python -m pip install -q pytest"
PYTHON_TEST_CMD = "python -m pytest -q"
NPM_INSTALL_CMD = "npm install --no-audit --no-fund"
NPM_TEST_CMD = "npm test"


# ---------------------------------------------------------------------- script builders


@dataclass(frozen=True)
class SandboxScript:
    """The generated ``sh`` script plus the human-readable commands it runs."""

    text: str
    build_command: str
    test_command: str | None  # None when tests are skipped
    tests_skipped_reason: str | None = None


def _step_lines(build_command: str, test_command: str | None, tests_skipped_reason: str | None) -> str:
    """Wrap the commands into the marker-emitting POSIX script (always exits 0)."""
    lines = ["#!/bin/sh", "set +e"]
    lines += [
        'echo "::step build start $(date +%s)"',
        build_command,
        "rc=$?",
        'echo "::step build end $rc $(date +%s)"',
        'if [ "$rc" -ne 0 ]; then',
        '  echo "::step tests skipped build failed"',
        "  exit 0",
        "fi",
    ]
    if test_command is None:
        lines.append(f'echo "::step tests skipped {tests_skipped_reason or "no test suite detected"}"')
    else:
        lines += [
            'echo "::step tests start $(date +%s)"',
            test_command,
            "rc=$?",
            'echo "::step tests end $rc $(date +%s)"',
        ]
    lines.append("exit 0")
    return "\n".join(lines) + "\n"


def _requirements_pin_pytest(workspace: Path, dependency_file: str) -> bool:
    """True when the requirements file already lists pytest (then the pin is respected)."""
    try:
        text = (workspace / dependency_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(re.match(r"^\s*pytest\s*(\[[^\]]*\])?\s*(==|===|>=|~=|>|<|!=|$|;|#)", line, re.IGNORECASE) for line in text.splitlines())


def _has_python_tests(workspace: Path, hints: dict) -> tuple[bool, str]:
    """(run tests?, reason) for a Python workspace: hint, ``tests/`` directory or ``test_*.py`` files."""
    if hints.get("has_pytest"):
        return True, "repository profile reports pytest"
    if any((workspace / d).is_dir() for d in ("tests", "test")):
        return True, "tests directory present"
    for directory, dirnames, filenames in os.walk(workspace):
        dirnames[:] = [d for d in dirnames if d not in SANDBOX_IGNORED_DIRS and not d.startswith(".")]
        if any(re.match(r"^test_.*\.py$", f) for f in filenames):
            return True, "test_*.py files present"
        if len(Path(directory).relative_to(workspace).parts) >= 3:
            dirnames[:] = []  # do not descend further than three levels
    return False, "no tests directory or test_*.py files found"


def build_python_script(workspace: Path, dependency_file: str, hints: dict | None = None) -> SandboxScript:
    """``pip install -r <file>`` then (when a test suite is detected) ``pytest -q``."""
    hints = hints or {}
    build_command = PYTHON_INSTALL_CMD.format(file=shlex.quote(dependency_file))
    run_tests, reason = _has_python_tests(workspace, hints)
    if not run_tests:
        return SandboxScript(_step_lines(build_command, None, reason), build_command, None, reason)
    parts = [] if _requirements_pin_pytest(workspace, dependency_file) else [PYTHON_PYTEST_INSTALL_CMD]
    parts.append(PYTHON_TEST_CMD)
    test_command = " && ".join(parts)
    return SandboxScript(_step_lines(build_command, test_command, None), build_command, test_command)


def _npm_test_script(workspace: Path, dependency_file: str, hints: dict) -> str | None:
    """The ``scripts.test`` entry of the manifest (None when missing or the npm placeholder)."""
    manifest = workspace / dependency_file
    script: str | None = None
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        scripts = data.get("scripts") if isinstance(data, dict) else None
        raw = scripts.get("test") if isinstance(scripts, dict) else None
        script = raw.strip() if isinstance(raw, str) and raw.strip() else None
    except (OSError, ValueError):
        hinted = hints.get("npm_test_script")
        script = hinted.strip() if isinstance(hinted, str) and hinted.strip() else None
    if script is None:
        return None
    normalised = " ".join(script.split())
    if normalised == NPM_PLACEHOLDER_TEST_SCRIPT or "no test specified" in normalised:
        return None
    return script


def build_node_script(workspace: Path, dependency_file: str, hints: dict | None = None) -> SandboxScript:
    """``npm install`` (refreshes the lock file) then ``npm test`` when a real test script exists.

    When the manifest lives in a sub-directory the build command changes into it first
    (the shell keeps the directory for the test step).
    """
    hints = hints or {}
    manifest_dir = PurePosixPath(dependency_file).parent.as_posix()
    build_command = NPM_INSTALL_CMD if manifest_dir in ("", ".") else f"cd {shlex.quote(manifest_dir)} && {NPM_INSTALL_CMD}"
    script = _npm_test_script(workspace, dependency_file, hints)
    if script is None:
        reason = "package.json has no test script"
        return SandboxScript(_step_lines(build_command, None, reason), build_command, None, reason)
    return SandboxScript(_step_lines(build_command, NPM_TEST_CMD, None), build_command, NPM_TEST_CMD)


def build_script(request: SandboxRequest) -> SandboxScript:
    if request.ecosystem == Ecosystem.PYPI:
        return build_python_script(Path(request.workspace_path), request.dependency_file, request.hints)
    if request.ecosystem == Ecosystem.NPM:
        return build_node_script(Path(request.workspace_path), request.dependency_file, request.hints)
    raise SandboxError(f"Unsupported ecosystem for the Docker sandbox: {request.ecosystem!r} (supported: PyPI, npm)")


# ---------------------------------------------------------------------- marker parsing


def _to_number(text: str | None) -> float | None:
    if text is None:
        return None
    text = text.strip()
    return float(text) if _NUMBER_RE.match(text) else None


def parse_step_markers(logs: str) -> dict[str, Any]:
    """Pure parser for the ``::step`` markers written by the sandbox script.

    Returns::

        {
          "build": <exit code> | None,          # None = the step never finished
          "tests": <exit code> | None,
          "tests_skipped_reason": str | None,
          "started": {"build": bool, "tests": bool},
          "durations": {"build": float | None, "tests": float | None},  # seconds, from the marker timestamps
        }
    """
    exit_codes: dict[str, int | None] = {name: None for name in STEP_NAMES}
    started: dict[str, bool] = {name: False for name in STEP_NAMES}
    start_at: dict[str, float | None] = {name: None for name in STEP_NAMES}
    end_at: dict[str, float | None] = {name: None for name in STEP_NAMES}
    skipped_reason: str | None = None

    for raw_line in logs.splitlines():
        match = _MARKER_RE.match(raw_line.strip())
        if not match:
            continue
        step, event, rest = match.group("step"), match.group("event"), match.group("rest")
        if event == "start":
            started[step] = True
            start_at[step] = _to_number(rest)
        elif event == "end":
            parts = (rest or "").split()
            code = _to_number(parts[0]) if parts else None
            exit_codes[step] = int(code) if code is not None else None
            end_at[step] = _to_number(parts[1]) if len(parts) > 1 else None
        elif event == "skipped" and step == "tests":
            skipped_reason = (rest or "").strip() or "skipped"

    durations = {
        name: (end_at[name] - start_at[name]) if start_at[name] is not None and end_at[name] is not None else None
        for name in STEP_NAMES
    }
    return {
        "build": exit_codes["build"],
        "tests": exit_codes["tests"],
        "tests_skipped_reason": skipped_reason,
        "started": started,
        "durations": durations,
    }


def step_output(logs: str, step: str) -> str:
    """The log text between a step's start marker and its end marker (or the end of the log)."""
    lines = logs.splitlines()
    start_idx: int | None = None
    for index, line in enumerate(lines):
        match = _MARKER_RE.match(line.strip())
        if not match or match.group("step") != step:
            continue
        if match.group("event") == "start":
            start_idx = index + 1
        elif start_idx is not None:
            return "\n".join(lines[start_idx:index])
    return "\n".join(lines[start_idx:]) if start_idx is not None else ""


def output_tail(text: str, lines: int = OUTPUT_TAIL_LINES, chars: int = OUTPUT_TAIL_CHARS) -> str:
    tail = "\n".join(text.splitlines()[-lines:])
    return tail[-chars:]


# ---------------------------------------------------------------------- workspace tar


def _should_skip(name: str) -> bool:
    return name in SANDBOX_IGNORED_DIRS


def build_workspace_tar(workspace: Path, prefix: str = "workspace") -> bytes:
    """In-memory tar of the working copy, rooted at ``<prefix>/`` (ignored directories excluded).

    Symlinks are stored as symlinks (never followed) and every entry is owned by root.
    """
    workspace = Path(workspace)
    if not workspace.is_dir():
        raise SandboxError(f"Sandbox workspace does not exist or is not a directory: {workspace}")
    buffer = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        root = tarfile.TarInfo(prefix + "/")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        root.mtime = int(time.time())
        tar.addfile(root)
        for directory, dirnames, filenames in os.walk(workspace):
            dirnames[:] = sorted(d for d in dirnames if not _should_skip(d))
            rel_dir = Path(directory).relative_to(workspace)
            for dirname in dirnames:
                tar.add(Path(directory) / dirname, arcname=_arcname(prefix, rel_dir / dirname), recursive=False, filter=_root_owned)
            for filename in sorted(filenames):
                source = Path(directory) / filename
                try:
                    if source.is_file() and not source.is_symlink():
                        total += source.stat().st_size
                    if total > MAX_WORKSPACE_BYTES:
                        raise SandboxError(
                            f"Workspace {workspace} exceeds {MAX_WORKSPACE_BYTES // (1024 * 1024)} MB and cannot be "
                            "streamed into the sandbox; remove build artefacts or large data files."
                        )
                    tar.add(source, arcname=_arcname(prefix, rel_dir / filename), recursive=False, filter=_root_owned)
                except OSError as exc:
                    log.warning("Skipping unreadable file %s: %s", source, exc)
    return buffer.getvalue()


def _arcname(prefix: str, relative: Path) -> str:
    return f"{prefix}/{relative.as_posix()}"


def _root_owned(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    return info


# ---------------------------------------------------------------------- provider


class DockerSandboxProvider(SandboxProvider):
    """Runs the sandbox in the local Docker daemon (``docker.from_env()`` unless a client is injected)."""

    name = "docker"

    def __init__(self, settings: Settings | None = None, client: Any | None = None) -> None:
        self.settings = settings or get_settings()
        self._client = client

    # ------------------------------------------------------------------ public API

    def health(self) -> tuple[bool, str]:
        try:
            client = self._get_client()
            client.ping()
        except SandboxError as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001 - any daemon problem means "not available"
            return False, f"Docker daemon not reachable: {exc}"
        version = self._daemon_version(client)
        return True, f"Docker daemon reachable{f' (server {version})' if version else ''}"

    def run(self, request: SandboxRequest) -> SandboxResult:
        image = self.image_for(request.ecosystem)
        workspace = Path(request.workspace_path)
        script = build_script(request)
        archive = build_workspace_tar(workspace)
        client = self._get_client()
        container = self._create_container(client, image, script.text, request)
        container_id = getattr(container, "id", None)
        started = time.monotonic()
        log.info(
            "Sandbox %s started for %s (%s, %d KB workspace, timeout %ds, tests %s)",
            _short(container_id), request.dependency_file, image, len(archive) // 1024, request.timeout_seconds,
            "enabled" if script.test_command else f"skipped: {script.tests_skipped_reason}",
        )
        try:
            self._copy_workspace_in(container, archive)
            container.start()
            timed_out = self._wait(container, request.timeout_seconds)
            logs = self._collect_logs(container)
            artifacts = self._collect_artifacts(container, request) if not timed_out else {}
        finally:
            self._remove(container)
        result = self._build_result(script, image, logs, container_id, timed_out, request.timeout_seconds, artifacts)
        log.info(
            "Sandbox %s finished in %.1fs: build %s, tests %s%s",
            _short(container_id), time.monotonic() - started, result.build.status, result.tests.status,
            " (timed out)" if timed_out else "",
        )
        return result

    def image_for(self, ecosystem: str) -> str:
        if ecosystem == Ecosystem.PYPI:
            return self.settings.docker_python_image
        if ecosystem == Ecosystem.NPM:
            return self.settings.docker_node_image
        raise SandboxError(f"Unsupported ecosystem for the Docker sandbox: {ecosystem!r} (supported: PyPI, npm)")

    # ------------------------------------------------------------------ docker plumbing

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import docker

                self._client = docker.from_env()
            except Exception as exc:  # noqa: BLE001 - docker.errors.DockerException and friends
                raise SandboxError(
                    "Docker is not available: could not connect to the Docker daemon "
                    f"({exc}). Start Docker (Docker Desktop / dockerd) or set DOCKER_HOST."
                ) from exc
        return self._client

    @staticmethod
    def _daemon_version(client: Any) -> str | None:
        try:
            return str(client.version().get("Version") or "") or None
        except Exception:  # noqa: BLE001
            return None

    def _create_container(self, client: Any, image: str, script: str, request: SandboxRequest) -> Any:
        kwargs = self.container_kwargs(image, script, request)
        try:
            return client.containers.create(image, **kwargs)
        except Exception as exc:  # noqa: BLE001
            if not _is_image_not_found(exc):
                raise SandboxError(f"Docker could not create the sandbox container from {image}: {exc}") from exc
        self._pull_image(client, image)
        try:
            return client.containers.create(image, **kwargs)
        except Exception as exc:  # noqa: BLE001
            raise SandboxError(f"Docker could not create the sandbox container from {image}: {exc}") from exc

    def container_kwargs(self, image: str, script: str, request: SandboxRequest) -> dict[str, Any]:
        """The hardened ``containers.create`` keyword arguments (no host mounts, no capabilities)."""
        return {
            "command": ["sh", "-c", script],
            "working_dir": CONTAINER_WORKDIR,
            "network_mode": "bridge",
            "mem_limit": self.settings.docker_memory_limit,
            "nano_cpus": int(self.settings.docker_cpu_limit * 1e9),
            "pids_limit": 512,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "environment": dict(SANDBOX_ENVIRONMENT),
            "labels": {"sentinel-chain": "sandbox", **{str(k): str(v) for k, v in request.labels.items()}},
        }

    @staticmethod
    def _pull_image(client: Any, image: str) -> None:
        log.info("Image %s not present locally; pulling it (the first validation can take a few minutes)", image)
        try:
            client.images.pull(image)
        except Exception as exc:  # noqa: BLE001
            raise SandboxError(
                f"Docker could not pull the sandbox image {image}: {exc}. "
                f"Check the network connection or run `docker pull {image}` manually."
            ) from exc
        log.info("Image %s pulled", image)

    @staticmethod
    def _copy_workspace_in(container: Any, archive: bytes) -> None:
        try:
            ok = container.put_archive("/", archive)
        except Exception as exc:  # noqa: BLE001
            raise SandboxError(f"Docker could not copy the workspace into the sandbox: {exc}") from exc
        if ok is False:
            raise SandboxError("Docker rejected the workspace archive (put_archive returned False)")

    @staticmethod
    def _wait(container: Any, timeout_seconds: int) -> bool:
        """Block until the container exits; True when the timeout hit (the container is then killed)."""
        import requests

        try:
            container.wait(timeout=timeout_seconds)
            return False
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            log.warning("Sandbox %s exceeded %ds; killing the container", _short(getattr(container, "id", None)), timeout_seconds)
            try:
                container.kill()
            except Exception as exc:  # noqa: BLE001 - it may already be gone
                log.warning("Could not kill sandbox container: %s", exc)
            return True

    @staticmethod
    def _collect_logs(container: Any) -> str:
        try:
            raw = container.logs(stdout=True, stderr=True) or b""
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not read sandbox logs: %s", exc)
            return ""
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="replace")
        truncated = len(raw) > MAX_LOG_BYTES
        text = raw[-MAX_LOG_BYTES:].decode("utf-8", errors="replace")
        return f"[log truncated: first {len(raw) - MAX_LOG_BYTES} bytes dropped]\n{text}" if truncated else text

    @staticmethod
    def _collect_artifacts(container: Any, request: SandboxRequest) -> dict[str, str]:
        """Copy regenerated files (npm lock file) out of the container: {relative_path: content}."""
        if request.ecosystem != Ecosystem.NPM:
            return {}
        manifest_dir = PurePosixPath(request.dependency_file).parent
        relative = (manifest_dir / LOCK_FILE).as_posix()
        container_path = f"{CONTAINER_WORKDIR}/{relative}"
        try:
            stream, _stat = container.get_archive(container_path)
            raw = b"".join(stream)
        except Exception as exc:  # noqa: BLE001 - a missing lock file is not an error
            log.info("No %s to copy back from the sandbox (%s)", relative, exc.__class__.__name__)
            return {}
        content = _first_file_from_tar(raw)
        return {relative: content} if content is not None else {}

    @staticmethod
    def _remove(container: Any) -> None:
        try:
            container.remove(force=True)
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not remove sandbox container %s: %s", _short(getattr(container, "id", None)), exc)

    # ------------------------------------------------------------------ result assembly

    @staticmethod
    def _build_result(
        script: SandboxScript,
        image: str,
        logs: str,
        container_id: str | None,
        timed_out: bool,
        timeout_seconds: int,
        artifacts: dict[str, str],
    ) -> SandboxResult:
        markers = parse_step_markers(logs)
        build = _step_result("build", script.build_command, markers, logs, timed_out, timeout_seconds)
        tests = _step_result("tests", script.test_command, markers, logs, timed_out, timeout_seconds)
        return SandboxResult(
            build=build, tests=tests, image=image, logs=logs, container_id=container_id, timed_out=timed_out, artifacts=artifacts
        )


def _step_result(
    name: str, command: str | None, markers: dict[str, Any], logs: str, timed_out: bool, timeout_seconds: int
) -> StepResult:
    exit_code = markers[name]
    duration = markers["durations"].get(name) or 0.0
    tail = output_tail(step_output(logs, name))
    if exit_code is not None:
        status = CheckResult.PASS if exit_code == 0 else CheckResult.FAIL
        note = None if exit_code == 0 else f"{name} command exited with code {exit_code}"
        return StepResult(name, status, command, exit_code, duration, tail, note)
    if name == "tests" and markers["tests_skipped_reason"]:
        return StepResult(name, CheckResult.SKIPPED, command, None, 0.0, "", markers["tests_skipped_reason"])
    if timed_out:
        phase = "during this step" if markers["started"][name] else "before this step started"
        note = f"timed out after {timeout_seconds} s ({phase})"
    else:
        note = "no result marker in the sandbox output (container crashed or was interrupted)"
    return StepResult(name, CheckResult.UNKNOWN, command, None, duration, tail, note)


def _first_file_from_tar(raw: bytes) -> str | None:
    try:
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            for member in tar.getmembers():
                if member.isfile():
                    handle = tar.extractfile(member)
                    return handle.read().decode("utf-8", errors="replace") if handle else None
    except (tarfile.TarError, OSError):
        return None
    return None


def _is_image_not_found(exc: Exception) -> bool:
    try:
        import docker.errors

        return isinstance(exc, docker.errors.ImageNotFound)
    except Exception:  # noqa: BLE001 - docker SDK missing: fall back to the class name
        return exc.__class__.__name__ == "ImageNotFound"


def _short(container_id: str | None) -> str:
    return (container_id or "?")[:12]


__all__ = [
    "DockerSandboxProvider",
    "SandboxScript",
    "build_python_script",
    "build_node_script",
    "build_script",
    "build_workspace_tar",
    "parse_step_markers",
    "step_output",
    "output_tail",
    "SANDBOX_IGNORED_DIRS",
    "SANDBOX_ENVIRONMENT",
]
