"""Docker sandbox provider: installs the proposed dependency state and runs the tests in a container.

How a validation run works
--------------------------
1. The image is chosen by ecosystem (``settings.docker_python_image`` / ``docker_node_image``).
   **The first validation on a machine pulls the image** (``docker pull``), which can take a
   few minutes; later runs reuse the cached image.
2. A container is created with a hardened configuration (non-root user, read-only root
   filesystem with in-memory ``/workspace`` and ``/tmp``, no capabilities, no privilege
   escalation, memory / CPU / pid limits, ``bridge`` network by default so package registries
   are reachable — ``DOCKER_SANDBOX_NETWORK=none`` for vendored projects) and **no host
   mounts**: the working copy is streamed into the started container with ``put_archive``,
   owned by the sandbox user.
3. The container only runs a keep-alive process. **Every step (install, tests) is a separate
   ``docker exec``** driven from the host: the exit code comes from the Docker daemon, so
   nothing the repository prints to stdout can influence the verdict (a repository's own
   output used to be able to forge step markers — audit finding F-01).
4. A host-side deadline of ``request.timeout_seconds`` covers all steps; on timeout the
   container is killed and the interrupted step plus every later step is reported as
   UNKNOWN (never PASS), whatever the exec returned.
5. The combined log is assembled on the host from each step's captured output (last 2 MB
   kept), ``package-lock.json`` is copied back for npm projects and the container is always
   removed.

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
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout
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
#: Writable, in-memory locations inside the otherwise read-only container.
CONTAINER_HOME = f"{CONTAINER_WORKDIR}/.home"
CONTAINER_VENV = f"{CONTAINER_WORKDIR}/.venv"
TMP_TMPFS_SIZE = "256m"
MAX_LOG_BYTES = 2 * 1024 * 1024  # keep the tail of the combined log
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024  # a regenerated lock file larger than this is not copied back
MAX_WORKSPACE_BYTES = 256 * 1024 * 1024  # refuse to stream absurdly large working copies
OUTPUT_TAIL_LINES = 40
OUTPUT_TAIL_CHARS = 4000
NPM_PLACEHOLDER_TEST_SCRIPT = 'echo "Error: no test specified" && exit 1'
LOCK_FILE = "package-lock.json"
STEP_NAMES = ("build", "tests")
#: The container's own process does nothing; steps are ``docker exec``'d into it.
KEEPALIVE_COMMAND = ["sleep", "infinity"]
#: How long to wait for an exec to return after the container was killed on timeout.
KILL_GRACE_SECONDS = 10

SANDBOX_ENVIRONMENT = {
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "npm_config_update_notifier": "false",
    "CI": "1",
    # The root filesystem is read-only and the process is not root: every cache / config
    # location must point into the writable workspace tmpfs.
    "HOME": CONTAINER_HOME,
    "XDG_CACHE_HOME": f"{CONTAINER_HOME}/.cache",
    "PIP_CACHE_DIR": f"{CONTAINER_HOME}/.cache/pip",
    "npm_config_cache": f"{CONTAINER_HOME}/.npm",
    "TMPDIR": "/tmp",
}

# Python installs go into a virtualenv inside the workspace: the image's site-packages is on
# the read-only root filesystem and the sandbox user could not write there anyway.
PYTHON_INSTALL_CMD = f"python -m venv {CONTAINER_VENV} && {CONTAINER_VENV}/bin/python -m pip install --no-cache-dir -r {{file}}"
PYTHON_PYTEST_INSTALL_CMD = f"{CONTAINER_VENV}/bin/python -m pip install -q pytest"
PYTHON_TEST_CMD = f"{CONTAINER_VENV}/bin/python -m pytest -q"
NPM_INSTALL_CMD = "npm install --no-audit --no-fund"
NPM_TEST_CMD = "npm test"


# ---------------------------------------------------------------------- step plans


@dataclass(frozen=True)
class SandboxPlan:
    """The commands to ``docker exec`` in the sandbox (each one is a separate exec)."""

    build_command: str
    test_command: str | None  # None when tests are skipped
    tests_skipped_reason: str | None = None


# Backwards-compatible alias (earlier versions generated one shell script).
SandboxScript = SandboxPlan


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


def build_python_script(workspace: Path, dependency_file: str, hints: dict | None = None) -> SandboxPlan:
    """``pip install -r <file>`` then (when a test suite is detected) ``pytest -q``."""
    hints = hints or {}
    build_command = PYTHON_INSTALL_CMD.format(file=shlex.quote(dependency_file))
    run_tests, reason = _has_python_tests(workspace, hints)
    if not run_tests:
        return SandboxPlan(build_command, None, reason)
    parts = [] if _requirements_pin_pytest(workspace, dependency_file) else [PYTHON_PYTEST_INSTALL_CMD]
    parts.append(PYTHON_TEST_CMD)
    return SandboxPlan(build_command, " && ".join(parts))


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


def build_node_script(workspace: Path, dependency_file: str, hints: dict | None = None) -> SandboxPlan:
    """``npm install`` (refreshes the lock file) then ``npm test`` when a real test script exists.

    When the manifest lives in a sub-directory both commands change into it first (each
    step is its own exec, so the directory change is repeated).
    """
    hints = hints or {}
    manifest_dir = PurePosixPath(dependency_file).parent.as_posix()
    prefix = "" if manifest_dir in ("", ".") else f"cd {shlex.quote(manifest_dir)} && "
    build_command = prefix + NPM_INSTALL_CMD
    script = _npm_test_script(workspace, dependency_file, hints)
    if script is None:
        return SandboxPlan(build_command, None, "package.json has no test script")
    return SandboxPlan(build_command, prefix + NPM_TEST_CMD)


def build_plan(request: SandboxRequest) -> SandboxPlan:
    if request.ecosystem == Ecosystem.PYPI:
        return build_python_script(Path(request.workspace_path), request.dependency_file, request.hints)
    if request.ecosystem == Ecosystem.NPM:
        return build_node_script(Path(request.workspace_path), request.dependency_file, request.hints)
    raise SandboxError(f"Unsupported ecosystem for the Docker sandbox: {request.ecosystem!r} (supported: PyPI, npm)")


build_script = build_plan  # backwards-compatible alias


# ---------------------------------------------------------------------- output helpers


def output_tail(text: str, lines: int = OUTPUT_TAIL_LINES, chars: int = OUTPUT_TAIL_CHARS) -> str:
    tail = "\n".join(text.splitlines()[-lines:])
    return tail[-chars:]


# ---------------------------------------------------------------------- workspace tar


def _should_skip(name: str) -> bool:
    return name in SANDBOX_IGNORED_DIRS


def build_workspace_tar(workspace: Path, prefix: str = "workspace", *, uid: int = 0, gid: int = 0) -> bytes:
    """In-memory tar of the working copy, rooted at ``<prefix>/`` (ignored directories excluded).

    Symlinks are stored as symlinks (never followed) and every entry is owned by ``uid:gid``
    (the sandbox user, so installs can write next to the manifests).
    """
    workspace = Path(workspace)
    owned = _owned_by(uid, gid)
    if not workspace.is_dir():
        raise SandboxError(f"Sandbox workspace does not exist or is not a directory: {workspace}")
    buffer = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        root = tarfile.TarInfo(prefix + "/")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        root.mtime = int(time.time())
        tar.addfile(owned(root))
        for directory, dirnames, filenames in os.walk(workspace):
            dirnames[:] = sorted(d for d in dirnames if not _should_skip(d))
            rel_dir = Path(directory).relative_to(workspace)
            for dirname in dirnames:
                tar.add(Path(directory) / dirname, arcname=_arcname(prefix, rel_dir / dirname), recursive=False, filter=owned)
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
                    tar.add(source, arcname=_arcname(prefix, rel_dir / filename), recursive=False, filter=owned)
                except OSError as exc:
                    log.warning("Skipping unreadable file %s: %s", source, exc)
    return buffer.getvalue()


def _arcname(prefix: str, relative: Path) -> str:
    return f"{prefix}/{relative.as_posix()}"


def _owned_by(uid: int, gid: int):
    def _apply(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid, info.gid = uid, gid
        info.uname = info.gname = ""
        return info

    return _apply


def parse_user(spec: str) -> tuple[int, int]:
    """``"uid[:gid]"`` → (uid, gid); refuses root and non-numeric specs."""
    parts = str(spec).strip().split(":")
    try:
        uid = int(parts[0])
        gid = int(parts[1]) if len(parts) > 1 and parts[1] else uid
    except (ValueError, IndexError) as exc:
        raise SandboxError(f"DOCKER_SANDBOX_USER must be numeric 'uid[:gid]', got {spec!r}") from exc
    if uid == 0 or gid == 0:
        raise SandboxError("DOCKER_SANDBOX_USER must not be root (uid/gid 0)")
    return uid, gid


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
        plan = build_plan(request)
        uid, gid = parse_user(self.settings.docker_sandbox_user)
        archive = build_workspace_tar(workspace, uid=uid, gid=gid)
        client = self._get_client()
        container = self._create_container(client, image, request)
        container_id = getattr(container, "id", None)
        started = time.monotonic()
        deadline = started + max(1, int(request.timeout_seconds))
        log.info(
            "Sandbox %s started for %s (%s, %d KB workspace, timeout %ds, tests %s)",
            _short(container_id), request.dependency_file, image, len(archive) // 1024, request.timeout_seconds,
            "enabled" if plan.test_command else f"skipped: {plan.tests_skipped_reason}",
        )
        steps: list[_ExecOutcome] = []
        try:
            container.start()  # the /workspace tmpfs only exists on a started container
            self._copy_workspace_in(client, container, archive)
            build = self._exec_step(container, "build", plan.build_command, deadline)
            steps.append(build)
            if build.timed_out or build.exit_code is None:
                tests = _ExecOutcome("tests", plan.test_command, None, "", 0.0, timed_out=build.timed_out,
                                     skipped_reason=None, not_run_reason="build did not complete")
            elif build.exit_code != 0:
                tests = _ExecOutcome("tests", plan.test_command, None, "", 0.0, skipped_reason="build failed")
            elif plan.test_command is None:
                tests = _ExecOutcome("tests", None, None, "", 0.0, skipped_reason=plan.tests_skipped_reason)
            else:
                tests = self._exec_step(container, "tests", plan.test_command, deadline)
            steps.append(tests)
            timed_out = any(step.timed_out for step in steps)
            artifacts = self._collect_artifacts(container, request) if not timed_out else {}
        finally:
            self._remove(container)
        result = self._build_result(steps, image, container_id, timed_out, request.timeout_seconds, artifacts)
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

    def _create_container(self, client: Any, image: str, request: SandboxRequest) -> Any:
        kwargs = self.container_kwargs(image, request)
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

    def container_kwargs(self, image: str, request: SandboxRequest) -> dict[str, Any]:
        """The hardened ``containers.create`` keyword arguments (no host mounts, no capabilities).

        The container's own command is a keep-alive; the real work happens in ``exec``s.
        """
        uid, gid = parse_user(self.settings.docker_sandbox_user)
        network = self.settings.docker_sandbox_network.strip() or "bridge"
        if network not in ("bridge", "none"):
            raise SandboxError(f"DOCKER_SANDBOX_NETWORK must be 'bridge' or 'none', got {network!r}")
        return {
            "command": list(KEEPALIVE_COMMAND),
            "working_dir": CONTAINER_WORKDIR,
            "user": f"{uid}:{gid}",
            "network_mode": network,
            "read_only": bool(self.settings.docker_read_only_rootfs),
            # Writable in-memory areas: the workspace (installs happen there) and /tmp.
            "tmpfs": {
                CONTAINER_WORKDIR: f"rw,exec,size={self.settings.docker_workspace_tmpfs_size},uid={uid},gid={gid},mode=0755",
                "/tmp": f"rw,exec,size={TMP_TMPFS_SIZE},uid={uid},gid={gid},mode=1777",
            },
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

    def _copy_workspace_in(self, client: Any, container: Any, archive: bytes) -> None:
        """Stream the workspace tar into the running container through ``tar -x`` on an exec's stdin.

        ``put_archive`` is refused by the daemon for a read-only root filesystem (even when
        the target is a tmpfs), so the archive is written by the sandbox user itself into the
        writable ``/workspace`` tmpfs. No host path is ever mounted.
        """
        import socket as _socket

        api = client.api
        user = self.settings.docker_sandbox_user
        try:
            created = api.exec_create(container.id, ["tar", "-x", "-C", "/"], stdin=True, stdout=True, stderr=True, user=user)
            stream = api.exec_start(created["Id"], socket=True)
            raw = getattr(stream, "_sock", stream)
            raw.sendall(archive)
            raw.shutdown(_socket.SHUT_WR)  # EOF for tar; the pooled response releases the socket itself
            output = b"".join(iter(lambda: raw.recv(65536), b""))
            exit_code = api.exec_inspect(created["Id"]).get("ExitCode")
        except Exception as exc:  # noqa: BLE001
            raise SandboxError(f"Docker could not copy the workspace into the sandbox: {exc}") from exc
        if exit_code != 0:
            raise SandboxError(
                f"Extracting the workspace inside the sandbox failed (tar exit {exit_code}): {output.decode(errors='replace')[-300:]}"
            )

    @staticmethod
    def _exec_step(container: Any, name: str, command: str, deadline: float) -> "_ExecOutcome":
        """Run one step as ``docker exec`` and take its exit code from the daemon.

        The exec runs in a worker thread so the host can enforce the deadline: when it
        passes, the container is killed (which ends the exec) and the step is reported
        as timed out — the exit code the daemon then reports is deliberately ignored.
        """
        remaining = deadline - time.monotonic()
        started = time.monotonic()
        if remaining <= 0:
            return _ExecOutcome(name, command, None, "", 0.0, timed_out=True)
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"sandbox-{name}")
        future: Future = executor.submit(
            container.exec_run, ["sh", "-c", command], workdir=CONTAINER_WORKDIR,
            environment=dict(SANDBOX_ENVIRONMENT), stdout=True, stderr=True, demux=False,
        )
        timed_out = False
        exit_code: int | None = None
        output = b""
        try:
            exit_code, output = _unpack_exec(future.result(timeout=remaining))
        except FutureTimeout:
            timed_out = True
            log.warning("Sandbox %s: step %s exceeded the deadline; killing the container", _short(getattr(container, "id", None)), name)
            try:
                container.kill()
            except Exception as exc:  # noqa: BLE001 - it may already be gone
                log.warning("Could not kill sandbox container: %s", exc)
            try:  # collect whatever output the exec produced before the kill
                _code, output = _unpack_exec(future.result(timeout=KILL_GRACE_SECONDS))
            except Exception:  # noqa: BLE001
                output = b""
            exit_code = None
        except Exception as exc:  # noqa: BLE001 - daemon/transport failure during the exec
            raise SandboxError(f"Docker exec for step {name!r} failed: {exc}") from exc
        finally:
            executor.shutdown(wait=False)
        duration = round(time.monotonic() - started, 2)
        text = _decode_capped(output)
        return _ExecOutcome(name, command, exit_code, text, duration, timed_out=timed_out)

    @staticmethod
    def _collect_artifacts(container: Any, request: SandboxRequest) -> dict[str, str]:
        """Copy regenerated files (npm lock file) out of the container: {relative_path: content}.

        Read through an exec (``get_archive`` cannot read from the in-memory workspace of a
        read-only container); the file is capped at ``MAX_ARTIFACT_BYTES``.
        """
        if request.ecosystem != Ecosystem.NPM:
            return {}
        manifest_dir = PurePosixPath(request.dependency_file).parent
        relative = (manifest_dir / LOCK_FILE).as_posix()
        container_path = f"{CONTAINER_WORKDIR}/{relative}"
        try:
            exit_code, output = _unpack_exec(
                container.exec_run(["sh", "-c", f"head -c {MAX_ARTIFACT_BYTES} -- {shlex.quote(container_path)}"], stdout=True, stderr=False, demux=False)
            )
        except Exception as exc:  # noqa: BLE001 - a missing lock file is not an error
            log.info("No %s to copy back from the sandbox (%s)", relative, exc.__class__.__name__)
            return {}
        if exit_code != 0 or not output:
            log.info("No %s to copy back from the sandbox (exit %s)", relative, exit_code)
            return {}
        if len(output) >= MAX_ARTIFACT_BYTES:
            log.warning("%s exceeds %d bytes; not copied back", relative, MAX_ARTIFACT_BYTES)
            return {}
        return {relative: output.decode("utf-8", errors="replace")}

    @staticmethod
    def _remove(container: Any) -> None:
        try:
            container.remove(force=True)
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not remove sandbox container %s: %s", _short(getattr(container, "id", None)), exc)

    # ------------------------------------------------------------------ result assembly

    @staticmethod
    def _build_result(
        steps: list["_ExecOutcome"],
        image: str,
        container_id: str | None,
        timed_out: bool,
        timeout_seconds: int,
        artifacts: dict[str, str],
    ) -> SandboxResult:
        by_name = {step.name: step for step in steps}
        build = _step_result(by_name["build"], timeout_seconds)
        tests = _step_result(by_name["tests"], timeout_seconds)
        logs = _assemble_logs(steps, timed_out, timeout_seconds)
        return SandboxResult(
            build=build, tests=tests, image=image, logs=logs, container_id=container_id, timed_out=timed_out, artifacts=artifacts
        )


@dataclass
class _ExecOutcome:
    """Raw outcome of one exec'd step (exit code as reported by the Docker daemon)."""

    name: str
    command: str | None
    exit_code: int | None
    output: str
    duration_seconds: float
    timed_out: bool = False
    skipped_reason: str | None = None  # step deliberately not run (no tests, build failed)
    not_run_reason: str | None = None  # step could not run (earlier step did not complete)


def _step_result(outcome: _ExecOutcome, timeout_seconds: int) -> StepResult:
    """Map a raw outcome to a StepResult. A timed-out step is UNKNOWN whatever the exec returned."""
    tail = output_tail(outcome.output)
    if outcome.skipped_reason:
        return StepResult(outcome.name, CheckResult.SKIPPED, outcome.command, None, 0.0, "", outcome.skipped_reason)
    if outcome.timed_out:
        note = f"timed out after {timeout_seconds} s ({'during this step' if outcome.command and outcome.duration_seconds else 'before this step started'})"
        return StepResult(outcome.name, CheckResult.UNKNOWN, outcome.command, None, outcome.duration_seconds, tail, note)
    if outcome.not_run_reason:
        return StepResult(outcome.name, CheckResult.UNKNOWN, outcome.command, None, 0.0, "", outcome.not_run_reason)
    if outcome.exit_code is None:
        return StepResult(outcome.name, CheckResult.UNKNOWN, outcome.command, None, outcome.duration_seconds, tail,
                          "the Docker daemon reported no exit code for this step")
    if outcome.exit_code == 0:
        return StepResult(outcome.name, CheckResult.PASS, outcome.command, 0, outcome.duration_seconds, tail, None)
    return StepResult(outcome.name, CheckResult.FAIL, outcome.command, outcome.exit_code, outcome.duration_seconds, tail,
                      f"{outcome.name} command exited with code {outcome.exit_code}")


def _assemble_logs(steps: list[_ExecOutcome], timed_out: bool, timeout_seconds: int) -> str:
    """Host-written log: every header line is ours, the indented body is the step's raw output."""
    lines: list[str] = []
    for step in steps:
        lines.append(f"### step {step.name}: {step.command or '-'}")
        if step.skipped_reason:
            lines.append(f"[skipped: {step.skipped_reason}]")
        elif step.not_run_reason:
            lines.append(f"[not run: {step.not_run_reason}]")
        else:
            if step.output:
                lines.append(step.output.rstrip("\n"))
            if step.timed_out:
                lines.append(f"[killed: deadline of {timeout_seconds} s exceeded after {step.duration_seconds}s]")
            else:
                lines.append(f"[exit {step.exit_code} in {step.duration_seconds}s]")
        lines.append("")
    if timed_out:
        lines.append(f"[sandbox timed out after {timeout_seconds} s; unfinished steps are UNKNOWN]")
    text = "\n".join(lines)
    return text[-MAX_LOG_BYTES:]


def _unpack_exec(result: Any) -> tuple[int | None, bytes]:
    """Normalise ``ExecResult`` / tuples / dicts returned by the docker SDK (or fakes)."""
    exit_code = getattr(result, "exit_code", None)
    output = getattr(result, "output", None)
    if exit_code is None and output is None and isinstance(result, tuple) and len(result) == 2:
        exit_code, output = result
    if isinstance(output, str):
        output = output.encode("utf-8", errors="replace")
    return (int(exit_code) if exit_code is not None else None), (output or b"")


def _decode_capped(raw: bytes) -> str:
    if len(raw) > MAX_LOG_BYTES:
        return f"[output truncated: first {len(raw) - MAX_LOG_BYTES} bytes dropped]\n" + raw[-MAX_LOG_BYTES:].decode("utf-8", errors="replace")
    return raw.decode("utf-8", errors="replace")


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
    "SandboxPlan",
    "SandboxScript",
    "KEEPALIVE_COMMAND",
    "build_python_script",
    "build_node_script",
    "build_plan",
    "build_script",
    "build_workspace_tar",
    "parse_user",
    "output_tail",
    "SANDBOX_IGNORED_DIRS",
    "SANDBOX_ENVIRONMENT",
]
