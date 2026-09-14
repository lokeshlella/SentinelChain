"""An in-memory stand-in for the docker SDK client used by the sandbox unit tests.

The sandbox runs every step as ``container.exec_run(["sh", "-c", cmd])``; the fake answers
each exec from ``exec_results`` (keyed by step name — "build" / "tests" — matched on the
command text) and can simulate a step that hangs until the container is killed.
Records every ``containers.create`` call (image + keyword arguments), the archives streamed
in with ``put_archive``, every exec and the lifecycle calls (start / kill / remove).
"""

from __future__ import annotations

import io
import tarfile
import threading
from collections import namedtuple
from typing import Any

import docker.errors

ExecResult = namedtuple("ExecResult", ["exit_code", "output"])

# Realistic outputs for the two steps.
PIP_INSTALL_OK = b"Collecting requests==2.33.0\n  Downloading requests-2.33.0-py3-none-any.whl (65 kB)\nSuccessfully installed requests-2.33.0\n"
PIP_INSTALL_FAIL = b"ERROR: Could not find a version that satisfies the requirement requests==99.0.0\nERROR: No matching distribution found for requests==99.0.0\n"
PYTEST_OK = b".................                                                        [100%]\n17 passed in 0.10s\n"
PYTEST_FAIL = b"F.\nFAILED tests/test_client.py::test_get - AssertionError\n1 failed, 1 passed in 0.20s\n"
NPM_INSTALL_OK = b"added 1 package in 2s\n"


def tar_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def tar_names(data: bytes) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return tar.getnames()


class FakeContainer:
    def __init__(self, client: "FakeDockerClient", image: str, kwargs: dict[str, Any]) -> None:
        self.client = client
        self.image = image
        self.kwargs = kwargs
        self.id = "fakecontainer0123456789abcdef"
        self.archives: list[tuple[str, bytes]] = []
        self.started = False
        self.killed = False
        self.removed: dict[str, Any] | None = None
        self.execs: list[dict[str, Any]] = []
        self._killed_event = threading.Event()

    def put_archive(self, path: str, data: bytes) -> bool:
        self.archives.append((path, data))
        return True

    def start(self) -> None:
        self.started = True

    def exec_run(self, cmd, **kwargs) -> ExecResult:
        self.execs.append({"cmd": list(cmd), **kwargs})
        step = self.client.step_for(cmd)
        if step in self.client.hang_on:
            # Behave like a real exec: block until the container is killed, then report the kill.
            self._killed_event.wait()
            return ExecResult(137, self.client.hang_output)
        if self.client.exec_error is not None:
            raise self.client.exec_error
        exit_code, output = self.client.exec_results.get(step, (0, b""))
        return ExecResult(exit_code, output)

    def kill(self) -> None:
        self.killed = True
        self._killed_event.set()

    def get_archive(self, path: str):
        for name, content in self.client.archive_files.items():
            if path.endswith(name):
                return iter([tar_bytes({name.rsplit("/", 1)[-1]: content})]), {"name": name, "size": len(content)}
        raise docker.errors.NotFound(f"no such file: {path}")

    def remove(self, force: bool = False) -> None:
        self.removed = {"force": force}
        self._killed_event.set()


class FakeContainers:
    def __init__(self, client: "FakeDockerClient") -> None:
        self.client = client
        self.created: list[FakeContainer] = []

    def create(self, image: str, **kwargs: Any) -> FakeContainer:
        if image not in self.client.images.present:
            raise docker.errors.ImageNotFound(f"No such image: {image}")
        if self.client.create_error is not None:
            raise self.client.create_error
        container = FakeContainer(self.client, image, kwargs)
        self.created.append(container)
        return container


class FakeImages:
    def __init__(self, present: set[str], pull_error: Exception | None) -> None:
        self.present = set(present)
        self.pull_error = pull_error
        self.pulled: list[str] = []

    def pull(self, image: str):
        self.pulled.append(image)
        if self.pull_error is not None:
            raise self.pull_error
        self.present.add(image)
        return image


class FakeDockerClient:
    """``exec_results``: {"build": (exit_code, output_bytes), "tests": (...)}; ``hang_on``: steps that block until killed."""

    def __init__(
        self,
        *,
        exec_results: dict[str, tuple[int | None, bytes]] | None = None,
        hang_on: set[str] | frozenset[str] = frozenset(),
        hang_output: bytes = b"",
        exec_error: Exception | None = None,
        images_present: tuple[str, ...] = ("python:3.12-slim", "node:20-slim"),
        pull_error: Exception | None = None,
        create_error: Exception | None = None,
        archive_files: dict[str, bytes] | None = None,
        ping_error: Exception | None = None,
    ) -> None:
        self.exec_results = exec_results if exec_results is not None else {"build": (0, PIP_INSTALL_OK), "tests": (0, PYTEST_OK)}
        self.hang_on = set(hang_on)
        self.hang_output = hang_output
        self.exec_error = exec_error
        self.create_error = create_error
        self.archive_files = archive_files or {}
        self.ping_error = ping_error
        self.images = FakeImages(set(images_present), pull_error)
        self.containers = FakeContainers(self)

    @staticmethod
    def step_for(cmd) -> str:
        text = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        is_build = ("pip install" in text and " -r " in text) or "npm install" in text
        return "build" if is_build else "tests"

    def ping(self) -> bool:
        if self.ping_error is not None:
            raise self.ping_error
        return True

    def version(self) -> dict[str, Any]:
        return {"Version": "fake-29.0"}

    @property
    def last_container(self) -> FakeContainer:
        return self.containers.created[-1]
