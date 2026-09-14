"""An in-memory stand-in for the docker SDK client used by the sandbox unit tests.

Records every ``containers.create`` call (image + keyword arguments), the archives
streamed in with ``put_archive`` and the lifecycle calls (start / wait / kill / remove),
and answers ``logs`` / ``get_archive`` with canned data.
"""

from __future__ import annotations

import io
import tarfile
from typing import Any

import docker.errors
import requests

PASSING_PYTHON_LOGS = """::step build start 1700000000
Collecting requests==2.33.0 (from -r requirements.txt (line 1))
  Downloading requests-2.33.0-py3-none-any.whl.metadata (5.1 kB)
Installing collected packages: requests
Successfully installed requests-2.33.0
WARNING: Running pip as the 'root' user can result in broken permissions.
::step build end 0 1700000012
::step tests start 1700000012
.................                                                        [100%]
17 passed in 0.10s
::step tests end 0 1700000015
"""

FAILING_BUILD_LOGS = """::step build start 1700000000
ERROR: Could not find a version that satisfies the requirement requests==99.0.0 (from versions: 2.30.0, 2.31.0)
ERROR: No matching distribution found for requests==99.0.0
::step build end 1 1700000004
::step tests skipped build failed
"""

FAILING_TESTS_LOGS = """::step build start 1700000000
Successfully installed requests-2.33.0
::step build end 0 1700000010
::step tests start 1700000010
F.
FAILED tests/test_client.py::test_get - AssertionError
1 failed, 1 passed in 0.20s
::step tests end 1 1700000013
"""

SKIPPED_TESTS_LOGS = """::step build start 1700000000
added 1 package in 2s
::step build end 0 1700000002
::step tests skipped package.json has no test script
"""

TIMEOUT_DURING_TESTS_LOGS = """::step build start 1700000000
Successfully installed requests-2.33.0
::step build end 0 1700000010
::step tests start 1700000010
tests/test_slow.py .
"""


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
        self.wait_calls: list[int | None] = []

    def put_archive(self, path: str, data: bytes) -> bool:
        self.archives.append((path, data))
        return True

    def start(self) -> None:
        self.started = True

    def wait(self, timeout: int | None = None) -> dict[str, Any]:
        self.wait_calls.append(timeout)
        if self.client.wait_timeout:
            raise requests.exceptions.ConnectionError("UnixHTTPConnectionPool: Read timed out.")
        return {"StatusCode": 0}

    def kill(self) -> None:
        self.killed = True

    def logs(self, stdout: bool = True, stderr: bool = True) -> bytes:
        return self.client.logs

    def get_archive(self, path: str):
        for name, content in self.client.archive_files.items():
            if path.endswith(name):
                return iter([tar_bytes({name.rsplit("/", 1)[-1]: content})]), {"name": name, "size": len(content)}
        raise docker.errors.NotFound(f"no such file: {path}")

    def remove(self, force: bool = False) -> None:
        self.removed = {"force": force}


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
    def __init__(
        self,
        *,
        logs: str | bytes = PASSING_PYTHON_LOGS,
        wait_timeout: bool = False,
        images_present: tuple[str, ...] = ("python:3.12-slim", "node:20-slim"),
        pull_error: Exception | None = None,
        create_error: Exception | None = None,
        archive_files: dict[str, bytes] | None = None,
        ping_error: Exception | None = None,
    ) -> None:
        self.logs = logs.encode() if isinstance(logs, str) else logs
        self.wait_timeout = wait_timeout
        self.create_error = create_error
        self.archive_files = archive_files or {}
        self.ping_error = ping_error
        self.images = FakeImages(set(images_present), pull_error)
        self.containers = FakeContainers(self)

    def ping(self) -> bool:
        if self.ping_error is not None:
            raise self.ping_error
        return True

    def version(self) -> dict[str, Any]:
        return {"Version": "fake-1.0"}

    @property
    def last_container(self) -> FakeContainer:
        return self.containers.created[-1]
