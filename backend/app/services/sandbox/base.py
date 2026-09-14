"""Sandbox provider contract (Docker in V1)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from app.models.enums import CheckResult


@dataclass
class SandboxRequest:
    workspace_path: Path  # temporary working copy that already contains the proposed change
    ecosystem: str  # "PyPI" | "npm"
    dependency_file: str  # relative path of the modified dependency file
    timeout_seconds: int = 600
    # Optional hints from the repository profile (e.g. {"has_pytest": True, "npm_test_script": "jest"}).
    hints: dict = field(default_factory=dict)
    labels: dict = field(default_factory=dict)


@dataclass
class StepResult:
    name: str  # "build" | "tests"
    status: CheckResult
    command: str | None = None
    exit_code: int | None = None
    duration_seconds: float = 0.0
    output_tail: str = ""  # last lines of output for quick display
    note: str | None = None  # why SKIPPED / UNKNOWN


@dataclass
class SandboxResult:
    build: StepResult
    tests: StepResult
    image: str
    logs: str = ""  # full combined log
    container_id: str | None = None
    timed_out: bool = False
    error: str | None = None  # sandbox infrastructure error (Docker unavailable, ...)
    # Files regenerated inside the sandbox that should be copied back (e.g. package-lock.json): {relative_path: content}
    artifacts: dict[str, str] = field(default_factory=dict)


class SandboxError(Exception):
    """Raised when the sandbox infrastructure itself is unavailable."""


class SandboxProvider(ABC):
    name: ClassVar[str]

    @abstractmethod
    def run(self, request: SandboxRequest) -> SandboxResult:
        """Install dependencies and run tests in isolation. Never raises for build/test failures —
        those are reported through StepResult; raises SandboxError only for infrastructure problems."""

    @abstractmethod
    def health(self) -> tuple[bool, str]: ...
