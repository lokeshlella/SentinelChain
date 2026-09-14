"""String enumerations shared by models, schemas and services.

Stored as plain strings so the schema stays portable (PostgreSQL + SQLite for tests).
"""

from __future__ import annotations

from enum import StrEnum


class SourceType(StrEnum):
    GITHUB = "github"
    LOCAL = "local"


class RepositoryStatus(StrEnum):
    PENDING = "PENDING"
    READY = "READY"
    FAILED = "FAILED"


class Ecosystem(StrEnum):
    PYPI = "PyPI"
    NPM = "npm"


class DependencyScope(StrEnum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


class VulnerabilityStatus(StrEnum):
    SAFE = "SAFE"
    VULNERABLE = "VULNERABLE"
    UNKNOWN = "UNKNOWN"
    UNCHECKED = "UNCHECKED"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class AnalysisStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class StageStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    OK = "OK"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class RiskLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class ImpactLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class AIStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    SKIPPED = "SKIPPED"


class RemediationStatus(StrEnum):
    PENDING = "PENDING"
    PROPOSED = "PROPOSED"
    FAILED = "FAILED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    PR_CREATED = "PR_CREATED"


class CheckResult(StrEnum):
    """Result of a single sandbox check (build / test / security)."""

    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"
    UNKNOWN = "UNKNOWN"


class ValidationStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class PullRequestStatus(StrEnum):
    DRAFT = "DRAFT"
    OPEN = "OPEN"
    MERGED = "MERGED"
    CLOSED = "CLOSED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"


class ComponentType(StrEnum):
    SOURCE = "source"
    TESTS = "tests"
    DOCS = "docs"
    CONFIG = "config"
    SCRIPTS = "scripts"
    OTHER = "other"
