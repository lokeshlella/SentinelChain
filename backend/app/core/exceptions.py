"""Domain exceptions. The API layer converts these into HTTP errors."""

from __future__ import annotations


class SentinelError(Exception):
    """Base class for all application errors."""

    status_code = 500

    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NotFoundError(SentinelError):
    status_code = 404


class ValidationFailedError(SentinelError):
    """Invalid user input (bad URL, unsupported project, ...)."""

    status_code = 400


class ConflictError(SentinelError):
    status_code = 409


class ExternalServiceError(SentinelError):
    """An optional external service (OSV, Ollama, Neo4j, Docker, GitHub) failed."""

    status_code = 502


class RepositoryError(SentinelError):
    status_code = 400


class UnsupportedProjectError(SentinelError):
    status_code = 422
