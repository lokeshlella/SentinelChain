"""Health-check endpoints for the application and its backing services."""

from __future__ import annotations

import httpx
from fastapi import APIRouter

from app import __version__
from app.core.config import get_settings
from app.db.neo4j import check_neo4j
from app.db.session import check_database
from app.schemas.common import HealthResponse, ServiceStatus

router = APIRouter(tags=["health"])


def _check_ollama() -> tuple[bool, str]:
    settings = get_settings()
    try:
        response = httpx.get(f"{settings.ollama_base_url}/api/tags", timeout=5)
        response.raise_for_status()
        models = [m.get("name") for m in response.json().get("models", [])]
        if settings.ollama_model in models or any(m.startswith(settings.ollama_model) for m in models):
            return True, f"model '{settings.ollama_model}' available"
        return False, f"reachable but model '{settings.ollama_model}' not pulled (available: {models or 'none'})"
    except Exception as exc:  # noqa: BLE001
        return False, f"unreachable at {settings.ollama_base_url}: {str(exc)[:120]}"


def _check_docker() -> tuple[bool, str]:
    try:
        import docker  # imported lazily so the API still starts without the docker SDK

        client = docker.from_env(timeout=5)
        version = client.version()
        return True, f"docker {version.get('Version', '?')}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc).splitlines()[0][:160]


def _check_github() -> tuple[bool, str]:
    settings = get_settings()
    if not settings.github_token:
        return False, "GITHUB_TOKEN not configured (PR creation unavailable)"
    return True, "token configured"


@router.get("/health", response_model=HealthResponse, summary="Liveness + dependency health")
def health() -> HealthResponse:
    settings = get_settings()
    checks = {
        "postgresql": check_database(),
        "neo4j": check_neo4j(),
        "ollama": _check_ollama(),
        "docker": _check_docker(),
        "github": _check_github(),
    }
    services = [ServiceStatus(name=name, ok=ok, detail=detail) for name, (ok, detail) in checks.items()]
    # PostgreSQL is mandatory; everything else is optional and only degrades functionality.
    status = "ok" if checks["postgresql"][0] else "degraded"
    return HealthResponse(
        status=status,
        app=settings.app_name,
        version=__version__,
        environment=settings.app_env,
        services=services,
    )


@router.get("/health/live", summary="Simple liveness probe")
def live() -> dict:
    return {"status": "ok"}
