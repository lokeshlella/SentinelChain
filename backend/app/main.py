"""Sentinel Chain — FastAPI application entry point."""

from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.router import api_router
from app.core.config import get_settings
from app.core.exceptions import SentinelError
from app.core.logging import configure_logging

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("sentinel.app")


def mark_interrupted_jobs() -> None:
    """Background jobs do not survive a restart: every in-progress row is marked FAILED with a reason."""
    from app.db.session import get_session_factory
    from app.services.jobs import sweep_stale_jobs

    try:
        with get_session_factory()() as db:
            counts = sweep_stale_jobs(db, settings, everything=True)
        if any(counts.values()):
            logger.warning("Marked jobs interrupted by restart: %s", ", ".join(f"{k}={v}" for k, v in counts.items() if v))
    except Exception as exc:  # noqa: BLE001 - the database may be down; health reports it
        logger.warning("Could not sweep interrupted jobs: %s", str(exc).splitlines()[0][:160])


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s v%s (%s)", settings.app_name, __version__, settings.app_env)
    logger.info("Workspace: %s", settings.workspace_path)
    logger.info("Ollama: %s (model=%s)", settings.ollama_base_url, settings.ollama_model)
    if settings.app_env != "test":
        mark_interrupted_jobs()
    yield
    logger.info("Shutting down")


app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="Agentic AI for Secure Software Supply Chains — V1 API",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,  # no cookies/sessions are used; keep the CORS surface minimal (audit F-17)
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_key_guard(request: Request, call_next):
    """Optional shared-secret authentication (audit F-17).

    The API clones arbitrary URLs and starts containers; when it is exposed beyond localhost,
    set API_KEY and send it as ``X-API-Key`` (or ``?api_key=``). Health endpoints stay open
    so orchestrators can probe them; the interactive docs stay reachable but calls need the key.
    """
    expected = settings.api_key
    path = request.url.path
    if expected and path.startswith(settings.api_prefix) and not path.startswith(f"{settings.api_prefix}/health"):
        provided = request.headers.get("x-api-key") or request.query_params.get("api_key")
        if not provided or not secrets.compare_digest(provided, expected):
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "message": "A valid X-API-Key header is required", "details": {}},
            )
    return await call_next(request)


@app.exception_handler(SentinelError)
async def sentinel_error_handler(_: Request, exc: SentinelError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.__class__.__name__, "message": exc.message, "details": exc.details},
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"error": "InternalServerError", "message": str(exc)[:500], "details": {}},
    )


app.include_router(api_router, prefix=settings.api_prefix)


@app.get("/", include_in_schema=False)
def root() -> dict:
    return {"app": settings.app_name, "version": __version__, "docs": "/docs", "api": settings.api_prefix}
