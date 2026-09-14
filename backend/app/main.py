"""Sentinel Chain — FastAPI application entry point."""

from __future__ import annotations

import logging
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
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
