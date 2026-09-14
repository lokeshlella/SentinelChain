"""Aggregates all route modules under the API prefix."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import analyses, dashboard, dependencies, findings, health, remediations, repositories, vulnerabilities

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(dashboard.router)
api_router.include_router(repositories.router)
api_router.include_router(analyses.router)
api_router.include_router(dependencies.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(findings.router)
api_router.include_router(remediations.router)
