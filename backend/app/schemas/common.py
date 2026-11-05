from __future__ import annotations

from pydantic import BaseModel


class ServiceStatus(BaseModel):
    name: str
    ok: bool
    detail: str


class HealthResponse(BaseModel):
    status: str  # ok | degraded
    app: str
    version: str
    environment: str
    services: list[ServiceStatus]


class FeaturesResponse(BaseModel):
    phase: int  # 1 = Phase-1 build, 2 = complete product
    features: dict[str, bool]


class ErrorResponse(BaseModel):
    error: str
    message: str
    details: dict = {}


class MessageResponse(BaseModel):
    message: str
