from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import deps
from app.core.exceptions import NotFoundError
from app.models import Vulnerability
from app.schemas.entities import VulnerabilityDetail

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("/by-identifier/{identifier}", response_model=VulnerabilityDetail)
def get_vulnerability_by_identifier(identifier: str, db: Session = deps.DbDep):
    row = db.scalar(select(Vulnerability).where(Vulnerability.identifier == identifier))
    if row is None:
        raise NotFoundError(f"Vulnerability {identifier} not found")
    return VulnerabilityDetail.model_validate(row)


@router.get("/{vulnerability_id}", response_model=VulnerabilityDetail)
def get_vulnerability(vulnerability_id: int, db: Session = deps.DbDep):
    row = db.get(Vulnerability, vulnerability_id)
    if row is None:
        raise NotFoundError(f"Vulnerability {vulnerability_id} not found")
    return VulnerabilityDetail.model_validate(row)
