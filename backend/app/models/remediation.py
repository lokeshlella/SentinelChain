from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, utcnow


class Remediation(Base):
    __tablename__ = "remediations"

    remediation_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.finding_id", ondelete="CASCADE"), nullable=False, index=True
    )
    current_version: Mapped[str | None] = mapped_column(String(100))
    recommended_version: Mapped[str | None] = mapped_column(String(100))
    alternative_package: Mapped[str | None] = mapped_column(String(255))
    recommendation: Mapped[str | None] = mapped_column(Text)
    confidence_score: Mapped[float | None] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="PENDING", index=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Deterministic candidate information (fixed versions from OSV, registry lookups, ...).
    candidates: Mapped[dict | None] = mapped_column(JSON)
    # Structured RemediationAgent output.
    ai_result: Mapped[dict | None] = mapped_column(JSON)
    # The concrete file modification: {"file": ..., "before": ..., "after": ..., "diff": ..., "workspace": ...}
    proposed_change: Mapped[dict | None] = mapped_column(JSON)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    finding: Mapped["Finding"] = relationship(back_populates="remediations")  # noqa: F821
    validations: Mapped[list["Validation"]] = relationship(  # noqa: F821
        back_populates="remediation", cascade="all, delete-orphan"
    )
    pull_requests: Mapped[list["PullRequest"]] = relationship(  # noqa: F821
        back_populates="remediation", cascade="all, delete-orphan"
    )
