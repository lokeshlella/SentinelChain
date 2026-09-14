from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, utcnow


class Finding(Base):
    """A vulnerable dependency observed during one analysis."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("analysis_id", "dependency_id", "vulnerability_id", name="uq_finding_identity"),
    )

    finding_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True
    )
    dependency_id: Mapped[int] = mapped_column(
        ForeignKey("dependencies.dependency_id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.vulnerability_id", ondelete="CASCADE"), nullable=False, index=True
    )
    impact_level: Mapped[str | None] = mapped_column(String(20))
    risk_level: Mapped[str | None] = mapped_column(String(20), index=True)
    # Component paths observed to reference the dependency (FACT, derived from source scanning).
    affected_components: Mapped[list | None] = mapped_column(JSON)
    # Source files / lines referencing the dependency: [{"file": ..., "line": ..., "snippet": ...}]
    usage_evidence: Mapped[list | None] = mapped_column(JSON)
    # Human-readable reasoning assembled from the AI agents (INFERENCE).
    reasoning: Mapped[str | None] = mapped_column(Text)
    # Structured agent outputs: {"dependency_analysis": {...}, "impact": {...}, "risk": {...}}
    ai_results: Mapped[dict | None] = mapped_column(JSON)
    ai_status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    ai_error: Mapped[str | None] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    analysis: Mapped["Analysis"] = relationship(back_populates="findings")  # noqa: F821
    dependency: Mapped["Dependency"] = relationship(back_populates="findings")  # noqa: F821
    vulnerability: Mapped["Vulnerability"] = relationship()  # noqa: F821
    remediations: Mapped[list["Remediation"]] = relationship(  # noqa: F821
        back_populates="finding", cascade="all, delete-orphan"
    )
