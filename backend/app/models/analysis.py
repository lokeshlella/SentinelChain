from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, utcnow


class Analysis(Base):
    __tablename__ = "analyses"

    analysis_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.repository_id", ondelete="CASCADE"), nullable=False, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING", index=True)
    overall_risk: Mapped[str | None] = mapped_column(String(20))
    triggered_by: Mapped[str] = mapped_column(String(50), nullable=False, default="api")
    # Per-stage status: {"repository": "OK", "dependencies": "OK", "vulnerabilities": "UNAVAILABLE", ...}
    stages: Mapped[dict | None] = mapped_column(JSON)
    # Counters and human-readable notes (dependencies extracted, vulnerable count, ...).
    summary: Mapped[dict | None] = mapped_column(JSON)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    repository: Mapped["Repository"] = relationship(back_populates="analyses")  # noqa: F821
    dependencies: Mapped[list["Dependency"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
