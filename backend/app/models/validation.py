from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, utcnow


class Validation(Base):
    """Result of validating a proposed change inside the Docker sandbox."""

    __tablename__ = "validations"

    validation_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    remediation_id: Mapped[int] = mapped_column(
        ForeignKey("remediations.remediation_id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    build_status: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN")
    test_status: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN")
    security_scan_status: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN")
    overall_result: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN")
    logs_path: Mapped[str | None] = mapped_column(Text)
    # Details: image, commands, durations, exit codes, security scan findings, ...
    details: Mapped[dict | None] = mapped_column(JSON)
    error_message: Mapped[str | None] = mapped_column(Text)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    remediation: Mapped["Remediation"] = relationship(back_populates="validations")  # noqa: F821
