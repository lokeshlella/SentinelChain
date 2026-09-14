from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, utcnow


class PullRequest(Base):
    __tablename__ = "pull_requests"

    pr_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    remediation_id: Mapped[int] = mapped_column(
        ForeignKey("remediations.remediation_id", ondelete="CASCADE"), nullable=False, index=True
    )
    pr_url: Mapped[str | None] = mapped_column(Text)
    pr_number: Mapped[int | None] = mapped_column()
    branch_name: Mapped[str | None] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str | None] = mapped_column(Text)
    # Evidence report (JSON) captured at PR creation time.
    evidence: Mapped[dict | None] = mapped_column(JSON)
    review_status: Mapped[str] = mapped_column(String(20), nullable=False, default="DRAFT")
    # Manual instructions when GitHub PR creation is unavailable.
    instructions: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    remediation: Mapped["Remediation"] = relationship(back_populates="pull_requests")  # noqa: F821
