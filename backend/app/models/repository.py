from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, utcnow


class Repository(Base):
    __tablename__ = "repositories"

    repository_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)  # github | local
    branch: Mapped[str | None] = mapped_column(String(255))
    # PENDING (ingestion queued/running) | READY | FAILED — ingestion runs as a background job.
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING", server_default="READY")
    error_message: Mapped[str | None] = mapped_column(Text)
    language: Mapped[str | None] = mapped_column(String(50))
    # Path of the clone / working copy that Sentinel Chain owns (never the user's original for github).
    local_path: Mapped[str | None] = mapped_column(Text)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    # Structure summary produced by the repository analyser (dependency files, source dirs, ...).
    profile: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    components: Mapped[list["Component"]] = relationship(  # noqa: F821
        back_populates="repository", cascade="all, delete-orphan"
    )
    dependencies: Mapped[list["Dependency"]] = relationship(  # noqa: F821
        back_populates="repository", cascade="all, delete-orphan"
    )
    analyses: Mapped[list["Analysis"]] = relationship(  # noqa: F821
        back_populates="repository", cascade="all, delete-orphan"
    )
