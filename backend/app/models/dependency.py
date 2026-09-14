from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, utcnow


class Dependency(Base):
    """A dependency observed in a repository during one analysis run.

    Dependencies are stored as a per-analysis snapshot (``analysis_id``) so that
    re-analysing a repository never deletes the findings / remediations that
    were produced for an earlier dependency state.
    """

    __tablename__ = "dependencies"
    __table_args__ = (
        UniqueConstraint(
            "analysis_id", "ecosystem", "package_name", "version", "source_file",
            name="uq_dependency_identity",
        ),
        Index("ix_dependency_pkg", "ecosystem", "package_name"),
    )

    dependency_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.repository_id", ondelete="CASCADE"), nullable=False, index=True
    )
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True
    )
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Concrete version when known (pinned or lock-file resolved); None when only a range is declared.
    version: Mapped[str | None] = mapped_column(String(100))
    # The raw specifier as written in the dependency file (e.g. ">=2.0,<3", "^4.17.15").
    version_spec: Mapped[str | None] = mapped_column(String(255))
    ecosystem: Mapped[str] = mapped_column(String(30), nullable=False)
    direct_or_transitive: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    source_file: Mapped[str] = mapped_column(Text, nullable=False)
    vulnerability_status: Mapped[str] = mapped_column(String(20), nullable=False, default="UNCHECKED")
    status_reason: Mapped[str | None] = mapped_column(Text)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    repository: Mapped["Repository"] = relationship(back_populates="dependencies")  # noqa: F821
    analysis: Mapped["Analysis"] = relationship(back_populates="dependencies")  # noqa: F821
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        back_populates="dependency", cascade="all, delete-orphan"
    )


class DependencyRelation(Base):
    """Parent -> child edge between two dependencies (from lock files)."""

    __tablename__ = "dependency_relations"
    __table_args__ = (
        UniqueConstraint("parent_dependency_id", "child_dependency_id", name="uq_dependency_relation"),
    )

    relation_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    parent_dependency_id: Mapped[int] = mapped_column(
        ForeignKey("dependencies.dependency_id", ondelete="CASCADE"), nullable=False, index=True
    )
    child_dependency_id: Mapped[int] = mapped_column(
        ForeignKey("dependencies.dependency_id", ondelete="CASCADE"), nullable=False, index=True
    )
    relation_type: Mapped[str] = mapped_column(String(30), nullable=False, default="depends_on")
