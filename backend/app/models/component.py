from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Component(Base):
    """A logical part of the application (a source directory, test suite, ...)."""

    __tablename__ = "components"
    __table_args__ = (UniqueConstraint("repository_id", "path", name="uq_component_repo_path"),)

    component_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.repository_id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    component_type: Mapped[str] = mapped_column(String(30), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    file_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    repository: Mapped["Repository"] = relationship(back_populates="components")  # noqa: F821
