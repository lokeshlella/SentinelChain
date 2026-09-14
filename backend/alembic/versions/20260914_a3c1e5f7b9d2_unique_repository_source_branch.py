"""unique index on repositories (lower(source_url), coalesce(branch, ''))

Revision ID: a3c1e5f7b9d2
Revises: 87d49b40789f
Create Date: 2026-09-14
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "a3c1e5f7b9d2"
down_revision = "87d49b40789f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "uq_repositories_source_branch",
        "repositories",
        [sa.text("lower(source_url)"), sa.text("coalesce(branch, '')")],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_repositories_source_branch", table_name="repositories")
