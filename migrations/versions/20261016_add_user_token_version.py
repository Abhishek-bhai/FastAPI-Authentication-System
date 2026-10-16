"""Add user token version for session invalidation.

Revision ID: 20261016_add_user_token_version
Revises: 20250217_initial_auth
Create Date: 2026-10-16 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20261016_add_user_token_version"
down_revision = "20250217_initial_auth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), server_default="0", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("users", "token_version")
