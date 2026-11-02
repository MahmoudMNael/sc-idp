"""idp roles and preassignments

Revision ID: 002
Revises: 001
Create Date: 2026-11-02
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: Union[str, Sequence[str], None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "idp_roles",
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )
    op.create_table(
        "user_idp_roles",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_name", sa.String(length=64), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_name"], ["idp_roles.name"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "role_name"),
    )
    op.create_table(
        "email_idp_role_preassignments",
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("role_name", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["role_name"], ["idp_roles.name"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("email", "role_name"),
    )


def downgrade() -> None:
    op.drop_table("email_idp_role_preassignments")
    op.drop_table("user_idp_roles")
    op.drop_table("idp_roles")
