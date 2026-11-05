"""
Add ingestion_api_keys table for machine-to-machine authentication.

STEP 8.4 - Web Application Real-Time Log Collector
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = "step8_4_001"
down_revision = None  # Update with actual previous migration
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create ingestion_api_keys table."""
    op.create_table(
        "ingestion_api_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("key_prefix", sa.String(20), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", sa.String(20), nullable=False, default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("use_count", sa.Integer, nullable=False, default=0),
        sa.Column("created_by", sa.String(36), nullable=True),
    )

    # Index for fast authentication lookup
    op.create_index(
        "ix_ingestion_api_keys_key_hash",
        "ingestion_api_keys",
        ["key_hash"],
        unique=True,
    )

    # Index for listing keys by source
    op.create_index(
        "ix_ingestion_api_keys_source_id",
        "ingestion_api_keys",
        ["source_id"],
    )

    # Index for listing keys by organization
    op.create_index(
        "ix_ingestion_api_keys_organization_id",
        "ingestion_api_keys",
        ["organization_id"],
    )

    # Index for finding active keys
    op.create_index(
        "ix_ingestion_api_keys_status",
        "ingestion_api_keys",
        ["status"],
    )


def downgrade() -> None:
    """Drop ingestion_api_keys table."""
    op.drop_index("ix_ingestion_api_keys_status")
    op.drop_index("ix_ingestion_api_keys_organization_id")
    op.drop_index("ix_ingestion_api_keys_source_id")
    op.drop_index("ix_ingestion_api_keys_key_hash")
    op.drop_table("ingestion_api_keys")
