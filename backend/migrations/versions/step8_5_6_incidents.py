"""Add a tenant-scoped incident lifecycle after the earlier removal."""

from alembic import op


revision = "step8_5_6_001"
down_revision = "step8_5_5_001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id VARCHAR(255) NOT NULL,
            fingerprint VARCHAR(64) NOT NULL,
            title VARCHAR(500) NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            severity VARCHAR(20) NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'open',
            finding_ids UUID[] NOT NULL DEFAULT '{}',
            alert_ids UUID[] NOT NULL DEFAULT '{}',
            event_ids UUID[] NOT NULL DEFAULT '{}',
            correlation_ids UUID[] NOT NULL DEFAULT '{}',
            recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
            actions_taken JSONB NOT NULL DEFAULT '[]'::jsonb,
            history JSONB NOT NULL DEFAULT '[]'::jsonb,
            created_by VARCHAR(255),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_incidents_tenant_fingerprint UNIQUE (tenant_id, fingerprint)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_tenant_status ON incidents(tenant_id, status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_updated ON incidents(updated_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS incidents")
