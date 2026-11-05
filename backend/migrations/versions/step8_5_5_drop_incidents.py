"""
Remove the incident management feature.

STEP 8.5.5 - Drop Incidents Table and Related Columns

The incidents table and the correlation-to-incident escalation path have
been removed from the application (CorrelationAlertIntegration no longer
creates or enriches incidents; the Incident model, IncidentManager, and
/api/v1/incidents routes have been deleted). This migration drops the
now-unused database objects for existing installations:

1. notifications.incident_id column (and its index) - notifications are
   alert-only now.
2. users.can_manage_incidents column - no longer a real permission.
3. incidents table itself (and its indexes/trigger).

This migration is destructive for any incident data still stored in the
database. It is intentional: the application code that read/wrote that
data no longer exists, so the rows are already unreachable through the
API. Operators who still need the historical data should export the
`incidents` table before running this migration.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = "step8_5_5_001"
down_revision = "step8_5_4_2_001"  # Verified: exists in step8_5_4_2_alert_schema.py
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Drop incidents table and incident-related columns."""

    # =========================================================================
    # STAGE A: Drop the notifications.incident_id column (and its index)
    # =========================================================================

    op.drop_index("idx_notifications_incident", table_name="notifications", if_exists=True)
    op.drop_column("notifications", "incident_id")

    # =========================================================================
    # STAGE B: Drop the users.can_manage_incidents column
    # =========================================================================

    op.drop_column("users", "can_manage_incidents")

    # =========================================================================
    # STAGE C: Drop the incidents table (indexes and the updated_at trigger
    # are dropped automatically with the table / via CASCADE)
    # =========================================================================

    op.execute("DROP TRIGGER IF EXISTS incidents_updated ON incidents")
    op.drop_table("incidents")


def downgrade() -> None:
    """Recreate incidents table and incident-related columns.

    Note: this restores structure only. Any data dropped by upgrade()'s
    DROP TABLE / DROP COLUMN is not recoverable through this downgrade -
    restore from a backup taken before upgrade() if the data is needed.
    """

    # Recreate users.can_manage_incidents
    op.add_column(
        "users",
        sa.Column("can_manage_incidents", sa.Boolean(), nullable=True, server_default=sa.false()),
    )

    # Recreate incidents table
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

            title VARCHAR(500) NOT NULL,
            description TEXT,
            severity VARCHAR(20) NOT NULL,

            status VARCHAR(30) DEFAULT 'open',
            priority INTEGER DEFAULT 3,

            alert_ids UUID[] DEFAULT '{}',
            event_ids UUID[] DEFAULT '{}',

            owner VARCHAR(255),
            team VARCHAR(255),

            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            detected_at TIMESTAMPTZ,
            contained_at TIMESTAMPTZ,
            resolved_at TIMESTAMPTZ,

            affected_systems TEXT[] DEFAULT '{}',
            affected_users TEXT[] DEFAULT '{}',
            data_involved TEXT[] DEFAULT '{}',

            timeline JSONB DEFAULT '[]',
            root_cause TEXT,
            lessons_learned TEXT
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(priority)")
    op.execute(
        """
        DROP TRIGGER IF EXISTS incidents_updated ON incidents;
        CREATE TRIGGER incidents_updated
            BEFORE UPDATE ON incidents
            FOR EACH ROW EXECUTE FUNCTION update_updated_at();
        """
    )

    # Recreate notifications.incident_id (and its index)
    op.add_column(
        "notifications",
        sa.Column("incident_id", sa.dialects.postgresql.UUID(as_uuid=False), nullable=True),
    )
    op.create_foreign_key(
        "notifications_incident_id_fkey",
        "notifications",
        "incidents",
        ["incident_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("idx_notifications_incident", "notifications", ["incident_id"])
