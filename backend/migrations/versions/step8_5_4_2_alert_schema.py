"""
Safe alert schema migration with verified historical tenant ownership.

STEP 8.5.4.2 - Alert Migration Safety + Production Persistence Verification

This migration:
1. Adds fingerprint column (VARCHAR 64) for alert deduplication
2. Adds tenant_id column (VARCHAR 255) for tenant isolation
3. Uses SHA-256 for fingerprints (NOT MD5)
4. Backfills safely based on verified data analysis
5. Creates UNIQUE constraint on (tenant_id, fingerprint)
6. Handles historical alerts properly

IMPORTANT - Historical Tenant Ownership Analysis:
The existing 4 alerts (as of 2026-09-18) are test records:
- No event_id associations
- No correlation_id associations
- Titles indicate test data: "Test Persistence Alert", "STEP3 Test Alert"
- Created during development testing

Since these are clearly development/test alerts with no real tenant association,
assigning them to 'default' tenant is safe and appropriate.

For production systems with real historical alerts, this migration should be
reviewed and the tenant derivation logic verified against actual ownership data.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = "step8_5_4_2_001"
down_revision = "step8_4_001"  # Verified: exists in add_ingestion_api_keys.py
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add fingerprint and tenant_id columns to alerts table with safe backfill."""

    # =========================================================================
    # STAGE A: Add new columns as NULLABLE
    # =========================================================================

    op.add_column(
        "alerts",
        sa.Column("fingerprint", sa.String(64), nullable=True),
    )

    op.add_column(
        "alerts",
        sa.Column("tenant_id", sa.String(255), nullable=True),
    )

    # =========================================================================
    # STAGE B: Backfill existing records with deterministic SHA-256 fingerprints
    # =========================================================================

    # Historical alerts get a legacy fingerprint using SHA-256 (NOT MD5)
    # Format: legacy-alert:{uuid} -> SHA256 -> first 32 chars
    # This is deterministic - running twice produces same result
    op.execute(
        """
        UPDATE alerts
        SET
            -- SHA-256 fingerprint using encode/digest (PostgreSQL native)
            -- Input: 'legacy-alert:' || id::text (deterministic)
            fingerprint = SUBSTRING(
                encode(digest('legacy-alert:' || id::text, 'sha256'), 'hex'),
                1, 32
            ),
            -- Historical tenant assignment based on ownership analysis:
            -- All existing alerts are test records with no authoritative tenant
            tenant_id = 'default'
        WHERE fingerprint IS NULL
        """
    )

    # =========================================================================
    # STAGE C: Verify no duplicates before constraint creation
    # =========================================================================

    # This will fail the migration if duplicates exist, which is correct behavior
    # We verify rather than silently allowing duplicates
    op.execute(
        """
        DO $$
        DECLARE
            dup_count INTEGER;
        BEGIN
            SELECT COUNT(*) INTO dup_count
            FROM (
                SELECT tenant_id, fingerprint, COUNT(*) as cnt
                FROM alerts
                WHERE tenant_id IS NOT NULL AND fingerprint IS NOT NULL
                GROUP BY tenant_id, fingerprint
                HAVING COUNT(*) > 1
            ) dupes;

            IF dup_count > 0 THEN
                RAISE EXCEPTION 'Migration blocked: % duplicate (tenant_id, fingerprint) pairs found', dup_count;
            END IF;
        END $$;
        """
    )

    # =========================================================================
    # STAGE D: Create unique constraint BEFORE making columns NOT NULL
    # This catches any edge cases the verification might have missed
    # =========================================================================

    op.create_unique_constraint(
        "uq_alerts_tenant_fingerprint",
        "alerts",
        ["tenant_id", "fingerprint"],
    )

    # =========================================================================
    # STAGE E: Make columns NOT NULL after successful constraint creation
    # =========================================================================

    op.alter_column("alerts", "fingerprint", nullable=False)
    op.alter_column("alerts", "tenant_id", nullable=False)

    # =========================================================================
    # STAGE F: Create indexes for efficient lookups
    # =========================================================================

    op.create_index(
        "ix_alerts_fingerprint",
        "alerts",
        ["fingerprint"],
    )

    op.create_index(
        "ix_alerts_tenant_id",
        "alerts",
        ["tenant_id"],
    )

    op.create_index(
        "ix_alerts_correlation_id",
        "alerts",
        ["correlation_id"],
    )


def downgrade() -> None:
    """Remove fingerprint and tenant_id columns from alerts table."""

    # Drop indexes first
    op.drop_index("ix_alerts_correlation_id", table_name="alerts")
    op.drop_index("ix_alerts_tenant_id", table_name="alerts")
    op.drop_index("ix_alerts_fingerprint", table_name="alerts")

    # Drop unique constraint
    op.drop_constraint("uq_alerts_tenant_fingerprint", "alerts", type_="unique")

    # Drop columns
    op.drop_column("alerts", "tenant_id")
    op.drop_column("alerts", "fingerprint")
