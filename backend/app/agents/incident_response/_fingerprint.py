"""
CyberGuard AI — Incident Fingerprint Helper
============================================================================

Extracts the incident fingerprint computation from
``incident_service`` into a reusable helper. The incident response
agent uses it to check "would this alert merge into an existing
incident?" without importing the service's private internal function.

The algorithm is identical to ``incident_service._compute_incident_
fingerprint`` — same version, same fields. If the service changes its
fingerprint algorithm in a future release, this file must be updated
in the same commit, or the agent will make incorrect merge/create
decisions.

Version: v1
"""

from __future__ import annotations

import hashlib
import uuid

from app.models.enums import FindingCategory, IncidentSeverity


_FP_VERSION = "v1"


def compute_incident_fingerprint(
    *,
    workspace_id: uuid.UUID,
    category: FindingCategory,
    severity: IncidentSeverity,
    primary_source_id: uuid.UUID | None,
) -> str:
    """
    Compute the pattern-level fingerprint for an incident.

    Two incidents with the same fingerprint (and both open) are the
    same pattern — a new alert of that pattern merges into the existing
    incident rather than creating a new one.
    """
    source_scope = str(primary_source_id) if primary_source_id else "cross_source"
    payload = "|".join([
        _FP_VERSION,
        str(workspace_id),
        category.value,
        severity.value,
        source_scope,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


__all__ = ["compute_incident_fingerprint"]