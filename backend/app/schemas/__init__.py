"""
CyberGuard AI — Pydantic Schemas
============================================================================

Request/response schemas for every API endpoint. One module per entity.
Each module typically defines:

    *Create   — fields accepted on POST (no id, no server-managed timestamps)
    *Update   — fields accepted on PATCH (all optional, partial updates)
    *Read     — fields returned on GET (from_attributes=True; no secrets)
    *List     — lightweight variant for list views (fewer fields, faster)
    *Filter   — query parameters for list endpoints

Design rules
------------
1. **Pydantic v2 only.** Schemas use `model_config = ConfigDict(...)`,
   `field_validator`, `model_validator`. No Pydantic v1 syntax.

2. **Never leak secrets.** A *Read schema must not declare any of:
   password_hash, mfa_secret, token_hash, secret_hash, api keys,
   encryption keys. If the field is not declared, it cannot be leaked
   via FastAPI's response serializer.

3. **`from_attributes=True` on Read schemas.** Enables
   `UserRead.model_validate(user_orm_instance)` — no manual mapping.

4. **`extra="forbid"` on Create/Update schemas.** Unknown fields are
   rejected with a 422 — prevents silent typos in client requests.

5. **`extra="ignore"` on Read schemas.** Forward-compatibility: if the
   model gains a new field that a Read schema doesn't yet declare, the
   extra field is silently dropped instead of raising.

6. **Business logic stays in services.** Schemas validate shape and
   type, but not domain rules like "severity can only go up" or "case
   must be resolved before closure". Those belong in app.services.

7. **Schemas are the API contract.** If an endpoint's response schema
   changes, that's a breaking API change. Version accordingly.

Module layout
-------------
    common.py         — base schemas (pagination, errors, filters)
    auth.py           — register/login/refresh request + response
    user.py           — user CRUD schemas
    organization.py   — org CRUD schemas
    workspace.py      — workspace CRUD schemas
    membership.py     — org/workspace membership schemas
    analyst.py        — analyst profile schemas
    source.py         — security source + credential schemas
    enrollment.py     — enrollment token schemas
    event.py          — event read + filter schemas
    finding.py        — finding read schemas
    alert.py          — alert read + update schemas
    incident.py       — incident CRUD schemas
    case.py           — case + assignment + access grant schemas
    evidence.py       — evidence upload + read schemas
    conversation.py   — conversation + message schemas
    notification.py   — notification read schemas
    report.py         — report request + read schemas
    marketplace.py    — offering + purchase schemas
    audit.py          — audit log read schemas

Import order
------------
Modules are imported here as they land. Until all modules exist, this
file's imports are commented out. After the full build, every import
will be active. This preserves the pattern used in `app.models.__init__`:
the canonical imports live here, so that `from app.schemas import UserRead`
works anywhere in the codebase.
"""

from __future__ import annotations

# ============================================================================
# SCHEMA IMPORTS
# ============================================================================
# Uncomment each line as its module file is delivered.

# ── Base schemas (always imported first) ────────────────────────────────────
# from app.schemas.common import (
#     ErrorResponse,
#     PageMeta,
#     PageParams,
#     PaginatedResponse,
#     SortParams,
# )

# ── Authentication ──────────────────────────────────────────────────────────
# from app.schemas.auth import (
#     LoginRequest,
#     RefreshRequest,
#     RegisterRequest,
#     TokenResponse,
# )

# ── Core entities ──────────────────────────────────────────────────────────
# from app.schemas.user import UserCreate, UserRead, UserUpdate
# from app.schemas.organization import (
#     OrganizationCreate, OrganizationRead, OrganizationUpdate,
# )
# from app.schemas.workspace import (
#     WorkspaceCreate, WorkspaceRead, WorkspaceUpdate,
# )
# from app.schemas.membership import (
#     OrganizationMembershipRead,
#     WorkspaceMembershipRead,
# )
# from app.schemas.analyst import (
#     AnalystProfileApply,
#     AnalystProfileRead,
#     AnalystProfileUpdate,
# )

# ── Sources & collectors ───────────────────────────────────────────────────
# from app.schemas.source import (
#     SecuritySourceCreate,
#     SecuritySourceRead,
#     SecuritySourceUpdate,
#     SourceCredentialRead,
# )
# from app.schemas.enrollment import (
#     EnrollmentTokenCreate,
#     EnrollmentTokenRead,
#     EnrollmentTokenRedemption,
# )

# ── Detection ──────────────────────────────────────────────────────────────
# from app.schemas.event import EventFilter, EventRead
# from app.schemas.finding import FindingRead
# from app.schemas.alert import AlertRead, AlertUpdate
# from app.schemas.incident import (
#     IncidentCreate, IncidentRead, IncidentUpdate,
# )

# ── Investigation ──────────────────────────────────────────────────────────
# from app.schemas.case import (
#     CaseAssignmentCreate,
#     CaseAssignmentRead,
#     CaseCreate,
#     CaseRead,
#     CaseUpdate,
# )
# from app.schemas.evidence import EvidenceRead, EvidenceUpload
# from app.schemas.conversation import (
#     ConversationRead,
#     MessageCreate,
#     MessageRead,
# )

# ── Communication & reporting ──────────────────────────────────────────────
# from app.schemas.notification import NotificationRead
# from app.schemas.report import ReportCreate, ReportRead

# ── Marketplace ────────────────────────────────────────────────────────────
# from app.schemas.marketplace import (
#     OfferingCreate,
#     OfferingRead,
#     PurchaseCreate,
#     PurchaseRead,
# )

# ── Governance ─────────────────────────────────────────────────────────────
# from app.schemas.audit import AuditLogRead


# ============================================================================
# PUBLIC EXPORTS
# ============================================================================
# Uncomment each symbol as its module import is activated above.

__all__: list[str] = [
    # Common
    # "ErrorResponse",
    # "PageMeta",
    # "PageParams",
    # "PaginatedResponse",
    # "SortParams",
    # Auth
    # "LoginRequest",
    # "RefreshRequest",
    # "RegisterRequest",
    # "TokenResponse",
    # User / org / workspace / membership / analyst
    # "UserCreate", "UserRead", "UserUpdate",
    # "OrganizationCreate", "OrganizationRead", "OrganizationUpdate",
    # "WorkspaceCreate", "WorkspaceRead", "WorkspaceUpdate",
    # "OrganizationMembershipRead", "WorkspaceMembershipRead",
    # "AnalystProfileApply", "AnalystProfileRead", "AnalystProfileUpdate",
    # Sources
    # "SecuritySourceCreate", "SecuritySourceRead", "SecuritySourceUpdate",
    # "SourceCredentialRead",
    # "EnrollmentTokenCreate", "EnrollmentTokenRead", "EnrollmentTokenRedemption",
    # Detection
    # "EventFilter", "EventRead",
    # "FindingRead",
    # "AlertRead", "AlertUpdate",
    # "IncidentCreate", "IncidentRead", "IncidentUpdate",
    # Investigation
    # "CaseAssignmentCreate", "CaseAssignmentRead",
    # "CaseCreate", "CaseRead", "CaseUpdate",
    # "EvidenceRead", "EvidenceUpload",
    # "ConversationRead", "MessageCreate", "MessageRead",
    # Communication & reporting
    # "NotificationRead",
    # "ReportCreate", "ReportRead",
    # Marketplace
    # "OfferingCreate", "OfferingRead",
    # "PurchaseCreate", "PurchaseRead",
    # Governance
    # "AuditLogRead",
]