"""
CyberGuard AI — Business Logic Services
============================================================================

The service layer: business logic between the HTTP endpoints and the ORM.

Everything that isn't HTTP plumbing (``app/api``) and isn't schema
(``app/models``) lives here — permission checks, state transitions, event
ingestion, agent dispatch, report generation, and every rule that isn't a
database constraint.

Service contract — every file in this package MUST follow these
-----------------------------------------------------------------
1. **Receive ``Session`` from the caller.**
   Signature: ``def do_thing(db: Session, *, ...) -> ...``. Never create
   a session. Never call ``session_scope()``. The caller (endpoint or
   another service) owns the session lifecycle.

2. **Never commit. Never rollback.**
   The API layer commits at the end of a successful request. The
   ``session_scope`` context manager handles commit/rollback for
   background tasks. Services call ``db.flush()`` when they need
   server-generated IDs before continuing — that's the only write
   operation a service should ever perform.

3. **Raise ``CyberGuardError`` subclasses on failure.**
   ``NotFoundError``, ``AuthorizationError``, ``ConflictError``,
   ``ValidationError`` — never ``return None`` to signal "not found",
   never ``return (value, error)``, never ``raise ValueError``. The
   exception handler in ``main.py`` translates ``CyberGuardError`` into
   HTTP responses automatically.

4. **Return ORM instances or domain results.**
   Not Pydantic DTOs. Not JSON. The API layer converts ORM → schema via
   ``ModelRead.model_validate(orm_instance)``. Services never know about
   HTTP shapes.

5. **No HTTP awareness.**
   No ``Request``, no ``Response``, no ``HTTPException``, no status
   codes. If a service is being written to "return 404 for X", the
   logic is in the wrong layer — the endpoint should translate
   ``NotFoundError`` into 404.

6. **No imports from ``app.api`` or ``app.main``.**
   The dependency direction is strict::

       app.api → app.services → app.models → app.db → app.core

   A service may import from ``models``, ``schemas`` (for input
   validation), ``core``, and ``db``. Never from ``api`` or ``main``.

7. **Business rules live here.**
   "A case cannot close until it is resolved." "An analyst can only see
   cases they're assigned to or granted access to." "Consecutive failed
   logins increment a counter and trigger lockout." These are service
   rules — not model ``@validates`` (that's per-field format), not
   endpoint logic (that's HTTP shape).

8. **Authorization is centralized in ``authorization.py``.**
   No service performs ad-hoc permission checks. Every permission
   question goes through:

       from app.services.authorization import check_permission
       check_permission(db, user, permission, resource=case)

   The reason: permission logic is complex (roles, scope, tenant,
   resource grants, admin overrides). Putting it in one file makes it
   auditable, testable, and impossible to accidentally bypass.

Service inventory (as files land)
---------------------------------
Foundation:
    ``authorization.py``        — permission checks (RBAC + resource grants)
    ``user_service.py``         — user CRUD, authentication, lockout

Tenancy:
    ``organization_service.py`` — org CRUD, ownership transfer, invitations
    ``workspace_service.py``    — workspace CRUD, membership
    ``membership_service.py``   — invite/accept/suspend/remove, role changes
    ``analyst_service.py``      — analyst profile CRUD, verification workflow

Sources & ingestion:
    ``source_service.py``       — source CRUD, status transitions
    ``enrollment_service.py``   — enrollment token lifecycle
    ``collector_credential_service.py`` — credential issuance, rotation, revocation
    ``event_fingerprint.py``    — SHA-256 dedup fingerprints
    ``event_ingestion_service.py`` — normalize, dedup, persist, dispatch

Detection & response:
    ``finding_service.py``      — finding CRUD, dedup, status transitions
    ``alert_service.py``        — finding→alert promotion, dedup, SLA
    ``incident_service.py``     — incident CRUD, NIST lifecycle, action log
    ``case_service.py``         — case CRUD, assignment, access grants
    ``evidence_service.py``     — upload, integrity verify, chain of custody

Communication & reporting:
    ``conversation_service.py`` — threads, messages, read receipts
    ``notification_service.py`` — create, deliver, track engagement
    ``report_service.py``       — report generation, storage, sharing

Marketplace:
    ``marketplace_service.py``  — offering CRUD, purchase flow, payment
    ``engagement_service.py``   — engagement lifecycle, scope, revocation

Governance:
    ``audit_service.py``        — audit log writer (append-only)

Total: ~20 service files.

Patterns used across services
-----------------------------
**Pattern: create()**

    def create_user(
        db: Session,
        *,
        email: str,
        password: str,
        full_name: str | None = None,
        status: UserStatus = UserStatus.PENDING_VERIFICATION,
    ) -> User:
        # Validate uniqueness
        existing = get_by_email(db, email)
        if existing is not None:
            raise ConflictError(
                message="Email already registered",
                code="EMAIL_ALREADY_EXISTS",
            )

        # Hash password
        password_hash = hash_password(password)

        # Create ORM instance
        user = User(
            email=email,
            password_hash=password_hash,
            full_name=full_name,
            status=status,
        )
        db.add(user)
        db.flush()  # populate id and server defaults
        return user

**Pattern: get() — raises on miss**

    def get_user_by_id(db: Session, user_id: UUID) -> User:
        user = db.get(User, user_id)
        if user is None or user.deleted_at is not None:
            raise UserNotFoundError(
                message=f"User {user_id} not found",
                details={"user_id": str(user_id)},
            )
        return user

**Pattern: list() — returns paginated results**

    def list_users(
        db: Session,
        *,
        page: PageParams,
        filters: UserFilter,
    ) -> tuple[list[User], int]:
        stmt = select(User).where(User.deleted_at.is_(None))
        stmt = apply_user_filters(stmt, filters)

        total = db.execute(
            select(func.count()).select_from(stmt.subquery())
        ).scalar_one()

        users = (
            db.execute(stmt.offset(page.offset).limit(page.limit))
            .scalars()
            .all()
        )
        return list(users), total

**Pattern: update() — partial updates**

    def self_update_user(
        db: Session,
        user: User,
        update: UserSelfUpdate,
    ) -> User:
        # Only apply fields that were explicitly provided
        data = update.model_dump(exclude_unset=True)
        for field, value in data.items():
            setattr(user, field, value)
        db.flush()
        return user

**Pattern: state transitions**

    def acknowledge_alert(
        db: Session,
        alert: SecurityAlert,
        *,
        by_user: User,
    ) -> SecurityAlert:
        if alert.status not in (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED):
            raise InvalidStateTransitionError(
                message=f"Cannot acknowledge an alert in {alert.status.value} state",
                code="ALERT_CANNOT_ACKNOWLEDGE",
            )
        alert.acknowledge()
        db.flush()
        return alert

**Pattern: audit-logging writes**

Every state change in a service that touches sensitive resources
(evidence, cases, users, orgs, credentials) MUST also write an audit
log. The pattern:

    from app.services.audit_service import audit_action

    def assign_case_to_analyst(db, case, *, analyst, assigned_by):
        case.set_primary_analyst(analyst_user_id=analyst.id, assigned_by_id=assigned_by.id)
        db.flush()
        audit_action(
            db,
            actor=assigned_by,
            action="case.assigned",
            target_type="case",
            target_id=case.id,
            before_state={"assigned_to_id": None},
            after_state={"assigned_to_id": str(analyst.id)},
        )
        return case

The audit row is written in the same transaction as the state change —
if the state change rolls back, the audit row rolls back too.

Testing philosophy
------------------
Services are the **easiest** layer to test because they have no HTTP
awareness. A test looks like:

    def test_create_user_duplicate_email(db_session):
        create_user(db_session, email="a@b.com", password="Password123")
        with pytest.raises(ConflictError):
            create_user(db_session, email="a@b.com", password="Other123")

No FastAPI test client, no auth headers, no JSON parsing. Just Python.

Endpoint tests (in ``app/api/tests/``) use the ``TestClient`` and
exercise the full HTTP stack. They should be fewer and higher-level.

What NOT to put here
--------------------
- HTTP handling (→ ``app.api``)
- Database models (→ ``app.models``)
- Pydantic schemas (→ ``app.schemas``)
- Raw session creation (→ ``app.db.session``)
- Configuration loading (→ ``app.core.config``)

Services import FROM these layers; they never define them.
"""

from __future__ import annotations

# Intentionally no imports. See "No re-exports" pattern from app/core,
# app/db, app/auth, and app/api — same reasoning: keep the import graph
# flat, avoid implicit chains, make every dependency visible at the call
# site.

__all__: list[str] = []