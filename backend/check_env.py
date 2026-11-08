"""
Diagnostic script: verifies .env is loaded, DB is reachable, and models register.
Run with: python check_env.py
"""
import sys
from pathlib import Path

env_path = Path(__file__).parent / ".env"

print("=" * 70)
print("STEP 1: .env file")
print("=" * 70)
print(f"Path:      {env_path}")
print(f"Exists:    {env_path.exists()}")
if env_path.exists():
    stat = env_path.stat()
    print(f"Size:      {stat.st_size} bytes")
    print(f"Modified:  {stat.st_mtime_ns}")

print()
print("=" * 70)
print("STEP 2: Parse .env keys (values masked)")
print("=" * 70)

if not env_path.exists():
    print("ERROR: .env is missing. Cannot continue.")
    sys.exit(1)

env_vars = {}
for line in env_path.read_text(encoding="utf-8").splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        continue
    key, _, value = stripped.partition("=")
    env_vars[key.strip()] = value.strip()

print(f"Total keys: {len(env_vars)}")
print()

required = ["DATABASE_URL"]
important = ["JWT_SECRET_KEY", "APP_ENV", "REDIS_URL", "JWT_ALGORITHM"]

print("CRITICAL KEYS:")
for k in required:
    status = "PRESENT" if k in env_vars else "MISSING"
    length = len(env_vars.get(k, ""))
    print(f"  {k:25} {status:8} (len={length})")

print()
print("IMPORTANT KEYS:")
for k in important:
    status = "PRESENT" if k in env_vars else "MISSING"
    length = len(env_vars.get(k, ""))
    print(f"  {k:25} {status:8} (len={length})")

print()
print("DATABASE_URL preview (password hidden):")
url = env_vars.get("DATABASE_URL", "")
if not url:
    print("  MISSING")
else:
    at = url.find("@")
    scheme_end = url.find("://")
    if at > 0 and scheme_end > 0:
        scheme = url[:scheme_end]
        rest = url[at + 1:]
        print(f"  {scheme}://***@{rest}")
    else:
        print(f"  {url[:80]}")

print()
jwt = env_vars.get("JWT_SECRET_KEY", "")
print("JWT_SECRET_KEY strength:")
print(f"  length:                 {len(jwt)}")
print(f"  starts_with_CHANGE_ME:  {jwt.startswith('CHANGE_ME')}")
print(f"  strong_enough:          {len(jwt) >= 32 and not jwt.startswith('CHANGE_ME')}")

print()
print("=" * 70)
print("STEP 3: Load Settings via app.core.config")
print("=" * 70)

try:
    from app.core.config import settings
    print(f"APP_NAME:   {settings.APP_NAME}")
    print(f"APP_ENV:    {settings.APP_ENV}")
    print(f"APP_DEBUG:  {settings.APP_DEBUG}")
    print(f"DATABASE:   {settings.safe_database_url()}")
    print("Settings loaded OK.")
except Exception as exc:
    print(f"FAILED to load settings: {type(exc).__name__}: {exc}")
    sys.exit(2)

print()
print("=" * 70)
print("STEP 4: Database connectivity")
print("=" * 70)

try:
    from app.db.session import health_check
    ok = health_check()
    print(f"DB reachable: {ok}")
    if not ok:
        sys.exit(3)
except Exception as exc:
    print(f"FAILED: {type(exc).__name__}: {exc}")
    sys.exit(3)

print()
print("=" * 70)
print("STEP 5: Model registry")
print("=" * 70)

try:
    from app.db.base import Base
    import app.models  # noqa: F401
    tables = sorted(Base.metadata.tables.keys())
    print(f"Tables registered: {len(tables)}")
    for t in tables:
        print(f"  {t}")
except Exception as exc:
    print(f"FAILED: {type(exc).__name__}: {exc}")
    sys.exit(4)

print()
print("=" * 70)
print("STEP 6: Existing tables in the database")
print("=" * 70)

try:
    from app.db.session import session_scope
    from sqlalchemy import text

    with session_scope() as db:
        result = db.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
        ))
        existing = [row[0] for row in result]
    print(f"Existing tables: {len(existing)}")
    for t in existing:
        print(f"  {t}")
    print()
    if not existing:
        print("Database is empty — READY for alembic autogenerate.")
    else:
        print("Database has tables — autogenerate would produce ALTER/DROP operations.")
        print("Either point DATABASE_URL to a fresh DB, or reset the schema first.")
except Exception as exc:
    print(f"FAILED: {type(exc).__name__}: {exc}")
    sys.exit(5)

print()
print("=" * 70)
print("ALL CHECKS COMPLETE")
print("=" * 70)