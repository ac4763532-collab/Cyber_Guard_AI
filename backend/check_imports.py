"""
Boot-time import check. Loads every module in `app.*` and reports
which ones fail. Does NOT touch the database.
"""
import importlib
import pkgutil
import sys
import traceback

failed = []
loaded = 0

# Walk every module under `app`
import app
for module_info in pkgutil.walk_packages(app.__path__, prefix="app."):
    name = module_info.name
    try:
        importlib.import_module(name)
        loaded += 1
    except Exception as exc:
        failed.append((name, exc, traceback.format_exc()))
        print(f"[FAIL] {name}: {type(exc).__name__}: {exc}")

print()
print("=" * 70)
print(f"Loaded: {loaded} | Failed: {len(failed)}")
print("=" * 70)

if failed:
    print()
    print("FAILURES:")
    for name, exc, tb in failed:
        print()
        print(f"--- {name} ---")
        print(tb)
    sys.exit(1)

# Also try to import `app.main` explicitly
try:
    from app.main import app as fastapi_app
    print()
    print(f"[OK] app.main imports cleanly")
    print(f"[OK] FastAPI app has {len(fastapi_app.routes)} routes")
except Exception:
    print()
    print("[FAIL] app.main failed to import:")
    traceback.print_exc()
    sys.exit(1)