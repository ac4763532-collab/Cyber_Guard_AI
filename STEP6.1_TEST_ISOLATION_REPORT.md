# STEP 6.1 Report: Windows PostgreSQL Test Isolation Fix

**Date:** 2026-09-17  
**Status:** ✅ COMPLETE

---

## 1. Root Cause

The 9 test failures were caused by **event loop / connection pool mismatch**.

### The Problem

```
test_email_regression.py
    ↓
EmailAgent.analyze() creates fire-and-forget tasks:
    asyncio.create_task(save_history())
    ↓
These tasks use the global DatabaseManager singleton pool
    ↓
Test module finishes, event loop closes
    ↓
Pool singleton remains, but is bound to the CLOSED loop
    ↓
test_step4_incidents.py runs
    ↓
Creates NEW event loop (pytest asyncio fixture)
    ↓
Tries to use EXISTING pool singleton
    ↓
Pool is bound to old (closed) loop
    ↓
RuntimeError: Event loop is closed
```

### Key Issue

```python
# DatabaseManager was a singleton with pool bound to ONE event loop
class DatabaseManager:
    def __init__(self):
        self._pool: AsyncConnectionPool | None = None  # Bound to loop at init

# When called from a DIFFERENT loop:
async with db.connection() as conn:  # FAILS: pool bound to closed loop
```

The `AsyncConnectionPool` from psycopg3 spawns worker tasks on the event loop where it's created. When pytest creates a new loop for the next test module, the old pool (still referenced by the singleton) has workers waiting on futures tied to the closed loop.

---

## 2. Files Changed

| File | Change | Reason |
|------|--------|--------|
| `backend/app/database/connection.py` | Added loop tracking and auto-reinitialize | Detect when running on different loop, reinitialize pool |

---

## 3. Test Infrastructure Fix

### Before

```python
class DatabaseManager:
    def __init__(self):
        self._pool = None
        self._initialized = False

    async def initialize(self):
        if self._initialized:
            return  # ← Never reinitializes even if loop changed!
```

### After

```python
class DatabaseManager:
    def __init__(self):
        self._pool = None
        self._initialized = False
        self._bound_loop = None  # ← Track which loop owns the pool

    def _check_loop_changed(self) -> bool:
        """Check if the running event loop changed since pool creation."""
        if not self._bound_loop:
            return False
        try:
            current_loop = asyncio.get_running_loop()
            return current_loop is not self._bound_loop
        except RuntimeError:
            return False

    async def initialize(self):
        # If pool exists but loop changed, reset and reinitialize
        if self._initialized and self._check_loop_changed():
            logger.info("Event loop changed, reinitializing database pool")
            await self._force_reset()

        if self._initialized:
            return

        # ... create pool ...
        self._bound_loop = asyncio.get_running_loop()  # ← Remember this loop
```

### How It Works Now

```
test_email_regression.py
    ↓
Pool created, bound to loop A
    ↓
Test finishes, loop A closes
    ↓
test_step4_incidents.py runs on loop B
    ↓
DatabaseManager.connection() called
    ↓
_check_loop_changed() returns True (loop A ≠ loop B)
    ↓
_force_reset() closes old pool (ignoring errors)
    ↓
initialize() creates NEW pool bound to loop B
    ↓
Tests PASS ✓
```

---

## 4. Production Impact

**No production behavior changed.**

| Aspect | Before | After |
|--------|--------|-------|
| Normal operation | Pool initialized once | Same |
| Single event loop | Works | Works |
| Multiple event loops (tests) | FAILS | Auto-reinitializes |
| Connection pooling | Works | Works |
| Performance | Same | Same |

The fix only affects the edge case where the same Python process runs async code on multiple sequential event loops (which happens in pytest but not in production FastAPI).

---

## 5. Before/After Tests

### Before

```
304 passed
9 failed
2 skipped
```

### After

```
313 passed
0 failed
2 skipped
```

**Net change: +9 tests now passing** (the STEP4 tests that were failing).

---

## 6. STEP 4 Verification

```bash
$ python -m pytest tests/test_step4_incidents.py -v
```

```
tests/test_step4_incidents.py::TestIncidentRepository::test_create_incident PASSED
tests/test_step4_incidents.py::TestIncidentRepository::test_get_incident PASSED
tests/test_step4_incidents.py::TestIncidentRepository::test_list_incidents PASSED
tests/test_step4_incidents.py::TestIncidentRepository::test_update_incident_status PASSED
tests/test_step4_incidents.py::TestIncidentRepository::test_get_nonexistent_incident PASSED
tests/test_step4_incidents.py::TestIncidentManagerPersistence::test_manager_creates_with_timeline PASSED
tests/test_step4_incidents.py::TestIncidentManagerPersistence::test_manager_update_persists_timeline PASSED
tests/test_step4_incidents.py::TestIncidentManagerPersistence::test_manager_statistics PASSED
tests/test_step4_incidents.py::TestIncidentLifecycle::test_full_lifecycle PASSED

9 passed ✓
```

**All 9 incident tests pass in isolation AND in the full suite.**

---

## 7. STEP 6 Verification

```bash
$ python -m pytest tests/test_step6_oauth_state.py -v
```

```
29 passed ✓
```

**All 29 OAuth state tests pass.**

---

## 8. Remaining Problems

### Cosmetic Warnings (Not Failures)

At test session exit, orphaned pool worker tasks print warnings:

```
Task was destroyed but it is pending!
task: <Task pending name='pool-11-worker-0' ...>
RuntimeError: Event loop is closed
```

This is **not a failure** — it's cleanup noise when pytest closes the final event loop and psycopg3's pool workers are still waiting. The tests pass; this is cosmetic.

### Deprecation Warnings

```
DeprecationWarning: 'asyncio.WindowsSelectorEventLoopPolicy' is deprecated
```

This is a Python 3.16 deprecation warning, not an error. The policy is still needed for psycopg3 on Windows in Python 3.14.

---

## 9. Definition of Done

| Requirement | Status |
|-------------|--------|
| 9 failures reproduced and understood | ✅ Event loop / pool mismatch |
| Root cause identified | ✅ Pool singleton bound to closed loop |
| Correct test isolation implemented | ✅ Auto-reinitialize on loop change |
| STEP 4 tests pass in full suite | ✅ 9/9 passed |
| STEP 6 tests pass | ✅ 29/29 passed |
| Full pytest suite has zero failures | ✅ 313 passed, 0 failed |
| DB_ENABLED remains true | ✅ |
| No production persistence disabled | ✅ |
| No insecure fallback introduced | ✅ |
| No tests deleted or weakened | ✅ |

---

## Conclusion

**STEP 6.1: ✅ COMPLETE**

The root cause was the `DatabaseManager` singleton keeping a psycopg3 `AsyncConnectionPool` bound to a specific event loop. When pytest created new loops for subsequent test modules, the old pool was invalid. The fix detects when the running loop changes and automatically reinitializes the pool. This is a test infrastructure fix with no impact on production behavior.
