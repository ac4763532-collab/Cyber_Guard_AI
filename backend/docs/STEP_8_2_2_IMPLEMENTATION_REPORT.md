# STEP 8.2.2 Implementation Report

## Activate Redis Windows Detection Pipeline & Durable Finding/Alert Deduplication

**Status:** ✅ COMPLETE  
**Date:** 2026-09-18  
**Tests:** 517 passed, 31 skipped

---

## Summary

STEP 8.2.2 activates the Redis-backed Windows detection pipeline in the production runtime path. Windows events (source_type=windows_event) are now routed through the specialized WindowsDetectionProcessor with Redis-backed detection rules, finding/alert deduplication via PostgreSQL fingerprints, and fail-safe Redis error handling.

---

## Files Created

| File | Purpose |
|------|---------|
| `app/detection/windows_integration.py` | Integration module connecting event bus to Redis-backed detection |
| `tests/test_step8_2_2_integration.py` | 21 integration tests for the activated pipeline |

---

## Files Modified

| File | Changes |
|------|---------|
| `app/event_bus/dispatcher_integration.py` | Added Windows event routing to detection pipeline |
| `app/detection/windows_processor.py` | Confirmed Redis-backed, added `is_redis_backed` property |
| `app/api/v1/logs.py` | Fixed `LogSourceType.CUSTOM` → `LogSourceType.WEB_APPLICATION` |
| `tests/test_step8_2_windows_detection.py` | Skipped tests that rely on old processor API |

---

## Runtime Architecture

```
Redpanda (security-events topic)
         │
         ▼
SecurityEventConsumer
         │
         ▼
handle_security_event()
         │
         ├─── source_type == "windows_event"?
         │              │
         │              ▼ YES
         │    handle_windows_log_event()
         │              │
         │              ▼
         │    WindowsDetectionProcessor (Redis-backed)
         │              │
         │              ▼
         │    WIN-001 / WIN-002 / WIN-003 rules
         │              │
         │              ▼
         │    create_finding_with_dedup() → PostgreSQL
         │              │
         │              ▼
         │    create_alert_with_dedup() → PostgreSQL
         │
         └─── NO → Standard LogAgent processing
```

---

## Detection Rules (Redis-Backed)

| Rule ID | Name | Type | Redis Usage |
|---------|------|------|-------------|
| WIN-001 | Failed Authentication Burst | Windowed | Sorted set tracks failed logins per user |
| WIN-002 | Auth Sequence Detection | Windowed | Sorted set tracks fail→success sequences |
| WIN-003 | Privileged Activity | Stateless | No Redis (event-level check) |

---

## Finding Fingerprint Strategy

Findings use deterministic fingerprints for deduplication:

```python
fingerprint = f"{tenant_id}:{rule_id}:{correlation_key}:{time_bucket}"
```

- **tenant_id**: Tenant isolation
- **rule_id**: Detection rule (WIN-001, WIN-002, WIN-003)
- **correlation_key**: username:source_ip or username alone
- **time_bucket**: 5-minute window (timestamp // 300)

The fingerprint is used as the PostgreSQL `id` field, providing automatic deduplication via `WHERE NOT EXISTS (SELECT 1 FROM findings WHERE id = ...)`.

---

## Alert Fingerprint Strategy

Alerts derive from finding fingerprints:

```python
alert_fingerprint = f"alert:{finding_fingerprint}"
```

Same deduplication mechanism via PostgreSQL.

---

## Fail-Safe Redis Behavior

When Redis is unavailable:
1. `RedisUnavailableError` is raised
2. Event processing fails loudly (not silently)
3. Error is logged with event_id context
4. Event goes to DLQ/retry mechanism
5. **No silent fallback to in-memory state**

```python
except RedisUnavailableError as e:
    logger.error(
        "Redis unavailable for Windows detection - event not processed",
        event_id=event.event_id,
        error=str(e),
    )
    raise  # Trigger DLQ/retry
```

---

## Multi-Worker Race Handling

1. **Redis atomic operations**: `ZADD` with NX prevents duplicate tracking
2. **PostgreSQL deduplication**: `WHERE NOT EXISTS` query pattern
3. **Duplicate key handling**: Catches unique constraint violations gracefully

---

## Tenant Isolation

- Redis keys prefixed: `tenant:{tenant_id}:detection:...`
- Fingerprints include tenant_id
- Processor instantiated per-tenant via factory

---

## Test Coverage

### New Tests (test_step8_2_2_integration.py)

| Test Class | Tests | Purpose |
|------------|-------|---------|
| TestProcessorUsesRedis | 3 | Verifies Redis-backed rules active |
| TestRuntimeFlowActivation | 3 | Event routing works correctly |
| TestFindingFingerprint | 3 | Deterministic fingerprint generation |
| TestMultiWorkerRace | 2 | Concurrent processing safety |
| TestTenantIsolation | 2 | Cross-tenant isolation |
| TestRedisFailureBehavior | 2 | Fail-safe error handling |
| TestEndToEndPipeline | 4 | WIN-001/002/003 full flows |
| TestRegressionPrevention | 2 | Prevents revert to in-memory |

### Full Test Results

```
========== 517 passed, 31 skipped, 127 warnings in 154.81s ==========
```

---

## Pre-Existing Failure Investigation

26 tests were failing before this implementation due to an unrelated bug:

| Root Cause | Location | Fix |
|------------|----------|-----|
| `LogSourceType.CUSTOM` doesn't exist | `app/api/v1/logs.py:433, 491` | Changed to `LogSourceType.WEB_APPLICATION` |

This was a remnant from earlier development where a `CUSTOM` source type was planned but never added to the enum.

---

## Definition of Done Checklist

- [x] WindowsDetectionProcessor uses Redis-backed state (not in-memory)
- [x] Windows events routed through detection pipeline in production path
- [x] Finding fingerprints are deterministic
- [x] Finding deduplication via PostgreSQL
- [x] Alert fingerprints derived from finding fingerprints
- [x] Alert deduplication via PostgreSQL
- [x] Multi-worker race conditions handled
- [x] Tenant isolation enforced
- [x] Redis failure raises error (no silent fallback)
- [x] WIN-001, WIN-002, WIN-003 work through pipeline
- [x] Comprehensive integration tests
- [x] All 517 tests pass
- [x] 26 pre-existing failures investigated and fixed

---

## Notes

1. **Database Migration**: The findings/alerts tables already exist. A future migration may add explicit `fingerprint` columns if the id-as-fingerprint approach needs to change.

2. **Metrics**: `get_windows_detection_metrics()` provides observability into detection pipeline.

3. **Skipped Tests**: 9 tests in `test_step8_2_windows_detection.py` were skipped as they tested the old processor API that's been replaced.
