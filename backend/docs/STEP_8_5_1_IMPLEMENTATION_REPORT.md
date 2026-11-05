# STEP 8.5.1 Implementation Report

## Correlation Data Model + Cross-Source Entity Normalization

**Status:** ✅ IMPLEMENTATION COMPLETE + TEST VERIFIED  
**Date:** 2026-09-18  
**Tests:** 714 passed, 31 skipped (66 new correlation context tests)

---

## Summary

STEP 8.5.1 implements a canonical correlation context model that normalizes entities from Windows Event Logs, Linux/SSH logs, and Web Application logs into a common structure the existing CorrelationEngine can consume.

**Key principles:**
- Explicit field mappings (not fuzzy regex extraction)
- Missing entities remain `None` (never fabricated)
- Tenant isolation is mandatory
- Correlation keys are deterministic
- Secrets never enter correlation data

---

## 1. Files Created

| File | Purpose | Lines |
|------|---------|-------|
| `app/correlation/context.py` | Correlation context model + normalizers + extractors | ~950 |
| `tests/test_step8_5_1_correlation_context.py` | Comprehensive tests (66 tests) | ~900 |

---

## 2. Files Modified

| File | Changes |
|------|---------|
| `app/correlation/__init__.py` | Exported new context classes and functions |

---

## 3. Existing CorrelationEngine Integration Points

### Discovered Architecture

```
app/correlation/engine.py:
├── CorrelationEngine (singleton)
├── EventData (normalized event for correlation)
├── Correlation (link between events)
├── CorrelatedGroup (group of related events)
└── CorrelationResult (analysis output)

Integration point: CorrelationContext.to_event_data_dict() → EventData
```

### EventData Compatibility

```python
# CorrelationContext converts to EventData format:
ctx.to_event_data_dict() → {
    "event_id": str,
    "domain": "windows_event" | "linux_ssh" | "web_application",
    "timestamp": datetime,
    "ips": [source_ip, destination_ip],
    "users": [username, user_id],
    "assets": [hostname],
}
```

---

## 4. CorrelationContext Design

### Model Fields

```python
class CorrelationContext(BaseModel):
    # === Tenant Isolation (REQUIRED) ===
    tenant_id: str | None          # REQUIRED for cross-source correlation
    
    # === Source Identification ===
    source_id: str | None          # LogSource identifier
    source_type: LogSourceType     # windows_event, linux_ssh, web_application
    source_event_id: str | None    # Stable event ID from source
    finding_id: str | None         # Associated finding ID
    event_id: str | None           # Internal log event ID
    
    # === Timestamps ===
    timestamp: datetime             # UTC, timezone-aware
    
    # === Network Entities ===
    source_ip: str | None          # Normalized IPv4/IPv6
    destination_ip: str | None     # Normalized destination IP
    
    # === Identity Entities ===
    username: str | None           # Normalized username
    user_id: str | None            # User identifier (distinct from username)
    
    # === Host Entities ===
    hostname: str | None           # Normalized hostname
    
    # === Session/Request Entities ===
    session_id: str | None         # Session identifier
    request_id: str | None         # Request correlation ID
    trace_id: str | None           # Distributed trace ID
    
    # === Process Entities ===
    process_id: int | None         # Process ID
    parent_process_id: int | None  # Parent process ID
    process_name: str | None       # Process/executable name
    
    # === Application Context ===
    application_name: str | None   # Application name
```

### Key Methods

```python
# Check if correlation is possible
ctx.can_correlate() → bool  # Requires tenant_id + at least one entity

# Generate tenant-isolated correlation keys
ctx.get_correlation_keys() → ["tenant:org-123:ip:10.0.0.5", "tenant:org-123:user:admin"]

# Generate stable fingerprint
ctx.get_entity_fingerprint() → str  # SHA-256 hash of sorted keys

# Convert to EventData format
ctx.to_event_data_dict() → dict  # Compatible with CorrelationEngine
```

---

## 5. Windows Normalization Mappings

| Event ID | Windows Field | Correlation Field |
|----------|---------------|-------------------|
| 4624/4625 | TargetUserName | username |
| 4624/4625 | IpAddress | source_ip |
| 4624/4625 | WorkstationName | hostname |
| 4624/4625 | TargetLogonId | session_id |
| 4648 | SubjectUserName | username (fallback) |
| 4648 | TargetUserName | username (primary) |
| 4672 | SubjectUserName | username |
| 4672 | SubjectLogonId | session_id |
| 4688 | SubjectUserName | username |
| 4688 | NewProcessId | process_id (hex → int) |
| 4688 | ParentProcessId | parent_process_id |
| 4688 | NewProcessName | process_name (basename) |
| 4720/4726 | TargetUserName | username |
| All | Computer | hostname (fallback) |

**Hex PID handling:**
```python
# Windows PIDs like "0x1234" are converted
if raw_pid.startswith("0x"):
    process_id = int(raw_pid, 16)
```

---

## 6. Linux/SSH Normalization Mappings

| Linux Field | Correlation Field | Notes |
|-------------|-------------------|-------|
| username / user | username | Normalized, system accounts filtered |
| target_user / sudo_user | user_id | Preserved for privilege escalation (root NOT filtered) |
| source_ip / ip | source_ip | Normalized IPv4/IPv6 |
| hostname | hostname | From LogEvent |
| session / session_id | session_id | Preserved |
| pid | process_id | From LogEvent or extracted_fields |
| program | process_name | From LogEvent |

**Sudo target handling:**
```python
# For sudo/su, "root" is NOT filtered - privilege escalation matters
if raw_target and raw_target != raw_username:
    user_id = target_str  # Even "root"
```

---

## 7. Web Application Normalization Mappings

| Web Field | Correlation Field | Notes |
|-----------|-------------------|-------|
| user_id | user_id | Preserved as-is |
| username | username | Preserved with email domain |
| ip_address / client_ip | source_ip | Normalized |
| hostname | hostname | From LogEvent |
| session_id | session_id | Preserved |
| request_id | request_id | Preserved |
| trace_id | trace_id | Preserved |
| application | application_name | From LogEvent.program or fields |
| client_event_id | source_event_id | NOT a correlation entity |

**Email username handling:**
```python
# Web usernames preserve email format
username = normalize_username(raw_username, preserve_domain=True)
# "jsmith@example.com" → "jsmith@example.com" (not "jsmith")
```

---

## 8. Tenant Isolation Mechanism

### Correlation Key Format
```
tenant:{tenant_id}:{entity_type}:{entity_value}
```

### Examples
```
tenant:org-A:ip:192.168.1.100
tenant:org-A:user:jsmith
tenant:org-B:ip:192.168.1.100  # Different tenant, no correlation
tenant:org-B:user:jsmith       # Different tenant, no correlation
```

### Enforcement

```python
def get_correlation_keys(self) -> list[str]:
    if not self.tenant_id:
        return []  # No keys without tenant
    
    keys = []
    prefix = f"tenant:{self.tenant_id}"
    
    if self.source_ip and not is_localhost_ip(self.source_ip):
        keys.append(f"{prefix}:ip:{self.source_ip}")
    # ... etc
```

---

## 9. Correlation Key Mechanism

### Entity Types

| Type | Key Format |
|------|------------|
| IP Address | `tenant:T:ip:192.168.1.1` |
| Username | `tenant:T:user:jsmith` |
| User ID | `tenant:T:user_id:u-12345` |
| Hostname | `tenant:T:host:server01` |
| Session | `tenant:T:session:sess-abc` |
| Request | `tenant:T:request:req-123` |
| Trace | `tenant:T:trace:trace-xyz` |

### Deterministic Fingerprint

```python
def get_entity_fingerprint(self) -> str | None:
    keys = sorted(self.get_correlation_keys())
    content = "|".join(keys)
    return hashlib.sha256(content.encode()).hexdigest()[:16]
```

---

## 10. Database Changes/Migrations

**No database schema changes required.**

The CorrelationContext is computed at runtime from existing `LogEvent.extracted_fields`. All necessary data already exists in:
- `log_events.extracted_fields` (JSONB)
- `log_sources.organization_id` (tenant isolation)

---

## 11. Redpanda Compatibility

**Existing architecture preserved.**

```
LogEvent → SecurityEvent → Redpanda (security-events)
                               ↓
         CorrelationContextExtractor.extract(log_event, tenant_id)
                               ↓
                      CorrelationContext
                               ↓
                      CorrelationEngine
```

The extraction happens **after** events are received from Redpanda, not during publishing.

---

## 12. Tests Added

### Test Categories (66 tests)

| Test Class | Tests | Coverage |
|------------|-------|----------|
| TestWindows4624Normalization | 4 | Username, domain, logon ID, workstation |
| TestWindows4625Normalization | 2 | Failed logon username, attacker IP |
| TestWindows4648Normalization | 2 | Subject user, target server |
| TestWindows4672Normalization | 2 | Privileged user, logon ID |
| TestWindows4688Normalization | 3 | Process name, hex PID, subject user |
| TestWindowsAccountEvents | 2 | 4720/4726 account events |
| TestLinuxSSHSuccess | 2 | Username, session |
| TestLinuxSSHFailure | 2 | Attacker IP, invalid user |
| TestLinuxSudo | 2 | User + target user, failed |
| TestLinuxSession | 2 | PAM session opened/closed |
| TestWebAuthentication | 2 | User ID, username only |
| TestWebRequest | 2 | Request ID, application |
| TestWebSession | 1 | Session ID |
| TestWebTraceId | 2 | Trace ID, client_event_id isolation |
| TestMissingEntities | 3 | Missing IP, username, empty fields |
| TestInvalidIP | 3 | Invalid, placeholder, zero IP |
| TestEmptyUsername | 3 | Empty, system accounts, placeholder |
| TestIPv4Normalization | 2 | Normalized, localhost |
| TestIPv6Normalization | 3 | Normalized, localhost, compressed |
| TestTenantAIsolation | 2 | Tenant A has ID, keys include tenant |
| TestTenantBIsolation | 2 | Different tenant ID, different keys |
| TestSameUsernameAcrossTenants | 1 | Same user, different keys |
| TestSameIPAcrossTenants | 1 | Same IP, different keys |
| TestSameRequestIdAcrossTenants | 1 | Same request, different keys |
| TestRedactionSafety | 2 | No password in context, no token in keys |
| TestDeterministicKeys | 5 | Same input → same keys/fingerprint |
| TestCorrelationContextMethods | 6 | can_correlate, localhost exclusion, etc. |
| TestEmailAnalysisUnchanged | 2 | Email agent import, correlation engine works |

---

## 13. Test Results

```
========== 714 passed, 31 skipped, 117 warnings in 146.74s ==========
```

### New Tests
- `test_step8_5_1_correlation_context.py`: **66 passed**

### Existing Tests (Unchanged)
- All STEP 8.1-8.4 tests pass
- All Windows detection tests pass
- All Linux collector/parser tests pass
- All web ingestion tests pass
- All correlation tests pass
- All email analysis tests pass

---

## 14. Ruff Result

```
Found 1 error (1 fixed, 0 remaining).
```

Import sorting was auto-fixed. No other issues.

---

## 15. Mypy Result

Mypy not configured for this project.

---

## 16. Limitations

1. **No time windowing implementation** - This step focuses on the data contract; windowed correlation is a later step
2. **No persistence of correlation context** - Computed at runtime from existing LogEvent fields
3. **Tenant ID must be passed explicitly** - Not automatically looked up from LogSource (caller provides)
4. **System account filtering** - "root" is filtered as a username but preserved for sudo target_user

---

## 17. Items NOT Live-Verified

| Item | Reason |
|------|--------|
| Windows Event Log extraction | No live Windows test server |
| Linux SSH log extraction | No live Linux test server |
| Redpanda integration | No running Redpanda cluster |
| PostgreSQL tenant isolation | Unit tests only |

All items are **TEST VERIFIED** through comprehensive unit tests.

---

## 18. Final Classification

### ✅ IMPLEMENTATION COMPLETE
- Canonical CorrelationContext model created
- All source types (Windows/Linux/Web) mapped
- Entity normalization is deterministic
- Missing entities remain None (not fabricated)

### ✅ TEST VERIFIED
- 66 new tests covering all requirements (A-Z)
- 714 total tests pass (full regression)
- Email analysis unchanged
- Existing CorrelationEngine intact

### ⚠️ NOT LIVE INFRASTRUCTURE VERIFIED
- No live Windows/Linux/Redpanda/PostgreSQL testing performed
- All verification is through unit/integration tests
