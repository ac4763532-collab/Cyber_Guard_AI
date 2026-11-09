"""
CyberGuard AI — Windows Event Explanation Engine
============================================================================
Enriches genuine collected Windows security events with knowledge-base
explanations from the 10 Windows event definition catalogs at:
`backend/app/agents/log_analysis/knowledge_base/windows/`.

Provides dual perspectives:
  1. Simple View — for everyday computer users (6 core questions:
     What happened, Who was involved, Where, When, Why it matters,
     What should I do).
  2. Analyst View — for cybersecurity professionals (forensic properties,
     MITRE ATT&CK techniques, raw payload, status codes).

Ensures strict separation between:
  - Severity: informational, low, medium, high, critical
  - Assessment: normal, unusual, suspicious, unknown
  - Threat status: no_threat_established, under_investigation, confirmed_threat
  - Definition verification status: verified, partially_verified, unverified, unknown_definition
"""

from __future__ import annotations

import glob
import json
import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.event import SecurityEvent
from app.models.source import SecuritySource
from app.schemas.event_explanation import (
    AnalystViewSchema,
    EventExplanationResponse,
    MitreAttackSchema,
    SimpleViewSchema,
    WhenHappenedSchema,
    WhereHappenedSchema,
    WhoInvolvedSchema,
)

logger = get_logger(__name__)

# ─── Knowledge Base In-Memory Cache ──────────────────────────────────────────
_KB_LOCK = threading.Lock()
_KB_CACHE: Optional[Dict[str, Dict[str, Any]]] = None

# Known MITRE ATT&CK techniques for common Windows events
_MITRE_MAPPINGS: Dict[str, Dict[str, str]] = {
    "4624": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "4625": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "4688": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "7045": {
        "technique_id": "T1543.003",
        "technique_name": "Create or Modify System Process: Windows Service",
        "tactic": "Persistence, Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1543/003/",
    },
    "4672": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "4720": {
        "technique_id": "T1136.001",
        "technique_name": "Create Account: Local Account",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1136/001/",
    },
    "4726": {
        "technique_id": "T1531",
        "technique_name": "Account Access Removal",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1531/",
    },
    "4728": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "4732": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "1102": {
        "technique_id": "T1070.001",
        "technique_name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1070/001/",
    },
}

# Windows Logon Types
_LOGON_TYPES: Dict[int, str] = {
    2: "Interactive (Console or local keyboard login)",
    3: "Network (Remote share or network connection)",
    4: "Batch (Scheduled task execution)",
    5: "Service (Windows Service background startup)",
    7: "Unlock (Screen lock workstation unlocked)",
    8: "NetworkCleartext (Credentials sent over plaintext network)",
    9: "NewCredentials (RunAs command with cloned credentials)",
    10: "RemoteInteractive (Remote Desktop Protocol / RDP)",
    11: "CachedInteractive (Logon using locally cached credentials)",
    12: "CachedRemoteInteractive (Cached Remote Desktop logon)",
    13: "CachedUnlock (Cached workstation unlock)",
}

# Windows Status & SubStatus NTSTATUS Codes
_STATUS_CODES: Dict[str, str] = {
    "0x0": "Success (Operation completed normally)",
    "0xc000006a": "Bad password entered",
    "0xc0000064": "Username does not exist",
    "0xc000006d": "Invalid logon credentials",
    "0xc0000234": "Account locked out due to failed attempts",
    "0xc0000072": "Account is disabled by administrator",
    "0xc0000193": "Account has expired",
    "0xc0000070": "Workstation or logon time restriction violated",
    "0xc000006e": "Account restriction prevented logon",
}


def _get_kb_dir() -> str:
    """Resolve absolute path to windows knowledge base files."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    # from app/services to app/agents/log_analysis/knowledge_base/windows
    kb_path = os.path.normpath(
        os.path.join(base_dir, "..", "agents", "log_analysis", "knowledge_base", "windows")
    )
    return kb_path


def load_knowledge_base() -> Dict[str, Dict[str, Any]]:
    """
    Thread-safe lazy loader for the 10 Windows knowledge base files.
    Caches definitions in memory once for fast lookup.
    """
    global _KB_CACHE
    if _KB_CACHE is not None:
        return _KB_CACHE

    with _KB_LOCK:
        if _KB_CACHE is not None:
            return _KB_CACHE

        definitions: Dict[str, Dict[str, Any]] = {}
        kb_dir = _get_kb_dir()

        if os.path.isdir(kb_dir):
            json_files = glob.glob(os.path.join(kb_dir, "*.json"))
            for fpath in json_files:
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        file_data = json.load(f)
                    category_name = file_data.get("category", "General")
                    events_map = file_data.get("events", {})
                    for ev_id, ev_def in events_map.items():
                        ev_copy = dict(ev_def)
                        if "category" not in ev_copy:
                            ev_copy["category"] = category_name
                        if "definition_status" not in ev_copy:
                            ev_copy["definition_status"] = "verified"
                        definitions[str(ev_id)] = ev_copy
                except Exception as exc:
                    logger.error("Failed loading knowledge base file", extra={"file": fpath, "error": str(exc)})

        # Built-in verified system events (7045, 7036) if not already in JSON files
        if "7045" not in definitions:
            definitions["7045"] = {
                "event_id": 7045,
                "name": "Service Installed",
                "category": "System",
                "title": "A new Windows service was installed",
                "description": "Windows registered a new service in the system Service Control Manager.",
                "what_happened": "A new background service was installed on this computer. Windows services run continuously or on-demand in the background to support software and operating system capabilities.",
                "who": {
                    "SubjectUserName": "The user or process account that requested the service installation.",
                    "ServiceAccount": "The account context the service will run under (e.g. LocalSystem or user).",
                },
                "where": {
                    "ServiceName": "The registered name of the newly created service.",
                    "ImagePath": "The binary executable file path executed when the service starts.",
                },
                "when": "When the service registration was committed to the Service Control Manager database.",
                "why_it_matters": "New services are common during legitimate software installations and updates. However, malware and attackers frequently create services to establish permanent persistence and gain administrative privileges.",
                "severity_guidance": {
                    "low": "A recognized service installed by a known application or administrative update.",
                    "medium": "An unfamiliar service installed without recent software activity.",
                    "high": "A service running from temporary directories or executing suspicious commands.",
                },
                "recommendations": [
                    "Verify whether you recently installed or updated software corresponding to this service name.",
                    "Inspect the service file path (ImagePath) to ensure it originates from a verified program folder (like Program Files) and not an unexpected location.",
                ],
                "definition_status": "verified",
            }

        if "7036" not in definitions:
            definitions["7036"] = {
                "event_id": 7036,
                "name": "Service State Changed",
                "category": "System",
                "title": "A service transitioned state",
                "description": "A Windows service entered the running or stopped state.",
                "what_happened": "A background service on this computer changed its operating status (for example, started or stopped).",
                "who": {"SubjectUserName": "System Service Control Manager"},
                "where": {"ServiceName": "The name of the service that changed state."},
                "when": "When the service status update was reported to the operating system.",
                "why_it_matters": "Services start and stop regularly during routine computer usage, software execution, and system maintenance.",
                "severity_guidance": {
                    "low": "Routine service startup or shutdown during regular operation.",
                },
                "recommendations": [
                    "No action is required for routine background service transitions.",
                ],
                "definition_status": "verified",
            }

        _KB_CACHE = definitions
        logger.info("Windows event knowledge base loaded", extra={"total_definitions": len(definitions)})
        return _KB_CACHE


def resolve_event_id(event: SecurityEvent) -> Optional[str]:
    """
    Extracts canonical Windows Event ID from raw payload or event type string.
    Examples:
      - raw_payload["EventID"] = 4624 -> "4624"
      - event_type = "windows.security.4624" -> "4624"
      - event_type = "windows.4624" -> "4624"
    """
    raw = event.raw_payload or {}
    ev_id = raw.get("EventID") or raw.get("event_id") or raw.get("eventId")
    if ev_id is not None:
        return str(ev_id).strip()

    # Fallback: check event_type string
    ev_type = str(event.event_type or "").lower()
    m = re.search(r"(?:windows(?:\.[a-z]+)?\.)(\d{3,5})", ev_type)
    if m:
        return m.group(1)

    m2 = re.search(r"\b(\d{4,5})\b", ev_type)
    if m2:
        return m2.group(1)

    return None


def format_relative_time(dt: datetime) -> str:
    """Format datetime into friendly relative string (e.g. '5 minutes ago')."""
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    delta = now - dt
    total_seconds = int(delta.total_seconds())

    if total_seconds < 30:
        return "just now"
    if total_seconds < 90:
        return "1 minute ago"
    if total_seconds < 3600:
        minutes = max(1, total_seconds // 60)
        return f"{minutes} minutes ago"
    if total_seconds < 7200:
        return "1 hour ago"
    if total_seconds < 86400:
        hours = total_seconds // 3600
        return f"{hours} hours ago"
    if total_seconds < 172800:
        return "yesterday"
    days = total_seconds // 86400
    return f"{days} days ago"


def determine_account_type(account: Optional[str]) -> str:
    """Classify Windows account type for non-technical users."""
    if not account:
        return "Not available"
    acc_lower = account.lower().strip()
    if acc_lower in ("system", "local system", "localsystem", "local service", "network service"):
        return "Windows System Account (Operating System Internal)"
    if acc_lower.endswith("$"):
        return "Computer / Machine Identity (Internal Device Account)"
    if "admin" in acc_lower:
        return "Administrator Account (High Privilege)"
    return "Standard User Account"


def decode_logon_type(raw_val: Any) -> Optional[str]:
    """Convert numerical Windows LogonType to human description."""
    if raw_val is None:
        return None
    try:
        val_int = int(raw_val)
        return _LOGON_TYPES.get(val_int, f"Type {val_int}")
    except (ValueError, TypeError):
        return str(raw_val)


def decode_status_code(code_val: Any) -> Optional[str]:
    """Convert NTSTATUS hex code into description."""
    if not code_val:
        return None
    code_str = str(code_val).strip().lower()
    return _STATUS_CODES.get(code_str)


def explain_security_event(
    db: Session,
    event: SecurityEvent,
) -> EventExplanationResponse:
    """
    Main engine entry point: produces a validated, comprehensive EventExplanationResponse
    using knowledge base definitions and real event attributes.
    """
    kb = load_knowledge_base()
    event_id_str = resolve_event_id(event)
    raw = event.raw_payload or {}
    device = db.get(SecuritySource, event.source_id) if event.source_id else None
    device_name = (
        (device.name if device else None)
        or event.hostname
        or raw.get("Computer")
        or raw.get("Hostname")
        or "Windows Device"
    )

    # ── 1. Resolve Definition ────────────────────────────────────────────────
    kb_def: Optional[Dict[str, Any]] = kb.get(event_id_str) if event_id_str else None

    if kb_def:
        definition_status = kb_def.get("definition_status", "verified")
        title = kb_def.get("title") or kb_def.get("name") or f"Windows Event {event_id_str}"
        short_desc = kb_def.get("description") or f"Windows logged event {event_id_str}."
        what_happened_text = kb_def.get("what_happened") or short_desc
        why_it_matters_text = kb_def.get("why_it_matters") or "Windows routinely records diagnostic events."
        recommendations = list(kb_def.get("recommendations", []))
        category = kb_def.get("category") or (event.category.value if event.category else "Security")
    else:
        definition_status = "unknown_definition"
        title = f"Windows Event {event_id_str}" if event_id_str else "Generic Windows Activity"
        short_desc = (
            f"Windows logged event {event_id_str} on this computer. "
            "A verified explanation definition is not currently cataloged in the offline knowledge base."
            if event_id_str
            else "Windows recorded an activity on this device."
        )
        what_happened_text = (
            f"Windows generated an audit event with ID {event_id_str}. "
            "The system recorded this event as part of its ongoing operational and security telemetry."
            if event_id_str
            else "Windows recorded security telemetry from this computer."
        )
        why_it_matters_text = (
            "Windows regularly logs diagnostic and operational events during normal background activity. "
            "Without an enriched definition, this event is preserved for diagnostic and forensic integrity."
        )
        recommendations = [
            "No immediate action is required unless this coincides with other security alerts.",
            "Consult Windows system documentation if diagnosing a specific operational issue.",
        ]
        category = event.category.value if event.category else "System"

    # ── 2. Determine Severity, Assessment, Threat Status ────────────────────
    # Severity
    sev = str(event.severity.value if hasattr(event.severity, "value") else event.severity).lower()
    if sev not in ("informational", "info", "low", "medium", "high", "critical"):
        sev = "informational"
    if sev == "info":
        sev = "informational"

    # Behavioral Assessment (normal, unusual, suspicious, unknown)
    if event_id_str == "4624":
        assessment = "normal"
    elif event_id_str == "4625":
        assessment = "unusual" if sev in ("low", "informational") else "suspicious"
    elif event_id_str in ("4688", "7045", "7036"):
        assessment = "normal" if event.findings_count == 0 else "suspicious"
    elif definition_status == "unknown_definition":
        assessment = "unknown"
    else:
        assessment = "normal" if sev in ("informational", "low") else "unusual"

    # Threat Status (no_threat_established, under_investigation, confirmed_threat)
    if event.findings_count > 0:
        threat_status = "confirmed_threat"
    elif assessment == "suspicious":
        threat_status = "under_investigation"
    else:
        threat_status = "no_threat_established"

    # ── 3. Extract Entity Fields ─────────────────────────────────────────────
    # User / Account
    target_user = raw.get("TargetUserName") or raw.get("TargetUser")
    subject_user = raw.get("SubjectUserName") or raw.get("SubjectUser")
    raw_user = raw.get("UserName") or raw.get("Username") or event.username
    primary_account = target_user or raw_user or subject_user
    domain = raw.get("TargetDomainName") or raw.get("SubjectDomainName") or raw.get("Domain")
    sid = raw.get("TargetUserSid") or raw.get("SubjectUserSid") or raw.get("UserSid")

    account_type_desc = determine_account_type(primary_account)

    if subject_user and target_user and subject_user != target_user:
        who_expl = f"Initiated by caller '{subject_user}' acting on target account '{target_user}'."
    elif primary_account:
        acc_lower = primary_account.lower().strip()
        if acc_lower in ("system", "localsystem", "local system"):
            who_expl = "The Windows operating system itself (SYSTEM account) performed this action for routine internal maintenance."
        elif acc_lower in ("local service", "network service"):
            who_expl = f"Windows built-in service identity '{primary_account}' executed this background operation with limited system privileges."
        elif acc_lower.endswith("$"):
            who_expl = f"Computer machine account '{primary_account}' performed this operation automatically as part of domain or network synchronization."
        elif "admin" in acc_lower:
            who_expl = f"Privileged administrative account '{primary_account}' initiated or was targeted by this activity."
        else:
            who_expl = f"User account '{primary_account}' was involved in this event."
    else:
        who_expl = "No specific user account was recorded in this event record. It originated from kernel or hardware-level telemetry."

    # Location / Workstation / Process
    channel = raw.get("Channel") or "Security"
    process_path = (
        raw.get("ProcessName")
        or raw.get("NewProcessName")
        or raw.get("ImagePath")
        or event.process_name
    )
    source_workstation = raw.get("WorkstationName") or raw.get("Workstation")
    source_ip = raw.get("IpAddress") or raw.get("SourceNetworkAddress") or event.source_ip
    if source_ip and source_ip not in ("-", "127.0.0.1", "::1", "localhost"):
        ip_display = source_ip
        where_expl = f"Activity targeted monitored computer '{device_name}' from remote source IP {source_ip} over the {channel} log channel."
    elif source_workstation and source_workstation != device_name:
        ip_display = None
        where_expl = f"Recorded on '{device_name}' requested remotely from workstation '{source_workstation}' via {channel} log."
    else:
        ip_display = None
        where_expl = f"Activity occurred locally on monitored computer '{device_name}' recorded in the Windows {channel} log channel."
    if process_path:
        where_expl += f" Executable program: {process_path}."

    # When
    ev_time = event.event_time
    if ev_time.tzinfo is None:
        ev_time = ev_time.replace(tzinfo=timezone.utc)
    ev_time_formatted = ev_time.strftime("%B %d, %Y at %I:%M:%S %p UTC")
    rel_time = format_relative_time(ev_time)

    # Dynamic plain-English synthesis for What Happened
    if event_id_str == "4624":
        l_desc = decode_logon_type(raw.get("LogonType")) or "a valid session"
        acc_txt = f"account '{primary_account}'" if primary_account else "an authorized user"
        what_happened_text = (
            f"A user or process successfully signed in as {acc_txt} via {l_desc}. "
            f"Windows verified the credentials and created an authorized logon session on this computer."
        )
    elif event_id_str == "4625":
        acc_txt = f"account '{primary_account}'" if primary_account else "an unrecorded account"
        st_desc = decode_status_code(raw.get("Status")) or decode_status_code(raw.get("SubStatus")) or "the credentials were invalid"
        what_happened_text = (
            f"Windows rejected an attempted sign-in for {acc_txt}. "
            f"The logon attempt failed because {st_desc}."
        )
    elif event_id_str == "4688":
        proc_txt = process_path or raw.get("NewProcessName") or "an executable process"
        acc_txt = f"account '{primary_account}'" if primary_account else "the operating system"
        what_happened_text = (
            f"A new application process ('{proc_txt}') was launched by {acc_txt}. "
            f"Windows recorded the program start and assigned it an execution ID."
        )
    elif event_id_str == "7045":
        svc_name = raw.get("ServiceName") or "a background service"
        what_happened_text = (
            f"A new Windows background service named '{svc_name}' was registered on this computer. "
            f"The Service Control Manager recorded the service registration."
        )
    elif kb_def and kb_def.get("what_happened"):
        what_happened_text = kb_def["what_happened"]

    # Dynamic contextual synthesis for Why It Matters
    if event.findings_count > 0:
        why_it_matters_text = (
            "This event triggered an active security detection rule. "
            "Investigation is recommended to verify whether the recorded activity was authorized."
        )
    elif event_id_str == "4624":
        why_it_matters_text = (
            "Successful logons happen continuously throughout standard computer usage. "
            "This is normal routine activity unless you do not recognize the user account or the logon occurred at an unexpected time."
        )
    elif event_id_str == "4625":
        why_it_matters_text = (
            "A single logon failure is frequently caused by a mistyped password. "
            "However, multiple failed attempts in close succession can indicate an unauthorized access or brute-force attempt."
        )
    elif event_id_str == "4688":
        why_it_matters_text = (
            "Applications launch continually as you use software on your computer. "
            "This is expected system behavior unless the executable program path is unfamiliar or located in a temporary download folder."
        )
    elif event_id_str == "7045":
        why_it_matters_text = (
            "Legitimate software frequently installs background services for updates and operation. "
            "However, malware tools also install services to establish persistent access. Verify that you recognize the newly added service."
        )
    elif kb_def and kb_def.get("why_it_matters"):
        why_it_matters_text = kb_def["why_it_matters"]
    else:
        why_it_matters_text = (
            "Windows generated this operational telemetry during regular system activity. "
            "There is no evidence of an attack or security threat associated with this record."
        )

    # Dynamic contextual recommendations for What Should I Do
    if event.findings_count > 0:
        recommendations = [
            "Review the associated security finding details and correlated threat indicators.",
            "Verify whether this activity was executed by an authorized administrator.",
        ]
    elif event_id_str == "4625":
        recommendations = [
            "Verify whether you or an authorized user mistyped your password around this time.",
            "If you do not recognize this sign-in attempt, verify that your account password is strong.",
        ]
    elif event_id_str in ("4624", "4688", "7036") or assessment == "normal":
        recommendations = [
            "No action is required if you recognize this activity.",
            "Continue regular monitoring with CyberGuard AI.",
        ]
    elif not recommendations:
        recommendations = [
            "No action is required if you recognize this activity.",
        ]

    # ── 4. Build Simple View ─────────────────────────────────────────────────
    simple_view = SimpleViewSchema(
        what_happened=what_happened_text,
        who=WhoInvolvedSchema(
            account_name=primary_account,
            account_type=account_type_desc,
            initiating_user=subject_user,
            target_user=target_user,
            domain=domain,
            user_sid=sid,
            explanation=who_expl,
        ),
        where=WhereHappenedSchema(
            monitored_device=device_name,
            source_workstation=source_workstation,
            source_ip=ip_display,
            channel=channel,
            process_path=process_path,
            explanation=where_expl,
        ),
        when=WhenHappenedSchema(
            timestamp=ev_time,
            timestamp_formatted=ev_time_formatted,
            relative_time=rel_time,
            timezone="UTC",
        ),
        why_it_matters=why_it_matters_text,
        what_should_i_do=recommendations,
    )

    # ── 5. Build Analyst View ────────────────────────────────────────────────
    # Technical properties (strictly hide missing/null fields)
    tech_props: Dict[str, Any] = {}
    if raw.get("Provider"):
        tech_props["Provider"] = raw.get("Provider")
    elif raw.get("ProviderName"):
        tech_props["Provider"] = raw.get("ProviderName")

    if event_id_str:
        tech_props["Event ID"] = event_id_str
    if raw.get("Version") is not None:
        tech_props["Version"] = raw.get("Version")
    if channel:
        tech_props["Channel"] = channel
    if device_name:
        tech_props["Computer"] = device_name
    if raw.get("RecordNumber") or raw.get("RecordId"):
        tech_props["Record ID"] = raw.get("RecordNumber") or raw.get("RecordId")
    tech_props["Timestamp (UTC)"] = ev_time.isoformat()

    if sid:
        tech_props["Account SID"] = sid
    if primary_account:
        tech_props["Account Name"] = primary_account
    if domain:
        tech_props["Domain Context"] = domain

    # Logon details
    logon_type_raw = raw.get("LogonType")
    if logon_type_raw is not None:
        tech_props["Logon Type"] = decode_logon_type(logon_type_raw)
    if raw.get("LogonProcessName"):
        tech_props["Logon Process"] = raw.get("LogonProcessName")
    if raw.get("AuthenticationPackageName"):
        tech_props["Auth Package"] = raw.get("AuthenticationPackageName")

    # Status / SubStatus
    status_raw = raw.get("Status")
    if status_raw:
        decoded_st = decode_status_code(status_raw)
        tech_props["Status"] = f"{status_raw} ({decoded_st})" if decoded_st else status_raw
    substatus_raw = raw.get("SubStatus")
    if substatus_raw:
        decoded_sub = decode_status_code(substatus_raw)
        tech_props["SubStatus"] = f"{substatus_raw} ({decoded_sub})" if decoded_sub else substatus_raw

    # Process details
    if raw.get("ProcessId") is not None:
        tech_props["Process ID"] = raw.get("ProcessId")
    if process_path:
        tech_props["Process Path"] = process_path
    if raw.get("CommandLine"):
        tech_props["Command Line"] = raw.get("CommandLine")
    if raw.get("ParentProcessName"):
        tech_props["Parent Process"] = raw.get("ParentProcessName")
    if raw.get("ServiceName"):
        tech_props["Service Name"] = raw.get("ServiceName")
    if raw.get("ServiceType"):
        tech_props["Service Type"] = raw.get("ServiceType")
    if raw.get("StartType"):
        tech_props["Start Type"] = raw.get("StartType")

    # Network
    if ip_display:
        tech_props["Source IP"] = ip_display
    if raw.get("IpPort") or raw.get("SourcePort"):
        tech_props["Source Port"] = raw.get("IpPort") or raw.get("SourcePort")

    # MITRE ATT&CK: Strictly do NOT assign based on Event ID alone!
    # Only display if detection engine has supporting evidence (findings > 0 or rule_id).
    mitre_data: Optional[MitreAttackSchema] = None
    has_detection_evidence = (event.findings_count > 0) or bool(raw.get("rule_id")) or bool(raw.get("finding_id"))

    if has_detection_evidence and event_id_str and event_id_str in _MITRE_MAPPINGS:
        m_info = _MITRE_MAPPINGS[event_id_str]
        rule_ref = raw.get("rule_id") or "DEFENSE-ENGINE"
        mitre_data = MitreAttackSchema(
            technique_id=m_info["technique_id"],
            technique_name=m_info["technique_name"],
            tactic=m_info["tactic"],
            url=m_info["url"],
            mapping_reason=f"Detection rule '{rule_ref}' matched anomalous activity for event {event_id_str}.",
            supporting_evidence=f"Correlated with {event.findings_count} active security finding(s) on device '{device_name}'.",
        )

    # Detection rule reference if findings exist
    detection_rule_id = None
    if event.findings_count > 0 and raw.get("rule_id"):
        detection_rule_id = str(raw.get("rule_id"))

    analyst_view = AnalystViewSchema(
        technical_properties=tech_props,
        mitre_attack=mitre_data,
        detection_rule=detection_rule_id,
        raw_payload=raw,
    )

    return EventExplanationResponse(
        event_id=event.id,
        device_id=event.source_id,
        device_name=device_name,
        original_event_id=event_id_str,
        title=title,
        short_description=short_desc,
        severity=sev,
        assessment=assessment,
        threat_status=threat_status,
        definition_status=definition_status,
        category=category,
        event_time=ev_time,
        event_time_formatted=ev_time_formatted,
        relative_time=rel_time,
        simple_view=simple_view,
        analyst_view=analyst_view,
    )
