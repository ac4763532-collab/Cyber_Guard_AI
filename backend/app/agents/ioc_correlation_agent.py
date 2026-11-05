"""
CyberGuard AI - IOC Correlation Agent

Thin, explicit on-demand entrypoint around the existing CorrelationEngine
(app.correlation.engine) so analysts/API callers can re-run correlation
over a chosen set of findings through TaskDispatcher, like any other
agent. This is deliberately separate from and non-interfering with the
automatic pipeline (app.correlation.finding_lifecycle.on_finding_created,
app.correlation.realtime.RealtimeCorrelationService) - that pipeline,
its Redis sliding window, and its Alert-creation side effects are
untouched by this agent.

Boundary: this agent never creates or touches an Alert. It only loads
Findings, correlates them, and persists CorrelatedActivity rows via
CorrelatedActivityRepository. That keeps repeated on-demand runs safe -
re-running correlation over the same findings is a read + idempotent
upsert, never a new alert.

Idempotency: CorrelatedActivity rows persisted here are tagged with
correlation_bucket="on_demand" (a constant, unlike the automatic
pipeline's real time-bucket values from get_correlation_bucket()). Since
compute_correlation_fingerprint() hashes (finding_ids, source_types,
bucket), using a constant bucket means the fingerprint depends only on
the finding set + source types - so re-running this agent on the same
findings always recomputes the same fingerprint, and the repository's
ON CONFLICT (tenant_id, fingerprint) DO NOTHING makes the second run a
no-op rather than a duplicate row.
"""

import ipaddress
import re
from typing import Any
from uuid import uuid4

import structlog

from app.agents.base import AgentResult, AgentType, BaseAgent, Finding as AgentFinding, Severity
from app.correlation.engine import EventData, get_correlation_engine
from app.correlation.realtime import CorrelatedActivity, compute_correlation_fingerprint
from app.database.models import Finding as DBFinding
from app.database.repositories.correlated_activities import CorrelatedActivityRepository
from app.database.repositories.events import get_event_repository
from app.database.repositories.findings import get_finding_repository

logger = structlog.get_logger(__name__)

_ON_DEMAND_BUCKET = "on_demand"

# Mirrors the severity->risk_score mapping already used by
# app.correlation.integration (CorrelationContextAdapter) and
# app.correlation.realtime (_severity_to_risk) - reused verbatim rather
# than re-derived, so a given severity always maps to the same risk
# score everywhere in the correlation stack.
_SEVERITY_TO_RISK = {
    "critical": 95,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
}

_SEVERITY_TO_AGENT_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_STRENGTH_TO_FLOAT = {
    "strong": 0.9,
    "moderate": 0.6,
    "weak": 0.3,
}


class IOCCorrelationAgent(BaseAgent):
    """Dispatchable agent for on-demand correlation over a chosen set of findings."""

    agent_type = AgentType.IOC_CORRELATION
    agent_name = "IOC Correlation Agent"
    agent_version = "1.0.0"

    async def validate(self, data: dict[str, Any]) -> tuple[bool, str | None]:
        finding_ids = data.get("finding_ids")
        tenant_id = data.get("tenant_id")

        if not tenant_id or not isinstance(tenant_id, str) or not tenant_id.strip():
            return False, "tenant_id is required and must be a non-empty string"

        if not finding_ids or not isinstance(finding_ids, list):
            return False, "finding_ids is required and must be a non-empty list"

        if len(finding_ids) < 2:
            return False, "finding_ids must contain at least 2 findings to correlate"

        return True, None

    async def analyze(self, data: dict[str, Any]) -> AgentResult:
        tenant_id = data["tenant_id"].strip()
        finding_ids: list[str] = data["finding_ids"]

        finding_repo = get_finding_repository()

        # Tenant-scoped load: FindingRepository.get() returns None (not a
        # leaked existence signal) for a finding that belongs to another
        # tenant - same no-existence-leakage convention as every other
        # repository in this codebase. Findings that don't resolve here
        # are silently dropped from correlation rather than erroring the
        # whole request, since a stale/foreign finding_id in the request
        # shouldn't block correlating the ones that are valid.
        db_findings: list[DBFinding] = []
        missing_ids: list[str] = []
        for finding_id in finding_ids:
            db_finding = await finding_repo.get(finding_id, tenant_ids=[tenant_id])
            if db_finding is None:
                missing_ids.append(finding_id)
                continue
            db_findings.append(db_finding)

        if len(db_findings) < 2:
            return self._create_error_result(
                f"Fewer than 2 findings resolved for tenant (requested={len(finding_ids)}, "
                f"resolved={len(db_findings)}, missing={missing_ids}) - cannot correlate."
            )

        parent_events = await get_event_repository().list_by_ids(
            [finding.event_id for finding in db_findings],
            tenant_ids=[tenant_id],
        )
        parent_event_map = {event.id: event for event in parent_events}
        source_types = {
            event_id: getattr(event.event_type, "value", str(event.event_type))
            for event_id, event in parent_event_map.items()
        }
        finding_event_map = {finding.id: finding.event_id for finding in db_findings}
        events = [
            self._finding_to_event_data(
                finding,
                source_types.get(finding.event_id, "unknown"),
                parent_event_map.get(finding.event_id).created_at
                if finding.event_id in parent_event_map
                else finding.created_at,
            )
            for finding in db_findings
        ]

        engine = get_correlation_engine()
        result = engine.correlate(events=events)

        persisted_activities: list[dict[str, Any]] = []
        repo = CorrelatedActivityRepository(db=self._get_db())

        for group in result.groups:
            activity = self._group_to_activity(group, tenant_id, finding_event_map)
            persisted = await repo.create(activity)
            if persisted is not None:
                persisted_activities.append(persisted)

        findings_out: list[AgentFinding] = []
        max_risk = 0
        highest_severity = Severity.INFO
        for group in result.groups:
            severity_str = group.severity.lower()
            agent_severity = _SEVERITY_TO_AGENT_SEVERITY.get(severity_str, Severity.INFO)
            if group.risk_score > max_risk:
                max_risk = group.risk_score
                highest_severity = agent_severity

            findings_out.append(
                AgentFinding(
                    name=f"Correlated activity: {len(group.event_ids)} findings across {len(group.domains)} domain(s)",
                    description=(
                        f"On-demand correlation grouped {len(group.event_ids)} findings "
                        f"({', '.join(group.domains)}) via "
                        f"{len(group.correlations)} correlation link(s)."
                    ),
                    severity=agent_severity,
                    confidence=min(1.0, group.risk_score / 100.0),
                    evidence=[
                        f"{c.correlation_type.value}: {c.evidence[0] if c.evidence else ''}"
                        for c in group.correlations
                    ],
                    mitre_techniques=group.attack_techniques,
                    metadata={
                        "group_id": group.group_id,
                        "finding_ids": group.event_ids,
                        "event_ids": list(dict.fromkeys(
                            finding_event_map[finding_id]
                            for finding_id in group.event_ids
                            if finding_id in finding_event_map
                        )),
                        "domains": group.domains,
                        "shared_iocs": group.shared_iocs,
                        "shared_users": group.shared_users,
                    },
                )
            )

        summary = (
            f"Correlated {len(db_findings)} findings into {len(result.groups)} group(s), "
            f"{result.cross_domain_groups} spanning multiple domains. "
            f"{len(persisted_activities)} new correlated activity record(s) persisted "
            f"({len(result.groups) - len(persisted_activities)} already existed - idempotent re-run)."
            if result.groups
            else f"No correlations found among the {len(db_findings)} resolved findings."
        )

        return AgentResult(
            agent_type=self.agent_type,
            agent_version=self.agent_version,
            classification="correlated" if result.groups else "no_correlation",
            severity=highest_severity,
            confidence=min(1.0, max_risk / 100.0),
            risk_score=max_risk,
            findings=findings_out,
            indicators=[f.id for f in db_findings],
            summary=summary,
            recommendations=(
                ["Review the correlated activity group(s) for a potential multi-stage incident."]
                if result.groups
                else ["No cross-finding relationships detected with the current correlation thresholds."]
            ),
            metadata={
                "tenant_id": tenant_id,
                "requested_finding_ids": finding_ids,
                "missing_finding_ids": missing_ids,
                "groups_found": len(result.groups),
                "cross_domain_groups": result.cross_domain_groups,
                "persisted_activity_ids": [a.get("correlation_id") for a in persisted_activities],
                "correlation_bucket": _ON_DEMAND_BUCKET,
            },
            data_source="correlation_engine",
        )

    def _finding_to_event_data(
        self,
        finding: DBFinding,
        source_type: str = "unknown",
        event_timestamp: Any = None,
    ) -> EventData:
        """Adapt a persisted Finding to the correlation engine's EventData.

        Glue code only - no new correlation logic. Mirrors the existing
        extraction pattern in app.correlation.engine._agent_result_to_event
        (evidence["ips"]/["domains"]/["urls"]/["source_ip"]/["user"]), just
        sourced from a persisted Finding's evidence dict instead of an
        in-flight AgentResult's Finding.
        """
        evidence = finding.evidence or {}
        metadata = evidence.get("metadata") if isinstance(evidence.get("metadata"), dict) else {}
        sources = (evidence, metadata)

        def values(keys: tuple[str, ...]) -> list[str]:
            found: list[str] = []
            for source in sources:
                for key in keys:
                    value = source.get(key)
                    if isinstance(value, str) and value.strip():
                        found.append(value.strip())
                    elif isinstance(value, list):
                        found.extend(item.strip() for item in value if isinstance(item, str) and item.strip())
            return list(dict.fromkeys(found))

        ips = values(("ips", "source_ip", "ip", "remote_ip"))
        domains = values(("domains", "domain"))
        urls = values(("urls", "url", "original_url", "final_url"))
        hashes = values(("hashes", "hash", "file_hash", "sha256"))
        users = values(("users", "user", "username", "account"))

        iocs = metadata.get("iocs", [])
        if isinstance(iocs, list):
            for ioc in iocs:
                if not isinstance(ioc, dict) or not isinstance(ioc.get("value"), str):
                    continue
                ioc_type = str(ioc.get("type", "")).lower()
                target = {
                    "ip": ips,
                    "domain": domains,
                    "url": urls,
                    "hash": hashes,
                    "sha256": hashes,
                    "md5": hashes,
                    "sha1": hashes,
                }.get(ioc_type)
                if target is not None:
                    target.append(ioc["value"].strip())

        evidence_items = evidence.get("items", [])
        if isinstance(evidence_items, list):
            for item in evidence_items:
                if not isinstance(item, str):
                    continue
                for url in re.findall(r"https?://[^\s\"'<>]+", item, flags=re.IGNORECASE):
                    urls.append(url.rstrip(".,);]"))
                label, separator, raw_value = item.partition(":")
                if not separator or label.strip().lower() not in {"ip", "source ip", "remote", "host"}:
                    continue
                candidate = raw_value.strip().split()[0].strip(",;()") if raw_value.strip() else ""
                if candidate.startswith("[") and "]" in candidate:
                    candidate = candidate[1:candidate.index("]")]
                elif candidate.count(":") == 1 and "." in candidate:
                    candidate = candidate.rsplit(":", 1)[0]
                try:
                    ips.append(ipaddress.ip_address(candidate).compressed)
                except ValueError:
                    continue

        ips = list(dict.fromkeys(ips))
        domains = list(dict.fromkeys(value.lower().rstrip(".") for value in domains))
        urls = list(dict.fromkeys(urls))
        hashes = list(dict.fromkeys(value.lower() for value in hashes))
        users = list(dict.fromkeys(value.lower() for value in users))

        severity_str = (
            finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        ).lower()

        return EventData(
            event_id=finding.id,
            domain=source_type,
            timestamp=event_timestamp or finding.created_at,
            ips=list(set(ips)),
            domains=list(set(domains)),
            urls=list(set(urls)),
            hashes=list(set(hashes)),
            users=list(set(users)),
            risk_score=_SEVERITY_TO_RISK.get(severity_str, 50),
            severity=severity_str,
            mitre_techniques=list(finding.mitre_techniques or []),
            mitre_tactics=list(finding.mitre_tactics or []),
        )

    def _group_to_activity(
        self,
        group: Any,
        tenant_id: str,
        finding_event_map: dict[str, str],
    ) -> CorrelatedActivity:
        """Adapt the engine's CorrelatedGroup to the persistence-layer
        CorrelatedActivity, tagging it as an on-demand run (see module
        docstring for the idempotency rationale)."""
        finding_ids = group.event_ids
        event_ids = list(dict.fromkeys(
            finding_event_map[finding_id]
            for finding_id in finding_ids
            if finding_id in finding_event_map
        ))
        source_types = group.domains

        fingerprint = compute_correlation_fingerprint(
            finding_ids=finding_ids,
            source_types=source_types,
            correlation_bucket=_ON_DEMAND_BUCKET,
        )

        # Average correlation strength across this group's links, mapped
        # strong/moderate/weak -> float (same scale CorrelatedActivity
        # already uses - see RealtimeCorrelationService, which stores
        # target_group.correlation_strength as a plain float).
        strengths = [
            _STRENGTH_TO_FLOAT.get(c.strength.value, 0.5) for c in group.correlations
        ] or [0.5]
        avg_strength = sum(strengths) / len(strengths)

        correlation_type = self._determine_correlation_type(group)

        shared_entities = {
            "ips": [ioc["value"] for ioc in group.shared_iocs if ioc.get("type") == "ip"],
            "domains": [ioc["value"] for ioc in group.shared_iocs if ioc.get("type") == "domain"],
            "urls": [ioc["value"] for ioc in group.shared_iocs if ioc.get("type") == "url"],
            "hashes": [ioc["value"] for ioc in group.shared_iocs if ioc.get("type") == "hash"],
            "users": list(group.shared_users),
        }

        return CorrelatedActivity(
            correlation_id=str(uuid4()),
            tenant_id=tenant_id,
            fingerprint=fingerprint,
            finding_ids=finding_ids,
            event_ids=event_ids,
            source_types=source_types,
            correlation_type=correlation_type,
            correlation_strength=avg_strength,
            shared_entities=shared_entities,
            risk_score=group.risk_score,
            timestamp=group.last_seen,
            correlation_bucket=_ON_DEMAND_BUCKET,
        )

    @staticmethod
    def _determine_correlation_type(group: Any) -> str:
        """Same classification rule as
        RealtimeCorrelationService._determine_correlation_type - kept
        consistent across the automatic and on-demand paths."""
        if len(group.domains) > 1:
            return "cross_source"
        if group.shared_iocs:
            return "ioc_based"
        if group.shared_users:
            return "user_based"
        for corr in group.correlations:
            if "temporal" in corr.correlation_type.value.lower():
                return "temporal"
        return "unknown"

    @staticmethod
    def _get_db():
        from app.database.connection import get_database
        return get_database()
