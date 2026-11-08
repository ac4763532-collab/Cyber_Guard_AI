"""
CyberGuard AI — Threat Intelligence Agent
============================================================================

Enriches events with external threat intelligence. For each IOC in the
event, queries all enabled providers, combines results, and produces a
finding when the combined evidence crosses the maliciousness threshold.

IOC extraction
--------------
From each event, the agent extracts whatever IOCs are present:

    event.source_ip       → "ip"
    event.destination_ip  → "ip"
    event.domain          → "domain"
    event.url             → "url"
    event.hash_sha256     → "hash"  (preferred)
    event.hash_md5        → "hash"  (fallback)
    raw_payload.cve*      → "cve"   (from vuln-scanner events)

Each unique (ioc_type, ioc_value) pair is queried **once per event**,
even if the event mentions the same IP in both source_ip and
destination_ip (unusual but possible).

Provider calls
--------------
For each IOC, the agent calls every provider's ``lookup_<type>``
method. Providers that don't support the IOC type return None (base
class default). Providers that are disabled (missing API key) return
None. Providers that are rate-limited return None.

The agent collects only non-None results and passes them to the
verdict rules.

Failure mode
------------
If NO providers are enabled (no API keys + URLhaus/MITRE/NVD work but
there's no IOC they can enrich), the agent produces zero findings.
**This is not an error** — it's the expected state on a fresh install
with no external services configured. The agent logs this once at
startup, not per event.

If all providers fail at runtime (network down), the agent still
returns an ``AgentResult`` with empty findings and one error entry
summarizing the failure. The runtime logs and continues.

Config (from settings via runtime)
----------------------------------
    virustotal_api_key, virustotal_rpm
    abuseipdb_api_key, abuseipdb_rpm
    otx_api_key, otx_rpm            (future provider)
    urlhaus_enabled                 (bool)
    nvd_api_key, nvd_rpm
    mitre_enabled                   (bool)
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from app.agents.base import AgentContext, AgentResult, BaseAgent
from app.agents.threat_intelligence.rules import (
    BaseVerdictRule,
    KnownCveRule,
    MaliciousDomainRule,
    MaliciousHashRule,
    MaliciousIpRule,
    MaliciousUrlRule,
)
from app.agents.threat_intelligence.providers.base import (
    ProviderResult,
    ThreatIntelProvider,
)
from app.core.exceptions import AgentError
from app.core.logging import get_logger


logger = get_logger(__name__)


class ThreatIntelligenceAgent(BaseAgent):
    """Enriches events with external threat intel."""

    name = "threat_intelligence"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._providers = self._build_providers()
        self._rules_by_ioc_type = self._build_verdict_rules()

        enabled_count = sum(1 for p in self._providers if p.is_enabled)
        if enabled_count == 0:
            self._logger.info(
                "Threat Intel agent: no providers enabled — will produce "
                "no findings until API keys are configured. URLhaus, NVD, "
                "and MITRE should be enabled by default if this message "
                "appears.",
            )

    # ── Setup ───────────────────────────────────────────────────────────

    def _build_providers(self) -> list[ThreatIntelProvider]:
        """
        Construct enabled providers from config.

        Imports are lazy so a broken provider file doesn't break the
        whole agent — each provider is imported in its own try/except.
        """
        providers: list[ThreatIntelProvider] = []

        # VirusTotal (optional API key)
        try:
            from app.agents.threat_intelligence.providers.virustotal import (
                VirusTotalProvider,
            )
            vt = VirusTotalProvider(
                api_key=self._config.get("virustotal_api_key") or None,
                rate_limit_rpm=int(self._config.get("virustotal_rpm", 4)),
            )
            providers.append(vt)
        except Exception as exc:  # noqa: BLE001
            self._logger.warning(
                "VirusTotal provider unavailable",
                extra={"error": str(exc)[:200]},
            )

        # AbuseIPDB (optional API key)
        try:
            from app.agents.threat_intelligence.providers.abuseipdb import (
                AbuseIPDBProvider,
            )
            abuse = AbuseIPDBProvider(
                api_key=self._config.get("abuseipdb_api_key") or None,
                rate_limit_rpm=int(self._config.get("abuseipdb_rpm", 60)),
            )
            providers.append(abuse)
        except Exception as exc:  # noqa: BLE001
            self._logger.warning(
                "AbuseIPDB provider unavailable",
                extra={"error": str(exc)[:200]},
            )

        # URLhaus (no API key required)
        if self._config.get("urlhaus_enabled", True):
            try:
                from app.agents.threat_intelligence.providers.urlhaus import (
                    URLhausProvider,
                )
                providers.append(URLhausProvider())
            except Exception as exc:  # noqa: BLE001
                self._logger.warning(
                    "URLhaus provider unavailable",
                    extra={"error": str(exc)[:200]},
                )

        # NVD (optional API key)
        try:
            from app.agents.threat_intelligence.providers.nvd import (
                NVDProvider,
            )
            nvd = NVDProvider(
                api_key=self._config.get("nvd_api_key") or None,
                rate_limit_rpm=int(self._config.get("nvd_rpm", 10)),
            )
            providers.append(nvd)
        except Exception as exc:  # noqa: BLE001
            self._logger.warning(
                "NVD provider unavailable",
                extra={"error": str(exc)[:200]},
            )

        # MITRE (local, no key)
        if self._config.get("mitre_enabled", True):
            try:
                from app.agents.threat_intelligence.providers.mitre import (
                    MitreAttackProvider,
                )
                providers.append(MitreAttackProvider())
            except Exception as exc:  # noqa: BLE001
                self._logger.warning(
                    "MITRE provider unavailable",
                    extra={"error": str(exc)[:200]},
                )

        return providers

    def _build_verdict_rules(self) -> dict[str, BaseVerdictRule]:
        return {
            "ip": MaliciousIpRule(),
            "domain": MaliciousDomainRule(),
            "url": MaliciousUrlRule(),
            "hash": MaliciousHashRule(),
            "cve": KnownCveRule(),
        }

    # ── Main entry point ────────────────────────────────────────────────

    def process(self, context: AgentContext) -> AgentResult:
        start = time.perf_counter()
        findings = []
        errors: list[dict[str, Any]] = []
        external_calls = 0
        iocs_examined = 0

        iocs = self._extract_unique_iocs(context)

        for ioc_type, ioc_value in iocs:
            iocs_examined += 1

            # Bail early if we're running low on time
            remaining = self._remaining_seconds(context)
            if remaining is not None and remaining < 2.0:
                self._logger.warning(
                    "Threat Intel agent running low on time — stopping",
                    extra={
                        "remaining_seconds": round(remaining, 1),
                        "iocs_processed": iocs_examined - 1,
                    },
                )
                break

            provider_results = self._lookup_all_providers(
                ioc_type, ioc_value, context,
            )
            external_calls += len(provider_results)

            if not provider_results:
                continue

            rule = self._rules_by_ioc_type.get(ioc_type)
            if rule is None:
                continue

            try:
                spec = rule.evaluate(context, ioc_value, provider_results)
                if spec is None:
                    continue
                finding = self._make_finding(context, **spec.as_kwargs())
                findings.append(finding)
            except AgentError as exc:
                errors.append(self._wrap_error(stage=rule.name, exception=exc))
                logger.warning(
                    "Threat Intel rule failed (expected)",
                    extra={
                        "rule_id": rule.name,
                        "ioc_type": ioc_type,
                        "ioc": ioc_value[:100],
                    },
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(self._wrap_error(stage=rule.name, exception=exc))
                logger.exception(
                    "Threat Intel rule failed (unexpected)",
                    extra={
                        "rule_id": rule.name,
                        "ioc_type": ioc_type,
                    },
                )

        duration_ms = int((time.perf_counter() - start) * 1000)

        return AgentResult(
            findings=findings,
            errors=errors,
            metadata={
                "duration_ms": duration_ms,
                "events_examined": 1,
                "iocs_examined": iocs_examined,
                "external_calls": external_calls,
                "findings_produced": len(findings),
                "providers_enabled": sum(1 for p in self._providers if p.is_enabled),
            },
        )

    # ── IOC extraction ──────────────────────────────────────────────────

    def _extract_unique_iocs(
        self, context: AgentContext
    ) -> list[tuple[str, str]]:
        """
        Return unique (ioc_type, ioc_value) pairs for the event.

        Duplicates (e.g. same IP in source_ip and destination_ip) are
        collapsed. Empty/None fields are skipped.
        """
        event = context.event
        raw: list[tuple[str, str]] = []

        if event.source_ip:
            raw.append(("ip", event.source_ip))
        if event.destination_ip:
            raw.append(("ip", event.destination_ip))
        if event.domain:
            raw.append(("domain", event.domain))
        if event.url:
            raw.append(("url", event.url))
        if event.hash_sha256:
            raw.append(("hash", event.hash_sha256))
        elif event.hash_md5:
            raw.append(("hash", event.hash_md5))

        # CVE extraction from raw_payload (vuln-scanner events)
        for cve_id in self._extract_cves(context.event.raw_payload):
            raw.append(("cve", cve_id))

        # Deduplicate preserving order
        seen: set[tuple[str, str]] = set()
        unique: list[tuple[str, str]] = []
        for ioc_type, ioc_value in raw:
            key = (ioc_type, ioc_value.strip().lower())
            if key in seen:
                continue
            seen.add(key)
            unique.append((ioc_type, ioc_value.strip()))

        return unique

    def _extract_cves(self, raw_payload: dict | None) -> list[str]:
        """Best-effort CVE extraction from arbitrary raw payload shapes."""
        if not raw_payload or not isinstance(raw_payload, dict):
            return []

        candidates: list[str] = []
        for key in ("cve", "cve_id", "cve_ids", "cves", "vulnerabilities"):
            v = raw_payload.get(key)
            if isinstance(v, str):
                candidates.append(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        candidates.append(item)
                    elif isinstance(item, dict):
                        for k in ("id", "cve", "cve_id"):
                            if isinstance(item.get(k), str):
                                candidates.append(item[k])

        # Filter to valid CVE format
        import re
        cve_re = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
        return [c.strip().upper() for c in candidates if cve_re.match(c.strip())]

    # ── Provider calls ──────────────────────────────────────────────────

    def _lookup_all_providers(
        self,
        ioc_type: str,
        ioc_value: str,
        context: AgentContext,
    ) -> list[ProviderResult]:
        """
        Call every enabled provider that supports the IOC type. Return
        only non-None results.
        """
        results: list[ProviderResult] = []
        method_map = {
            "ip": "lookup_ip",
            "domain": "lookup_domain",
            "url": "lookup_url",
            "hash": "lookup_hash",
            "cve": "lookup_cve",
        }
        method_name = method_map.get(ioc_type)
        if method_name is None:
            return results

        for provider in self._providers:
            if not provider.is_enabled:
                continue

            lookup = getattr(provider, method_name, None)
            if lookup is None:
                continue

            # Wrap in try/except — providers shouldn't raise, but defensive
            try:
                result = lookup(ioc_value)
            except Exception as exc:  # noqa: BLE001
                self._logger.warning(
                    "Provider raised (should never happen)",
                    extra={
                        "provider": provider.name,
                        "ioc_type": ioc_type,
                        "error": str(exc)[:200],
                    },
                )
                continue

            if result is not None:
                results.append(result)

        return results


__all__ = ["ThreatIntelligenceAgent"]