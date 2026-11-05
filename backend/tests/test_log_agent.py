"""
CyberGuard AI - LogAgent unit tests

Covers two changes made to app/agents/log_agent.py and app/agents/base.py:

1. The LOG-001 (auth failures, >=3/IP) vs LOG-002/LOG-003 (brute force,
   >=5/IP) overlap: any IP with >=5 plain auth_failure events used to
   satisfy both thresholds and get two findings for the same underlying
   failures. analyze() now suppresses the LOG-001 finding for an IP once
   a brute-force finding exists for that same IP.
2. Finding now carries source_ip/host/timestamp (populated from the
   already-parsed event dicts), and AgentResult carries
   source/processed_event_count/affected_systems/affected_accounts.
   These tests assert the values are real (not fabricated placeholders)
   and None/empty when the underlying data genuinely isn't available.
"""

from __future__ import annotations

import asyncio

import pytest

from app.agents.log_agent import LogAgent


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# Same scenario as tests/test_integration_e2e_malicious_ssh.py's
# MALICIOUS_AUTH_LOG: 6 failed SSH attempts against root from one IP -
# crosses both LOG-001's >=3 threshold and LOG-002/003's >=5 threshold.
BRUTE_FORCE_LOG = "\n".join(
    f"Oct  9 02:{10 + i}:00 prod-bastion sshd[500{i}]: Failed password for root "
    f"from 198.51.100.200 port {40000 + i} ssh2"
    for i in range(6)
)

# Exactly 3 failures - crosses LOG-001's threshold but not LOG-002/003's,
# so this finding must NOT be suppressed.
AUTH_FAILURES_ONLY_LOG = "\n".join(
    f"Oct  9 03:{10 + i}:00 prod-bastion sshd[600{i}]: Failed password for alice "
    f"from 203.0.113.50 port {41000 + i} ssh2"
    for i in range(3)
)

SUDO_FAILURES_LOG = "\n".join(
    f"Oct  9 04:{10 + i}:00 prod-bastion sudo: bob : {i} incorrect password attempts ; "
    f"TTY=pts/0 ; PWD=/home/bob ; USER=root ; authentication failure"
    for i in range(3)
)

BENIGN_LOG = "Oct  9 05:00:00 prod-bastion systemd[1]: Started Daily apt download activities."


class TestOverlapFix:
    def test_brute_force_ip_produces_one_finding_not_two(self):
        """
        Before the fix: an IP with 6 plain auth failures got both a
        LOG-001 (auth failures) and a LOG-002/003 (brute force) finding.
        After the fix: only the brute-force finding (LOG-003 here, since
        all 6 attempts target the same user "root", not multiple users)
        survives for that IP.
        """
        agent = LogAgent()
        result = _run(agent.analyze({"log_content": BRUTE_FORCE_LOG}))

        rule_ids = [f.rule_id for f in result.findings]
        assert rule_ids.count("LOG-001") == 0, (
            f"LOG-001 should be suppressed once LOG-003 fires for the same IP, "
            f"got rule_ids={rule_ids}"
        )
        assert "LOG-003" in rule_ids

        # Exactly one finding should reference this IP.
        findings_for_ip = [f for f in result.findings if f.source_ip == "198.51.100.200"]
        assert len(findings_for_ip) == 1

    def test_auth_failures_below_brute_force_threshold_is_not_suppressed(self):
        """3 failures crosses LOG-001's threshold (>=3) but not LOG-002/003's
        (>=5), so the LOG-001 finding must still be reported."""
        agent = LogAgent()
        result = _run(agent.analyze({"log_content": AUTH_FAILURES_ONLY_LOG}))

        rule_ids = [f.rule_id for f in result.findings]
        assert "LOG-001" in rule_ids
        assert "LOG-002" not in rule_ids
        assert "LOG-003" not in rule_ids


class TestStructuredFindingFields:
    def test_brute_force_finding_has_real_source_ip_and_host(self):
        agent = LogAgent()
        result = _run(agent.analyze({"log_content": BRUTE_FORCE_LOG}))

        brute_force = next(f for f in result.findings if f.rule_id == "LOG-003")
        assert brute_force.source_ip == "198.51.100.200"
        assert brute_force.host == "prod-bastion"
        assert brute_force.timestamp is not None
        assert "Oct" in brute_force.timestamp  # raw syslog string, not fabricated datetime

    def test_sudo_failure_finding_has_host_but_no_source_ip(self):
        """Sudo events never populate source_ip in _parse_log_events (no IP
        to extract from a sudo line) - the field must stay None, not a
        fabricated or guessed value."""
        agent = LogAgent()
        result = _run(agent.analyze({"log_content": SUDO_FAILURES_LOG}))

        sudo_finding = next(f for f in result.findings if f.rule_id == "LOG-005")
        assert sudo_finding.source_ip is None
        assert sudo_finding.host == "prod-bastion"


class TestResultLevelAggregates:
    def test_affected_systems_and_accounts_reflect_real_findings(self):
        agent = LogAgent()
        result = _run(agent.analyze({"log_content": BRUTE_FORCE_LOG}))

        assert "198.51.100.200" in result.affected_systems
        assert "prod-bastion" in result.affected_systems
        assert "root" in result.affected_accounts

    def test_processed_event_count_matches_parsed_events(self):
        agent = LogAgent()
        result = _run(agent.analyze({"log_content": BRUTE_FORCE_LOG}))

        # 6 failed-password lines + 1 would-be success line in the fuller
        # fixture; this log only has the 6 failure lines.
        assert result.processed_event_count == 6

    def test_benign_log_has_empty_aggregates_not_placeholders(self):
        agent = LogAgent()
        result = _run(agent.analyze({"log_content": BENIGN_LOG}))

        assert result.classification == "benign"
        assert result.affected_systems == []
        assert result.affected_accounts == []

    def test_source_field_echoes_declared_log_type(self):
        agent = LogAgent()
        result = _run(agent.analyze({"log_content": BRUTE_FORCE_LOG, "log_type": "auth"}))
        assert result.source == "auth"

    def test_source_field_none_when_log_type_is_auto_or_absent(self):
        agent = LogAgent()
        result = _run(agent.analyze({"log_content": BRUTE_FORCE_LOG}))
        assert result.source is None
