"""
CyberGuard AI - Complete Tool Verification Script
Run this to verify all components are working correctly.

Usage: cd backend && python verify_all_tools.py
"""

import asyncio
import sys
import os

sys.path.insert(0, ".")

def print_header(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)

def print_status(name: str, success: bool, details: str = ""):
    status = "[OK]" if success else "[FAIL]"
    print(f"  {status} {name}")
    if details:
        for line in details.split("\n"):
            print(f"       {line}")


async def check_backend_health():
    """Check if backend server is running."""
    print_header("1. Backend Server Health")

    try:
        import httpx
        async with httpx.AsyncClient() as client:
            r = await client.get("http://localhost:8000/api/v1/health", timeout=5)
            if r.status_code == 200:
                print_status("Backend is running", True)
                return True
            else:
                print_status("Backend returned error", False, f"Status: {r.status_code}")
                return False
    except Exception as e:
        print_status("Backend not reachable", False,
                     "Start with: cd backend && uvicorn app.main:app --reload")
        return False


async def check_env_config():
    """Check environment configuration."""
    print_header("2. Environment Configuration")

    from dotenv import load_dotenv
    load_dotenv()

    checks = {
        "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY"),
        "ABUSEIPDB_API_KEY": os.getenv("ABUSEIPDB_API_KEY"),
    }

    all_good = True
    for key, value in checks.items():
        if value and len(value) > 10:
            print_status(key, True, f"Configured ({len(value)} chars)")
        else:
            print_status(key, False, "Not set or too short")
            all_good = False

    return all_good


async def check_threat_intel_apis():
    """Test actual API connectivity."""
    print_header("3. Threat Intelligence APIs")

    from app.services.threat_intel import get_threat_intel_service

    ti_service = get_threat_intel_service()

    if not ti_service.is_configured:
        print_status("Threat Intel Service", False, "No API keys configured")
        return False

    print_status("Threat Intel Service", True, "API keys detected")

    # Test with a known safe IP (Google DNS)
    test_ip = "8.8.8.8"
    try:
        from app.services.threat_intel.service import IOCType
        result = await ti_service.lookup(IOCType.IP, test_ip)

        if result:
            sources = ", ".join(result.sources) if result.sources else "none"
            print_status(f"API Lookup Test ({test_ip})", True,
                        f"Sources: {sources}, Risk: {result.risk_score}, Time: {result.lookup_time_ms}ms")
            return True
        else:
            print_status(f"API Lookup Test ({test_ip})", False, "No results returned")
            return False
    except Exception as e:
        print_status("API Lookup Test", False, str(e)[:100])
        return False


async def check_email_analysis():
    """Test email analysis pipeline."""
    print_header("4. Email Analysis (Rule-Based)")

    from app.agents import get_dispatcher

    # Test with a suspicious email
    test_email = {
        "sender": "security@paypa1-verify.com",
        "subject": "URGENT: Your account will be suspended",
        "body": """
        Dear Customer,

        Your account has been compromised. Click here immediately to verify:
        http://192.168.1.100/verify?user=victim

        Enter your password and SSN to confirm identity.

        Best regards,
        PayPal Security Team
        """,
        "headers": {"from": "security@paypa1-verify.com"}
    }

    try:
        dispatcher = get_dispatcher()
        result = await dispatcher.dispatch_email(test_email)

        print_status("Email Analysis Engine", True)
        print_status(f"Classification: {result.classification}", True,
                    f"Risk Score: {result.risk_score}/100")
        print_status(f"Findings detected: {len(result.findings)}", len(result.findings) > 0)
        print_status(f"IOCs extracted: {len(result.indicators)}", len(result.indicators) > 0,
                    f"IOCs: {', '.join(result.indicators[:5])}")

        return result.risk_score > 50  # Should be flagged as suspicious
    except Exception as e:
        print_status("Email Analysis Engine", False, str(e)[:100])
        return False


async def check_ml_model():
    """Test ML phishing detection model."""
    print_header("5. ML Phishing Detection Model")

    try:
        from app.services.ml_training import PhishingDetector

        detector = PhishingDetector()

        if not detector.is_model_available:
            print_status("ML Model", False,
                        "Not trained. Run: python app/services/ml_training.py")
            return False

        print_status("ML Model Loaded", True)

        # Test predictions
        tests = [
            {
                "name": "Obvious phishing",
                "subject": "URGENT: Verify your account NOW",
                "body": "Click http://192.168.1.1/login to enter your password immediately",
                "sender": "admin@fake-bank.com",
                "expected_phishing": True
            },
            {
                "name": "Legitimate email",
                "subject": "Meeting tomorrow",
                "body": "Hi, just confirming our meeting at 3pm tomorrow. See you then!",
                "sender": "colleague@company.com",
                "expected_phishing": False
            }
        ]

        all_correct = True
        for test in tests:
            result = detector.predict(
                subject=test["subject"],
                body=test["body"],
                sender=test["sender"]
            )

            correct = result.is_phishing == test["expected_phishing"]
            all_correct = all_correct and correct

            print_status(
                f"Test: {test['name']}",
                correct,
                f"Phishing: {result.is_phishing}, Confidence: {result.confidence:.0%}, Expected: {test['expected_phishing']}"
            )

        return all_correct
    except ImportError as e:
        print_status("ML Model", False, f"Missing dependency: {e}")
        return False
    except Exception as e:
        print_status("ML Model", False, str(e)[:100])
        return False


async def check_ioc_extraction():
    """Test IOC extraction logic."""
    print_header("6. IOC Extraction Logic")

    from app.agents.email_agent_v2 import EmailAgent

    agent = EmailAgent()

    # Test artifacts
    test_artifacts = {
        "domains": ["gmail.com", "paypa1-verify.com", "suspicious.xyz", "microsoft.com"],
        "ips": ["192.168.1.100", "8.8.8.8"],
        "urls": ["http://192.168.1.100/verify", "https://google.com/search"],
        "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
        "emails": []
    }

    iocs = agent._promote_to_iocs([], test_artifacts)

    # Verify trusted domains are filtered
    trusted_filtered = "gmail.com" not in iocs and "microsoft.com" not in iocs
    suspicious_included = "paypa1-verify.com" in iocs or "suspicious.xyz" in iocs
    ips_included = "192.168.1.100" in iocs

    print_status("Trusted domains filtered", trusted_filtered,
                "gmail.com and microsoft.com should be excluded")
    print_status("Suspicious domains included", suspicious_included,
                "paypa1-verify.com should be included")
    print_status("IPs included", ips_included,
                "192.168.1.100 should be included")
    print_status(f"Total IOCs: {len(iocs)}", True, f"IOCs: {iocs}")

    return trusted_filtered and suspicious_included and ips_included


async def check_report_builder():
    """Test report builder status detection."""
    print_header("7. Report Builder Status Detection")

    from app.services.email_report_builder import EmailReportBuilder
    from app.services.threat_intel import get_threat_intel_service

    ti_service = get_threat_intel_service()
    builder = EmailReportBuilder()

    # Test with no threat intel data (no IOCs extracted)
    section = builder._build_threat_intel_section(None)

    if ti_service.is_configured:
        expected_status = "no_iocs"
        correct = section.status == expected_status
        print_status("Status when configured but no IOCs", correct,
                    f"Got: {section.status}, Expected: {expected_status}")
    else:
        expected_status = "not_configured"
        correct = section.status == expected_status
        print_status("Status when not configured", correct,
                    f"Got: {section.status}, Expected: {expected_status}")

    # Test with actual threat intel data
    test_data = {
        "8.8.8.8": {
            "type": "ip",
            "is_malicious": False,
            "risk_score": 0,
            "sources": ["VirusTotal"],
            "cached": False,
            "lookup_time_ms": 150
        }
    }
    section2 = builder._build_threat_intel_section(test_data)
    has_results = section2.status == "configured" and len(section2.results) > 0
    print_status("Status with threat intel data", has_results,
                f"Status: {section2.status}, Results: {len(section2.results)}")

    return correct and has_results


async def main():
    print("\n" + "#" * 60)
    print("#  CyberGuard AI - Complete Tool Verification")
    print("#" * 60)

    results = {}

    # Run all checks
    results["Backend"] = await check_backend_health()
    results["Environment"] = await check_env_config()
    results["Threat Intel APIs"] = await check_threat_intel_apis()
    results["Email Analysis"] = await check_email_analysis()
    results["ML Model"] = await check_ml_model()
    results["IOC Extraction"] = await check_ioc_extraction()
    results["Report Builder"] = await check_report_builder()

    # Summary
    print_header("SUMMARY")

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for name, success in results.items():
        status = "[OK]" if success else "[FAIL]"
        print(f"  {status} {name}")

    print(f"\n  Result: {passed}/{total} checks passed")

    if passed == total:
        print("\n  [OK] All tools are working correctly!")
    else:
        print("\n  [!] Some tools need attention. Check the details above.")

    print("\n" + "=" * 60)

    return passed == total


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
