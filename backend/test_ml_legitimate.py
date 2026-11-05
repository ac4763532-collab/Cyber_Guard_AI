import asyncio
from app.agents.email_agent import EmailAgent

async def main():
    agent = EmailAgent()

    result = await agent.analyze({
        "sender": "newsletter@example.com",
        "subject": "Your monthly newsletter",
        "body": "Hello, here is your monthly newsletter with updates and information. Thank you for being a subscriber.",
        "headers": {},
        "urls": [],
        "attachments": []
    })

    print("Risk:", result.risk_score)
    print("Findings:")
    for finding in result.findings:
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        print(f"  {finding.rule_id} | {finding.name} | {severity}")

    print("ML-001:", any(f.rule_id == "ML-001" for f in result.findings))

asyncio.run(main())
