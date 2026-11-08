"""
CyberGuard AI — Linux Endpoint Collector
============================================================================
Lightweight agent monitoring Linux authentication logs and transmitting
authenticated telemetry batches to the CyberGuard backend.
"""
import sys
import time
import argparse
import logging
from .config import config
from .api_client import client
from .heartbeat_worker import HeartbeatWorker
from .event_sender import event_sender
from .event_normalizer import normalize_event

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("cyberguard.collector.linux")

def simulate_sample_telemetry():
    """Generates a sample ssh auth failure event for testing."""
    ev1 = normalize_event(
        event_type="linux.auth.ssh_failure",
        severity="medium",
        action="ssh_login",
        outcome="failure",
        username="root",
        source_ip="192.168.1.105",
        process_name="sshd",
        details={"message": "Failed password for root from 192.168.1.105 port 54212 ssh2"}
    )
    event_sender.enqueue(ev1)

def main():
    parser = argparse.ArgumentParser(description="CyberGuard AI Linux Endpoint Collector")
    parser.add_argument("--enroll", help="Enroll device with registration token")
    parser.add_argument("--run", action="store_true", help="Run collector in foreground")
    parser.add_argument("--status", action="store_true", help="Check collector status")
    parser.add_argument("--test-event", action="store_true", help="Send a simulated security event")
    args = parser.parse_args()

    if args.enroll:
        logger.info("Initiating enrollment with token %s...", args.enroll)
        ok = client.enroll(args.enroll)
        sys.exit(0 if ok else 1)

    if args.status:
        if config.is_enrolled:
            print(f"Status: ENROLLED\nCollector ID: {config.collector_id}\nAPI URL: {config.api_base_url}")
        else:
            print(f"Status: NOT ENROLLED\nAPI URL: {config.api_base_url}")
        sys.exit(0)

    if not config.is_enrolled:
        logger.error("Collector is not enrolled. Run with --enroll <TOKEN> first.")
        sys.exit(1)

    logger.info("Starting CyberGuard Linux Collector [ID: %s]...", config.collector_id)
    
    event_sender.start()
    hb = HeartbeatWorker(queue_ref=event_sender)
    hb.start()

    if args.test_event:
        simulate_sample_telemetry()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping collector workers...")
        hb.stop()
        event_sender.stop()
        hb.join()
        event_sender.join()
        logger.info("Collector shutdown cleanly.")

if __name__ == "__main__":
    main()
