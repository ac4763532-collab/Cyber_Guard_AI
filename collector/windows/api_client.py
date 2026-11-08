"""
CyberGuard AI Collector — Secure API Client
"""
import logging
import platform
import uuid
import socket
import urllib.request
import urllib.error
import json
from typing import Optional, Dict, Any, List
from .config import config

logger = logging.getLogger("cyberguard.collector.api")

class CollectorAPIClient:
    def __init__(self):
        self.base_url = config.api_base_url.rstrip("/")

    def _post(self, endpoint: str, data: Dict[str, Any], authenticated: bool = True) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}{endpoint}"
        body = json.dumps(data).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"CyberGuard-Collector/{platform.system()}"
        }

        if authenticated:
            if not config.is_enrolled:
                logger.error("Cannot call authenticated endpoint: collector is not enrolled")
                return None
            headers["X-Collector-ID"] = str(config.collector_id)
            headers["X-Collector-Credential"] = config.collector_credential

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_body = resp.read().decode("utf-8")
                return json.loads(resp_body) if resp_body else {}
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8", errors="ignore")
            logger.error("HTTP error %d on %s: %s", e.code, endpoint, err_msg)
            return None
        except Exception as e:
            logger.error("Network error on %s: %s", endpoint, str(e))
            return None

    def enroll(self, token: str) -> bool:
        """Enroll collector using single-use or tenant token."""
        new_collector_id = uuid.uuid4()
        payload = {
            "token": token,
            "collector_id": str(new_collector_id),
            "hostname": socket.gethostname(),
            "os_version": f"{platform.system()} {platform.release()}",
            "agent_version": "1.0.0",
            "hardware_fingerprint": str(uuid.getnode()),
        }

        res = self._post("/collector/enroll", payload, authenticated=False)
        if res and "plaintext_credential" in res:
            config.collector_id = new_collector_id
            config.collector_credential = res["plaintext_credential"]
            config.save()
            logger.info("Collector successfully enrolled! ID: %s", config.collector_id)
            return True
        logger.error("Enrollment failed.")
        return False

    def send_heartbeat(self, metrics: Dict[str, Any]) -> bool:
        res = self._post("/collector/heartbeat", metrics, authenticated=True)
        return res is not None

    def send_events(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        payload = {
            "batch_id": str(uuid.uuid4()),
            "events": events
        }
        return self._post("/collector/events", payload, authenticated=True)

client = CollectorAPIClient()
