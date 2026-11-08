"""
CyberGuard AI Collector — Configuration Loader
"""
import os
import json
import uuid
from pathlib import Path

CONFIG_FILE = Path(__file__).parent / "collector_config.json"

class CollectorConfig:
    def __init__(self):
        self.api_base_url = os.environ.get("CYBERGUARD_API_URL", "http://localhost:8000/api/v1")
        self.enrollment_token = os.environ.get("CYBERGUARD_ENROLL_TOKEN", "")
        self.collector_id = None
        self.collector_credential = None
        self.heartbeat_interval = int(os.environ.get("CYBERGUARD_HEARTBEAT_INTERVAL", "30"))
        self.batch_interval = int(os.environ.get("CYBERGUARD_BATCH_INTERVAL", "10"))
        self.max_batch_size = int(os.environ.get("CYBERGUARD_MAX_BATCH", "50"))
        self.load()

    def load(self):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.api_base_url = data.get("api_base_url", self.api_base_url)
                    self.collector_id = data.get("collector_id")
                    self.collector_credential = data.get("collector_credential")
            except Exception:
                pass

    def save(self):
        data = {
            "api_base_url": self.api_base_url,
            "collector_id": str(self.collector_id) if self.collector_id else None,
            "collector_credential": self.collector_credential,
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @property
    def is_enrolled(self) -> bool:
        return bool(self.collector_id and self.collector_credential)

config = CollectorConfig()
