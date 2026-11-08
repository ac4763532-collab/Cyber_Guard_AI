"""
CyberGuard AI Collector — Heartbeat Worker
"""
import time
import threading
import logging
import socket
import os
from .config import config
from .api_client import client

logger = logging.getLogger("cyberguard.collector.heartbeat")

class HeartbeatWorker(threading.Thread):
    def __init__(self, queue_ref=None):
        super().__init__(daemon=True, name="HeartbeatWorker")
        self.queue_ref = queue_ref
        self._stop_event = threading.Event()
        self.start_time = time.time()

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("Heartbeat worker started. Interval: %d seconds.", config.heartbeat_interval)
        while not self._stop_event.is_set():
            try:
                metrics = self._collect_metrics()
                success = client.send_heartbeat(metrics)
                if success:
                    logger.debug("Heartbeat transmitted successfully.")
                else:
                    logger.warning("Heartbeat failed to send.")
            except Exception as e:
                logger.error("Error in heartbeat worker: %s", e)

            self._stop_event.wait(config.heartbeat_interval)

    def _collect_metrics(self):
        cpu_usage = 0.0
        mem_usage = 0.0
        disk_free = 50.0

        try:
            import psutil
            cpu_usage = psutil.cpu_percent(interval=None)
            mem_usage = psutil.virtual_memory().percent
            disk_free = round(psutil.disk_usage("/").free / (1024**3), 2)
        except ImportError:
            pass

        queued_count = self.queue_ref.size() if self.queue_ref else 0
        uptime = int(time.time() - self.start_time)

        return {
            "cpu_usage_pct": float(cpu_usage),
            "memory_usage_pct": float(mem_usage),
            "disk_free_gb": float(disk_free),
            "events_queued_count": int(queued_count),
            "agent_version": "1.0.0",
            "uptime_seconds": uptime,
        }
