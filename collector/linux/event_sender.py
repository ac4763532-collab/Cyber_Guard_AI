"""
CyberGuard AI Collector — Event Queue and Batch Dispatcher
"""
import time
import threading
import queue
import logging
from typing import Dict, Any, List
from .config import config
from .api_client import client

logger = logging.getLogger("cyberguard.collector.sender")

class EventSender(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="EventSenderWorker")
        self._queue = queue.Queue(maxsize=10000)
        self._stop_event = threading.Event()

    def size(self) -> int:
        return self._queue.qsize()

    def enqueue(self, event: Dict[str, Any]):
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            logger.warning("Event queue is full! Dropping event to avoid memory saturation.")

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("Event batch dispatcher started.")
        while not self._stop_event.is_set():
            batch = []
            start_wait = time.time()

            while len(batch) < config.max_batch_size and (time.time() - start_wait) < config.batch_interval:
                try:
                    ev = self._queue.get(timeout=1.0)
                    batch.append(ev)
                except queue.Empty:
                    if self._stop_event.is_set():
                        break

            if batch:
                try:
                    logger.info("Flushing event batch of size %d to backend...", len(batch))
                    res = client.send_events(batch)
                    if res:
                        logger.info("Batch ingestion response: %d ingested, %d duplicates", res.get("ingested", 0), res.get("duplicates", 0))
                    else:
                        logger.warning("Batch dispatch failed. Re-queuing %d events.", len(batch))
                        for ev in batch:
                            self.enqueue(ev)
                        time.sleep(5)
                except Exception as e:
                    logger.error("Exception during batch dispatch: %s", e)

event_sender = EventSender()
