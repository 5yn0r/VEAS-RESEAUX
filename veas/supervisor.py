"""Restart background workers that exit or raise, and report their health."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

logger = logging.getLogger(__name__)


class ThreadSupervisor:
    def __init__(
        self,
        stop_event: threading.Event | None = None,
        restart_delay: float = 1.0,
        max_restart_delay: float = 60.0,
        stable_after: float = 60.0,
    ) -> None:
        self.stop_event = stop_event or threading.Event()
        self.restart_delay = restart_delay
        self.max_restart_delay = max_restart_delay
        self.stable_after = stable_after
        self._workers: dict[str, dict] = {}
        self._lock = threading.Lock()

    def add(self, name: str, target: Callable[[], None]) -> None:
        with self._lock:
            self._workers[name] = {
                "target": target,
                "thread": None,
                "restarts": 0,
                "last_error": None,
                "last_error_at": None,
                "started_at": None,
                "last_heartbeat": None,
            }

    def start(self) -> None:
        with self._lock:
            names = [name for name, worker in self._workers.items() if worker["thread"] is None]
        for name in names:
            thread = threading.Thread(target=self._run, args=(name,), daemon=True, name=name)
            with self._lock:
                self._workers[name]["thread"] = thread
            thread.start()
            logger.info("Worker %s started", name)

    def stop(self, timeout: float | None = None) -> None:
        self.stop_event.set()
        with self._lock:
            threads = [worker["thread"] for worker in self._workers.values() if worker["thread"]]
        for thread in threads:
            thread.join(timeout)

    def heartbeat(self, name: str) -> None:
        with self._lock:
            worker = self._workers.get(name)
            if worker is not None:
                worker["last_heartbeat"] = time.time()

    def status(self) -> dict[str, dict]:
        with self._lock:
            return {
                name: {
                    "alive": bool(worker["thread"] and worker["thread"].is_alive()),
                    "restarts": worker["restarts"],
                    "last_error": worker["last_error"],
                    "last_error_at": worker["last_error_at"],
                    "started_at": worker["started_at"],
                    "last_heartbeat": worker["last_heartbeat"],
                }
                for name, worker in self._workers.items()
            }

    def _run(self, name: str) -> None:
        delay = self.restart_delay
        while not self.stop_event.is_set():
            with self._lock:
                worker = self._workers[name]
                worker["started_at"] = time.time()
                target = worker["target"]
            started = time.monotonic()
            try:
                target()
                error = None if self.stop_event.is_set() else "worker exited unexpectedly"
            except Exception as exc:  # noqa: BLE001 - a worker must never take the supervisor down
                logger.exception("Worker %s crashed", name)
                error = f"{type(exc).__name__}: {exc}"

            if self.stop_event.is_set():
                break

            if time.monotonic() - started >= self.stable_after:
                delay = self.restart_delay
            with self._lock:
                worker["restarts"] += 1
                worker["last_error"] = error
                worker["last_error_at"] = time.time()
            logger.warning("Worker %s stopped (%s); restarting in %.1fs", name, error, delay)
            if self.stop_event.wait(delay):
                break
            delay = min(delay * 2, self.max_restart_delay)
