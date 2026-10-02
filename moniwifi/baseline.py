"""Per-device behaviour baselines: upload volume and usual destinations."""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict

MAX_DESTINATIONS = 500


class BaselineTracker:
    """Learn what is normal for each device and report deviations.

    Upload volume is summed in fixed buckets (``bucket_seconds``) and compared
    with an exponentially weighted mean and variance, so the baseline follows
    slow changes while a sudden spike stands out. Destinations are only
    judged for "quiet" devices (IoT, printers, cameras) that talk to a small,
    stable set of hosts once the learning period is over.
    """

    def __init__(
        self,
        bucket_seconds: float = 300.0,
        min_samples: int = 72,
        alpha: float = 0.05,
        sigma: float = 4.0,
        min_anomaly_bytes: int = 50 * 1024 * 1024,
        learning_seconds: float = 86400.0,
        quiet_destination_limit: int = 30,
        max_devices: int = 2000,
    ) -> None:
        self.bucket_seconds = bucket_seconds
        self.min_samples = min_samples
        self.alpha = alpha
        self.sigma = sigma
        self.min_anomaly_bytes = min_anomaly_bytes
        self.learning_seconds = learning_seconds
        self.quiet_destination_limit = quiet_destination_limit
        self.max_devices = max_devices
        self._lock = threading.Lock()
        self._devices: OrderedDict[str, dict] = OrderedDict()
        self._dirty: set[str] = set()

    # Persistence ---------------------------------------------------------

    def load(self, baselines: dict[str, dict]) -> None:
        with self._lock:
            for key, data in baselines.items():
                baseline = self._blank(data.get("first_seen", time.time()))
                baseline.update(data)
                baseline["destinations"] = OrderedDict(data.get("destinations") or {})
                self._devices[key] = baseline

    def drain_dirty(self) -> dict[str, dict]:
        with self._lock:
            dirty = {key: self._export(self._devices[key]) for key in self._dirty if key in self._devices}
            self._dirty.clear()
            return dirty

    # Observation ---------------------------------------------------------

    def add_traffic(self, key: str, upload: int, download: int, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        findings = []
        with self._lock:
            baseline = self._get(key, now)
            bucket_start = baseline["bucket_start"]
            if now >= bucket_start + self.bucket_seconds:
                findings += self._close_buckets(baseline, now)
            baseline["bucket_upload"] += upload
            baseline["bucket_download"] += download
            self._dirty.add(key)
        return findings

    def add_destination(self, key: str, destination: str, now: float | None = None) -> dict | None:
        now = time.time() if now is None else now
        with self._lock:
            baseline = self._get(key, now)
            destinations = baseline["destinations"]
            known = destination in destinations
            learned = now - baseline["first_seen"] >= self.learning_seconds
            quiet = len(destinations) <= self.quiet_destination_limit
            destinations[destination] = now
            destinations.move_to_end(destination)
            while len(destinations) > MAX_DESTINATIONS:
                destinations.popitem(last=False)
            self._dirty.add(key)
            if known or not learned or not quiet:
                return None
            return {"kind": "new_destination", "destination": destination, "known_destinations": len(destinations) - 1}

    # Queries -------------------------------------------------------------

    def snapshot(self, key: str) -> dict | None:
        with self._lock:
            baseline = self._devices.get(key)
            if baseline is None:
                return None
            data = self._export(baseline)
        data["upload_std"] = math.sqrt(max(data["upload_var"], 0.0))
        data["destinations"] = sorted(data["destinations"], key=data["destinations"].get, reverse=True)[:50]
        data["learning"] = time.time() - data["first_seen"] < self.learning_seconds
        return data

    # Helpers -------------------------------------------------------------

    def _close_buckets(self, baseline: dict, now: float) -> list[dict]:
        findings = []
        value = baseline["bucket_upload"]
        finding = self._evaluate(baseline, value)
        if finding:
            finding["bucket_start"] = baseline["bucket_start"]
            findings.append(finding)
        self._update(baseline, value)
        # Idle buckets count as zero upload, capped so a long gap cannot erase the baseline.
        elapsed = int((now - baseline["bucket_start"]) // self.bucket_seconds)
        for _ in range(min(elapsed - 1, 12)):
            self._update(baseline, 0)
        baseline["bucket_start"] += elapsed * self.bucket_seconds
        baseline["bucket_upload"] = 0
        baseline["bucket_download"] = 0
        return findings

    def _evaluate(self, baseline: dict, value: float) -> dict | None:
        if baseline["samples"] < self.min_samples or value < self.min_anomaly_bytes:
            return None
        std = math.sqrt(max(baseline["upload_var"], 0.0))
        threshold = baseline["upload_mean"] + self.sigma * std
        if value <= threshold:
            return None
        return {
            "kind": "upload_spike",
            "upload_bytes": int(value),
            "baseline_mean": round(baseline["upload_mean"]),
            "baseline_std": round(std),
            "bucket_seconds": self.bucket_seconds,
        }

    def _update(self, baseline: dict, value: float) -> None:
        if baseline["samples"] == 0:
            baseline["upload_mean"] = float(value)
            baseline["upload_var"] = 0.0
        else:
            diff = value - baseline["upload_mean"]
            increment = self.alpha * diff
            baseline["upload_mean"] += increment
            baseline["upload_var"] = (1 - self.alpha) * (baseline["upload_var"] + diff * increment)
        baseline["samples"] += 1

    def _get(self, key: str, now: float) -> dict:
        baseline = self._devices.get(key)
        if baseline is None:
            baseline = self._blank(now)
            self._devices[key] = baseline
            while len(self._devices) > self.max_devices:
                self._devices.popitem(last=False)
        else:
            self._devices.move_to_end(key)
        return baseline

    def _blank(self, now: float) -> dict:
        return {
            "first_seen": now,
            "samples": 0,
            "upload_mean": 0.0,
            "upload_var": 0.0,
            "bucket_start": now - (now % self.bucket_seconds),
            "bucket_upload": 0,
            "bucket_download": 0,
            "destinations": OrderedDict(),
        }

    @staticmethod
    def _export(baseline: dict) -> dict:
        data = dict(baseline)
        data["destinations"] = dict(baseline["destinations"])
        return data
