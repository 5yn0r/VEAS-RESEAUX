"""Background forensic analyses: upload storage, queue, progress, and persisted reports."""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import threading
import time
import uuid
from pathlib import Path

from veas.forensics.engine import analyse_pcap, detect_format

logger = logging.getLogger(__name__)

JOB_ID = re.compile(r"^[0-9a-f]{32}$")
EXTENSIONS = {"pcapng": ".pcapng"}


class ForensicsManager:
    """One analysis runs at a time; others wait in a queue. Metadata and reports live on disk."""

    def __init__(self, directory: str, max_reports: int = 20, max_packets: int | None = None, analyse=analyse_pcap) -> None:
        self.directory = Path(directory)
        self.max_reports = max_reports
        self.max_packets = max_packets
        self.analyse = analyse
        self._lock = threading.Lock()
        self._jobs: dict[str, dict] = {}
        self._queue: queue.Queue = queue.Queue()
        self._worker: threading.Thread | None = None
        self._load()

    # Storage ---------------------------------------------------------------

    def _paths(self, job_id: str) -> dict[str, Path]:
        return {
            "meta": self.directory / f"{job_id}.meta.json",
            "report": self.directory / f"{job_id}.report.json",
        }

    def _load(self) -> None:
        if not self.directory.is_dir():
            return
        for meta_path in self.directory.glob("*.meta.json"):
            try:
                job = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not JOB_ID.match(job.get("id", "")):
                continue
            self._jobs[job["id"]] = job
            if job["status"] in ("queued", "running"):
                # Interrupted by a restart: run it again.
                job.update(status="queued", progress=0.0, frames=0)
                self._queue.put(job["id"])
        if not self._queue.empty():
            self._ensure_worker()

    def _save(self, job: dict) -> None:
        path = self._paths(job["id"])["meta"]
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(job, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)

    # Public API ------------------------------------------------------------

    def submit(self, upload, filename: str) -> dict:
        """Store an uploaded capture (a file-like object) and queue its analysis."""
        header = upload.read(4)
        file_format = detect_format(header)
        if file_format is None:
            raise ValueError("ce fichier n'est pas une capture pcap ou pcapng (signature inconnue)")
        self.directory.mkdir(parents=True, exist_ok=True)
        job_id = uuid.uuid4().hex
        capture = self.directory / f"{job_id}{EXTENSIONS.get(file_format, '.pcap')}"
        with capture.open("wb") as handle:
            handle.write(header)
            while True:
                chunk = upload.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
        job = {
            "id": job_id,
            "filename": os.path.basename(filename or "capture.pcap")[:200],
            "capture": capture.name,
            "format": file_format,
            "size": capture.stat().st_size,
            "status": "queued",
            "progress": 0.0,
            "frames": 0,
            "created_at": time.time(),
            "started_at": None,
            "finished_at": None,
            "error": None,
            "summary": None,
        }
        with self._lock:
            self._jobs[job_id] = job
            self._save(job)
        self._queue.put(job_id)
        self._ensure_worker()
        self._purge()
        return dict(job)

    def list(self) -> list[dict]:
        with self._lock:
            return sorted((dict(job) for job in self._jobs.values()), key=lambda job: job["created_at"], reverse=True)

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None

    def report(self, job_id: str) -> dict | None:
        path = self._paths(job_id)["report"]
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def report_path(self, job_id: str) -> Path | None:
        path = self._paths(job_id)["report"]
        return path if path.is_file() else None

    def capture_path(self, job_id: str) -> Path | None:
        job = self.get(job_id)
        if not job:
            return None
        path = self.directory / job["capture"]
        return path if path.is_file() else None

    def delete(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job["status"] == "running":
                return False
            del self._jobs[job_id]
        job["status"] = "deleted"
        for path in (*self._paths(job_id).values(), self.directory / job["capture"]):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        return True

    def wait(self, timeout: float = 30.0) -> None:
        """Block until the queue is empty (used by tests and offline tools)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                busy = any(job["status"] in ("queued", "running") for job in self._jobs.values())
            if not busy:
                return
            time.sleep(0.05)

    # Worker ----------------------------------------------------------------

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._run, name="Forensics", daemon=True)
                self._worker.start()

    def _run(self) -> None:
        while True:
            try:
                job_id = self._queue.get(timeout=60)
            except queue.Empty:
                return
            with self._lock:
                job = self._jobs.get(job_id)
                if job is None:
                    continue
                job.update(status="running", started_at=time.time())
                self._save(job)

            def progress(frames: int, percent: float, job=job) -> None:
                with self._lock:
                    job["frames"], job["progress"] = frames, round(percent, 1)

            try:
                report = self.analyse(str(self.directory / job["capture"]), progress=progress, max_packets=self.max_packets, filename=job["filename"])
                path = self._paths(job_id)["report"]
                temporary = path.with_suffix(".tmp")
                temporary.write_text(json.dumps(report, ensure_ascii=False, default=str), encoding="utf-8")
                temporary.replace(path)
                summary = {
                    **report["summary"],
                    "packets": report["overview"]["packets"],
                    "duration": report["overview"]["duration"],
                    "start": report["overview"]["start"],
                    "mitre_techniques": len(report["summary"]["mitre_techniques"]),
                }
                with self._lock:
                    job.update(status="done", progress=100.0, frames=report["overview"]["packets"], summary=summary, finished_at=time.time())
            except Exception as exc:  # noqa: BLE001 - report the failure to the user instead of killing the worker
                logger.exception("Forensic analysis %s failed", job_id)
                with self._lock:
                    job.update(status="error", error=str(exc)[:500], finished_at=time.time())
            with self._lock:
                if job_id in self._jobs:
                    self._save(job)

    def _purge(self) -> None:
        finished = [job for job in self.list() if job["status"] in ("done", "error")]
        for job in finished[self.max_reports:]:
            self.delete(job["id"])
