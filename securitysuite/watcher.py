"""Directory monitor.

Polls the watched paths, waits for each file to stop changing before scanning
(so a half-written upload is never scanned), and correlates every hit with
authentication telemetry from the same time window.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from .engine import YaraEngine
from .store import EventStore, now_iso
from .telemetry import AuthTelemetry


class Monitor(threading.Thread):
    def __init__(self, cfg, engine: YaraEngine, store: EventStore,
                 telemetry: AuthTelemetry, remediator=None):
        super().__init__(name="securitysuite-monitor", daemon=True)
        self.cfg = cfg
        self.engine = engine
        self.store = store
        self.telemetry = telemetry
        self.remediator = remediator
        self._stop_event = threading.Event()
        self._pause = threading.Event()
        # Never scan our own output: findings.ndjson contains the strings that
        # tripped the rules, so scanning it would alert on itself forever.
        self._self_paths = {
            os.path.normcase(os.path.abspath(p))
            for p in (cfg.findings_log, cfg.triage_file,
                      getattr(cfg, "remediation_file", ""))
            if p
        }
        # A quarantined file still contains whatever tripped the rule. If the
        # quarantine sits inside a watched tree it would be re-detected on every
        # sweep - the findings.ndjson feedback loop again, with a file that was
        # deliberately set aside.
        self._excluded_dirs = [
            os.path.normcase(os.path.abspath(d))
            for d in (getattr(cfg, "quarantine_dir", ""),) if d
        ]
        # path -> (mtime, size) at the moment we last scanned it
        self._scanned: dict[str, tuple] = {}
        # path -> (mtime, size, first_seen_at) for files still settling
        self._pending: dict[str, tuple] = {}
        self.scanned_count = 0
        self.last_sweep: str | None = None
        self.last_error: str | None = None

    # --------------------------------------------------------------- control
    def stop(self) -> None:
        self._stop_event.set()

    def pause(self) -> None:
        self._pause.set()

    def resume(self) -> None:
        self._pause.clear()

    @property
    def paused(self) -> bool:
        return self._pause.is_set()

    def status(self) -> dict:
        return {
            "running": self.is_alive() and not self._stop_event.is_set(),
            "paused": self.paused,
            "watch_paths": list(self.cfg.watch_paths),
            "recursive": self.cfg.recursive,
            "poll_interval": self.cfg.poll_interval,
            "tracked_files": len(self._scanned),
            "pending_files": len(self._pending),
            "scanned_count": self.scanned_count,
            "last_sweep": self.last_sweep,
            "last_error": self.last_error,
        }

    # ------------------------------------------------------------------ loop
    def run(self) -> None:
        if not self.cfg.scan_existing_on_start:
            # Baseline: remember what is already there so we only alert on new work.
            for path, stat in self._iter_files():
                if self._stop_event.is_set():
                    return
                self._scanned[path] = (stat.st_mtime, stat.st_size)
        self.store.broadcast(
            {
                "event_type": "monitor",
                "timestamp": now_iso(),
                "message": "Monitoring " + ", ".join(self.cfg.watch_paths),
            }
        )
        while not self._stop_event.is_set():
            if not self._pause.is_set():
                try:
                    self._sweep()
                    self.last_error = None
                except Exception as exc:  # keep the monitor alive through bad paths
                    self.last_error = str(exc)
            self._stop_event.wait(self.cfg.poll_interval)

    def _iter_files(self):
        for root in self.cfg.watch_paths:
            root_path = Path(root)
            if not root_path.exists():
                continue
            walker = root_path.rglob("*") if self.cfg.recursive else root_path.glob("*")
            for entry in walker:
                if self._stop_event.is_set():
                    return
                try:
                    if not entry.is_file():
                        continue
                    if entry.suffix.lower() in self.cfg.ignore_suffixes:
                        continue
                    resolved = os.path.normcase(os.path.abspath(entry))
                    if resolved in self._self_paths:
                        continue
                    if any(resolved.startswith(d + os.sep) or resolved == d
                           for d in self._excluded_dirs):
                        continue
                    yield str(entry), entry.stat()
                except OSError:
                    continue

    def _sweep(self) -> None:
        now = time.time()
        seen_now = set()
        for path, stat in self._iter_files():
            seen_now.add(path)
            signature = (stat.st_mtime, stat.st_size)
            if self._scanned.get(path) == signature:
                continue  # unchanged since the last scan

            previous = self._pending.get(path)
            if previous is None or previous[:2] != signature:
                # New or still being written: restart the settle timer.
                self._pending[path] = (stat.st_mtime, stat.st_size, now)
                continue
            if now - previous[2] < self.cfg.settle_seconds:
                continue  # not settled yet

            self._pending.pop(path, None)
            self._scanned[path] = signature
            self.scan_and_record(path, trigger="monitor")

        # Forget files that disappeared so a re-upload is scanned again.
        for gone in [p for p in self._scanned if p not in seen_now]:
            self._scanned.pop(gone, None)
        for gone in [p for p in self._pending if p not in seen_now]:
            self._pending.pop(gone, None)
        self.last_sweep = now_iso()

    # ------------------------------------------------------------- scanning
    def scan_and_record(self, path: str, trigger: str = "manual") -> dict:
        """Scan one file and record the outcome. Returns the stored event."""
        try:
            result = self.engine.scan_file(path)
        except (FileNotFoundError, PermissionError) as exc:
            # Normal on a live endpoint: antivirus quarantined the file, or it
            # was moved/locked between the sweep and the scan. Not an error.
            return self.store.add(
                {
                    "event_type": "scan",
                    "file_path": str(path),
                    "file_name": os.path.basename(path),
                    "skipped": "unavailable at scan time (" + type(exc).__name__ + ")",
                    "trigger": trigger,
                },
                persist=False,
            )
        except Exception as exc:
            return self.store.add(
                {
                    "event_type": "error",
                    "severity": "low",
                    "file_path": str(path),
                    "file_name": os.path.basename(path),
                    "message": "Scan failed: " + str(exc),
                    "trigger": trigger,
                }
            )

        if result.get("skipped"):
            return self.store.add(
                {
                    "event_type": "scan",
                    "file_path": result["file_path"],
                    "file_name": os.path.basename(path),
                    "file_size": result.get("file_size"),
                    "skipped": result["skipped"],
                    "trigger": trigger,
                },
                persist=False,
            )

        self.scanned_count += 1
        if not result["matches"]:
            event = dict(result)
            event.update({"event_type": "scan", "trigger": trigger, "verdict": "clean"})
            # Clean scans stay in memory only; findings.ndjson remains an alert log.
            return self.store.add(event, persist=False)

        telemetry = self.telemetry.recent()
        event = dict(result)
        event.update(
            {
                "event_type": "yara_match",
                "verdict": "rule_match",
                "trigger": trigger,
                "rule_names": [m["rule"] for m in result["matches"]],
                "telemetry": telemetry,
                "correlated_auth_failures": telemetry.get("count", 0),
            }
        )
        stored = self.store.add(event)
        # Opt-in, off by default. The finding is stored first so the action has
        # an id to reference and an audit trail to append to.
        if self.remediator is not None:
            try:
                auto = self.remediator.consider_auto(stored)
                if auto and auto.get("ok"):
                    print("[!] AUTO-REMEDIATE " + str(auto.get("outcome"))
                          + " " + str(stored.get("file_path")))
            except Exception as exc:
                print("[-] Auto-remediation failed: " + str(exc))
        print(
            "[!] ALERT "
            + str(stored.get("severity", "?")).upper()
            + " "
            + ", ".join(stored["rule_names"])
            + " in "
            + result["file_path"]
        )
        return stored

    def scan_path(self, target: str, max_files: int | None = None) -> dict:
        """Wait cooperatively for a streaming scan; max_files is deprecated."""
        import warnings
        from .jobs import ScanJobs

        if max_files is not None:
            warnings.warn("max_files is deprecated and ignored; scans stream the complete tree.",
                          FutureWarning, stacklevel=2)
        # Keep one owner across concurrent CLI requests, including cancellation.
        lock = self.__dict__.setdefault("_scan_path_lock", threading.Lock())
        with lock:
            jobs = self.__dict__.get("_scan_path_jobs")
            if jobs is None:
                jobs = self._scan_path_jobs = ScanJobs(self)
            started = time.perf_counter()
            snapshot = jobs.start(target)
            worker = jobs._worker
        if snapshot.get("error"):
            return snapshot
        identifier = snapshot["id"]
        try:
            while snapshot["state"] in ("queued", "running"):
                if self._stop_event.is_set():
                    jobs.cancel(identifier)
                worker.join(0.1)
                snapshot = next(job for job in jobs.status()["jobs"] if job["id"] == identifier)
        except BaseException:
            jobs.cancel(identifier)
            while worker.is_alive():
                worker.join(0.1)
            raise
        result = {
            "path": snapshot["path"], "files_scanned": snapshot["scanned"],
            "matches": snapshot["matches"], "skipped": snapshot["skipped"],
            "errors": snapshot["errors"], "state": snapshot["state"],
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }
        if snapshot["error"]:
            result["error"] = snapshot["error"]
        return result
