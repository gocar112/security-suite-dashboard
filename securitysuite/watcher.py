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
    def __init__(self, cfg, engine: YaraEngine, store: EventStore, telemetry: AuthTelemetry):
        super().__init__(name="securitysuite-monitor", daemon=True)
        self.cfg = cfg
        self.engine = engine
        self.store = store
        self.telemetry = telemetry
        self._stop = threading.Event()
        self._pause = threading.Event()
        # Never scan our own output: findings.ndjson contains the strings that
        # tripped the rules, so scanning it would alert on itself forever.
        self._self_paths = {
            os.path.normcase(os.path.abspath(p))
            for p in (cfg.findings_log, cfg.triage_file)
        }
        # path -> (mtime, size) at the moment we last scanned it
        self._scanned: dict[str, tuple] = {}
        # path -> (mtime, size, first_seen_at) for files still settling
        self._pending: dict[str, tuple] = {}
        self.scanned_count = 0
        self.last_sweep: str | None = None
        self.last_error: str | None = None

    # --------------------------------------------------------------- control
    def stop(self) -> None:
        self._stop.set()

    def pause(self) -> None:
        self._pause.set()

    def resume(self) -> None:
        self._pause.clear()

    @property
    def paused(self) -> bool:
        return self._pause.is_set()

    def status(self) -> dict:
        return {
            "running": self.is_alive() and not self._stop.is_set(),
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
                self._scanned[path] = (stat.st_mtime, stat.st_size)
        self.store.broadcast(
            {
                "event_type": "monitor",
                "timestamp": now_iso(),
                "message": "Monitoring " + ", ".join(self.cfg.watch_paths),
            }
        )
        while not self._stop.is_set():
            if not self._pause.is_set():
                try:
                    self._sweep()
                    self.last_error = None
                except Exception as exc:  # keep the monitor alive through bad paths
                    self.last_error = str(exc)
            self._stop.wait(self.cfg.poll_interval)

    def _iter_files(self):
        for root in self.cfg.watch_paths:
            root_path = Path(root)
            if not root_path.exists():
                continue
            walker = root_path.rglob("*") if self.cfg.recursive else root_path.glob("*")
            for entry in walker:
                try:
                    if not entry.is_file():
                        continue
                    if entry.suffix.lower() in self.cfg.ignore_suffixes:
                        continue
                    if os.path.normcase(os.path.abspath(entry)) in self._self_paths:
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

        self.scanned_count += 1
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
                "verdict": "malicious",
                "trigger": trigger,
                "rule_names": [m["rule"] for m in result["matches"]],
                "telemetry": telemetry,
                "correlated_auth_failures": telemetry.get("count", 0),
            }
        )
        stored = self.store.add(event)
        print(
            "[!] ALERT "
            + str(stored.get("severity", "?")).upper()
            + " "
            + ", ".join(stored["rule_names"])
            + " in "
            + result["file_path"]
        )
        return stored

    def scan_path(self, target: str, max_files: int = 5000) -> dict:
        """On-demand scan of a file or directory tree."""
        root = Path(target).expanduser()
        if not root.exists():
            return {"error": "Path not found: " + str(root)}
        files: list[Path] = []
        if root.is_file():
            files = [root]
        else:
            for entry in root.rglob("*"):
                try:
                    if entry.is_file() and entry.suffix.lower() not in self.cfg.ignore_suffixes:
                        files.append(entry)
                except OSError:
                    continue
                if len(files) >= max_files:
                    break
        started = time.perf_counter()
        hits = 0
        for entry in files:
            event = self.scan_and_record(str(entry), trigger="manual")
            if event.get("event_type") == "yara_match":
                hits += 1
            try:
                stat = entry.stat()
                self._scanned[str(entry)] = (stat.st_mtime, stat.st_size)
            except OSError:
                pass
        return {
            "path": str(root),
            "files_scanned": len(files),
            "matches": hits,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }
