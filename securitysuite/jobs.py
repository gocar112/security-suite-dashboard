"""Bounded background scans, independent of the watcher's settle/extension rules.

Successful start/cancel calls return a job snapshot; rejected calls return an
``error`` string. Status returns newest jobs first. ``scanned`` counts successful
file scans and ``matches`` counts matching files, not individual matching rules.
``skipped`` counts encountered entries (a pruned directory counts once, not its
unknown contents). ``errors`` counts failures, including inaccessible skips.

Cancellation is cooperative: an in-flight engine/OS call cannot be interrupted.
The job stays active with cancellation_requested=True until that call returns,
so repeated cancellations/starts cannot accumulate blocked scanner threads.
"""
from __future__ import annotations

import ctypes
import os
import stat
import sys
import threading
import uuid
from collections import deque
from pathlib import Path

from .store import now_iso


HISTORY_LIMIT = 20
MAX_OPEN_DIRECTORIES = 128
PSEUDO_FILESYSTEMS = ("/proc", "/sys", "/dev", "/run")


def _normal(path) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _is_link(info) -> bool:
    # Reparse points include Windows junctions and mount-point aliases.
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _windows_drives() -> list[dict]:
    kernel = ctypes.windll.kernel32
    kernel.GetLogicalDrives.argtypes = []
    kernel.GetLogicalDrives.restype = ctypes.c_ulong
    kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel.GetDriveTypeW.restype = ctypes.c_uint
    mask = kernel.GetLogicalDrives()
    result = []
    for index in range(26):
        path = chr(ord("A") + index) + ":\\"
        if mask & (1 << index) and kernel.GetDriveTypeW(path) == 3:
            result.append({"path": path, "label": "Local disk (" + path[:2] + ")"})
    return result


class ScanJobs:
    """One worker and at most HISTORY_LIMIT snapshots per monitor owner.

    Traversal holds at most MAX_OPEN_DIRECTORIES scandir handles, no file list
    or per-file history. Deeper subtrees are reported as depth_limit skips.
    Scanning never modifies watch_paths, remediation_roots or watcher baselines.
    """

    def __init__(self, monitor):
        self.monitor = monitor
        self._lock = threading.Lock()
        self._jobs: deque[dict] = deque(maxlen=HISTORY_LIMIT)
        self._active_id: str | None = None
        self._cancel_event = threading.Event()
        self._worker: threading.Thread | None = None

    def drives(self) -> list[dict]:
        if os.name == "nt":
            return _windows_drives()
        return [{"path": "/", "label": "Filesystem (/)"}]

    @staticmethod
    def _snapshot(job: dict) -> dict:
        return {**job, "skip_reasons": dict(job["skip_reasons"])}

    def start(self, path) -> dict:
        try:
            raw = os.fspath(path)
            if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
                return {"error": "A non-empty filesystem path is required"}
            target = os.path.abspath(os.path.expanduser(raw))
        except (TypeError, ValueError, OSError) as exc:
            return {"error": "Invalid path: " + str(exc)}
        with self._lock:
            if self._active_id is not None:
                return {"error": "A scan job is already active", "job_id": self._active_id}
            job = {
                "id": uuid.uuid4().hex,
                "path": target,
                "state": "queued",
                "current_path": None,
                "started_at": None,
                "finished_at": None,
                "scanned": 0,
                "matches": 0,
                "skipped": 0,
                "errors": 0,
                "skip_reasons": {},
                "cancellation_requested": False,
                "error": None,
                "last_error": None,
            }
            self._jobs.appendleft(job)
            self._active_id = job["id"]
            cancel = self._cancel_event = threading.Event()
            try:
                self._worker = threading.Thread(
                    target=self._run, args=(job, cancel),
                    name="securitysuite-scan-job", daemon=True,
                )
                self._worker.start()
            except Exception as exc:
                job.update(state="error", error=str(exc), last_error=str(exc),
                           errors=1, finished_at=now_iso())
                self._active_id = None
            return self._snapshot(job)

    def status(self) -> dict:
        with self._lock:
            return {"jobs": [self._snapshot(job) for job in self._jobs]}

    def cancel(self, job_id: str) -> dict:
        with self._lock:
            job = next((job for job in self._jobs if job["id"] == job_id), None)
            if job is None:
                return {"error": "Unknown scan job"}
            if job["id"] == self._active_id:
                job["cancellation_requested"] = True
                self._cancel_event.set()
            return self._snapshot(job)

    def _exclusions(self) -> tuple[set[str], set[str]]:
        cfg = self.monitor.cfg
        files = set()
        directories = set()
        for attr in ("findings_log", "triage_file", "remediation_file"):
            path = getattr(cfg, attr, None)
            if path:
                files.add(_normal(path))
                files.add(_normal(os.path.realpath(path)))
        triage = getattr(cfg, "triage_file", None)
        if triage:
            for name in ("playbooks.json", "response-policy.json", "blocked-domains.json"):
                sidecar = os.path.join(os.path.dirname(triage), name)
                files.update((_normal(sidecar), _normal(os.path.realpath(sidecar))))
        for attr in ("quarantine_dir", "nvd_cache_dir", "osv_cache_dir",
                     "vt_cache_dir", "guidance_cache_dir"):
            path = getattr(cfg, attr, None)
            if path:
                directories.add(_normal(path))
                directories.add(_normal(os.path.realpath(path)))
        findings = getattr(cfg, "findings_log", None)
        if findings:
            backups = os.path.join(os.path.dirname(findings), "log-backups")
            directories.update((_normal(backups), _normal(os.path.realpath(backups))))
        if sys.platform.startswith("linux"):
            directories.update(_normal(path) for path in PSEUDO_FILESYSTEMS)
        return files, directories

    def _skip(self, job: dict, reason: str, exc: Exception | None = None) -> None:
        with self._lock:
            job["skipped"] += 1
            reasons = job["skip_reasons"]
            reasons[reason] = reasons.get(reason, 0) + 1
            if exc is not None:
                job["errors"] += 1
                job["last_error"] = str(exc)

    def _run(self, job: dict, cancel: threading.Event) -> None:
        failed = False
        try:
            with self._lock:
                if not cancel.is_set():
                    job.update(state="running", started_at=now_iso())
            if not cancel.is_set():
                self._walk(job, cancel)
        except Exception as exc:
            failed = True
            with self._lock:
                job.update(error=str(exc), last_error=str(exc))
                job["errors"] += 1
        finally:
            with self._lock:
                job.update(
                    state="cancelled" if cancel.is_set() else "error" if failed else "completed",
                    current_path=None, finished_at=now_iso(),
                )
                self._active_id = None

    def _walk(self, job: dict, cancel: threading.Event) -> None:
        excluded_files, excluded_dirs = self._exclusions()
        root = job["path"]
        # Check ancestors too: a user can explicitly request link/child.txt.
        for parent in reversed(Path(root).parents):
            if cancel.is_set():
                return
            if _is_link(os.lstat(parent)):
                self._skip(job, "link")
                return

        stack = []
        path = root
        try:
            while not cancel.is_set():
                if path is None:
                    if not stack:
                        break
                    directory, iterator = stack[-1]
                    try:
                        path = next(iterator).path
                    except StopIteration:
                        stack.pop()[1].close()
                        continue
                    except OSError as exc:
                        self._skip(job, "unavailable", None if directory == root else exc)
                        stack.pop()[1].close()
                        if directory == root:
                            with self._lock:
                                job["error"] = str(exc)
                            raise
                        continue
                if cancel.is_set():
                    break
                with self._lock:
                    job["current_path"] = path
                normalized = _normal(path)
                if normalized in excluded_files or any(
                    _within(normalized, excluded) for excluded in excluded_dirs
                ):
                    self._skip(job, "excluded")
                    path = None
                    continue
                try:
                    info = os.lstat(path)
                    if _is_link(info):
                        self._skip(job, "link")
                    elif stat.S_ISDIR(info.st_mode):
                        if len(stack) >= MAX_OPEN_DIRECTORIES:
                            self._skip(job, "depth_limit")
                        else:
                            stack.append((path, os.scandir(path)))
                    elif stat.S_ISREG(info.st_mode):
                        if not cancel.is_set():
                            self._scan(job, path)
                    else:
                        self._skip(job, "special_file")
                except OSError as exc:
                    # A failed root is not a successfully completed empty scan.
                    if path == root:
                        self._skip(job, "unavailable")
                        raise
                    self._skip(job, "unavailable", exc)
                path = None
        finally:
            for _, iterator in reversed(stack):
                iterator.close()

    def _scan(self, job: dict, path: str) -> None:
        try:
            event = self.monitor.scan_and_record(path, trigger="job")
            if not isinstance(event, dict):
                raise ValueError("Scanner returned an invalid event")
        except Exception as exc:
            with self._lock:
                job["errors"] += 1
                job["last_error"] = str(exc)
            return
        if event.get("skipped"):
            reason = str(event["skipped"])
            if "unavailable" in reason:
                self._skip(job, "unavailable", OSError(reason))
            else:
                self._skip(job, "size" if "larger than" in reason else "engine")
        elif event.get("event_type") == "error":
            with self._lock:
                job["errors"] += 1
                job["last_error"] = event.get("message", "Scan failed")
        else:
            with self._lock:
                job["scanned"] += 1
                if event.get("event_type") == "yara_match":
                    job["matches"] += 1
