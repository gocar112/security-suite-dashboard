"""Append-only NDJSON event store with an in-memory index and a pub/sub bus."""
from __future__ import annotations

import json
import os
import queue
import shutil
import threading
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def new_id() -> str:
    return uuid.uuid4().hex[:12]


class EventStore:
    """Thread-safe store: durable NDJSON on disk, ring buffer in memory."""

    def __init__(self, findings_log: str, triage_file: str, history_limit: int = 2000):
        self.path = Path(findings_log)
        self.triage_path = Path(triage_file)
        self.history_limit = history_limit
        self._lock = threading.RLock()
        self._events: deque = deque(maxlen=history_limit)
        self._subscribers: list[queue.Queue] = []
        self._triage: dict[str, dict] = {}
        self.counters = Counter()
        self.started_at = time.time()
        os.makedirs(self.path.parent, exist_ok=True)
        self._load_triage()
        self._load_history()

    # ------------------------------------------------------------------ load
    def _load_triage(self) -> None:
        if self.triage_path.exists():
            try:
                self._triage = json.loads(self.triage_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self._triage = {}

    def _load_history(self) -> None:
        """Replay the tail of the findings log so a restart keeps the dashboard warm."""
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as handle:
                tail = deque(handle, maxlen=self.history_limit)
        except OSError:
            return
        for line in tail:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            event.setdefault("id", new_id())
            self._apply_triage(event)
            self._events.append(event)
            self._count(event)

    # ----------------------------------------------------------------- write
    def _count(self, event: dict) -> None:
        self.counters["type:" + str(event.get("event_type", "unknown"))] += 1
        if event.get("event_type") in ("scan", "yara_match") and not event.get("skipped"):
            self.counters["files_scanned"] += 1
        if event.get("event_type") == "yara_match":
            self.counters["sev:" + str(event.get("severity", "info"))] += 1

    def _apply_triage(self, event: dict) -> None:
        state = self._triage.get(event.get("id", ""))
        if state:
            event["status"] = state.get("status", "new")
            event["triaged_at"] = state.get("at")
            event["triage_note"] = state.get("note", "")
        else:
            event.setdefault("status", "new")

    def add(self, event: dict, persist: bool = True) -> dict:
        event.setdefault("id", new_id())
        event.setdefault("timestamp", now_iso())
        event.setdefault("status", "new")
        event.setdefault("_epoch", time.time())
        with self._lock:
            if persist:
                try:
                    with self.path.open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(event, default=str) + "\n")
                except OSError as exc:
                    print("[-] Could not persist finding: " + str(exc))
            self._events.append(event)
            self._count(event)
            dead = []
            for sub in self._subscribers:
                try:
                    sub.put_nowait(event)
                except queue.Full:
                    dead.append(sub)
            for sub in dead:
                self._subscribers.remove(sub)
        return event

    def set_status(self, event_id: str, status: str, note: str = "") -> dict | None:
        with self._lock:
            target = None
            for event in self._events:
                if event.get("id") == event_id:
                    target = event
                    break
            if target is None:
                return None
            target["status"] = status
            target["triaged_at"] = now_iso()
            target["triage_note"] = note
            self._triage[event_id] = {
                "status": status,
                "at": target["triaged_at"],
                "note": note,
            }
            try:
                self.triage_path.write_text(
                    json.dumps(self._triage, indent=2), encoding="utf-8"
                )
            except OSError as exc:
                print("[-] Could not persist triage state: " + str(exc))
            return dict(target)

    def clear(self, backup: bool = True) -> dict:
        """Clear detection noise from the dashboard.

        Remediation records are deliberately *not* cleared. findings.ndjson is
        the audit trail for every destructive action taken and every one
        refused, and truncating it would destroy the only evidence of what the
        tool deleted. Clearing is a dashboard convenience; it must not be a way
        to erase that history.

        The backup is unconditional for the same reason - a caller cannot opt
        out of it.
        """
        backup = True                     # not caller-controllable, see above
        backup_dir = ""
        with self._lock:
            event_count = len(self._events)
            triage_count = len(self._triage)
            kept = [e for e in self._events
                    if e.get("event_type") == "remediation"]
            if backup:
                stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                backup_path = self.path.parent / "log-backups" / stamp
                try:
                    backup_path.mkdir(parents=True, exist_ok=True)
                    if self.path.exists():
                        shutil.copy2(self.path, backup_path / self.path.name)
                    if self.triage_path.exists():
                        shutil.copy2(self.triage_path, backup_path / self.triage_path.name)
                    backup_dir = str(backup_path)
                except OSError as exc:
                    print("[-] Could not back up logs before clear: " + str(exc))
            self._events.clear()
            self._triage.clear()
            self.counters.clear()
            for event in kept:            # audit records survive the clear
                self._events.append(event)
                self._count(event)
            try:
                self.path.write_text(
                    "".join(json.dumps(e, default=str) + chr(10) for e in kept),
                    encoding="utf-8")
                self.triage_path.write_text("{}", encoding="utf-8")
            except OSError as exc:
                print("[-] Could not clear finding state: " + str(exc))
        return {
            "cleared": True,
            "events": event_count,
            "triage": triage_count,
            "audit_retained": len(kept),
            "backup_dir": backup_dir,
        }

    # ------------------------------------------------------------------ read
    def events(
        self,
        limit: int = 200,
        severity: str | None = None,
        event_type: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> list[dict]:
        with self._lock:
            items = list(self._events)
        items.reverse()  # newest first
        needle = (search or "").lower().strip()
        out: list[dict] = []
        for event in items:
            if severity and severity != "all" and event.get("severity") != severity:
                continue
            if event_type and event_type != "all" and event.get("event_type") != event_type:
                continue
            if status and status != "all" and event.get("status", "new") != status:
                continue
            if needle and needle not in json.dumps(event, default=str).lower():
                continue
            out.append(event)
            if len(out) >= limit:
                break
        return out

    def stats(self) -> dict:
        with self._lock:
            items = list(self._events)
            total_scanned = self.counters["files_scanned"]
        by_sev: Counter = Counter()
        by_rule: Counter = Counter()
        open_alerts = 0
        clean_scans = 0
        matches = 0
        errors = 0
        for event in items:
            kind = event.get("event_type")
            if kind == "scan":
                clean_scans += 1
            elif kind == "yara_match":
                matches += 1
                by_sev[event.get("severity", "info")] += 1
                if event.get("status", "new") == "new":
                    open_alerts += 1
                for match in event.get("matches", []):
                    by_rule[match.get("rule", "?")] += 1
            elif kind == "error":
                errors += 1
        return {
            "files_scanned": total_scanned,
            "matches": matches,
            "open_alerts": open_alerts,
            "errors": errors,
            "by_severity": {name: by_sev.get(name, 0) for name in SEVERITIES},
            "top_rules": by_rule.most_common(6),
            "timeline": self._timeline(items),
            "uptime_seconds": int(time.time() - self.started_at),
            "log_path": str(self.path),
            "log_size": self.path.stat().st_size if self.path.exists() else 0,
        }

    def _timeline(self, items: list[dict], buckets: int = 24, minutes: int = 60) -> list[dict]:
        """Match counts bucketed across the trailing window, oldest bucket first."""
        span = minutes * 60 / buckets
        now = time.time()
        counts = [0] * buckets
        for event in items:
            if event.get("event_type") != "yara_match":
                continue
            stamp = event.get("_epoch")
            if stamp is None:
                try:
                    stamp = datetime.fromisoformat(event["timestamp"]).timestamp()
                except (KeyError, ValueError, TypeError):
                    continue
            age = now - float(stamp)
            if age < 0 or age > minutes * 60:
                continue
            idx = buckets - 1 - int(age // span)
            if 0 <= idx < buckets:
                counts[idx] += 1
        return [
            {"minutes_ago": int((buckets - 1 - i) * (minutes / buckets)), "count": c}
            for i, c in enumerate(counts)
        ]

    # --------------------------------------------------------------- pub/sub
    def subscribe(self) -> queue.Queue:
        sub: queue.Queue = queue.Queue(maxsize=256)
        with self._lock:
            self._subscribers.append(sub)
        return sub

    def unsubscribe(self, sub: queue.Queue) -> None:
        with self._lock:
            if sub in self._subscribers:
                self._subscribers.remove(sub)

    def broadcast(self, event: dict) -> None:
        """Push a transient event to live clients without storing it."""
        with self._lock:
            for sub in list(self._subscribers):
                try:
                    sub.put_nowait(event)
                except queue.Full:
                    pass
