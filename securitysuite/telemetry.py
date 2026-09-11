"""Authentication telemetry, correlated against a real time window.

The original detector stamped every log line with datetime.now(), so nothing was
actually time-filtered. Here each source parses its own timestamps and only
events inside the lookback window are returned.

Sources:
  * Windows - Security event log, failed logons (4625) and explicit-credential
    logons (4648). Reading the Security log normally requires Administrator.
  * Linux/macOS - syslog-style auth log, "Failed password" / "Invalid user".
"""
from __future__ import annotations

import os
import re
import threading
import time
from datetime import datetime, timedelta

IS_WINDOWS = os.name == "nt"

# "Sep 11 14:23:01 host sshd[1234]: Failed password for invalid user root from 10.0.0.9 port 22"
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"(?:invalid user|user)\s+(?P<user>[\w.\-$\\]+)", re.IGNORECASE)
MONTHS = {
    m: i + 1
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    )
}

WINDOWS_EVENT_LABELS = {
    4625: "failed_logon",
    4648: "explicit_credential_logon",
    4740: "account_lockout",
    4771: "kerberos_preauth_failed",
    4776: "credential_validation_failed",
}
WATCHED_EVENT_IDS = set(WINDOWS_EVENT_LABELS)


class AuthTelemetry:
    """Collects recent authentication failures, with a short result cache."""

    def __init__(self, auth_log_path: str, lookback_minutes: int = 5,
                 cache_seconds: float = 15.0, max_events: int = 25):
        self.auth_log_path = auth_log_path
        self.lookback_minutes = lookback_minutes
        self.cache_seconds = cache_seconds
        self.max_events = max_events
        self._lock = threading.Lock()
        self._cache: dict | None = None
        self._cache_at = 0.0
        self.source = "windows_security_log" if IS_WINDOWS else "auth_log"

    # ------------------------------------------------------------------ api
    def recent(self, force: bool = False) -> dict:
        """Return {status, source, window_minutes, events:[...]} for the window."""
        with self._lock:
            fresh = self._cache and (time.time() - self._cache_at) < self.cache_seconds
            if fresh and not force:
                return self._cache
        result = self._collect_windows() if IS_WINDOWS else self._collect_syslog()
        result["window_minutes"] = self.lookback_minutes
        result["collected_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
        result["count"] = len(result.get("events", []))
        with self._lock:
            self._cache = result
            self._cache_at = time.time()
        return result

    # -------------------------------------------------------------- windows
    def _collect_windows(self) -> dict:
        try:
            import win32evtlog  # type: ignore
            import pywintypes  # type: ignore
        except ImportError:
            return {
                "status": "unavailable",
                "source": self.source,
                "detail": "pywin32 not installed (pip install pywin32)",
                "events": [],
            }

        cutoff = datetime.now() - timedelta(minutes=self.lookback_minutes)
        events: list[dict] = []
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, "Security")
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )
            scanned = 0
            while len(events) < self.max_events and scanned < 4000:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                for record in records:
                    scanned += 1
                    generated = record.TimeGenerated
                    when = datetime(
                        generated.year, generated.month, generated.day,
                        generated.hour, generated.minute, generated.second,
                    )
                    if when < cutoff:
                        scanned = 4000  # everything older follows; stop the outer loop
                        break
                    event_id = record.EventID & 0x1FFFFFFF
                    if event_id not in WATCHED_EVENT_IDS:
                        continue
                    inserts = [str(s) for s in (record.StringInserts or [])]
                    events.append(
                        {
                            "timestamp": when.astimezone().isoformat(timespec="seconds"),
                            "type": WINDOWS_EVENT_LABELS[event_id],
                            "event_id": event_id,
                            "account": self._pick_account(inserts),
                            "source_ip": self._pick_ip(inserts),
                            "raw": " | ".join(i for i in inserts if i and i != "-")[:400],
                        }
                    )
                    if len(events) >= self.max_events:
                        break
            return {"status": "ok", "source": self.source, "events": events}
        except pywintypes.error as exc:  # type: ignore[attr-defined]
            # 5 = access denied, 1314 = SeSecurityPrivilege not held.
            denied = exc.winerror in (5, 1314)
            return {
                "status": "denied" if denied else "error",
                "source": self.source,
                "detail": (
                    "Access denied reading the Security log - relaunch the suite as "
                    "Administrator to enable logon correlation."
                    if denied
                    else str(exc)
                ),
                "events": [],
            }
        except Exception as exc:  # pragma: no cover - defensive
            return {"status": "error", "source": self.source,
                    "detail": str(exc), "events": []}
        finally:
            if handle is not None:
                try:
                    import win32evtlog  # type: ignore
                    win32evtlog.CloseEventLog(handle)
                except Exception:
                    pass

    @staticmethod
    def _pick_account(inserts: list[str]) -> str:
        # 4625 layout: [0]=subject SID, [1]=subject user, ... [5]=target user name.
        for idx in (5, 1):
            if len(inserts) > idx and inserts[idx] and inserts[idx] != "-":
                return inserts[idx]
        return "unknown"

    @staticmethod
    def _pick_ip(inserts: list[str]) -> str:
        for value in inserts:
            match = IP_RE.search(value or "")
            if match:
                return match.group(0)
        return ""

    # ---------------------------------------------------------------- posix
    def _collect_syslog(self) -> dict:
        path = self.auth_log_path
        if not os.path.exists(path):
            return {
                "status": "unavailable",
                "source": self.source,
                "detail": path + " not found",
                "events": [],
            }
        cutoff = datetime.now() - timedelta(minutes=self.lookback_minutes)
        events: list[dict] = []
        try:
            size = os.path.getsize(path)
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                # Only the tail can be inside a few-minute window.
                handle.seek(max(0, size - 512 * 1024))
                if size > 512 * 1024:
                    handle.readline()  # discard the partial first line
                for line in handle:
                    if "Failed password" not in line and "Invalid user" not in line \
                            and "authentication failure" not in line:
                        continue
                    when = self._parse_syslog_time(line)
                    if when is None or when < cutoff:
                        continue
                    user = USER_RE.search(line)
                    ip = IP_RE.search(line)
                    events.append(
                        {
                            "timestamp": when.astimezone().isoformat(timespec="seconds"),
                            "type": "failed_logon",
                            "event_id": None,
                            "account": user.group("user") if user else "unknown",
                            "source_ip": ip.group(0) if ip else "",
                            "raw": line.strip()[:400],
                        }
                    )
        except PermissionError:
            return {
                "status": "denied",
                "source": self.source,
                "detail": "No read permission on " + path + " (try sudo).",
                "events": [],
            }
        except OSError as exc:
            return {"status": "error", "source": self.source,
                    "detail": str(exc), "events": []}
        return {"status": "ok", "source": self.source,
                "events": events[-self.max_events:]}

    @staticmethod
    def _parse_syslog_time(line: str) -> datetime | None:
        match = SYSLOG_RE.match(line)
        if not match:
            return None
        month = MONTHS.get(match.group("mon"))
        if not month:
            return None
        now = datetime.now()
        hour, minute, second = (int(p) for p in match.group("time").split(":"))
        try:
            when = datetime(now.year, month, int(match.group("day")), hour, minute, second)
        except ValueError:
            return None
        # Syslog omits the year: a timestamp in the future means last year.
        if when > now + timedelta(days=1):
            when = when.replace(year=now.year - 1)
        return when
