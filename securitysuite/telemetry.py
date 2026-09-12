"""Authentication telemetry, correlated against a real time window.

The original detector stamped every log line with datetime.now(), so nothing was
actually time-filtered. Here each source parses its own timestamps and only
events inside the lookback window are returned.

Each platform gets an ordered chain of providers, tried until one returns
usable data. Which one answered is reported, because "no failed logons" and
"nothing could read the logs" must never look the same.

  Windows   Security event log (4625/4648/4740/4771/4776). Needs Administrator.
  macOS     Unified logging via `log show`. There is no /var/log/auth.log on a
            modern macOS, so reading that file was never going to work.
  Linux     /var/log/auth.log or /var/log/secure when present, falling back to
            journalctl - several distributions ship journald with no text auth
            log at all.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

PLATFORM_NAME = "windows" if IS_WINDOWS else "macos" if IS_MACOS else \
    "linux" if IS_LINUX else sys.platform

# Text auth logs, in the order distributions tend to use them.
POSIX_AUTH_LOGS = ("/var/log/auth.log", "/var/log/secure", "/var/log/authlog")

# Message fragments that mean "an authentication attempt failed", across the
# wording used by sshd, sudo, PAM, loginwindow and opendirectoryd.
FAILURE_MARKERS = (
    "failed password", "invalid user", "authentication failure",
    "failed to authenticate", "authentication failed", "failed publickey",
    "incorrect password", "auth failure", "failed keyboard-interactive",
    "sudo: pam_unix", "failed login",
)

SUBPROCESS_TIMEOUT = 20.0

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
        self.platform = PLATFORM_NAME
        self.source = self._default_source()
        self.provider_used: str | None = None

    # ------------------------------------------------------------------ api
    def recent(self, force: bool = False) -> dict:
        """Return {status, source, window_minutes, events:[...]} for the window."""
        with self._lock:
            fresh = self._cache and (time.time() - self._cache_at) < self.cache_seconds
            if fresh and not force:
                return self._cache
        result = self._collect()
        result["window_minutes"] = self.lookback_minutes
        result["platform"] = self.platform
        result["collected_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
        result["count"] = len(result.get("events", []))
        with self._lock:
            self._cache = result
            self._cache_at = time.time()
        return result

    # ------------------------------------------------------------- providers
    def _default_source(self) -> str:
        if IS_WINDOWS:
            return "windows_security_log"
        if IS_MACOS:
            return "macos_unified_log"
        return "auth_log"

    def providers(self) -> list:
        """Ordered (name, callable) pairs to try for this platform."""
        if IS_WINDOWS:
            return [("windows_security_log", self._collect_windows)]
        if IS_MACOS:
            return [
                ("macos_unified_log", self._collect_macos),
                ("auth_log", self._collect_syslog),
            ]
        # Linux and other POSIX: prefer a text log, fall back to journald.
        return [
            ("auth_log", self._collect_syslog),
            ("journald", self._collect_journald),
        ]

    def _collect(self) -> dict:
        """Try each provider in turn; report what was tried and what answered."""
        attempts = []
        first_usable = None
        for name, collect in self.providers():
            try:
                result = collect()
            except Exception as exc:              # a provider must never crash the poll
                result = {"status": "error", "source": name, "detail": str(exc), "events": []}
            attempts.append({"provider": name, "status": result.get("status", "error"),
                             "detail": result.get("detail", "")})
            if result.get("status") == "ok":
                self.provider_used = name
                result["source"] = name
                result["attempts"] = attempts
                return result
            if first_usable is None:
                first_usable = result

        # Nothing worked: return the first provider's diagnosis, not an empty
        # success. An operator must be able to tell "quiet" from "blind".
        result = first_usable or {"status": "unavailable", "source": self.source,
                                  "detail": "no telemetry provider available",
                                  "events": []}
        result["attempts"] = attempts
        self.provider_used = None
        return result

    # ---------------------------------------------------------------- macOS
    def _collect_macos(self) -> dict:
        """Query the unified log. macOS has no /var/log/auth.log to read."""
        if not shutil.which("log"):
            return {"status": "unavailable", "source": "macos_unified_log",
                    "detail": "the `log` command is not available", "events": []}

        predicate = (
            'eventMessage CONTAINS[c] "Failed password" OR '
            'eventMessage CONTAINS[c] "authentication failure" OR '
            'eventMessage CONTAINS[c] "failed to authenticate" OR '
            'eventMessage CONTAINS[c] "Invalid user"'
        )
        command = ["log", "show", "--style", "ndjson",
                   "--last", str(self.lookback_minutes) + "m",
                   "--predicate", predicate]
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=SUBPROCESS_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"status": "error", "source": "macos_unified_log",
                    "detail": "`log show` timed out", "events": []}
        except OSError as exc:
            return {"status": "error", "source": "macos_unified_log",
                    "detail": str(exc), "events": []}

        if proc.returncode != 0:
            detail = (proc.stderr or "").strip()[:200]
            denied = "not permitted" in detail.lower() or "denied" in detail.lower()
            return {"status": "denied" if denied else "error",
                    "source": "macos_unified_log",
                    "detail": detail or "`log show` exited %d" % proc.returncode,
                    "events": []}

        cutoff = datetime.now().astimezone() - timedelta(minutes=self.lookback_minutes)
        events = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip().rstrip(",")
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            message = str(record.get("eventMessage") or "")
            if not any(marker in message.lower() for marker in FAILURE_MARKERS):
                continue
            when = self._parse_macos_time(str(record.get("timestamp") or ""))
            if when is None or when < cutoff:
                continue
            user = USER_RE.search(message)
            ip = IP_RE.search(message)
            process = str(record.get("processImagePath") or "").rsplit("/", 1)[-1]
            events.append({
                "timestamp": when.isoformat(timespec="seconds"),
                "type": "failed_logon",
                "event_id": None,
                "account": user.group("user") if user else "unknown",
                "source_ip": ip.group(0) if ip else "",
                "process": process,
                "raw": message.strip()[:400],
            })
            if len(events) >= self.max_events:
                break
        return {"status": "ok", "source": "macos_unified_log", "events": events}

    @staticmethod
    def _parse_macos_time(value: str):
        """`log show` emits e.g. 2026-09-12 02:34:56.789012-0500."""
        if not value:
            return None
        cleaned = value.strip().replace("  ", " ")
        for fmt in ("%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z"):
            try:
                return datetime.strptime(cleaned, fmt)
            except ValueError:
                continue
        try:                                   # ISO-8601 variants
            return datetime.fromisoformat(cleaned)
        except ValueError:
            return None

    # ------------------------------------------------------------- journald
    def _collect_journald(self) -> dict:
        """Fallback for systemd hosts with no text auth log."""
        if not shutil.which("journalctl"):
            return {"status": "unavailable", "source": "journald",
                    "detail": "journalctl is not available", "events": []}

        command = ["journalctl", "--no-pager", "-o", "json",
                   "--since", "%d min ago" % self.lookback_minutes,
                   "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"]
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=SUBPROCESS_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"status": "error", "source": "journald",
                    "detail": "journalctl timed out", "events": []}
        except OSError as exc:
            return {"status": "error", "source": "journald",
                    "detail": str(exc), "events": []}

        if proc.returncode != 0:
            detail = (proc.stderr or "").strip()[:200]
            denied = "permission" in detail.lower() or "not in the" in detail.lower()
            return {"status": "denied" if denied else "error", "source": "journald",
                    "detail": (detail + " - adding the user to the systemd-journal "
                               "group grants read access") if denied else
                              (detail or "journalctl exited %d" % proc.returncode),
                    "events": []}

        events = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            message = str(record.get("MESSAGE") or "")
            if not any(marker in message.lower() for marker in FAILURE_MARKERS):
                continue
            when = self._parse_journal_time(record.get("__REALTIME_TIMESTAMP"))
            user = USER_RE.search(message)
            ip = IP_RE.search(message)
            events.append({
                "timestamp": when.isoformat(timespec="seconds") if when else "",
                "type": "failed_logon",
                "event_id": None,
                "account": user.group("user") if user else "unknown",
                "source_ip": ip.group(0) if ip else "",
                "process": str(record.get("_COMM") or record.get("SYSLOG_IDENTIFIER") or ""),
                "raw": message.strip()[:400],
            })
            if len(events) >= self.max_events:
                break
        return {"status": "ok", "source": "journald", "events": events}

    @staticmethod
    def _parse_journal_time(value):
        """journald __REALTIME_TIMESTAMP is microseconds since the epoch."""
        try:
            return datetime.fromtimestamp(int(value) / 1_000_000, timezone.utc).astimezone()
        except (TypeError, ValueError, OSError):
            return None

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
        # Distributions disagree about the filename, so try the configured path
        # first and then the usual suspects.
        candidates = [self.auth_log_path] + [
            c for c in POSIX_AUTH_LOGS if c != self.auth_log_path]
        path = next((c for c in candidates if c and os.path.exists(c)), "")
        if not path:
            return {
                "status": "unavailable",
                "source": "auth_log",
                "detail": "no text auth log found (tried " + ", ".join(
                    c for c in candidates if c) + ")",
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
                    lowered = line.lower()
                    if not any(marker in lowered for marker in FAILURE_MARKERS):
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
                "source": "auth_log",
                "detail": "No read permission on " + path + " (try sudo).",
                "events": [],
            }
        except OSError as exc:
            return {"status": "error", "source": "auth_log",
                    "detail": str(exc), "events": []}
        return {"status": "ok", "source": "auth_log", "path": path,
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
