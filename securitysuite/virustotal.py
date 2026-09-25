"""VirusTotal adapter — hash reputation, with honest capability gating.

VT Hunting (Livehunt, Retrohunt, VTDIFF) and Intelligence search are Enterprise
features. On the public API tier every one of those endpoints returns 403, so
this client probes what the key can actually do and reports it, rather than
shipping panels that cannot work.

What the public tier does allow is the part that matters most here: looking up
a file by hash. The scanner already computes SHA-256 on every detection, so a
lookup turns a local YARA hit into "and here is what 70-odd engines think of
this exact file" without sending anything but the hash.

IMPORTANT - this client never uploads files. Submitting a file to VirusTotal
publishes it to the platform, where other users can download it; doing that
automatically to whatever lands in a watched directory would leak customer
data, credentials in config files, and anything else that happened to arrive.
Hashes only. Uploading is a decision for a human, in the VT web interface.
"""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from .net import HttpError, RateLimiter, get_json, ssl_source

BASE_URL = "https://www.virustotal.com/api/v3"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
HASH_RE = re.compile(r"^[0-9a-f]{32}([0-9a-f]{8})?([0-9a-f]{24})?$", re.IGNORECASE)

# Endpoints probed to work out what the key is allowed to reach.
CAPABILITY_PROBES = (
    ("file_lookup", "/files/44d88612fea8a8f36de82e1278abb02f"),   # EICAR, always present
    ("livehunt", "/intelligence/hunting_rulesets?limit=1"),
    ("retrohunt", "/intelligence/retrohunt_jobs?limit=1"),
    ("intelligence_search", "/intelligence/search?query=type%3Apeexe&limit=1"),
)

ENTERPRISE_ONLY = ("livehunt", "retrohunt", "intelligence_search", "vtdiff")
CAPABILITY_TTL_SECONDS = 24 * 3600   # a VT account tier changes rarely


def _now() -> datetime:
    return datetime.now(timezone.utc)


def severity_for(stats: dict) -> str:
    """Map engine consensus onto the suite's triage scale."""
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    if malicious >= 10:
        return "critical"
    if malicious >= 3:
        return "high"
    if malicious >= 1 or suspicious >= 3:
        return "medium"
    if suspicious >= 1:
        return "low"
    return "info"


def normalise(payload: dict) -> dict:
    """Flatten a VT file report into the shape the dashboard consumes."""
    attrs = (payload.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(int(v or 0) for v in stats.values()) or 0

    threat = attrs.get("popular_threat_classification") or {}
    label = threat.get("suggested_threat_label", "")
    families = [c.get("value", "") for c in (threat.get("popular_threat_name") or [])][:4]

    flagged = []
    for engine, result in (attrs.get("last_analysis_results") or {}).items():
        if result.get("category") in ("malicious", "suspicious"):
            flagged.append({
                "engine": engine,
                "category": result.get("category"),
                "result": result.get("result", ""),
            })
    flagged.sort(key=lambda r: r["engine"].lower())

    def stamp(value):
        if not value:
            return ""
        try:
            return datetime.fromtimestamp(int(value), timezone.utc).astimezone().isoformat(timespec="seconds")
        except (TypeError, ValueError, OSError):
            return ""

    return {
        "sha256": attrs.get("sha256", ""),
        "md5": attrs.get("md5", ""),
        "size": attrs.get("size"),
        "type": attrs.get("type_description", ""),
        "names": (attrs.get("names") or [])[:5],
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "engines_total": total,
        "detection_ratio": (str(stats.get("malicious", 0)) + "/" + str(total)) if total else "",
        "threat_label": label,
        "families": [f for f in families if f],
        "reputation": attrs.get("reputation"),
        "first_seen": stamp(attrs.get("first_submission_date")),
        "last_analysed": stamp(attrs.get("last_analysis_date")),
        "severity": severity_for(stats),
        "flagged_by": flagged[:25],
        "permalink": "https://www.virustotal.com/gui/file/" + attrs.get("sha256", ""),
    }


class VtClient:
    """VirusTotal hash lookups, plus a capability probe. Never uploads."""

    def __init__(self, api_key: str, cache_dir: str, timeout: float = 25.0):
        self.api_key = (api_key or "").strip()
        self.cache_dir = Path(cache_dir)
        self.timeout = timeout
        # Public tier allows 4 requests/minute; stay just under it.
        self.limiter = RateLimiter(15.5)
        self._lock = threading.Lock()
        self._capabilities: dict | None = None
        self._cap_path = self.cache_dir / "_capabilities.json"
        self._probing = False
        self.lookups = 0
        self.last_error: str | None = None
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def set_api_key(self, api_key: str) -> None:
        """Apply a key without exposing it and invalidate cached capabilities."""
        with self._lock:
            self.api_key = (api_key or "").strip()
            self._capabilities = None
            self.last_error = None

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict:
        return {"x-apikey": self.api_key}

    # --------------------------------------------------------- capabilities
    def capabilities(self, refresh: bool = False, block: bool = False) -> dict:
        """What this key may actually reach.

        On the public tier the probe costs four requests at roughly 15 s apart,
        so it must never run inside a request handler - an earlier version did,
        and /api/intel took 84 seconds on a cold start. The result is cached in
        memory and on disk, and refreshed on a background thread.
        """
        with self._lock:
            if self._capabilities is not None and not refresh:
                return self._capabilities

        if not self.configured:
            result = {
                "configured": False,
                "tier": "none",
                "detail": "No VIRUSTOTAL_API_KEY set; the adapter makes no requests.",
                "allowed": {}, "checked_at": None,
            }
            with self._lock:
                self._capabilities = result
            return result

        if not refresh:
            cached = self._load_cached_capabilities()
            if cached is not None:
                with self._lock:
                    self._capabilities = cached
                return cached

        if block:
            result = self._probe_capabilities()
            with self._lock:
                self._capabilities = result
            self._save_capabilities(result)
            return result

        self._start_probe()
        return {
            "configured": True,
            "tier": "checking",
            "allowed": {},
            "hunting_available": False,
            "retrohunt_available": False,
            "detail": "Probing what this key is permitted to reach (public tier "
                      "allows 4 requests/minute, so this takes about a minute).",
            "rate_limit": "unknown until the probe completes",
            "checked_at": None,
            "tls_bundle": ssl_source(),
        }

    # ------------------------------------------------------- probe machinery
    def _start_probe(self) -> None:
        with self._lock:
            if self._probing:
                return
            self._probing = True

        def run():
            try:
                result = self._probe_capabilities()
                with self._lock:
                    self._capabilities = result
                self._save_capabilities(result)
            except Exception as exc:            # never kill the thread silently
                self.last_error = str(exc)
            finally:
                with self._lock:
                    self._probing = False

        threading.Thread(target=run, name="vt-capability-probe", daemon=True).start()

    def _load_cached_capabilities(self) -> dict | None:
        """Reuse a probe from a previous run; tiers change rarely."""
        if not self._cap_path.exists():
            return None
        try:
            data = json.loads(self._cap_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        stamp = data.get("checked_at")
        if not stamp:
            return None
        try:
            age = (_now() - datetime.fromisoformat(stamp)).total_seconds()
        except (TypeError, ValueError):
            return None
        if age > CAPABILITY_TTL_SECONDS or age < -3600:
            return None
        data["from_cache"] = True
        return data

    def _save_capabilities(self, result: dict) -> None:
        try:
            self._cap_path.write_text(json.dumps(result, indent=1), encoding="utf-8")
        except OSError:
            pass

    def _probe_capabilities(self) -> dict:
        allowed: dict = {}
        for name, path in CAPABILITY_PROBES:
            self.limiter.wait()
            try:
                get_json(BASE_URL + path, headers=self._headers(), timeout=self.timeout)
                allowed[name] = True
            except HttpError as exc:
                # 403 is the definitive "your tier cannot do this" answer.
                allowed[name] = False
                if exc.status not in (403, 401, 429):
                    self.last_error = str(exc)

        enterprise = any(allowed.get(name) for name in ENTERPRISE_ONLY)
        return {
            "configured": True,
            "tier": "enterprise" if enterprise else "public",
            "allowed": allowed,
            "hunting_available": bool(allowed.get("livehunt")),
            "retrohunt_available": bool(allowed.get("retrohunt")),
            "detail": (
                "Enterprise features reachable."
                if enterprise else
                "Public API tier: hash lookups only. Livehunt, Retrohunt, VTDIFF "
                "and Intelligence search require a VT Enterprise account."
            ),
            "rate_limit": "4/min, 500/day (public tier)" if not enterprise else "per contract",
            "checked_at": _now().astimezone().isoformat(timespec="seconds"),
            "tls_bundle": ssl_source(),
        }

    # -------------------------------------------------------------- lookups
    def lookup_hash(self, file_hash: str, use_cache: bool = True) -> dict:
        """Look up one file by hash. Sends only the hash, never the file."""
        file_hash = (file_hash or "").strip().lower()
        if not HASH_RE.match(file_hash):
            return {"error": "not an md5/sha1/sha256 hash", "hash": file_hash}
        if not self.configured:
            return {"error": "no VirusTotal API key configured", "hash": file_hash}

        cached = self.cache_dir / (file_hash + ".json")
        if use_cache and cached.exists():
            try:
                record = json.loads(cached.read_text(encoding="utf-8"))
                record["cached"] = True
                return record
            except (OSError, json.JSONDecodeError):
                pass

        self.limiter.wait()
        try:
            payload = get_json(BASE_URL + "/files/" + file_hash,
                               headers=self._headers(), timeout=self.timeout)
        except HttpError as exc:
            if exc.status == 404:
                return {"hash": file_hash, "known": False,
                        "detail": "VirusTotal has never seen this file."}
            if exc.status == 429:
                return {"hash": file_hash, "error": "rate limited",
                        "detail": "Public tier allows 4 requests/minute and 500/day."}
            self.last_error = str(exc)
            return {"hash": file_hash, "error": str(exc)}

        record = normalise(payload)
        record["known"] = True
        with self._lock:
            self.lookups += 1
            self.last_error = None
        try:
            cached.write_text(json.dumps(record, indent=1), encoding="utf-8")
        except OSError:
            pass
        record["cached"] = False
        return record

    # -------------------------------------------------- hunting (gated)
    def hunting(self, what: str = "livehunt") -> dict:
        """Hunting endpoints, gated behind a real capability check."""
        caps = self.capabilities(block=True)
        if not caps.get("configured"):
            return {"error": "no VirusTotal API key configured", "available": False}
        if not caps.get("allowed", {}).get(what):
            return {
                "available": False,
                "feature": what,
                "tier": caps.get("tier"),
                "error": what + " requires a VirusTotal Enterprise account",
                "detail": (
                    "This key returns HTTP 403 for " + what + ". Livehunt, Retrohunt "
                    "and VTDIFF are Enterprise features; the public API tier cannot "
                    "reach them. See virustotal.com/gui/hunting-overview."
                ),
            }
        path = ("/intelligence/hunting_rulesets?limit=20" if what == "livehunt"
                else "/intelligence/retrohunt_jobs?limit=20")
        self.limiter.wait()
        try:
            return {"available": True, "feature": what,
                    "data": get_json(BASE_URL + path, headers=self._headers(),
                                     timeout=self.timeout)}
        except HttpError as exc:
            return {"available": False, "feature": what, "error": str(exc)}

    # --------------------------------------------------------------- status
    def status(self) -> dict:
        caps = self.capabilities()
        return {
            "source": "virustotal",
            "configured": self.configured,
            "tier": caps.get("tier"),
            "hunting_available": caps.get("hunting_available", False),
            "retrohunt_available": caps.get("retrohunt_available", False),
            "detail": caps.get("detail"),
            "rate_limit": caps.get("rate_limit"),
            "cached_lookups": len(list(self.cache_dir.glob("*.json"))),
            "lookups_this_session": self.lookups,
            "uploads": "never - this client only sends hashes",
            "last_error": self.last_error,
        }
