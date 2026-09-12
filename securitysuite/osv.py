"""OSV.dev adapter — vulnerability lookup by commit, package, or purl.

    https://api.osv.dev/v1/query

OSV answers a different question from NVD. NVD is a catalog you browse by CVE
id or keyword; OSV is an index you query with something you actually have — a
source commit, a package name and version, or a package URL — and it tells you
which vulnerabilities affect exactly that thing.

That makes it the natural companion to a file detector: when a scan turns up a
dependency manifest, a vendored library, or a checked-out commit, OSV converts
that artifact into a vulnerability answer without you first knowing a CVE id.

No credential is required.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from .net import HttpError, RateLimiter, post_json, ssl_source

QUERY_URL = "https://api.osv.dev/v1/query"
BATCH_URL = "https://api.osv.dev/v1/querybatch"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

# OSV severity lives in several places depending on the source database.
SEVERITY_WORDS = ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW")
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def normalise(vuln: dict) -> dict:
    """Flatten one OSV record into the shape the dashboard consumes."""
    severity = ""
    vector = ""

    # OSV severity lives in different places depending on the source database.
    # 1. database_specific.severity - GitHub advisories populate this.
    db_specific = vuln.get("database_specific") or {}
    if isinstance(db_specific, dict):
        severity = str(db_specific.get("severity") or "").upper()

    # 2. severity[] carries CVSS vector strings. Keep the vector verbatim
    #    rather than pretending to compute a base score from it: scoring a
    #    vector properly is a real calculation, and a wrong number here would
    #    be worse than no number.
    for item in vuln.get("severity") or []:
        candidate = str(item.get("score") or "")
        if candidate.startswith("CVSS:"):
            vector = candidate
            break

    # 3. affected[].ecosystem_specific.severity
    if not severity:
        for affected in vuln.get("affected") or []:
            eco = affected.get("ecosystem_specific") or {}
            candidate = str(eco.get("severity") or "").upper()
            if candidate in SEVERITY_WORDS:
                severity = candidate
                break

    packages = []
    for affected in (vuln.get("affected") or [])[:6]:
        package = affected.get("package") or {}
        name = package.get("name", "")
        if name:
            packages.append({
                "name": name,
                "ecosystem": package.get("ecosystem", ""),
                "purl": package.get("purl", ""),
            })

    mapped = SEVERITY_MAP.get(severity, "info" if not vector else "medium")
    return {
        "id": vuln.get("id", ""),
        "aliases": (vuln.get("aliases") or [])[:6],
        "summary": (vuln.get("summary") or "").strip()[:300],
        "details": (vuln.get("details") or "").strip()[:600],
        "published": vuln.get("published", ""),
        "modified": vuln.get("modified", ""),
        "withdrawn": vuln.get("withdrawn", ""),
        "osv_severity": severity,
        "vector": vector,
        "severity": mapped,
        "packages": packages,
        "affected_count": len(vuln.get("affected") or []),
        "references": len(vuln.get("references") or []),
    }


class OsvClient:
    """Queries OSV.dev and caches answers keyed by the query itself."""

    def __init__(self, cache_dir: str, timeout: float = 25.0):
        self.cache_dir = Path(cache_dir)
        self.timeout = timeout
        self.limiter = RateLimiter(0.25)      # OSV is generous; stay polite
        self._lock = threading.Lock()
        self.queries = 0
        self.last_query: str | None = None
        self.last_error: str | None = None
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- cache
    def _cache_path(self, payload: dict) -> Path:
        key = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()[:24]
        return self.cache_dir / (key + ".json")

    def _query(self, payload: dict, use_cache: bool = True) -> dict:
        cached = self._cache_path(payload)
        if use_cache and cached.exists():
            try:
                result = json.loads(cached.read_text(encoding="utf-8"))
                result["cached"] = True
                return result
            except (OSError, json.JSONDecodeError):
                pass

        self.limiter.wait()
        try:
            raw = post_json(QUERY_URL, payload, timeout=self.timeout)
        except HttpError as exc:
            self.last_error = str(exc)
            return {"error": str(exc), "query": payload, "vulns": []}

        with self._lock:
            self.queries += 1
            self.last_query = _now().astimezone().isoformat(timespec="seconds")
            self.last_error = None

        vulns = [normalise(v) for v in (raw.get("vulns") or [])]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulns.sort(key=lambda v: order.get(v.get("severity"), 9))
        result = {
            "query": payload,
            "count": len(vulns),
            "vulns": vulns,
            "fetched_at": self.last_query,
        }
        try:
            cached.write_text(json.dumps(result, indent=1), encoding="utf-8")
        except OSError:
            pass
        result["cached"] = False
        return result

    # -------------------------------------------------------------- queries
    def query_commit(self, commit: str, use_cache: bool = True) -> dict:
        commit = commit.strip().lower()
        if not COMMIT_RE.match(commit):
            return {"error": "not a 40-character git commit hash", "vulns": []}
        return self._query({"commit": commit}, use_cache)

    def query_package(self, name: str, ecosystem: str = "",
                      version: str = "", use_cache: bool = True) -> dict:
        package: dict = {"name": name.strip()}
        if ecosystem:
            package["ecosystem"] = ecosystem.strip()
        payload: dict = {"package": package}
        if version:
            payload["version"] = version.strip()
        return self._query(payload, use_cache)

    def query_purl(self, purl: str, use_cache: bool = True) -> dict:
        return self._query({"package": {"purl": purl.strip()}}, use_cache)

    def query(self, body: dict) -> dict:
        """Dispatch on whichever identifier the caller supplied."""
        if body.get("commit"):
            return self.query_commit(str(body["commit"]))
        if body.get("purl"):
            return self.query_purl(str(body["purl"]))
        if body.get("package"):
            return self.query_package(
                str(body.get("package", "")),
                str(body.get("ecosystem", "")),
                str(body.get("version", "")),
            )
        return {"error": "supply one of: commit, purl, or package", "vulns": []}

    # --------------------------------------------------------------- status
    def status(self) -> dict:
        return {
            "source": "osv",
            "query_url": QUERY_URL,
            "cache_dir": str(self.cache_dir),
            "cached_queries": len(list(self.cache_dir.glob("*.json"))),
            "queries_this_session": self.queries,
            "last_query": self.last_query,
            "last_error": self.last_error,
            "tls_bundle": ssl_source(),
            "credential": False,
        }
