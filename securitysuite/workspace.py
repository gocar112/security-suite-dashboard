"""Local workbench tools. Imported evidence is never an executable command."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import re
import subprocess
import threading
from pathlib import Path

from .store import now_iso


class Workspace:
    def __init__(self, cfg, engine, store):
        self.cfg, self.engine, self.store = cfg, engine, store
        self._lock = threading.RLock()
        self.policy_path = Path(cfg.triage_file).parent / "response-policy.json"
        self.domains_path = self.policy_path.with_name("blocked-domains.json")
        self.native_av = {"status": "not checked", "products": [], "checked_at": None}
        self._imported = set()
        try:
            saved = json.loads(self.policy_path.read_text(encoding="utf-8"))
            if type(saved.get("enabled")) is bool:
                cfg.auto_remediate = saved["enabled"]
                cfg.auto_remediate_action = "quarantine"
        except (OSError, ValueError, AttributeError):
            pass

    def policy(self):
        return {"enabled": bool(self.cfg.auto_remediate), "action": "quarantine",
                "severity": self.cfg.auto_remediate_severity,
                "requires_rule_opt_in": True,
                "roots": list(self.cfg.remediation_roots or self.cfg.watch_paths)}

    def set_policy(self, payload):
        if type(payload.get("enabled")) is not bool:
            raise ValueError("enabled must be true or false")
        with self._lock:
            self._save(self.policy_path, {"enabled": payload["enabled"]})
            self.cfg.auto_remediate_action = "quarantine"
            self.cfg.auto_remediate = payload["enabled"]
            self.store.add({"event_type": "policy", "message": "Automatic quarantine " +
                            ("enabled" if payload["enabled"] else "disabled")})
            return self.policy()

    @staticmethod
    def _save(path, payload):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, path)

    def analyze(self, payload):
        content = payload.get("text")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Paste text to analyze")
        data = content.encode("utf-8")
        if len(data) > 48000:
            raise ValueError("Text analysis accepts at most 48 KB")
        result = self.engine.scan_bytes(data, "<text-analysis>")
        result.update({"executed": False, "persisted": False,
                       "sha256": hashlib.sha256(data).hexdigest(),
                       "verdict": "rule match" if result["matches"] else "no rule match"})
        return result

    def import_eve(self, payload):
        """Import Suricata EVE alert records, without trusting their file paths.

        Format: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
        """
        content = payload.get("text")
        if not isinstance(content, str) or len(content.encode("utf-8")) > 48000:
            raise ValueError("EVE import accepts up to 48 KB of NDJSON")
        lines = [line for line in content.splitlines() if line.strip()]
        if len(lines) > 100 or not lines:
            raise ValueError("Import between 1 and 100 EVE records")
        records, skipped = [], 0
        for line in lines:
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise ValueError("Each EVE record must be an object")
            if raw.get("event_type") != "alert":
                skipped += 1
                continue
            alert = raw.get("alert")
            if not isinstance(alert, dict) or not isinstance(alert.get("signature"), str):
                raise ValueError("An alert needs a signature")
            for key in ("src_ip", "dest_ip"):
                if not isinstance(raw.get(key), str):
                    raise ValueError(key + " must be an IP address")
                ipaddress.ip_address(raw[key])
            severity = alert.get("severity", 3)
            if type(severity) is not int or severity not in (1, 2, 3, 4):
                raise ValueError("EVE severity must be 1, 2, 3 or 4")
            fingerprint = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()
            records.append((fingerprint, {
                "event_type": "ids_alert", "source": "suricata-import",
                "severity": {1: "high", 2: "medium", 3: "low", 4: "info"}[severity],
                "message": alert["signature"][:500], "src_ip": raw["src_ip"],
                "dest_ip": raw["dest_ip"], "network_action": str(alert.get("action", "unknown"))[:40],
                "observed_at": str(raw.get("timestamp", ""))[:80],
            }))
        added, duplicate = 0, 0
        with self._lock:
            for fingerprint, event in records:
                if fingerprint in self._imported:
                    duplicate += 1
                    continue
                if len(self._imported) >= 10000:
                    self._imported.clear()
                self._imported.add(fingerprint)
                self.store.add(event)
                added += 1
        return {"imported": added, "duplicates": duplicate, "skipped": skipped}

    def domains(self):
        try:
            value = json.loads(self.domains_path.read_text(encoding="utf-8"))
            return value if isinstance(value, list) else []
        except (OSError, ValueError):
            return []

    def save_domains(self, payload):
        text = payload.get("text")
        if not isinstance(text, str):
            raise ValueError("text must contain one domain per line")
        domains = set()
        for line in text.splitlines():
            domain = line.strip().lower().rstrip(".")
            if not domain or domain.startswith("#"):
                continue
            if (len(domain) > 253 or "." not in domain or
                    not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                            for label in domain.split("."))):
                raise ValueError("Use domain names only, one per line")
            try:
                ipaddress.ip_address(domain)
            except ValueError:
                pass
            else:
                raise ValueError("IP addresses do not belong in the domain list")
            if domain.endswith((".local", ".localhost", ".internal")):
                raise ValueError("Local network names cannot be blocked here")
            domains.add(domain)
        if len(domains) > 1000:
            raise ValueError("Limit the reviewed list to 1,000 domains")
        with self._lock:
            self._save(self.domains_path, sorted(domains))
        return {"domains": sorted(domains), "enforced": False}

    def check_native_av(self):
        if platform.system() != "Windows":
            self.native_av = {"status": "manual verification required", "products": [],
                              "checked_at": now_iso(), "detail": "Check your installed endpoint protection console."}
            return self.native_av
        command = ("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
                   "-ErrorAction Stop | Select-Object displayName,productState | ConvertTo-Json -Compress")
        try:
            completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                                       capture_output=True, text=True, timeout=12, check=True,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            raw = json.loads(completed.stdout or "[]")
            products = raw if isinstance(raw, list) else [raw]
            self.native_av = {"status": "registered products" if products else "none reported",
                              "products": [{"name": str(p.get("displayName", "Unknown")),
                                            "state": p.get("productState")} for p in products],
                              "checked_at": now_iso(),
                              "detail": "Registration does not verify current protection or signature freshness."}
        except (OSError, ValueError, subprocess.SubprocessError):
            self.native_av = {"status": "unavailable", "products": [], "checked_at": now_iso(),
                              "detail": "Windows Security Center did not return product information."}
        return self.native_av
