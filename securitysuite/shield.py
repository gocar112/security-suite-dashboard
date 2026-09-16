"""Defensive AV/IDS/IPS posture model for the dashboard.

This module is intentionally local and read-only. It does not attempt to drive
third-party products without their credentials; instead it shows what is active
inside Security Suite, where commercial controls such as Bitdefender GravityZone
would plug in, and which defensive playbooks cover common attack pressure.
"""
from __future__ import annotations

import os
import platform
from pathlib import Path

ATTACK_GOALS = (
    "credential theft", "ransomware deployment", "data theft",
    "persistence", "command and control", "defense evasion",
    "initial access", "privilege escalation", "lateral movement",
    "web shell access", "supply-chain abuse", "cloud token theft",
    "cryptomining", "phishing delivery", "living-off-the-land execution",
    "remote management abuse", "browser session theft", "payload staging",
    "vulnerable service exploitation", "insider misuse",
)

ENTRY_POINTS = (
    "email attachment", "downloaded executable", "PowerShell script",
    "Python script", "Office macro", "archive file", "web upload",
    "SSH account", "RDP account", "browser extension", "npm package",
    "pip package", "container image", "USB media", "scheduled task",
    "startup folder", "Windows service", "cron entry", "registry run key",
    "public-facing application", "VPN appliance", "router firmware",
    "database credential", "cloud access key", "shared folder",
)

CONTROL_MAP = (
    {
        "name": "Local antivirus sensor",
        "kind": "AV",
        "status": "active",
        "coverage": "YARA file scanning, entropy, hash identity, IOC extraction",
        "patch": "Keep rules current; quarantine before delete; reload after rule changes.",
    },
    {
        "name": "Remediation rails",
        "kind": "AV",
        "status": "active",
        "coverage": "SHA-256 recheck, path confinement, suite self-protection, audit log",
        "patch": "Use preview first; keep auto-remediation off until rules are tuned.",
    },
    {
        "name": "IDS stream",
        "kind": "IDS",
        "status": "active",
        "coverage": "Findings feed, auth telemetry correlation, live alerts, IOC pivots",
        "patch": "Investigate critical/high alerts first and export IOCs to your SIEM.",
    },
    {
        "name": "IPS decision layer",
        "kind": "IPS",
        "status": "guarded",
        "coverage": "Manual quarantine/delete/purge actions after preview and confirm",
        "patch": "Block by quarantine first; delete only after evidence review.",
    },
    {
        "name": "Bitdefender GravityZone",
        "kind": "AV/EDR",
        "status": "connector-ready",
        "coverage": "Policy, reports, quarantine, sandbox and network APIs can be bridged",
        "patch": "Set BITDEFENDER_API_KEY and BITDEFENDER_API_URL when adding a live connector.",
        "url": "https://www.bitdefender.com/business/support/en/77212-125277-public-api.html",
    },
    {
        "name": "NVD + CISA KEV",
        "kind": "Patch",
        "status": "active",
        "coverage": "CVE lookup, known-exploited prioritization, vendor patch references",
        "patch": "Patch KEV/critical CVEs first; use NVD URLs from IOC and guidance panels.",
        "url": "https://nvd.nist.gov/",
    },
)

PATCH_PLAYBOOKS = (
    {
        "name": "Ransomware",
        "patterns": ("ransom note", "wallet", "onion portal", "mass rename"),
        "actions": ("isolate host", "quarantine payload", "preserve evidence",
                    "rotate credentials", "restore from known-good backup"),
    },
    {
        "name": "Credential theft",
        "patterns": ("dump tool strings", "browser token paths", "LSASS access"),
        "actions": ("quarantine tool", "reset affected secrets",
                    "review logons", "enable MFA", "patch exposed services"),
    },
    {
        "name": "Web shell",
        "patterns": ("script upload", "eval/exec", "suspicious request parameter"),
        "actions": ("remove shell", "patch application", "rotate app secrets",
                    "review access logs", "block upload vector"),
    },
    {
        "name": "Supply chain",
        "patterns": ("package manifest", "install script", "obfuscated loader"),
        "actions": ("pin dependency", "upgrade package", "review lockfile",
                    "rebuild from clean source", "scan artifacts"),
    },
    {
        "name": "Vulnerable component",
        "patterns": ("CVE indicator", "product/version marker", "KEV match"),
        "actions": ("open NVD advisory", "apply vendor patch",
                    "use temporary mitigation", "rescan", "document exception"),
    },
)


def _status_from_env(key: str, url_key: str = "") -> dict:
    configured = bool(os.getenv(key, "").strip())
    if url_key:
        configured = configured and bool(os.getenv(url_key, "").strip())
    return {
        "configured": configured,
        "status": "configured" if configured else "not configured",
    }


def _attack_pressure(limit: int = 500) -> list[dict]:
    reasons: list[dict] = []
    for goal in ATTACK_GOALS:
        for entry in ENTRY_POINTS:
            if len(reasons) >= limit:
                return reasons
            severity = "critical" if goal in (
                "ransomware deployment", "credential theft", "data theft",
                "privilege escalation") else "high"
            reasons.append({
                "id": "AP-%03d" % (len(reasons) + 1),
                "goal": goal,
                "entry": entry,
                "severity": severity,
                "defense": _defense_for(goal, entry),
            })
    return reasons


def _defense_for(goal: str, entry: str) -> str:
    if "vulnerable" in goal or "firmware" in entry or "application" in entry:
        return "Patch from NVD/vendor guidance, then rescan the affected path."
    if "credential" in goal or "account" in entry or "key" in entry:
        return "Reset secrets, review auth telemetry, and quarantine detected tooling."
    if "ransomware" in goal:
        return "Isolate, quarantine, preserve evidence, and restore from clean backup."
    if "supply" in goal or "package" in entry:
        return "Pin or upgrade dependency, review install scripts, and rebuild artifacts."
    return "Alert, triage, quarantine suspicious files, and document the decision."


def posture(cfg, engine, store, remediator=None) -> dict:
    stats = store.stats()
    rule_count = int((engine.info() or {}).get("rule_count") or 0)
    open_alerts = int(stats.get("open_alerts") or 0)
    critical = int((stats.get("by_severity") or {}).get("critical") or 0)
    high = int((stats.get("by_severity") or {}).get("high") or 0)
    score = max(0, min(100, 100 - (critical * 12) - (high * 5) - open_alerts))
    reasons = _attack_pressure(500)
    bitdefender = _status_from_env("BITDEFENDER_API_KEY", "BITDEFENDER_API_URL")
    return {
        "platform": platform.system() or os.name,
        "score": score,
        "score_is_heuristic": True,
        "rules": rule_count,
        "attack_reasons": len(reasons),
        "attack_reasons_sample": reasons[:18],
        "layers": CONTROL_MAP,
        "patch_playbooks": PATCH_PLAYBOOKS,
        "integrations": {
            "bitdefender": bitdefender,
            "nvd": {"configured": bool(getattr(cfg, "nvd_api_key", "")),
                    "status": "configured" if getattr(cfg, "nvd_api_key", "") else "public rate"},
            "virustotal": {"configured": bool(getattr(cfg, "virustotal_api_key", ""))},
        },
        "file_groups": {
            "scripts": [".ps1", ".py", ".js", ".vbs", ".sh", ".bat", ".cmd"],
            "executables": [".exe", ".dll", ".scr", ".msi", ".elf", ".dylib"],
            "documents": [".doc", ".docm", ".xls", ".xlsm", ".pdf", ".rtf"],
            "archives": [".zip", ".rar", ".7z", ".iso", ".img", ".tar", ".gz"],
        },
        "remediation": remediator.status() if remediator is not None else {},
        "sources": [
            {"name": "Bitdefender GravityZone API",
             "url": "https://www.bitdefender.com/business/support/en/77212-125277-public-api.html"},
            {"name": "NVD",
             "url": "https://nvd.nist.gov/"},
            {"name": "CISA Known Exploited Vulnerabilities",
             "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
        ],
    }


def startup_targets() -> dict:
    root = Path(__file__).resolve().parent.parent
    return {
        "windows": "Startup shortcut uses pythonw.exe when available to hide the console.",
        "linux": "Desktop entry uses Terminal=false.",
        "macos": "App bundle launcher runs without a terminal window.",
        "root": str(root),
    }
