"""Deterministic vulnerability prioritization for the dashboard model form.

The referenced ML prototype ships simulated scans, hard-coded evaluation
metrics, and opaque pickle artifacts. This module provides the useful product
shape without presenting an unverifiable model score as evidence. It ranks
operator-supplied evidence and returns the factors used for every decision.
"""
from __future__ import annotations

import re


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

TYPE_WEIGHTS = (
    (("ransom", "remote code", "rce"), 30, "code execution or ransomware"),
    (("sql injection", "command injection", "buffer overflow"), 25, "direct execution path"),
    (("ssrf", "xxe", "path traversal"), 22, "server-side boundary bypass"),
    (("authentication", "credential", "idor", "access control"), 20, "identity or access-control impact"),
    (("xss", "cross-site scripting"), 14, "client-side execution"),
    (("csrf", "misconfiguration", "security header"), 9, "configuration weakness"),
)

IMPACT_WEIGHTS = (
    (("remote code execution", "system control"), 25, "system control"),
    (("credential", "account takeover", "privilege escalation"), 20, "identity compromise"),
    (("data loss", "sensitive data", "exfiltration"), 18, "data exposure or loss"),
    (("denial of service", "availability"), 10, "availability impact"),
)

EXPOSURE_WEIGHTS = {
    "local": (0, "local exposure"),
    "lan": (10, "LAN reachable"),
    "internet": (20, "internet exposed"),
}


class RiskRecommender:
    """Explainable baseline used by the dashboard and JSON API."""

    model_id = "soc-risk-baseline-v1"

    @classmethod
    def schema(cls) -> dict:
        return {
            "id": cls.model_id,
            "mode": "deterministic",
            "trained_model": False,
            "external_artifacts_loaded": False,
            "score_meaning": "priority estimate, not vulnerability proof or probability",
            "required": ["vulnerability_type", "impact"],
            "optional": [
                "affected_device", "exposure", "cvss", "known_exploited",
                "auth_failures", "cve", "purl", "sha256",
            ],
        }

    @staticmethod
    def _text(payload: dict, name: str, maximum: int, required: bool = False) -> str:
        value = str(payload.get(name, "") or "").strip()
        if required and not value:
            raise ValueError(name + " is required")
        if len(value) > maximum:
            raise ValueError(name + " exceeds " + str(maximum) + " characters")
        return value

    @staticmethod
    def _number(payload: dict, name: str, default: float,
                minimum: float, maximum: float) -> float:
        raw = payload.get(name, default)
        if raw in (None, ""):
            return default
        try:
            value = float(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(name + " must be numeric") from exc
        if value < minimum or value > maximum:
            raise ValueError(name + " must be between " + str(minimum) + " and " + str(maximum))
        return value

    @staticmethod
    def _boolean(payload: dict, name: str) -> bool:
        value = payload.get(name, False)
        if isinstance(value, bool):
            return value
        if value in (0, 1):
            return bool(value)
        if isinstance(value, str) and value.strip().lower() in ("true", "false"):
            return value.strip().lower() == "true"
        raise ValueError(name + " must be true or false")

    @classmethod
    def _normalise(cls, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("JSON object required")
        vulnerability_type = cls._text(payload, "vulnerability_type", 120, True)
        impact = cls._text(payload, "impact", 1200, True)
        affected_device = cls._text(payload, "affected_device", 120) or "Unknown"
        exposure = cls._text(payload, "exposure", 20).lower() or "local"
        if exposure not in EXPOSURE_WEIGHTS:
            raise ValueError("exposure must be local, lan, or internet")
        cvss = cls._number(payload, "cvss", 0.0, 0.0, 10.0)
        auth_failures = int(cls._number(payload, "auth_failures", 0, 0, 10000))
        cve = cls._text(payload, "cve", 24).upper()
        if cve and not CVE_RE.fullmatch(cve):
            raise ValueError("cve must look like CVE-2024-1234")
        purl = cls._text(payload, "purl", 300)
        if purl and not purl.startswith("pkg:"):
            raise ValueError("purl must start with pkg:")
        sha256 = cls._text(payload, "sha256", 64).lower()
        if sha256 and not SHA256_RE.fullmatch(sha256):
            raise ValueError("sha256 must be 64 hexadecimal characters")
        return {
            "vulnerability_type": vulnerability_type,
            "impact": impact,
            "affected_device": affected_device,
            "exposure": exposure,
            "cvss": cvss,
            "known_exploited": cls._boolean(payload, "known_exploited"),
            "auth_failures": auth_failures,
            "cve": cve,
            "purl": purl,
            "sha256": sha256,
        }

    @staticmethod
    def _recommendations(data: dict, severity: str) -> list[str]:
        combined = (data["vulnerability_type"] + " " + data["impact"]).lower()
        steps = []
        if severity in ("critical", "high"):
            steps.append("Contain the exposed system and preserve evidence before changing it.")
        if any(term in combined for term in ("sql injection", "command injection")):
            steps.append("Use parameterized operations and remove direct command or query construction.")
        if any(term in combined for term in ("xss", "cross-site scripting")):
            steps.append("Apply context-aware output encoding and validate the browser security policy.")
        if any(term in combined for term in ("authentication", "credential", "access control", "idor")):
            steps.append("Revoke exposed sessions, rotate affected credentials, and enforce MFA.")
        if data["exposure"] == "internet":
            steps.append("Restrict the service at the firewall or reverse proxy until the fix is verified.")
        if data["cve"]:
            steps.append("Confirm the affected version and follow vendor plus CISA remediation guidance.")
        if data["sha256"]:
            steps.append("Compare hash reputation with local YARA evidence; quarantine before deletion.")
        if not steps:
            steps.append("Validate the report with a real scanner and collect reproducible evidence.")
        steps.append("Rescan after remediation and close the finding only when the evidence is clean.")
        return steps[:6]

    @classmethod
    def assess(cls, payload: dict) -> dict:
        data = cls._normalise(payload)
        combined = (data["vulnerability_type"] + " " + data["impact"]).lower()
        score = data["cvss"] * 8 if data["cvss"] else 24.0
        factors = []
        if data["cvss"]:
            factors.append("CVSS " + ("%.1f" % data["cvss"]))

        for terms, weight, label in TYPE_WEIGHTS:
            if any(term in combined for term in terms):
                score += weight
                factors.append(label)
                break
        for terms, weight, label in IMPACT_WEIGHTS:
            if any(term in combined for term in terms):
                score += weight
                factors.append(label)
                break

        exposure_weight, exposure_label = EXPOSURE_WEIGHTS[data["exposure"]]
        score += exposure_weight
        factors.append(exposure_label)
        if data["known_exploited"]:
            score += 15
            factors.append("known exploited")
        if data["auth_failures"]:
            score += min(10, 2 + data["auth_failures"] / 10)
            factors.append("correlated authentication failures")

        score = round(max(0, min(100, score)))
        severity = ("critical" if score >= 85 else "high" if score >= 65
                    else "medium" if score >= 40 else "low")
        exploitability = round(min(1.0, score / 100 +
                                   (0.05 if data["exposure"] == "internet" else 0.0)), 2)
        evidence_fields = sum(bool(data[key]) for key in
                              ("cvss", "cve", "purl", "sha256", "auth_failures"))
        evidence_quality = "high" if evidence_fields >= 3 else "medium" if evidence_fields else "low"

        return {
            "status": "success",
            "model": cls.schema(),
            "input": data,
            "assessment": {
                "risk_score": score,
                "severity": severity,
                "affected_device": data["affected_device"],
                "exploitability_estimate": exploitability,
                "evidence_quality": evidence_quality,
                "factors": factors,
                "recommendations": cls._recommendations(data, severity),
            },
        }
