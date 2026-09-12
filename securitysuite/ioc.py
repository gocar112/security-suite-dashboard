"""Observable extraction — pulls IOCs out of files that tripped a rule.

A YARA match tells you *this file is bad*. It does not tell you what to hunt
for next. The strings that matched are the detection's own evidence; the
indicators an analyst actually pivots on — the C2 address, the exfil domain,
the wallet the ransom demands payment to — are usually sitting in the same
bytes, unmatched and unreported.

This module extracts those observables so a detection becomes a starting point
for hunting rather than a dead end.

Two deliberate choices:

* **Everything is defanged on output.** ``http://evil.test/x`` is returned as
  ``hxxp://evil[.]test/x``. Analysts paste these into tickets, chat, and
  spreadsheets that auto-link URLs; a live link in an alert is how somebody
  ends up clicking the C2. Defanged values are for display, and the original
  is kept alongside for machine use.

* **Noise is filtered aggressively, and the filtering is visible.** Private
  addresses, documentation ranges, and schema hosts are separated out rather
  than silently dropped, because "this file talks to 10.0.0.5" is sometimes
  exactly the finding.
"""
from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict

MAX_PER_TYPE = 40          # cap per indicator type, per file
CONTEXT_CHARS = 34         # snippet either side of a hit

# --------------------------------------------------------------- patterns
PATTERNS = {
    "url": re.compile(
        rb"\b(?:h(?:tt|xx)ps?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,240}",
        re.IGNORECASE),
    "ipv4": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(
        rb"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,18}\b"),
    "onion": re.compile(rb"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b", re.IGNORECASE),
    "domain": re.compile(
        rb"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
        rb"(?:com|net|org|info|biz|ru|cn|top|xyz|io|co|me|cc|su|tk|pw|"
        rb"click|link|live|online|site|shop|store|app|dev|gg|to|ws|cyou|monster)\b",
        re.IGNORECASE),
    "btc": re.compile(rb"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b"),
    "eth": re.compile(rb"\b0x[a-fA-F0-9]{40}\b"),
    "xmr": re.compile(rb"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "registry": re.compile(
        rb"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[A-Za-z0-9\\_\-. ]{3,140}"),
    "filepath": re.compile(rb"\b[A-Za-z]:\\\\?[A-Za-z0-9\\_\-. ()]{4,140}"),
    "cve": re.compile(rb"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "sha256": re.compile(rb"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(rb"\b[a-fA-F0-9]{32}\b"),
}

# Hosts that appear in almost every document and mean nothing on their own.
DOMAIN_DENYLIST = {
    "w3.org", "www.w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
    "example.com", "example.org", "example.net", "localhost", "microsoft.com",
    "purl.org", "adobe.com", "ns.adobe.com", "iptc.org", "openoffice.org",
    "sun.com", "xml.org", "apache.org", "python.org", "github.com",
    "githubusercontent.com", "googleapis.com", "gstatic.com", "jquery.com",
    "cloudflare.com", "cdnjs.cloudflare.com", "mozilla.org", "gnu.org",
    "nist.gov", "virustotal.com", "osv.dev", "cisa.gov", "mitre.org",
}

# File extensions that are not domains, however much they look like one.
NOT_DOMAIN_SUFFIX = (
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".zip", ".rar", ".7z", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".png",
    ".jpg", ".gif", ".svg", ".css", ".html", ".htm", ".php", ".asp", ".aspx",
    ".py", ".sh", ".txt", ".log", ".json", ".xml", ".yar", ".md", ".ini",
)


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def defang(value: str, kind: str) -> str:
    """Render an indicator unclickable for display."""
    if kind in ("url", "domain", "onion", "email", "ipv4"):
        value = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
        value = value.replace("ftp://", "fxp://")
        value = value.replace("@", "[at]") if kind == "email" else value
        # Only defang the host portion's dots, but for simplicity and safety
        # every dot is bracketed - it is unambiguous and never clickable.
        value = value.replace(".", "[.]")
    return value


def _classify_ip(value: str) -> str | None:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return "reserved"
    if addr.is_private:
        return "private"
    return "external"


def _host_of(url: str) -> str:
    """Best-effort host from a URL, without importing a parser for bytes."""
    stripped = re.sub(r"^[a-zA-Z]+://", "", url)
    stripped = stripped.split("/")[0].split("?")[0].split("#")[0]
    stripped = stripped.rsplit("@", 1)[-1]        # drop user:pass@
    return stripped.split(":")[0].strip().lower()  # drop :port


def _plausible_domain(value: str) -> bool:
    lowered = value.lower().rstrip(".")
    if lowered in DOMAIN_DENYLIST:
        return False
    if any(lowered.endswith(suffix) for suffix in NOT_DOMAIN_SUFFIX):
        return False
    # Strip one leading label and re-check, so cdn.example.com is filtered by
    # the example.com entry rather than needing its own.
    parts = lowered.split(".")
    for i in range(1, len(parts) - 1):
        if ".".join(parts[i:]) in DOMAIN_DENYLIST:
            return False
    return len(lowered) <= 253


def extract(raw: bytes, want_context: bool = True) -> dict:
    """Extract observables from a byte buffer.

    Returns {counts, indicators:[{type, value, defanged, count, offset,
    context, scope}], filtered:{...}} - never raises on binary input.
    """
    found: "OrderedDict[tuple, dict]" = OrderedDict()
    dropped = {"known_benign_domain": 0, "known_benign_url": 0}
    tagged = {"private": 0, "loopback": 0, "reserved": 0, "external": 0}

    for kind, pattern in PATTERNS.items():
        seen_this_kind = 0
        for match in pattern.finditer(raw):
            if seen_this_kind >= MAX_PER_TYPE:
                break
            value = _text(match.group(0)).strip()
            if not value:
                continue
            scope = ""

            if kind == "ipv4":
                scope = _classify_ip(value) or ""
                if not scope:
                    continue
                tagged[scope] = tagged.get(scope, 0) + 1
            elif kind == "domain":
                if not _plausible_domain(value):
                    dropped["known_benign_domain"] += 1
                    continue
            elif kind == "url":
                # The same denylist has to apply to the host inside a URL,
                # or every XML namespace declaration becomes an indicator.
                host = _host_of(value)
                if host and not _plausible_domain(host) and not host.endswith(".onion"):
                    dropped["known_benign_url"] += 1
                    continue
            elif kind == "cve":
                value = value.upper()
            elif kind in ("md5", "sha256"):
                # A 64-hex run inside a 32-hex pattern double-counts; keep the
                # longer form only.
                if kind == "md5" and len(value) != 32:
                    continue

            key = (kind, value.lower())
            if key in found:
                found[key]["count"] += 1
                continue

            entry = {
                "type": kind,
                "value": value,
                "defanged": defang(value, kind),
                "count": 1,
                "offset": match.start(),
                "scope": scope,
            }
            if want_context:
                start = max(0, match.start() - CONTEXT_CHARS)
                end = min(len(raw), match.end() + CONTEXT_CHARS)
                snippet = _text(raw[start:end])
                entry["context"] = "".join(
                    ch if 32 <= ord(ch) < 127 else "." for ch in snippet)
            found[key] = entry
            seen_this_kind += 1

    indicators = list(found.values())
    # Most interesting types first, then by how often they appear.
    priority = {"url": 0, "onion": 1, "domain": 2, "ipv4": 3, "btc": 4, "xmr": 5,
                "eth": 6, "email": 7, "cve": 8, "registry": 9, "sha256": 10,
                "md5": 11, "filepath": 12}
    indicators.sort(key=lambda i: (priority.get(i["type"], 99), -i["count"]))

    counts: dict = {}
    for item in indicators:
        counts[item["type"]] = counts.get(item["type"], 0) + 1

    return {
        "indicators": indicators,
        "counts": counts,
        "total": len(indicators),
        # "dropped" really means removed; IP scopes are kept and labelled.
        "dropped": {k: v for k, v in dropped.items() if v},
        "ip_scopes": {k: v for k, v in tagged.items() if v},
    }


def summarise(events: list) -> dict:
    """Aggregate indicators across many findings for the dashboard panel."""
    agg: "OrderedDict[tuple, dict]" = OrderedDict()
    for event in events:
        block = event.get("iocs") or {}
        for item in block.get("indicators", []):
            key = (item["type"], item["value"].lower())
            record = agg.get(key)
            if record is None:
                record = {
                    "type": item["type"],
                    "value": item["value"],
                    "defanged": item["defanged"],
                    "scope": item.get("scope", ""),
                    "occurrences": 0,
                    "files": [],
                    "first_seen": event.get("timestamp"),
                    "last_seen": event.get("timestamp"),
                }
                agg[key] = record
            record["occurrences"] += item.get("count", 1)
            name = event.get("file_name") or event.get("file_path", "")
            if name and name not in record["files"]:
                record["files"].append(name)
            stamp = event.get("timestamp")
            if stamp:
                if not record["first_seen"] or stamp < record["first_seen"]:
                    record["first_seen"] = stamp
                if not record["last_seen"] or stamp > record["last_seen"]:
                    record["last_seen"] = stamp

    items = list(agg.values())
    for item in items:
        item["file_count"] = len(item["files"])
        item["files"] = item["files"][:8]
    # Indicators seen across several files matter more than one-offs.
    items.sort(key=lambda i: (-i["file_count"], -i["occurrences"], i["type"]))

    by_type: dict = {}
    for item in items:
        by_type[item["type"]] = by_type.get(item["type"], 0) + 1
    return {"indicators": items, "by_type": by_type, "total": len(items)}


def to_csv(items: list) -> str:
    """Flat CSV for handing to a SIEM or a spreadsheet."""
    rows = ["type,value,defanged,scope,occurrences,file_count,first_seen,last_seen"]
    for item in items:
        def cell(value):
            text = str(value if value is not None else "")
            return '"' + text.replace('"', '""') + '"' if "," in text or '"' in text else text
        rows.append(",".join(cell(item.get(k)) for k in (
            "type", "value", "defanged", "scope", "occurrences",
            "file_count", "first_seen", "last_seen")))
    return "\n".join(rows) + "\n"
