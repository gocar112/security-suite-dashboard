"""Generate YARA rules from NVD CPE data, then throw most of them away.

The temptation with a CVE feed is to turn every record into a rule and quote
the total. That produces a ruleset nobody reviews, whose false positives bury
the detections that matter - the alert-fatigue failure in its purest form.

So this module generates *candidates* from structured data and then gates them
hard. A candidate only ships if:

  * it came from a CPE application entry with a concrete vendor and product,
  * the product name is distinctive enough to mean something on its own,
  * at least one specific affected version is known,
  * and it fires on none of a benign corpus.

The gate is the product. Expect most candidates to be rejected, and read the
rejection tally as the useful output - it tells you how much of a CVE feed is
simply not expressible as a file-matching rule.

What these rules detect is *exposure*, not compromise: a vulnerable component
present in a scanned artifact. That distinction drives the severity mapping -
finding a vulnerable library is not the same as finding a web shell, and
labelling it critical would wreck the scale everything else depends on.
"""
from __future__ import annotations

import re
from collections import defaultdict

import yara

from .nvd import NvdClient

# A product name shorter or more generic than this matches half the internet.
MIN_PRODUCT_LEN = 5
GENERIC_PRODUCTS = {
    "core", "server", "client", "http", "https", "web", "app", "api", "node",
    "java", "python", "linux", "windows", "macos", "android", "system", "data",
    "file", "files", "code", "test", "tests", "admin", "login", "user", "users",
    "portal", "cloud", "mobile", "desktop", "plugin", "module", "library",
    "framework", "engine", "service", "manager", "master", "agent", "common",
    "utils", "tools", "kernel", "driver", "network", "security", "database",
    "browser", "editor", "player", "reader", "viewer", "studio", "office",
    "project", "platform", "console", "gateway", "monitor", "backup", "update",
}
VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}(?:[-_.][A-Za-z0-9]{1,8})?$")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_]")


def _cpe_parts(criteria: str) -> tuple | None:
    """cpe:2.3:a:vendor:product:version:... -> (vendor, product, version)."""
    bits = criteria.split(":")
    if len(bits) < 6 or bits[0] != "cpe" or bits[1] != "2.3":
        return None
    part, vendor, product, version = bits[2], bits[3], bits[4], bits[5]
    if part != "a":                       # applications only, not OS or hardware
        return None
    if not vendor or not product or vendor == "*" or product == "*":
        return None
    return vendor, product, version


def _walk_matches(cve: dict):
    """Yield every cpeMatch in a CVE's nested configuration tree."""
    def walk(nodes):
        for node in nodes or []:
            for match in node.get("cpeMatch", []) or []:
                if match.get("vulnerable"):
                    yield match
            yield from walk(node.get("children"))
    for config in cve.get("configurations", []) or []:
        yield from walk(config.get("nodes"))


def _cvss(cve: dict) -> tuple:
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if items:
            data = items[0].get("cvssData", {}) or {}
            return data.get("baseScore"), (data.get("baseSeverity")
                                           or items[0].get("baseSeverity") or "")
    return None, ""


def severity_for(score, kev: bool) -> str:
    """Exposure, not compromise - see the module docstring.

    A vulnerable component that is *known to be exploited in the wild* earns
    high. Everything else is a review item, never an interrupt.
    """
    if kev:
        return "high"
    if score is not None and score >= 9.0:
        return "medium"
    return "low"


def candidates_from_cve(cve: dict, max_versions: int = 12) -> list:
    """Turn one CVE into zero or more rule candidates, one per product."""
    cve_id = cve.get("id", "")
    if not cve_id:
        return []
    score, cvss_severity = _cvss(cve)
    kev = bool(cve.get("cisaExploitAdd"))

    by_product = defaultdict(set)
    for match in _walk_matches(cve):
        parts = _cpe_parts(str(match.get("criteria") or ""))
        if not parts:
            continue
        vendor, product, version = parts
        if VERSION_RE.match(version):
            by_product[(vendor, product)].add(version)
        else:
            # A wildcard version with a bounded range still names the boundary,
            # which is a concrete string an artifact may carry.
            for bound in ("versionEndExcluding", "versionEndIncluding",
                          "versionStartIncluding", "versionStartExcluding"):
                value = str(match.get(bound) or "")
                if VERSION_RE.match(value):
                    by_product[(vendor, product)].add(value)

    description = ""
    for item in cve.get("descriptions", []) or []:
        if item.get("lang") == "en":
            description = item.get("value", "")
            break

    out = []
    for (vendor, product), versions in by_product.items():
        if not versions:
            continue
        out.append({
            "cve": cve_id,
            "vendor": vendor,
            "product": product,
            "versions": sorted(versions)[:max_versions],
            "score": score,
            "cvss_severity": cvss_severity,
            "kev": kev,
            "severity": severity_for(score, kev),
            "description": description[:220],
        })
    return out


# --------------------------------------------------------------------- gate
def reject_reason(candidate: dict) -> str | None:
    """Why this candidate must not ship, or None if it may."""
    product = candidate["product"].replace("_", " ").strip()
    flat = product.replace(" ", "")
    if len(flat) < MIN_PRODUCT_LEN:
        return "product name too short"
    if flat.lower() in GENERIC_PRODUCTS or product.lower() in GENERIC_PRODUCTS:
        return "product name too generic"
    if any(token in GENERIC_PRODUCTS for token in product.lower().split()) \
            and len(product.split()) == 1:
        return "product name too generic"
    if not candidate["versions"]:
        return "no concrete affected version"
    if not re.match(r"^[A-Za-z0-9 ._-]+$", product):
        return "product name has characters that do not survive matching"
    return None


def rule_name(candidate: dict) -> str:
    base = "NVD_%s_%s_%s" % (
        candidate["cve"].replace("-", "_"),
        SAFE_NAME_RE.sub("_", candidate["vendor"])[:24],
        SAFE_NAME_RE.sub("_", candidate["product"])[:32],
    )
    return re.sub(r"_+", "_", base).strip("_")


def render(candidate: dict) -> str:
    """Emit one YARA rule. Product token AND a specific version must co-occur."""
    product = candidate["product"].replace("_", " ")
    tags = "vulnerable_component"
    if candidate["kev"]:
        tags += " kev"

    strings = ['        $p = "%s" nocase' % product.replace('"', "")]
    if " " in product:
        strings.append('        $p2 = "%s" nocase' % product.replace(" ", "-"))
        strings.append('        $p3 = "%s" nocase' % product.replace(" ", "_"))
    for i, version in enumerate(candidate["versions"]):
        strings.append('        $v%d = "%s"' % (i, version))

    product_clause = "any of ($p*)" if " " in product else "$p"
    meta = [
        '        description = "Artifact appears to contain %s %s, affected by %s"'
        % (candidate["vendor"].replace("_", " "), product, candidate["cve"]),
        '        severity = "%s"' % candidate["severity"],
        '        cve = "%s"' % candidate["cve"],
        '        cvss = "%s"' % (candidate["score"] if candidate["score"] is not None else "n/a"),
        '        vendor = "%s"' % candidate["vendor"],
        '        product = "%s"' % candidate["product"],
        '        known_exploited = "%s"' % ("yes" if candidate["kev"] else "no"),
        '        generator = "nvd-rulegen"',
        '        reference = "https://nvd.nist.gov/vuln/detail/%s"' % candidate["cve"],
    ]
    return "\n".join([
        "rule %s : %s" % (rule_name(candidate), tags),
        "{",
        "    meta:",
        "\n".join(meta),
        "    strings:",
        "\n".join(strings),
        "    condition:",
        "        %s and any of ($v*) and filesize < 50MB" % product_clause,
        "}",
        "",
    ])


def gate(candidates: list, benign_corpus: list) -> tuple:
    """Return (survivors, rejections). A rule that fires on benign data dies."""
    survivors, rejections = [], defaultdict(int)
    seen_names = set()

    for candidate in candidates:
        reason = reject_reason(candidate)
        if reason:
            rejections[reason] += 1
            continue

        name = rule_name(candidate)
        if name in seen_names:
            rejections["duplicate rule name"] += 1
            continue

        source = render(candidate)
        try:
            compiled = yara.compile(source=source)
        except yara.Error as exc:
            rejections["does not compile: " + str(exc)[:40]] += 1
            continue

        fired = False
        for sample in benign_corpus:
            try:
                if compiled.match(data=sample):
                    fired = True
                    break
            except yara.Error:
                fired = True
                break
        if fired:
            rejections["fires on the benign corpus"] += 1
            continue

        seen_names.add(name)
        candidate["_source"] = source
        survivors.append(candidate)

    return survivors, dict(rejections)


def _harvest(client: NvdClient, params: dict, want: int, label: str,
             progress=None) -> list:
    """Page one NVD query until `want` records or the result set is exhausted."""
    out, start_index = [], 0
    while len(out) < want:
        query = dict(params)
        query["resultsPerPage"] = min(2000, want - len(out))
        query["startIndex"] = start_index
        try:
            payload = client._get(query)
        except Exception:
            break
        batch = payload.get("vulnerabilities", []) or []
        if not batch:
            break
        out.extend(v.get("cve", {}) for v in batch)
        start_index += len(batch)
        if progress:
            progress(label, len(out), payload.get("totalResults", 0))
        if start_index >= payload.get("totalResults", 0):
            break
    return out


def generate(client: NvdClient, days: int = 3650, limit: int = 1000,
             min_score: float = 7.0, benign_corpus: list | None = None,
             progress=None) -> dict:
    """Harvest CVEs worth generating from, build candidates, gate them.

    Two passes, in order of usefulness. CISA KEV entries come first: a
    vulnerability known to be exploited in the wild is worth detecting even
    when it is old. Then recent high-severity CVEs, because a rule for a 2001
    CVE in software nobody runs is shelf-filler - the NVD corpus is ordered
    oldest-first, so taking the first N records yields exactly that.
    """
    benign_corpus = benign_corpus or []
    severity = "CRITICAL" if min_score >= 9 else "HIGH"
    collected, seen_ids = [], set()

    passes = [
        ("known-exploited (KEV)", {"hasKev": True}),
        ("recent " + severity.lower(), {
            "cvssV3Severity": severity,
            "pubStartDate": _stamp_days_ago(days),
            "pubEndDate": _stamp_days_ago(0),
        }),
    ]
    for label, params in passes:
        for cve in _harvest(client, params, limit * 3, label, progress):
            cve_id = cve.get("id")
            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                collected.append(cve)
        if len(collected) >= limit * 3:
            break

    # KEV first, then newest first - so the limit keeps what matters most.
    collected.sort(key=lambda c: (0 if c.get("cisaExploitAdd") else 1,
                                  c.get("published", "")), reverse=False)
    collected.sort(key=lambda c: (0 if c.get("cisaExploitAdd") else 1,
                                  "" if c.get("cisaExploitAdd") else
                                  _invert(c.get("published", ""))))

    candidates = []
    for cve in collected:
        candidates.extend(candidates_from_cve(cve))
        if len(candidates) >= limit:
            break
    candidates = candidates[:limit]

    survivors, rejections = gate(candidates, benign_corpus)
    return {
        "cves_examined": len(collected),
        "candidates": len(candidates),
        "survivors": len(survivors),
        "rejections": rejections,
        "rules": survivors,
        "nvd_total_matching": None,
    }


def _invert(stamp: str) -> str:
    """Sort key that puts newer ISO timestamps first."""
    return "".join(chr(0x7E - ord(c)) if 32 < ord(c) < 0x7E else c for c in stamp)


def _stamp_days_ago(days: int) -> str:
    from datetime import datetime, timedelta, timezone
    when = datetime.now(timezone.utc) - timedelta(days=days)
    return when.strftime("%Y-%m-%dT%H:%M:%S.000")


def emit_file(survivors: list, header: str = "") -> str:
    """Assemble a .yar file from gated survivors."""
    kev = sum(1 for s in survivors if s["kev"])
    lines = [
        "/*",
        " * nvd_components.yar - GENERATED, do not hand-edit.",
        " *",
        " * Built from NVD CPE data by securitysuite/rulegen.py. Each rule detects a",
        " * known-vulnerable component present in a scanned artifact - exposure, not",
        " * compromise. Severity reflects that: KEV entries are high, everything else",
        " * is medium or low, because a vulnerable library is a review item and not",
        " * an interrupt.",
        " *",
        " * %d rules, %d of them for CISA KEV entries." % (len(survivors), kev),
        (" * " + header) if header else " *",
        " */",
        "",
    ]
    lines.extend(s["_source"] for s in survivors)
    return "\n".join(lines)
