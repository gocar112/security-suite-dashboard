"""MITRE ATT&CK mapping for the ruleset.

A YARA hit says *this file is bad*. ATT&CK says *what the adversary was trying
to do* - and that is the language detection coverage is argued in. A rule that
fires on `vssadmin delete shadows` is not just "critical"; it is T1490, Inhibit
System Recovery, and if nothing else in the ruleset covers Impact then that is
a gap worth knowing about.

Two deliberate choices, both matching the rest of the suite:

* **The table is embedded, not fetched.** The suite is loopback-bound and may
  run with no outbound network at all. A coverage matrix that needs
  attack.mitre.org to render is a coverage matrix that fails closed in the one
  environment this tool is built for. Only the techniques the ruleset actually
  references are carried here; this is not a mirror of ATT&CK.

* **Mapping lives in rule metadata.** `mitre = "T1486"` sits beside
  `severity = "critical"` in the rule itself, so the rule author owns it, the
  same way they already own triage priority. Nothing here hardcodes rule names.

Technique names and tactic assignments follow ATT&CK Enterprise v14.
"""
from __future__ import annotations

import re

# Kill-chain order. The dashboard renders tactic columns in this sequence, so
# it reads left-to-right the way an intrusion actually unfolds.
TACTICS: tuple[tuple[str, str], ...] = (
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
)

TACTIC_NAMES = dict(TACTICS)

# technique id -> (name, tactics). Sub-techniques carry their own entry so a
# finding can say T1003.001 rather than the vaguer T1003.
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1003": ("OS Credential Dumping", ("credential-access",)),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", ("credential-access",)),
    "T1003.002": ("OS Credential Dumping: Security Account Manager", ("credential-access",)),
    "T1005": ("Data from Local System", ("collection",)),
    "T1014": ("Rootkit", ("defense-evasion",)),
    "T1016": ("System Network Configuration Discovery", ("discovery",)),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", ("lateral-movement",)),
    "T1027": ("Obfuscated Files or Information", ("defense-evasion",)),
    "T1027.002": ("Obfuscated Files or Information: Software Packing", ("defense-evasion",)),
    "T1036.007": ("Masquerading: Double File Extension", ("defense-evasion",)),
    "T1041": ("Exfiltration Over C2 Channel", ("exfiltration",)),
    "T1053.003": ("Scheduled Task/Job: Cron",
                  ("execution", "persistence", "privilege-escalation")),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task",
                  ("execution", "persistence", "privilege-escalation")),
    "T1056.001": ("Input Capture: Keylogging", ("collection", "credential-access")),
    "T1056.003": ("Input Capture: Web Portal Capture",
                  ("collection", "credential-access")),
    "T1059": ("Command and Scripting Interpreter", ("execution",)),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ("execution",)),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", ("execution",)),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", ("execution",)),
    "T1070.002": ("Indicator Removal: Clear Linux or Mac System Logs",
                  ("defense-evasion",)),
    "T1070.003": ("Indicator Removal: Clear Command History", ("defense-evasion",)),
    "T1071.001": ("Application Layer Protocol: Web Protocols",
                  ("command-and-control",)),
    "T1071.004": ("Application Layer Protocol: DNS", ("command-and-control",)),
    "T1082": ("System Information Discovery", ("discovery",)),
    "T1105": ("Ingress Tool Transfer", ("command-and-control",)),
    "T1113": ("Screen Capture", ("collection",)),
    "T1115": ("Clipboard Data", ("collection",)),
    "T1125": ("Video Capture", ("collection",)),
    "T1190": ("Exploit Public-Facing Application", ("initial-access",)),
    "T1195.002": ("Supply Chain Compromise: Compromise Software Supply Chain",
                  ("initial-access",)),
    "T1204.002": ("User Execution: Malicious File", ("execution",)),
    "T1218": ("System Binary Proxy Execution", ("defense-evasion",)),
    "T1219": ("Remote Access Software", ("command-and-control",)),
    "T1486": ("Data Encrypted for Impact", ("impact",)),
    "T1490": ("Inhibit System Recovery", ("impact",)),
    "T1496": ("Resource Hijacking", ("impact",)),
    "T1505.003": ("Server Software Component: Web Shell", ("persistence",)),
    "T1543.002": ("Create or Modify System Process: Systemd Service",
                  ("persistence", "privilege-escalation")),
    "T1543.003": ("Create or Modify System Process: Windows Service",
                  ("persistence", "privilege-escalation")),
    "T1546.003": ("Event Triggered Execution: WMI Event Subscription",
                  ("persistence", "privilege-escalation")),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                  ("persistence", "privilege-escalation")),
    "T1552": ("Unsecured Credentials", ("credential-access",)),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", ("credential-access",)),
    "T1552.004": ("Unsecured Credentials: Private Keys", ("credential-access",)),
    "T1555": ("Credentials from Password Stores", ("credential-access",)),
    "T1555.003": ("Credentials from Password Stores: Credentials from Web Browsers",
                  ("credential-access",)),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ("defense-evasion",)),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall",
                  ("defense-evasion",)),
    "T1566.001": ("Phishing: Spearphishing Attachment", ("initial-access",)),
    "T1566.002": ("Phishing: Spearphishing Link", ("initial-access",)),
    "T1572": ("Protocol Tunneling", ("command-and-control",)),
    "T1573": ("Encrypted Channel", ("command-and-control",)),
    "T1574.006": ("Hijack Execution Flow: Dynamic Linker Hijacking",
                  ("persistence", "privilege-escalation", "defense-evasion")),
    "T1611": ("Escape to Host", ("privilege-escalation",)),
}

# The generated vulnerable-component rules are all "this file references a
# component with a known CVE", which is one technique. Tagging 931 generated
# rules individually would be noise; the namespace carries it instead.
NAMESPACE_DEFAULTS = {"nvd_components": ("T1190",)}

TECHNIQUE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")


def parse_ids(raw) -> list[str]:
    """Pull technique ids out of a rule's ``mitre`` metadata value.

    Accepts "T1486", "T1486,T1490", "T1486 T1490" and similar; anything that
    is not shaped like a technique id is ignored rather than guessed at.
    """
    if not raw:
        return []
    found = TECHNIQUE_PATTERN.findall(str(raw).upper())
    seen: list[str] = []
    for item in found:
        if item not in seen:
            seen.append(item)
    return seen


def describe(technique_id: str) -> dict:
    """One technique as the dashboard wants it, even if we don't know it.

    An unknown id is returned rather than dropped: a rule author adding
    T1xxx before this table knows about it should see their id in the UI, not
    silently lose the mapping.
    """
    name, tactics = TECHNIQUES.get(technique_id, ("", ()))
    return {
        "id": technique_id,
        "name": name or "Unmapped technique",
        "tactics": list(tactics),
        "known": bool(name),
        "url": "https://attack.mitre.org/techniques/"
               + technique_id.replace(".", "/") + "/",
    }


def resolve(meta: dict, namespace: str = "") -> list[dict]:
    """Technique objects for one rule match.

    Falls back to the namespace default so the generated ruleset is mapped
    without editing 931 files.
    """
    ids = parse_ids(meta.get("mitre") or meta.get("attack") or "")
    if not ids:
        ids = list(NAMESPACE_DEFAULTS.get(namespace, ()))
    return [describe(item) for item in ids]


def tactics_for(techniques: list[dict]) -> list[str]:
    """Distinct tactic ids covered by a set of techniques, in kill-chain order."""
    hit = {tactic for technique in techniques for tactic in technique.get("tactics", [])}
    return [tactic for tactic, _ in TACTICS if tactic in hit]


def coverage(rule_index: list[dict], findings: list[dict]) -> dict:
    """Build the ATT&CK view: what the ruleset can see, and what it has seen.

    ``rule_index`` is the engine's loaded-rule list, which carries the mapping
    parsed from rule sources. ``findings`` are yara_match events, which carry
    the techniques that actually fired. The difference between the two is the
    point of the whole view: a technique with rules but no detections is
    coverage; a technique with neither is a gap.
    """
    by_technique: dict[str, dict] = {}

    for rule in rule_index:
        for technique_id in rule.get("mitre") or []:
            entry = by_technique.setdefault(technique_id, {
                "technique": describe(technique_id), "rules": [], "detections": 0,
                "severities": {}})
            if rule.get("rule") not in entry["rules"]:
                entry["rules"].append(rule.get("rule"))

    for finding in findings:
        if finding.get("event_type") != "yara_match":
            continue
        severity = finding.get("severity") or "info"
        seen_here = set()
        for match in finding.get("matches", []):
            for technique in match.get("attack") or []:
                technique_id = technique.get("id")
                if not technique_id or technique_id in seen_here:
                    continue
                seen_here.add(technique_id)
                entry = by_technique.setdefault(technique_id, {
                    "technique": describe(technique_id), "rules": [],
                    "detections": 0, "severities": {}})
                entry["detections"] += 1
                entry["severities"][severity] = entry["severities"].get(severity, 0) + 1

    # Roll techniques up into the tactic columns the matrix renders.
    columns = []
    for tactic_id, tactic_name in TACTICS:
        cells = [entry for entry in by_technique.values()
                 if tactic_id in entry["technique"]["tactics"]]
        cells.sort(key=lambda e: (-e["detections"], e["technique"]["id"]))
        columns.append({
            "id": tactic_id,
            "name": tactic_name,
            "techniques": cells,
            "covered": sum(1 for c in cells if c["rules"]),
            "detected": sum(1 for c in cells if c["detections"]),
        })

    return {
        "tactics": columns,
        "technique_count": len(by_technique),
        "covered_techniques": sum(1 for e in by_technique.values() if e["rules"]),
        "detected_techniques": sum(1 for e in by_technique.values() if e["detections"]),
        "total_detections": sum(e["detections"] for e in by_technique.values()),
    }
