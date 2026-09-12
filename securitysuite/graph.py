"""Link analysis: findings, the indicators inside them, and the rules that fired.

Detections arrive as a flat list ordered by time, which is the one view that
hides the thing an analyst most wants to see: that six of them are the same
intrusion. Two files dropped an hour apart are unrelated rows in a table and
obviously related the moment you notice they beacon to the same host.

The edges are already in the data. ``ioc.summarise`` has always emitted the
finding ids each indicator appeared in; nothing walked them. This module turns
that relation into a graph and groups it into campaigns - connected components
over shared indicators, so a set of findings linked by a common C2 address
becomes one object with its own severity, span and story.

One caveat drove the design: ``summarise`` truncates ``finding_ids`` to eight
for display. Reusing that output would silently cap every campaign at eight
members, so this module aggregates indicators itself.
"""
from __future__ import annotations

from .store import SEVERITY_RANK, SEVERITIES

# Indicator types that say "these two files are the same operation". A shared
# SHA-256 or C2 host is evidence; a shared file path or CVE id usually is not -
# half the corpus mentions CVE-2021-44228 - so those stay in the graph as nodes
# but do not, on their own, merge two findings into one campaign.
LINKING_TYPES = {"url", "domain", "ipv4", "onion", "btc", "xmr", "eth",
                 "email", "sha256", "md5"}

MAX_NODES = 600


def _sev_rank(severity) -> int:
    return SEVERITY_RANK.get(str(severity or "info"), len(SEVERITIES))


def _worst(severities) -> str:
    ranked = sorted(severities, key=_sev_rank)
    return ranked[0] if ranked else "info"


def build(events: list[dict], max_nodes: int = MAX_NODES,
          linking_only: bool = False) -> dict:
    """Graph of findings, indicators and rules, plus campaign clusters."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    # indicator key -> finding ids, built here rather than taken from
    # ioc.summarise(), which truncates its finding_ids list for display.
    indicator_findings: dict[str, set] = {}
    indicator_meta: dict[str, dict] = {}

    findings = [e for e in events if e.get("event_type") == "yara_match"]

    for finding in findings:
        fid = "f:" + str(finding.get("id"))
        nodes[fid] = {
            "id": fid,
            "type": "finding",
            "label": finding.get("file_name") or _base(finding.get("file_path")),
            "severity": finding.get("severity") or "info",
            "status": finding.get("status") or "new",
            "timestamp": finding.get("timestamp"),
            "finding_id": finding.get("id"),
            "path": finding.get("file_path"),
        }

        for match in finding.get("matches") or []:
            rule = match.get("rule")
            if not rule:
                continue
            rid = "r:" + rule
            node = nodes.get(rid)
            if node is None:
                nodes[rid] = {
                    "id": rid, "type": "rule", "label": rule,
                    "severity": match.get("severity") or "info",
                    "namespace": match.get("namespace"),
                    "attack": [t.get("id") for t in (match.get("attack") or [])],
                    "count": 0,
                }
                node = nodes[rid]
            node["count"] += 1
            edges.append({"source": fid, "target": rid, "kind": "matched"})

        for item in ((finding.get("iocs") or {}).get("indicators") or []):
            kind = item.get("type")
            value = str(item.get("value") or "")
            if not kind or not value:
                continue
            if linking_only and kind not in LINKING_TYPES:
                continue
            key = kind + ":" + value.lower()
            indicator_findings.setdefault(key, set()).add(finding.get("id"))
            indicator_meta.setdefault(key, {
                "type": kind,
                "value": value,
                "defanged": item.get("defanged") or value,
                "scope": item.get("scope") or "",
            })

    # Indicator nodes. A singleton indicator is kept - it is still a pivot the
    # analyst may want - but only shared ones can merge findings below.
    for key, fids in indicator_findings.items():
        meta = indicator_meta[key]
        iid = "i:" + key
        nodes[iid] = {
            "id": iid,
            "type": "indicator",
            "label": meta["defanged"],
            "indicator_type": meta["type"],
            "scope": meta["scope"],
            "shared": len(fids),
        }
        for fid in fids:
            edges.append({"source": "f:" + str(fid), "target": iid,
                          "kind": "observed"})

    campaigns = _campaigns(findings, indicator_findings, indicator_meta)

    # Bound the payload: keep the most connected nodes, then drop edges whose
    # endpoints did not survive, so the client never renders a dangling edge.
    truncated = False
    if len(nodes) > max_nodes:
        truncated = True
        degree: dict[str, int] = {}
        for edge in edges:
            degree[edge["source"]] = degree.get(edge["source"], 0) + 1
            degree[edge["target"]] = degree.get(edge["target"], 0) + 1
        keep = sorted(nodes, key=lambda n: -degree.get(n, 0))[:max_nodes]
        kept = set(keep)
        nodes = {k: v for k, v in nodes.items() if k in kept}
        edges = [e for e in edges
                 if e["source"] in kept and e["target"] in kept]

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "campaigns": campaigns,
        "truncated": truncated,
        "counts": {
            "findings": sum(1 for n in nodes.values() if n["type"] == "finding"),
            "indicators": sum(1 for n in nodes.values() if n["type"] == "indicator"),
            "rules": sum(1 for n in nodes.values() if n["type"] == "rule"),
            "edges": len(edges),
        },
    }


def _campaigns(findings: list[dict], indicator_findings: dict[str, set],
               indicator_meta: dict[str, dict]) -> list[dict]:
    """Group findings into clusters joined by shared linking indicators.

    Union-find over the finding ids each shared indicator touches. Only
    LINKING_TYPES merge: a shared C2 host means "same operation", a shared
    mention of CVE-2021-44228 does not.
    """
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    by_id = {str(f.get("id")): f for f in findings}
    for fid in by_id:
        find(fid)

    shared_by_root: dict[str, set] = {}
    for key, fids in indicator_findings.items():
        if indicator_meta[key]["type"] not in LINKING_TYPES or len(fids) < 2:
            continue
        members = [str(f) for f in fids if str(f) in by_id]
        for other in members[1:]:
            union(members[0], other)

    groups: dict[str, list] = {}
    for fid in by_id:
        groups.setdefault(find(fid), []).append(fid)

    # Record which indicators tie each group together, for the "why" line.
    for key, fids in indicator_findings.items():
        if indicator_meta[key]["type"] not in LINKING_TYPES or len(fids) < 2:
            continue
        members = [str(f) for f in fids if str(f) in by_id]
        if members:
            shared_by_root.setdefault(find(members[0]), set()).add(key)

    campaigns = []
    for root, members in groups.items():
        if len(members) < 2:
            continue                       # a lone finding is not a campaign
        events = [by_id[m] for m in members]
        stamps = sorted(str(e.get("timestamp") or "") for e in events)
        links = sorted(shared_by_root.get(root, set()))
        campaigns.append({
            "id": "c:" + root,
            "size": len(members),
            "finding_ids": members,
            "severity": _worst(e.get("severity") for e in events),
            "first_seen": stamps[0] if stamps else "",
            "last_seen": stamps[-1] if stamps else "",
            "files": sorted({_base(e.get("file_path")) for e in events})[:8],
            "rules": sorted({m.get("rule") for e in events
                             for m in (e.get("matches") or []) if m.get("rule")})[:8],
            "attack": sorted({t.get("id") for e in events
                              for m in (e.get("matches") or [])
                              for t in (m.get("attack") or []) if t.get("id")}),
            "linked_by": [{"type": indicator_meta[k]["type"],
                           "value": indicator_meta[k]["defanged"]} for k in links][:8],
        })

    campaigns.sort(key=lambda c: (_sev_rank(c["severity"]), -c["size"]))
    return campaigns


def _base(path) -> str:
    text = str(path or "")
    for sep in ("\\", "/"):
        if sep in text:
            text = text.rsplit(sep, 1)[-1]
    return text or "(unnamed)"
