"""Tests for correlation, casework, and the incident report.

The report is the artefact that leaves the machine, so its safety properties -
no external requests, no unescaped attacker-controlled text - are tested as
hard as the logic that builds it.
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securitysuite import graph, report
from securitysuite.cases import CaseStore


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def finding(fid, severity, path, rule, indicators, technique="T1486"):
    return {
        "id": fid, "event_type": "yara_match", "severity": severity,
        "status": "new", "file_path": path, "file_name": path.split("/")[-1],
        "timestamp": "2026-09-12T12:0%s:00" % (len(fid) % 10),
        "sha256": "a" * 64, "file_size": 120, "entropy": 4.2,
        "matches": [{
            "rule": rule, "namespace": "windows_threats", "tags": ["malware"],
            "description": "test rule", "severity": severity,
            "attack": [{"id": technique, "name": "Data Encrypted for Impact",
                        "tactics": ["impact"]}],
            "strings": [{"identifier": "$a", "offset": 16, "preview": "evil"}],
        }],
        "iocs": {"indicators": [
            {"type": t, "value": v, "defanged": v.replace(".", "[.]"), "count": 1}
            for t, v in indicators]},
    }


def test_shared_indicator_forms_a_campaign() -> None:
    """Two files that beacon to the same host are one operation, not two rows."""
    events = [
        finding("f1", "critical", "C:/up/a.txt", "Ransom_Note_Template",
                [("ipv4", "198.51.100.7")]),
        finding("f2", "high", "C:/up/b.txt", "PowerShell_Download_Cradle",
                [("ipv4", "198.51.100.7")]),
        finding("f3", "medium", "C:/up/c.txt", "Suspicious_Double_Extension",
                [("domain", "unrelated.test")]),
    ]
    result = graph.build(events)
    campaigns = result["campaigns"]
    assert_true(len(campaigns) == 1, "expected exactly one campaign, got %d" % len(campaigns))
    campaign = campaigns[0]
    assert_true(sorted(campaign["finding_ids"]) == ["f1", "f2"],
                "wrong members: %s" % campaign["finding_ids"])
    assert_true(campaign["severity"] == "critical",
                "campaign severity should be the worst of its members")
    assert_true(any("198" in l["value"] for l in campaign["linked_by"]),
                "campaign did not record why it was linked")


def test_weak_indicators_do_not_merge_findings() -> None:
    """A shared CVE mention is not evidence of a shared operation.

    Half a corpus can mention CVE-2021-44228. If weak indicator types merged
    findings, every campaign would collapse into one meaningless blob.
    """
    events = [
        finding("f1", "critical", "C:/up/a.txt", "R1", [("cve", "CVE-2021-44228")]),
        finding("f2", "high", "C:/up/b.txt", "R2", [("cve", "CVE-2021-44228")]),
    ]
    assert_true(graph.build(events)["campaigns"] == [],
                "weak indicator type merged two unrelated findings")


def test_graph_never_emits_a_dangling_edge() -> None:
    """Truncation must drop edges whose endpoints did not survive."""
    events = [finding("f%d" % i, "high", "C:/up/%d.txt" % i, "R%d" % i,
                      [("ipv4", "10.0.0.%d" % i)]) for i in range(40)]
    result = graph.build(events, max_nodes=25)
    assert_true(result["truncated"], "expected truncation at max_nodes=25")
    ids = {n["id"] for n in result["nodes"]}
    for edge in result["edges"]:
        assert_true(edge["source"] in ids and edge["target"] in ids,
                    "dangling edge survived truncation: %s" % edge)


def test_case_lifecycle() -> None:
    with tempfile.TemporaryDirectory(prefix="ss_case_") as raw:
        store = CaseStore(str(Path(raw) / "cases.json"))
        case = store.create("Ransomware drop", owner="larry", severity="critical")
        assert_true(case["status"] == "open", "new case should open")

        store.link(case["id"], ["f1", "f2", "f1"])
        assert_true(store.get(case["id"])["finding_ids"] == ["f1", "f2"],
                    "link should de-duplicate")
        store.link(case["id"], ["f1"], detach=True)
        assert_true(store.get(case["id"])["finding_ids"] == ["f2"], "detach failed")

        store.add_note(case["id"], "Quarantined the note.", "larry")
        store.update(case["id"], status="contained")
        reloaded = store.get(case["id"])
        assert_true(reloaded["status"] == "contained", "status update failed")
        assert_true(len(reloaded["notes"]) == 1, "note not recorded")

        # An unknown status must be ignored, not stored.
        store.update(case["id"], status="banana")
        assert_true(store.get(case["id"])["status"] == "contained",
                    "invalid status was accepted")

        # State survives a reload from disk.
        again = CaseStore(str(Path(raw) / "cases.json")).get(case["id"])
        assert_true(again and again["status"] == "contained", "case did not persist")

        assert_true(store.delete(case["id"]), "delete failed")
        assert_true(store.get(case["id"]) is None, "case still present after delete")


def test_report_is_self_contained_and_escaped() -> None:
    """The report leaves the machine, so it must be inert and make no requests."""
    hostile = "<script>alert(1)</script>"
    case = {
        "id": "c1", "title": "Case " + hostile, "status": "open",
        "severity": "critical", "owner": hostile, "summary": hostile,
        "created_at": "2026-09-12T12:00:00", "updated_at": "2026-09-12T12:30:00",
        "notes": [{"at": "2026-09-12T12:10:00", "author": hostile, "text": hostile}],
    }
    findings = [finding("f1", "critical", "C:/up/" + hostile, hostile,
                        [("url", "http://evil.test/" + hostile)])]
    html = report.render(
        case, findings,
        [{"type": "url", "value": hostile, "defanged": hostile, "file_count": 1,
          "occurrences": 2}],
        graph.build(findings)["campaigns"],
        [{"timestamp": "2026-09-12T12:20:00", "action": "quarantine",
          "file_path": "C:/up/" + hostile, "ok": True}],
        "2026-09-12T12:40:00", "1.0.0")

    # No raw script tag anywhere, however the hostile string arrived.
    assert_true("<script>" not in html, "report rendered an unescaped script tag")
    assert_true("&lt;script&gt;" in html, "hostile text was not escaped at all")

    # No external requests: nothing may be fetched when this file is opened.
    for pattern in (r'src\s*=\s*"https?:', r'href\s*=\s*"https?:', r"@import",
                    r"url\(\s*https?:"):
        assert_true(not re.search(pattern, html),
                    "report would make an external request: %s" % pattern)

    # It still says the things a report has to say.
    for needed in ("Incident report", "ATT&amp;CK", "Evidence", "Indicators",
                   "Remediation ledger", "T1486"):
        assert_true(needed in html, "report is missing section: %s" % needed)


def main() -> int:
    test_shared_indicator_forms_a_campaign()
    test_weak_indicators_do_not_merge_findings()
    test_graph_never_emits_a_dangling_edge()
    test_case_lifecycle()
    test_report_is_self_contained_and_escaped()
    print("Correlation, case and report tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
