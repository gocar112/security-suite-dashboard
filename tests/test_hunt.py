"""Tests for the hunt query language.

The grammar is the part of the console an operator types into under pressure,
so its failure modes matter as much as its successes: a query that silently
matches nothing is worse than one that says why it cannot run.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securitysuite import hunt


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def make_events() -> list[dict]:
    return [
        {
            "id": "a1", "event_type": "yara_match", "severity": "critical",
            "status": "new", "file_path": "C:/uploads/README_RESTORE.txt",
            "matches": [{
                "rule": "Ransom_Note_Template", "namespace": "windows_threats",
                "tags": ["malware"],
                "attack": [{"id": "T1486", "tactics": ["impact"]}],
            }],
        },
        {
            "id": "b2", "event_type": "yara_match", "severity": "critical",
            "status": "resolved", "file_path": "C:/samples/task_setup.log",
            "matches": [{
                "rule": "PowerShell_Encoded_Command", "namespace": "windows_threats",
                "tags": ["suspicious"],
                "attack": [{"id": "T1059.001", "tactics": ["execution"]}],
            }],
        },
        {
            "id": "c3", "event_type": "yara_match", "severity": "medium",
            "status": "new", "file_path": "C:/uploads/mail_body.txt",
            "matches": [{
                "rule": "Suspicious_Double_Extension", "namespace": "windows_threats",
                "tags": ["suspicious"],
                "attack": [{"id": "T1036.007", "tactics": ["defense-evasion"]}],
            }],
        },
        {
            "id": "d4", "event_type": "scan", "severity": None,
            "status": "new", "file_path": "C:/uploads/report_q3.txt", "matches": [],
        },
    ]


def ids(result) -> list:
    return sorted(f["id"] for f in result["findings"])


def test_field_terms() -> None:
    events = make_events()
    assert_true(ids(hunt.run("severity:critical", events)) == ["a1", "b2"],
                "severity filter wrong")
    assert_true(ids(hunt.run("status:resolved", events)) == ["b2"], "status filter wrong")
    assert_true(ids(hunt.run("type:scan", events)) == ["d4"], "type filter wrong")
    assert_true(ids(hunt.run("namespace:windows_threats", events)) == ["a1", "b2", "c3"],
                "namespace filter wrong")
    assert_true(ids(hunt.run("tag:malware", events)) == ["a1"], "tag filter wrong")


def test_booleans_and_grouping() -> None:
    events = make_events()
    assert_true(ids(hunt.run("severity:critical AND NOT status:resolved", events)) == ["a1"],
                "AND/NOT wrong")
    assert_true(ids(hunt.run("severity:medium OR status:resolved", events)) == ["b2", "c3"],
                "OR wrong")
    assert_true(
        ids(hunt.run("severity:critical AND (rule:Ransom* OR rule:PowerShell*)", events))
        == ["a1", "b2"], "grouping wrong")
    # Adjacency implies AND, and "-" is shorthand for NOT.
    assert_true(ids(hunt.run("severity:critical -status:resolved", events)) == ["a1"],
                "adjacency/- shorthand wrong")


def test_wildcards_and_attack_fields() -> None:
    events = make_events()
    assert_true(ids(hunt.run("rule:PowerShell*", events)) == ["b2"], "wildcard wrong")
    assert_true(ids(hunt.run("file:*.log", events)) == ["b2"], "path wildcard wrong")
    assert_true(ids(hunt.run("technique:T1486", events)) == ["a1"], "technique filter wrong")
    assert_true(ids(hunt.run("tactic:execution", events)) == ["b2"], "tactic filter wrong")
    assert_true(ids(hunt.run("technique:T1486 OR technique:T1036.007", events)) == ["a1", "c3"],
                "technique OR wrong")


def test_free_text_still_works() -> None:
    events = make_events()
    assert_true(ids(hunt.run("restore", events)) == ["a1"], "bare word should be free text")
    assert_true(ids(hunt.run("", events)) == ["a1", "b2", "c3", "d4"],
                "a blank query should match everything")


def test_field_terms_are_not_substring_matches_on_the_blob() -> None:
    """severity:critical must not match a file merely named 'critical'.

    This is the whole reason the grammar exists: the old search box matched a
    substring against the entire JSON blob of an event, so a benign file named
    critical_report.txt answered a query for critical findings.
    """
    events = make_events() + [{
        "id": "e5", "event_type": "yara_match", "severity": "low", "status": "new",
        "file_path": "C:/uploads/critical_report.txt", "matches": [],
    }]
    assert_true("e5" not in ids(hunt.run("severity:critical", events)),
                "field term leaked into a whole-event substring match")
    assert_true("e5" in ids(hunt.run("critical", events)),
                "free text should still match the filename")


def test_bad_queries_explain_themselves() -> None:
    events = make_events()
    for query, expected in (
        ("severity:", "empty value"),
        ("bogus:x", "unknown field"),
        ("(severity:critical", "unclosed"),
        ("rule:LockBit AND", "expected a term"),
    ):
        result = hunt.run(query, events)
        assert_true(result.get("error"), "%r should not have parsed" % query)
        assert_true(expected in result["error"],
                    "%r gave unhelpful error: %s" % (query, result["error"]))
        assert_true(result["findings"] == [], "a failed parse must return no findings")


def main() -> int:
    test_field_terms()
    test_booleans_and_grouping()
    test_wildcards_and_attack_fields()
    test_free_text_still_works()
    test_field_terms_are_not_substring_matches_on_the_blob()
    test_bad_queries_explain_themselves()
    print("Hunt query tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
