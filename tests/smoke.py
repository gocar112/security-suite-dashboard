"""CI smoke tests for the Security Suite.

These deliberately avoid live network calls and local OS auth logs. They verify
that the core detector, generated rules, IOC extraction and destructive
remediation rails still hold on a clean checkout.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securitysuite import attack
from securitysuite.config import load_config
from securitysuite.engine import YaraEngine
from securitysuite.ioc import extract
from securitysuite.remediate import Remediator
from securitysuite.store import EventStore
from securitysuite.telemetry import AuthTelemetry
from securitysuite.watcher import Monitor


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def make_stack(tmp: Path, watch: Path):
    cfg = load_config()
    cfg.watch_paths = [str(watch)]
    cfg.findings_log = str(tmp / "findings.ndjson")
    cfg.triage_file = str(tmp / "triage.json")
    cfg.remediation_file = str(tmp / "remediation.json")
    cfg.quarantine_dir = str(tmp / "quarantine")
    cfg.auto_remediate = False
    engine = YaraEngine(cfg.rules_dir, cfg.max_file_bytes)
    store = EventStore(cfg.findings_log, cfg.triage_file, 500)
    telemetry = AuthTelemetry(cfg.auth_log_path, 5, 0, 25)
    remediator = Remediator(cfg, store)
    monitor = Monitor(cfg, engine, store, telemetry, remediator)
    return cfg, engine, store, telemetry, remediator, monitor


def test_ruleset() -> None:
    cfg = load_config()
    info = YaraEngine(cfg.rules_dir, cfg.max_file_bytes).info()
    assert_true(not info["load_errors"], "ruleset has compile errors")
    assert_true(info["rule_count"] >= 1004, "generated rules did not load")
    assert_true(len(info["rule_files"]) >= 16, "expected namespaces missing")


def test_ioc_extraction() -> None:
    data = (
        b"ALL YOUR FILES HAVE BEEN ENCRYPTED\n"
        b"Send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
        b"Portal http://abcdefghijklmnop.onion/pay and http://194.26.29.156/a.ps1\n"
        b"CVE-2021-44228 /tmp/.hidden/payload.sh HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\n"
    )
    result = extract(data)
    types = {item["type"] for item in result["indicators"]}
    assert_true({"btc", "url", "onion", "ipv4", "cve", "posixpath", "registry"}.issubset(types),
                "expected indicators missing")
    assert_true(all("http://" not in item["defanged"] for item in result["indicators"] if item["type"] == "url"),
                "URLs must be defanged")


def test_remediation_self_protection_and_delete() -> None:
    with tempfile.TemporaryDirectory(prefix="ss_ci_") as raw:
        tmp = Path(raw)
        watch = tmp / "watch"
        watch.mkdir()
        _, engine, store, _, remediator, monitor = make_stack(tmp, watch)

        # A malicious file inside the watch root can be deleted, but only after
        # confirm=true and only if the hash still matches the finding.
        target = watch / "ransom.ps1"
        target.write_text(
            "Your files have been encrypted. Pay 0.5 bitcoin at "
            "http://abcdefghijklmnop.onion for the decryption key.\n",
            encoding="utf-8",
        )
        event = monitor.scan_and_record(str(target), "ci-test")
        assert_true(event and event["event_type"] == "yara_match", "sample did not alert")
        dry = remediator.act(event["id"], "delete", dry_run=True)
        assert_true(dry["ok"] and target.exists(), "dry run touched the target")
        denied = remediator.act(event["id"], "delete")
        assert_true(not denied["ok"] and denied["refused"] == "confirmation required", "delete lacked confirmation rail")
        deleted = remediator.act(event["id"], "delete", confirm=True)
        assert_true(deleted["ok"] and not target.exists(), "confirmed delete failed")

        # Pointing a monitor at the project itself must not make repo files
        # deletable, even if a rule fires on their contents.
        _, _, project_store, _, project_remediator, project_monitor = make_stack(tmp / "project", ROOT)
        readme_event = project_monitor.scan_and_record(str(ROOT / "README.md"), "ci-self-protect")
        assert_true(readme_event, "README did not produce a scan event")
        refused = project_remediator.act(readme_event["id"], "delete", confirm=True, allow_directory=True)
        assert_true(not refused["ok"] and refused["refused"] == "suite-owned path", "project files became remediable")
        assert_true((ROOT / "README.md").exists(), "self-protection failed; README was deleted")


def test_clear_preserves_audit_trail_beyond_memory_window() -> None:
    """store.clear() must not lose remediation records older than the deque.

    The audit trail used to be rebuilt from the in-memory ring buffer, so a
    remediation older than history_limit events was erased from findings.ndjson
    by a dashboard "Clear lines" click - the exact loss clear()'s own docstring
    promises not to cause.
    """
    with tempfile.TemporaryDirectory(prefix="ss_clear_") as raw:
        tmp = Path(raw)
        log = tmp / "findings.ndjson"
        store = EventStore(str(log), str(tmp / "triage.json"), history_limit=50)
        store.add({"event_type": "remediation", "action": "delete",
                   "file_path": "/evil/payload.exe", "marker": "AUDIT_KEEP"})
        for i in range(200):                       # push it out of memory
            store.add({"event_type": "scan", "file_path": "/tmp/f%d" % i})

        assert_true("AUDIT_KEEP" in log.read_text(encoding="utf-8"),
                    "audit record missing before clear")
        result = store.clear()
        assert_true("AUDIT_KEEP" in log.read_text(encoding="utf-8"),
                    "clear() destroyed a remediation record older than the memory window")
        assert_true(result["audit_retained"] == 1,
                    "clear() misreported how many audit records it kept")


def test_overflowed_subscriber_is_notified() -> None:
    """A stream client that falls behind must be told, not silently detached.

    The store dropped a full subscriber from the bus while its SSE response
    stayed open and kept emitting stats frames, so the dashboard showed "live"
    and a green dot while receiving no findings at all.
    """
    with tempfile.TemporaryDirectory(prefix="ss_sse_") as raw:
        tmp = Path(raw)
        store = EventStore(str(tmp / "f.ndjson"), str(tmp / "t.json"), history_limit=5000)
        sub = store.subscribe()
        for i in range(sub.maxsize + 10):          # nobody drains it
            store.add({"event_type": "yara_match", "severity": "critical",
                       "file_path": "/evil/%d.exe" % i, "matches": []})

        drained = []
        while not sub.empty():
            drained.append(sub.get_nowait())
        assert_true(any(m.get("__stream__") == "overflow" for m in drained),
                    "overflowed client was detached with no notice")
        assert_true(drained[-1].get("__stream__") == "overflow",
                    "overflow notice must be the final message on the queue")
        assert_true(store.dropped_subscribers == 1,
                    "dropped subscriber was not counted")


def test_triage_survives_memory_window() -> None:
    """A finding on disk but out of memory is still triageable, not a 404."""
    with tempfile.TemporaryDirectory(prefix="ss_triage_") as raw:
        tmp = Path(raw)
        store = EventStore(str(tmp / "f.ndjson"), str(tmp / "t.json"), history_limit=20)
        first = store.add({"event_type": "yara_match", "severity": "critical",
                           "file_path": "/evil/first.exe", "matches": []})
        for i in range(60):
            store.add({"event_type": "scan", "file_path": "/tmp/f%d" % i})
        updated = store.set_status(first["id"], "resolved", "handled")
        assert_true(updated is not None,
                    "triage on a finding older than the memory window returned 404")
        assert_true(updated["status"] == "resolved", "triage status not applied")


def test_ids_are_stable_across_reload() -> None:
    """Log lines without an id must get the same id on every restart."""
    with tempfile.TemporaryDirectory(prefix="ss_ids_") as raw:
        tmp = Path(raw)
        log = tmp / "f.ndjson"
        log.write_text(json.dumps({
            "event_type": "yara_match", "severity": "critical",
            "file_path": "/evil/x.exe", "timestamp": "2026-09-12T10:00:00"})
            + chr(10),
            encoding="utf-8")
        first = list(EventStore(str(log), str(tmp / "t.json"), 50)._events)[0]["id"]
        second = list(EventStore(str(log), str(tmp / "t.json"), 50)._events)[0]["id"]
        assert_true(first == second,
                    "id regenerated on reload; triage state would be orphaned")



def test_attack_mapping() -> None:
    """Every handwritten rule carries a technique id that the table knows."""
    cfg = load_config()
    index = YaraEngine(cfg.rules_dir, cfg.max_file_bytes).info()["rules"]
    handwritten = [r for r in index if r["namespace"] != "nvd_components"]
    assert_true(len(handwritten) >= 70, "handwritten ruleset shrank unexpectedly")

    # Two demo fixtures are deliberately unmapped: they are test material, not
    # adversary behaviour, and tagging them would put phantom coverage in the
    # matrix.
    unmapped = [r["rule"] for r in handwritten if not r.get("mitre")]
    assert_true(set(unmapped) <= {"Demo_TestKeyword", "EICAR_Test_File"},
                "unmapped rules: %s" % unmapped)

    # Every id referenced by a rule must exist in the embedded table, or the
    # matrix renders a technique it cannot name or place in a tactic.
    for rule in handwritten:
        for technique_id in rule.get("mitre") or []:
            assert_true(technique_id in attack.TECHNIQUES,
                        "%s maps to unknown technique %s" % (rule["rule"], technique_id))

    # The generated ruleset is mapped by namespace, not rule by rule.
    generated = [r for r in index if r["namespace"] == "nvd_components"]
    if generated:
        assert_true(all(r.get("mitre") == ["T1190"] for r in generated[:50]),
                    "generated rules lost their namespace default")


def test_attack_resolves_on_a_real_match() -> None:
    """A scan result carries ATT&CK context, and coverage counts it."""
    cfg = load_config()
    engine = YaraEngine(cfg.rules_dir, cfg.max_file_bytes)
    result = engine.scan_bytes(
        b"ALL YOUR FILES HAVE BEEN ENCRYPTED. Send bitcoin for the decryption key.",
        "ransom-note")
    assert_true(result["matches"], "ransom note sample did not match any rule")
    techniques = {t["id"] for m in result["matches"] for t in m.get("attack", [])}
    assert_true("T1486" in techniques,
                "ransom note should map to T1486, got %s" % sorted(techniques))

    cov = attack.coverage(engine.info()["rules"], [{
        "event_type": "yara_match", "severity": "critical",
        "matches": result["matches"]}])
    impact = next(c for c in cov["tactics"] if c["id"] == "impact")
    assert_true(impact["detected"] >= 1, "Impact tactic showed no detection")
    assert_true(cov["covered_techniques"] > 0, "coverage found no mapped techniques")



def main() -> int:
    test_ruleset()
    test_ioc_extraction()
    test_remediation_self_protection_and_delete()
    test_clear_preserves_audit_trail_beyond_memory_window()
    test_overflowed_subscriber_is_notified()
    test_triage_survives_memory_window()
    test_ids_are_stable_across_reload()
    test_attack_mapping()
    test_attack_resolves_on_a_real_match()
    print("CI smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
