"""CI smoke tests for the Security Suite.

These deliberately avoid live network calls and local OS auth logs. They verify
that the core detector, generated rules, IOC extraction and destructive
remediation rails still hold on a clean checkout.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securitysuite.config import load_config
from securitysuite.engine import YaraEngine
from securitysuite.ioc import extract
from securitysuite.remediate import Remediator
from securitysuite.shield import posture
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


def test_shield_posture() -> None:
    with tempfile.TemporaryDirectory(prefix="ss_shield_") as raw:
        tmp = Path(raw)
        watch = tmp / "watch"
        watch.mkdir()
        cfg, engine, store, _, remediator, _ = make_stack(tmp, watch)
        data = posture(cfg, engine, store, remediator)
        assert_true(data["attack_reasons"] == 500, "shield pressure library is incomplete")
        kinds = {layer["kind"] for layer in data["layers"]}
        assert_true({"AV", "IDS", "IPS"}.issubset(kinds), "AV/IDS/IPS layers missing")
        assert_true("scripts" in data["file_groups"], "file split groups missing")
        assert_true(data["integrations"]["bitdefender"]["status"] in (
            "configured", "not configured"), "Bitdefender connector status missing")


def main() -> int:
    test_ruleset()
    test_ioc_extraction()
    test_remediation_self_protection_and_delete()
    test_shield_posture()
    print("CI smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
