"""Automatic quarantine policy and existing remediation rails, using temp files."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from securitysuite.remediate import Remediator
from securitysuite.store import EventStore


class AutoRemediationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ss_auto_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.watch = self.root / "watch"
        self.watch.mkdir()
        self.target = self.watch / "sample.bin"
        self.target.write_bytes(b"synthetic detection fixture")
        self.cfg = SimpleNamespace(
            watch_paths=[str(self.watch)], remediation_roots=[],
            quarantine_dir=str(self.root / "quarantine"),
            remediation_file=str(self.root / "remediation.json"),
            findings_log=str(self.root / "findings.ndjson"),
            triage_file=str(self.root / "triage.json"),
            auto_remediate=True, auto_remediate_action="quarantine",
            auto_remediate_severity="critical",
        )
        self.store = EventStore(self.cfg.findings_log, self.cfg.triage_file)
        self.remediator = Remediator(self.cfg, self.store)

    @staticmethod
    def match(**overrides):
        match = {
            "rule": "Specific_Malware_Detection", "namespace": "curated",
            "tags": ["malware"], "severity": "critical",
            "meta": {"severity": "critical", "confidence": "high"},
        }
        match.update(overrides)
        return match

    def finding(self, *, matches=None, path=None, **overrides):
        path = path or self.target
        event = {
            "event_type": "yara_match", "severity": "critical",
            "file_path": str(path), "file_name": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "matches": matches if matches is not None else [self.match()],
        }
        event.update(overrides)
        return self.store.add(event)

    def assert_refused(self, result, reason):
        self.assertFalse(result["ok"])
        self.assertEqual(result["refused"], reason)
        self.assertTrue(self.target.exists())
        audit = self.store.events(limit=1, event_type="remediation")[0]
        self.assertEqual(audit["outcome"], "refused")
        self.assertEqual(audit["trigger"], "auto")

    def test_opt_in_requires_boolean_true(self):
        finding = self.finding()
        for value in (False, None, "false", "true", 1):
            with self.subTest(value=value):
                self.cfg.auto_remediate = value
                self.assertIsNone(self.remediator.consider_auto(finding))
                self.assertTrue(self.target.exists())
        del self.cfg.auto_remediate
        self.assertIsNone(self.remediator.consider_auto(finding))

    def test_eligible_match_quarantines_with_existing_hash_check(self):
        finding = self.finding()
        result = self.remediator.consider_auto(finding)
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "quarantine")
        self.assertEqual(result["checks"]["hash"], "matches the finding")
        self.assertFalse(self.target.exists())
        held = Path(self.cfg.quarantine_dir) / finding["id"] / self.target.name
        self.assertEqual(hashlib.sha256(held.read_bytes()).hexdigest(), finding["sha256"])

    def test_automatic_actions_are_quarantine_only(self):
        finding = self.finding()
        for action in ("delete", "purge", "restore"):
            with self.subTest(action=action):
                self.cfg.auto_remediate_action = action
                self.assert_refused(self.remediator.consider_auto(finding),
                                    "automatic action must be quarantine")
                self.assert_refused(
                    self.remediator.act(finding["id"], action, confirm=True, trigger="auto"),
                    "automatic action must be quarantine",
                )

    def test_direct_auto_call_cannot_bypass_opt_in_or_confidence(self):
        finding = self.finding(matches=[self.match(meta={"severity": "critical"})])
        self.assert_refused(
            self.remediator.act(finding["id"], "quarantine", confirm=True, trigger="auto"),
            "no eligible high-confidence rule match",
        )
        self.cfg.auto_remediate = False
        self.assert_refused(
            self.remediator.act(finding["id"], "quarantine", confirm=True, trigger="auto"),
            "automatic remediation is disabled",
        )

    def test_confidence_must_be_explicit_rule_metadata(self):
        for confidence in (None, False, True, 1, 100, "critical", "medium", "true", [], {}):
            with self.subTest(confidence=confidence):
                finding = self.finding(
                    matches=[self.match(meta={"confidence": confidence})],
                    confidence="high", meta={"confidence": "high"},
                )
                self.assert_refused(self.remediator.consider_auto(finding),
                                    "no eligible high-confidence rule match")

    def test_generated_component_and_test_matches_never_authorize_auto(self):
        excluded = [
            self.match(meta={"confidence": "high", "generator": "nvd-rulegen"}),
            self.match(namespace="nvd_components"),
            self.match(rule="NVD_CVE_2026_1234_vendor_product"),
            self.match(tags=["vulnerable_component", "kev"]),
            self.match(tags=["TEST", "malware"]),
            self.match(namespace="demo"),
            self.match(namespace="builtin"),
            self.match(rule="Demo_TestKeyword"),
            self.match(rule="EICAR_Test_File"),
            self.match(rule="SecuritySuite_Fallback_TestRule"),
        ]
        for match in excluded:
            with self.subTest(match=match):
                self.assert_refused(
                    self.remediator.consider_auto(self.finding(matches=[match])),
                    "no eligible high-confidence rule match",
                )

    def test_confidence_and_severity_cannot_come_from_different_matches(self):
        finding = self.finding(matches=[
            self.match(meta={"severity": "critical"}),
            self.match(severity="low", meta={"severity": "low", "confidence": "high"}),
        ])
        self.assert_refused(self.remediator.consider_auto(finding),
                            "no eligible high-confidence rule match")

    def test_real_eligible_match_can_authorize_alongside_excluded_match(self):
        finding = self.finding(matches=[self.match(tags=["test"]), self.match()])
        self.assertTrue(self.remediator.consider_auto(finding)["ok"])

    def test_threshold_applies_to_eligible_match(self):
        finding = self.finding(matches=[self.match(severity="high")], severity="high")
        self.assert_refused(self.remediator.consider_auto(finding),
                            "no eligible high-confidence rule match")
        self.cfg.auto_remediate_severity = "high"
        self.assertTrue(self.remediator.consider_auto(finding)["ok"])

    def test_invalid_threshold_fails_closed(self):
        finding = self.finding()
        for threshold in (None, "unknown", [], {}):
            with self.subTest(threshold=threshold):
                self.cfg.auto_remediate_severity = threshold
                self.assert_refused(self.remediator.consider_auto(finding),
                                    "invalid automatic severity threshold")

    def test_missing_or_malformed_matches_fail_closed(self):
        invalid = [[], {}, "high", [None], ["high"],
                   [self.match(meta=None)], [self.match(tags="malware")],
                   [self.match(tags=[{}])], [self.match(rule=None)],
                   [self.match(namespace=None)], [self.match(severity=[])]]
        for matches in invalid:
            with self.subTest(matches=matches):
                finding = self.finding(matches=matches)
                self.assert_refused(self.remediator.consider_auto(finding),
                                    "no eligible high-confidence rule match")
        finding = self.finding()
        finding.pop("matches")
        self.assert_refused(self.remediator.consider_auto(finding),
                            "no eligible high-confidence rule match")

    def test_hash_change_still_refuses_quarantine(self):
        finding = self.finding()
        self.target.write_bytes(b"replacement benign bytes")
        self.assert_refused(self.remediator.consider_auto(finding), "hash mismatch")

    def test_outside_watch_root_still_refused(self):
        outside = self.root / "outside.bin"
        outside.write_bytes(b"outside fixture")
        self.assert_refused(self.remediator.consider_auto(self.finding(path=outside)),
                            "outside permitted roots")
        self.assertTrue(outside.exists())

    def test_suite_owned_path_still_refused_with_broad_watch_root(self):
        protected = self.remediator.state_path
        protected.write_bytes(b"{}")
        self.cfg.watch_paths = [str(self.root)]
        self.assert_refused(self.remediator.consider_auto(self.finding(path=protected)),
                            "suite-owned path")
        self.assertEqual(protected.read_bytes(), b"{}")

    def test_auto_cannot_enable_directory_remediation(self):
        finding = self.finding()
        self.target.unlink()
        self.target.mkdir()
        self.assert_refused(
            self.remediator.act(finding["id"], "quarantine", confirm=True,
                                trigger="auto", allow_directory=True),
            "target is a directory",
        )

    def test_manual_action_still_available_without_confidence(self):
        finding = self.finding(matches=[self.match(meta={})])
        result = self.remediator.act(finding["id"], "quarantine", confirm=True)
        self.assertTrue(result["ok"])
        self.assertFalse(self.target.exists())

    def test_auto_dry_run_does_not_move_file(self):
        finding = self.finding()
        result = self.remediator.act(finding["id"], "quarantine", trigger="auto",
                                    dry_run=True)
        self.assertTrue(result["ok"])
        self.assertTrue(self.target.exists())
        self.assertIsNone(self.remediator.state_for(finding["id"]))


if __name__ == "__main__":
    unittest.main()
