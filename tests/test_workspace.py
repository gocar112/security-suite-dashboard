"""Workbench input boundaries, offline analysis, and persistent response policy."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from securitysuite.config import Config
from securitysuite.store import EventStore
from securitysuite.workspace import Workspace


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.cfg = Config(triage_file=str(root / "triage.json"),
                          findings_log=str(root / "findings.ndjson"),
                          watch_paths=[str(root / "watch")])
        self.store = EventStore(self.cfg.findings_log, self.cfg.triage_file)
        self.engine = Mock()
        self.engine.scan_bytes.return_value = {"matches": [], "iocs": {}}
        self.workspace = Workspace(self.cfg, self.engine, self.store)

    def test_analysis_never_executes_or_records_evidence(self):
        with patch("subprocess.run", side_effect=AssertionError("Unexpected execution")):
            result = self.workspace.analyze({"text": "print('never execute')"})
        self.assertFalse(result["executed"])
        self.assertFalse(result["persisted"])
        self.assertEqual(self.store.events(event_type="all"), [])
        self.assertEqual(len(result["sha256"]), 64)
        with self.assertRaises(ValueError):
            self.workspace.analyze({"text": "x" * 48001})

    def test_policy_persists_only_quarantine(self):
        self.workspace.set_policy({"enabled": True})
        self.assertEqual(self.workspace.policy()["action"], "quarantine")
        self.cfg.auto_remediate = False
        Workspace(self.cfg, self.engine, self.store)
        self.assertTrue(self.cfg.auto_remediate)
        self.assertEqual(self.cfg.auto_remediate_action, "quarantine")
        with self.assertRaises(ValueError):
            self.workspace.set_policy({"enabled": "true"})

    @staticmethod
    def alert(**fields):
        return dict({"event_type": "alert", "src_ip": "192.168.1.2",
                     "dest_ip": "198.51.100.2", "alert": {
                         "signature": "Test network alert", "severity": 1}}, **fields)

    def test_eve_ignores_untrusted_file_paths_and_deduplicates(self):
        raw = json.dumps(self.alert(file_path="C:/Windows/important.exe", sha256="a" * 64))
        self.assertEqual(self.workspace.import_eve({"text": raw})["imported"], 1)
        self.assertEqual(self.workspace.import_eve({"text": raw})["duplicates"], 1)
        event = self.store.events(event_type="ids_alert")[0]
        self.assertNotIn("file_path", event)
        self.assertNotIn("sha256", event)
        self.assertEqual(event["severity"], "high")

    def test_eve_invalid_batch_does_not_partially_import(self):
        raw = json.dumps(self.alert()) + "\n" + json.dumps(self.alert(src_ip="invalid"))
        with self.assertRaises(ValueError):
            self.workspace.import_eve({"text": raw})
        self.assertEqual(self.store.events(event_type="ids_alert"), [])

    def test_domains_export_requires_reviewed_names(self):
        result = self.workspace.save_domains({"text": "ads.example.com\nads.example.com\nspy.example.net"})
        self.assertEqual(len(result["domains"]), 2)
        self.assertFalse(result["enforced"])
        for invalid in ("https://ads.example.com", "192.168.1.2", "router.local", "bad..example", "*.com"):
            with self.subTest(domain=invalid), self.assertRaises(ValueError):
                self.workspace.save_domains({"text": invalid})
        self.assertEqual(self.workspace.domains(), result["domains"])

    def test_native_av_check_uses_hidden_fixed_command(self):
        with patch("securitysuite.workspace.platform.system", return_value="Windows"), \
             patch("securitysuite.workspace.subprocess.run") as run:
            run.return_value.stdout = '[{"displayName":"Test AV","productState":123}]'
            result = self.workspace.check_native_av()
        self.assertEqual(result["products"][0]["name"], "Test AV")
        self.assertEqual(run.call_args.args[0][0], "powershell.exe")
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertIn("creationflags", run.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
