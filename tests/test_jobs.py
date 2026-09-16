import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from securitysuite.jobs import ScanJobs
from securitysuite.watcher import Monitor


class JobsTests(unittest.TestCase):
    def test_streams_more_than_5000_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(5001):
                (root / str(index)).touch()
            monitor = SimpleNamespace(cfg=SimpleNamespace(),
                                      scan_and_record=Mock(return_value={"event_type": "scan"}))
            jobs = ScanJobs(monitor)
            jobs.start(root)
            jobs._worker.join(30)
            self.assertFalse(jobs._worker.is_alive())
            snapshot = jobs.status()["jobs"][0]
            self.assertEqual(snapshot["state"], "completed")
            self.assertEqual(snapshot["scanned"], 5001)
            self.assertEqual(monitor.scan_and_record.call_count, 5001)

    def test_cancel_retains_active_worker_until_cleanup(self):
        entered, release = threading.Event(), threading.Event()
        def scan(*args, **kwargs):
            entered.set()
            release.wait(5)
            return {"event_type": "yara_match"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample"
            path.touch()
            jobs = ScanJobs(SimpleNamespace(cfg=SimpleNamespace(), scan_and_record=scan))
            started = jobs.start(path)
            try:
                self.assertTrue(entered.wait(3))
                self.assertTrue(jobs.cancel(started["id"])["cancellation_requested"])
                self.assertIn("error", jobs.start(path))
            finally:
                release.set()
                jobs._worker.join(5)
            self.assertEqual(jobs.status()["jobs"][0]["state"], "cancelled")

    def test_exclusions_and_invalid_events(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "findings"
            log.touch()
            (root / "sample").touch()
            jobs = ScanJobs(SimpleNamespace(cfg=SimpleNamespace(findings_log=log),
                                           scan_and_record=Mock(return_value=None)))
            jobs.start(root)
            jobs._worker.join(5)
            snapshot = jobs.status()["jobs"][0]
            self.assertEqual(snapshot["skip_reasons"], {"excluded": 1})
            self.assertEqual(snapshot["errors"], 1)
            self.assertEqual(snapshot["scanned"], 0)
            self.assertIn("error", jobs.cancel("unknown"))
            snapshot["skip_reasons"].clear()
            self.assertTrue(jobs.status()["jobs"][0]["skip_reasons"])

    def test_missing_root_is_error(self):
        with tempfile.TemporaryDirectory() as directory:
            jobs = ScanJobs(SimpleNamespace(cfg=SimpleNamespace()))
            jobs.start(Path(directory) / "missing")
            jobs._worker.join(5)
            self.assertEqual(jobs.status()["jobs"][0]["state"], "error")

    def test_root_enumeration_failure_is_counted_once(self):
        with tempfile.TemporaryDirectory() as directory:
            iterator = Mock()
            iterator.__next__ = Mock(side_effect=PermissionError("directory unavailable"))
            jobs = ScanJobs(SimpleNamespace(cfg=SimpleNamespace()))
            with patch("securitysuite.jobs.os.scandir", return_value=iterator):
                jobs.start(directory)
                jobs._worker.join(5)
            snapshot = jobs.status()["jobs"][0]
            self.assertEqual(snapshot["state"], "error")
            self.assertEqual(snapshot["errors"], 1)
            self.assertEqual(snapshot["skipped"], 1)
            iterator.close.assert_called_once()

    def test_cli_sidecars_and_legacy_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("triage.json", "playbooks.json", "response-policy.json", "blocked-domains.json", "sample1", "sample2"):
                (root / name).touch()
            monitor = SimpleNamespace(cfg=SimpleNamespace(triage_file=root / "triage.json"),
                                      _stop_event=threading.Event(),
                                      scan_and_record=Mock(return_value={"event_type": "scan"}))
            with self.assertWarns(FutureWarning):
                result = Monitor.scan_path(monitor, str(root), max_files=1)
            self.assertEqual(result["files_scanned"], 2)
            self.assertEqual(result["skipped"], 4)
            self.assertEqual(result["errors"], 0)
            self.assertEqual(result["state"], "completed")
            self.assertIn("elapsed_ms", result)
            self.assertFalse(hasattr(monitor, "_scanned"))
