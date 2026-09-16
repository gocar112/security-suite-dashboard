import tempfile
import unittest
from pathlib import Path

from securitysuite.store import EventStore


class StoreTests(unittest.TestCase):
    def test_scan_total_outgrows_findings_buffer_without_counting_skips(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = EventStore(str(root / "findings.ndjson"), str(root / "triage.json"), 2)
            for _ in range(5):
                store.add({"event_type": "scan", "verdict": "no match"}, persist=False)
            store.add({"event_type": "scan", "skipped": "too large"}, persist=False)
            self.assertEqual(len(store.events(event_type="all")), 2)
            self.assertEqual(store.stats()["files_scanned"], 5)


if __name__ == "__main__":
    unittest.main()
