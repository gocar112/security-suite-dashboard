import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from securitysuite.playbooks import PlaybookService, Training


class PlaybookTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.finding = {"id": "finding1", "event_type": "yara_match", "sha256": "a" * 64,
                        "file_path": str(Path(self.temporary.name) / "sample"), "status": "new", "matches": []}
        self.store = Mock()
        self.store.events.return_value = [self.finding]
        self.remediator = Mock()
        self.remediator.act.return_value = {"ok": True, "outcome": "would quarantine"}
        self.guidance = Mock()
        self.cfg = SimpleNamespace(triage_file=str(Path(self.temporary.name) / "triage.json"))
        self.service = PlaybookService(self.cfg, self.store, self.remediator, self.guidance)
        self.definition = {"id": "review", "name": "Review", "version": 1,
                           "steps": [{"action": "annotate", "note": "literal $(command)"},
                                     {"action": "guidance"}, {"action": "quarantine"}]}

    def test_dry_run_has_no_mutation_or_external_guidance(self):
        before = copy.deepcopy(self.finding)
        result = self.service.run({"playbook": self.definition, "finding_id": "finding1"})
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.finding, before)
        self.store.set_status.assert_not_called()
        self.guidance.for_finding.assert_not_called()
        self.assertTrue(self.remediator.act.call_args.kwargs["dry_run"])
        self.assertFalse(self.service.path.exists())

    def test_confirmation_precedes_any_live_step(self):
        result = self.service.run({"playbook": self.definition, "finding_id": "finding1", "dry_run": False})
        self.assertFalse(result["ok"])
        self.assertEqual(result["steps"], [])
        self.store.set_status.assert_not_called()
        self.remediator.act.assert_not_called()

    def test_strict_schema_and_cyclic_payload(self):
        for update in ({"version": True}, {"version": 2}, {"command": "echo unsafe"},
                       {"steps": [{"action": "execute", "command": "echo unsafe"}]},
                       {"id": "review\n"}, {"steps": []}):
            self.assertFalse(self.service.save({**self.definition, **update})["ok"])
        cyclic = {}
        cyclic["self"] = cyclic
        self.assertFalse(self.service.save(cyclic)["ok"])
        self.assertFalse(self.service.run(cyclic)["ok"])
        self.assertFalse(self.service.run({"playbook": self.definition, "finding_id": "finding1", "dry_run": 0})["ok"])

    def test_persistence_and_corrupt_storage_preserved(self):
        self.assertTrue(self.service.save(self.definition)["ok"])
        loaded = PlaybookService(self.cfg, self.store, self.remediator)
        self.assertEqual(loaded.list()["playbooks"], [self.definition])
        self.service.path.write_bytes(b'{"version":1,"version":1,"playbooks":[]}')
        corrupt = PlaybookService(self.cfg, self.store, self.remediator)
        self.assertFalse(corrupt.save(self.definition)["ok"])
        self.assertIn(b'"version":1,"version":1', self.service.path.read_bytes())

    def test_missing_hash_and_owned_storage_refused(self):
        self.finding["sha256"] = ""
        result = self.service.run({"playbook": self.definition, "finding_id": "finding1"})
        self.assertFalse(result["ok"])
        self.remediator.act.assert_not_called()
        self.finding["sha256"] = "a" * 64
        self.finding["file_path"] = str(self.service.path)
        self.assertFalse(self.service.run({"playbook": self.definition, "finding_id": "finding1"})["ok"])


class TrainingTests(unittest.TestCase):
    def test_all_500_have_exactly_one_correct_answer(self):
        training = Training()
        listing = training.list()
        self.assertEqual(listing["count"], 500)
        self.assertEqual(len({s["id"] for s in listing["scenarios"]}), 500)
        for scenario in listing["scenarios"]:
            self.assertNotIn("correct_answer", scenario)
            grades = [training.grade(scenario["id"], choice["id"]) for choice in scenario["choices"]]
            self.assertEqual(sum(g["score"] for g in grades), 1)
            self.assertTrue(all(g["synthetic"] for g in grades))
        listing["scenarios"].clear()
        self.assertEqual(len(training.list()["scenarios"]), 500)

    def test_invalid_grading_inputs(self):
        training = Training()
        scenario = training.list()["scenarios"][0]["id"]
        for identifier, answer in (([], "A"), ("unknown", "A"), (scenario, []), (scenario, True), (scenario, "A\n")):
            self.assertFalse(training.grade(identifier, answer)["ok"])
