"""Strict JSON playbooks and contained, synthetic tabletop training.

PlaybookService(cfg, store, remediator, guidance=None):
  schema() -> JSON Schema for a playbook; $defs.run describes run requests.
  list() -> {playbooks: [definitions], skills: [action metadata]}.
  save(definition) -> {ok, playbook}, upserting by id in playbooks.json beside
      cfg.triage_file. Errors return {ok: False, error}.
  run({playbook: definition_or_saved_id, finding_id, dry_run=True,
       confirm=False}) -> {ok, playbook: id, finding_id, dry_run, steps}.
      Live quarantine requires confirm=True. Steps stop on failure; completed
      live steps are not rolled back. Errors also include error/refused.

Training().list() -> {scenarios, count, synthetic, disclaimer, mode, players,
                     max_score}; choices contain id/label, never answer keys.
Training().grade(id, answer) -> {ok, id, answer, correct, correct_answer,
                                score, max_score, explanation, synthetic}.
      Answer is a choice id (A/B/C/D); score is 0 or 1 per player per question.
      Grading is stateless: the caller owns turns and each player's totals.

No scripts, commands, templates, uploads, or executable training artifacts are
accepted. The only filesystem action is delegated to Remediator.act.
"""
from __future__ import annotations

import copy
import json
import os
import re
import tempfile
import threading
from pathlib import Path

from .guidance import Guidance
from .shield import _attack_pressure

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "web" / "playbook.schema.json"
MAX_PLAYBOOKS = 100
MAX_PLAYBOOK_BYTES = 32 * 1024
MAX_STORAGE_BYTES = 256 * 1024
MAX_REQUEST_BYTES = MAX_PLAYBOOK_BYTES + 1024


def _validate(value, rule: dict, root: dict, location: str = "payload") -> None:
    """Validate the fixed schema's vocabulary without an extra dependency.

    This is intentionally limited to the keywords in our checked-in schema;
    callers cannot supply a schema or a reference to resolve.
    """
    if "$ref" in rule:
        target = root
        for part in rule["$ref"][2:].split("/") if rule["$ref"] != "#" else ():
            target = target[part]
        return _validate(value, target, root, location)
    if "oneOf" in rule:
        matches = 0
        for option in rule["oneOf"]:
            try:
                _validate(value, option, root, location)
                matches += 1
            except ValueError:
                pass
        if matches != 1:
            raise ValueError(location + " must match exactly one allowed shape")
        return
    kind = rule.get("type")
    types = {"object": dict, "array": list, "string": str,
             "integer": int, "boolean": bool}
    if kind and type(value) is not types[kind]:
        raise ValueError(location + " must be " + kind)
    if "const" in rule and value != rule["const"]:
        raise ValueError(location + " has an unsupported value/version")
    if "enum" in rule and value not in rule["enum"]:
        raise ValueError(location + " has an unsupported value")
    if kind == "object":
        properties = rule["properties"]
        if set(value) - set(properties):
            raise ValueError(location + " contains unknown fields")
        if set(rule.get("required", ())) - set(value):
            raise ValueError(location + " is missing required fields")
        for key, item in value.items():
            _validate(item, properties[key], root, location + "." + key)
    elif kind == "array":
        if not rule["minItems"] <= len(value) <= rule["maxItems"]:
            raise ValueError(location + " has an invalid number of steps (1-12)")
        for index, item in enumerate(value):
            _validate(item, rule["items"], root, "%s[%d]" % (location, index))
    elif kind == "string":
        if not rule.get("minLength", 0) <= len(value) <= rule.get("maxLength", 2000):
            raise ValueError(location + " has an invalid length")
        if "pattern" in rule and not re.search(rule["pattern"], value):
            raise ValueError(location + " has an invalid format")


def _encode(value, limit: int) -> bytes:
    try:
        data = json.dumps(value, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("payload must be strict UTF-8 JSON") from exc
    if len(data) > limit:
        raise ValueError("JSON byte limit exceeded (%d)" % limit)
    return data


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field: " + key)
        result[key] = value
    return result


class PlaybookService:
    def __init__(self, cfg, store, remediator, guidance=None):
        self.store = store
        self.remediator = remediator
        self.guidance = guidance
        self.path = Path(cfg.triage_file).with_name("playbooks.json")
        self._schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self._lock = threading.RLock()
        self._playbooks: dict[str, dict] = {}
        self._storage_error = ""
        self._load()

    def schema(self) -> dict:
        return copy.deepcopy(self._schema)

    def list(self) -> dict:
        with self._lock:
            skills = []
            for rule in self._schema["properties"]["steps"]["items"]["oneOf"]:
                action = rule["properties"]["action"]["const"]
                skills.append({"action": action, "label": rule["title"],
                               "description": rule["description"],
                               "mutates": action in ("annotate", "quarantine"),
                               "requires_confirmation": action == "quarantine"})
            result = {"playbooks": copy.deepcopy(list(self._playbooks.values())),
                      "skills": skills}
            if self._storage_error:
                result["error"] = self._storage_error
            return result

    def _definition(self, payload) -> dict:
        _encode(payload, MAX_PLAYBOOK_BYTES)
        _validate(payload, self._schema, self._schema)
        return copy.deepcopy(payload)

    def _load(self) -> None:
        try:
            with self.path.open("rb") as handle:
                raw = handle.read(MAX_STORAGE_BYTES + 1)
            if len(raw) > MAX_STORAGE_BYTES:
                raise ValueError("storage byte limit exceeded")
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
            if (type(document) is not dict or set(document) != {"version", "playbooks"}
                    or type(document["version"]) is not int or document["version"] != 1
                    or type(document["playbooks"]) is not list
                    or len(document["playbooks"]) > MAX_PLAYBOOKS):
                raise ValueError("invalid playbook storage envelope")
            loaded = {}
            for payload in document["playbooks"]:
                definition = self._definition(payload)
                if definition["id"] in loaded:
                    raise ValueError("duplicate saved playbook id")
                loaded[definition["id"]] = definition
            self._playbooks = loaded
        except FileNotFoundError:
            return
        except (OSError, ValueError, RecursionError) as exc:
            # Preserve corrupt/unsupported storage for inspection, never replace
            # it with an apparently successful empty catalog on the next save.
            self._storage_error = "Could not load playbooks: " + str(exc)

    def _persist(self, data: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", dir=self.path.parent,
                                             prefix=".playbooks-", suffix=".tmp",
                                             delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def save(self, payload) -> dict:
        try:
            definition = self._definition(payload)
            with self._lock:
                if self._storage_error:
                    return {"ok": False, "error": self._storage_error}
                candidate = dict(self._playbooks)
                candidate[definition["id"]] = definition
                if len(candidate) > MAX_PLAYBOOKS:
                    raise ValueError("at most %d playbooks may be saved" % MAX_PLAYBOOKS)
                data = _encode({"version": 1, "playbooks": list(candidate.values())},
                               MAX_STORAGE_BYTES)
                self._persist(data)
                self._playbooks = candidate
            return {"ok": True, "playbook": copy.deepcopy(definition)}
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}

    def _finding(self, finding_id: str) -> dict | None:
        for event in self.store.events(limit=5000, event_type="all"):
            if event.get("id") == finding_id:
                return copy.deepcopy(event)
        return None

    def _guidance(self, finding: dict, dry_run: bool) -> dict:
        if not dry_run and self.guidance is not None:
            return copy.deepcopy(self.guidance.for_finding(copy.deepcopy(finding)))
        return {"finding": finding["id"], "playbook": copy.deepcopy(
                    Guidance.playbook_for(copy.deepcopy(finding))),
                "offline": True, "cve_lookups_skipped": True}

    def _quarantine(self, finding_id: str, definition: dict, *, dry_run: bool,
                    confirm: bool = False) -> dict:
        # Resolve again before each attempt. The existing remediator re-resolves
        # the same stored id and performs the actual hash/path checks itself.
        finding = self._finding(finding_id)
        if finding is None or finding.get("event_type") != "yara_match":
            return {"ok": False, "refused": "not a stored yara_match finding"}
        digest = finding.get("sha256")
        if type(digest) is not str or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            return {"ok": False, "refused": "a recorded SHA-256 is required"}
        path = finding.get("file_path")
        if type(path) is not str or not path or "\x00" in path:
            return {"ok": False, "refused": "a stored file path is required"}
        # The new sidecar may live outside the remediator's suite-owned tree.
        target = os.path.normcase(os.path.realpath(path))
        sidecar = os.path.normcase(os.path.realpath(self.path))
        if target == sidecar or (self.path.exists() and os.path.exists(path)
                                 and os.path.samefile(path, self.path)):
            return {"ok": False, "refused": "suite-owned playbook storage"}
        return copy.deepcopy(self.remediator.act(
            finding_id, "quarantine", dry_run=dry_run, confirm=confirm,
            allow_directory=False, trigger="playbook:" + definition["id"]))

    def run(self, payload) -> dict:
        result = {"ok": False, "steps": []}
        try:
            _encode(payload, MAX_REQUEST_BYTES)
            _validate(payload, self._schema["$defs"]["run"], self._schema)
            request = copy.deepcopy(payload)
            selected = request["playbook"]
            if type(selected) is str:
                with self._lock:
                    if selected not in self._playbooks:
                        raise ValueError("unknown saved playbook")
                    definition = self._definition(self._playbooks[selected])
            else:
                definition = self._definition(selected)
            dry_run = request.get("dry_run", True)
            finding_id = request["finding_id"]
            result.update({"playbook": definition["id"], "finding_id": finding_id,
                           "dry_run": dry_run})
            finding = self._finding(finding_id)
            if finding is None or finding.get("event_type") != "yara_match":
                raise ValueError("only a stored yara_match finding can run a playbook")
            quarantine = any(s["action"] == "quarantine" for s in definition["steps"])
            if quarantine and not dry_run:
                if not request.get("confirm", False):
                    result["refused"] = "confirmation required"
                    raise ValueError("live quarantine requires confirm=true")
                preview = self._quarantine(finding_id, definition, dry_run=True)
                if not preview.get("ok"):
                    result.update({"refused": preview.get("refused", "quarantine refused"),
                                   "preflight": preview})
                    raise ValueError(result["refused"])
            for step in definition["steps"]:
                action = step["action"]
                outcome = {"action": action, "ok": True}
                try:
                    if action == "annotate":
                        status = step.get("status", finding.get("status", "new"))
                        if not dry_run:
                            updated = self.store.set_status(finding_id, status, step["note"])
                            if updated is None:
                                raise ValueError("finding is no longer stored")
                        finding.update(status=status, triage_note=step["note"])
                        outcome.update({"outcome": "would annotate" if dry_run else "annotated",
                                        "status": status, "note": step["note"]})
                    elif action == "guidance":
                        outcome.update({"outcome": "guidance", "guidance": self._guidance(
                            finding, dry_run)})
                    elif action == "quarantine":
                        outcome.update(self._quarantine(
                            finding_id, definition, dry_run=dry_run,
                            confirm=request.get("confirm", False) and not dry_run))
                except Exception as exc:
                    outcome.update({"ok": False, "error": str(exc)})
                result["steps"].append(outcome)
                if not outcome.get("ok"):
                    result.update({"error": outcome.get("error") or outcome.get("refused")
                                   or "step failed", "refused": outcome.get("refused", "step failed")})
                    return result
            result["ok"] = True
        except (OSError, ValueError) as exc:
            result["error"] = str(exc)
        return result


TRAINING_DISCLAIMER = (
    "500 synthetic tabletop scenarios derived from shield._attack_pressure. "
    "These are NOT 500 validated exploits or malware tests. "
    "No payloads are executed and no findings or remediation state are changed."
)


class Training:
    """Local two-player pass-and-play question bank; no shared game state or I/O."""

    def __init__(self):
        self._scenarios = {}
        self._answers = {}
        self._explanations = {}
        for index, pressure in enumerate(_attack_pressure(500)):
            scenario_id = pressure["id"]
            options = [
                (pressure["defense"], True),
                ("Close the alert without checking the evidence or documenting it.", False),
                ("Delete every file on the affected system before reviewing evidence.", False),
                ("Disable monitoring and keep using the suspected entry point.", False),
            ]
            rotation = index % len(options)
            options = options[rotation:] + options[:rotation]
            choices = []
            for letter, (label, correct) in zip("ABCD", options):
                choices.append({"id": letter, "label": label})
                if correct:
                    self._answers[scenario_id] = letter
            self._scenarios[scenario_id] = {
                "id": scenario_id, "synthetic": True, "goal": pressure["goal"],
                "entry": pressure["entry"], "severity": pressure["severity"],
                "question": "Synthetic tabletop: evidence suggests %s via %s. "
                            "Which response best matches the modeled defensive plan?"
                            % (pressure["goal"], pressure["entry"]),
                "choices": choices,
            }
            self._explanations[scenario_id] = (
                "For the modeled %s scenario via %s: %s Review evidence and "
                "scope before acting; a detection alone does not prove compromise. "
                "The other choices skip investigation, destroy evidence, or reduce visibility. "
                "This is a synthetic planning exercise, not a validated attack test."
                % (pressure["goal"], pressure["entry"], pressure["defense"]))

    def list(self) -> dict:
        return {"scenarios": copy.deepcopy(list(self._scenarios.values())),
                "count": len(self._scenarios), "synthetic": True,
                "disclaimer": TRAINING_DISCLAIMER, "mode": "pass-and-play",
                "players": 2, "max_score": 1}

    def grade(self, id: str, answer: str) -> dict:
        if type(id) is not str or id not in self._scenarios:
            return {"ok": False, "error": "unknown scenario id"}
        if type(answer) is not str or answer not in ("A", "B", "C", "D"):
            return {"ok": False, "error": "answer must be a choice id: A, B, C, or D"}
        correct = answer == self._answers[id]
        return {"ok": True, "id": id, "answer": answer, "correct": correct,
                "correct_answer": self._answers[id], "score": int(correct),
                "max_score": 1, "explanation": self._explanations[id],
                "synthetic": True}
