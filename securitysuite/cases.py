"""Cases: the container triage does not have.

Triage marks a single finding acknowledged or resolved. An intrusion is not a
single finding, and "resolved" on six rows says nothing about whether anyone
understood how they were related, what was done, or why it was closed. A case
holds those findings together with an owner, a status and the notes that make
the decision reviewable later.

Persistence follows the triage.json overlay already in store.py: a small JSON
file beside the findings log, written whole, holding only what the findings
themselves cannot. Cases reference findings by id and never copy them, so a
case cannot drift out of date with the evidence it points at.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from .store import SEVERITY_RANK, new_id, now_iso

STATUSES = ("open", "investigating", "contained", "closed")


class CaseStore:
    """Thread-safe JSON-backed case list."""

    def __init__(self, path: str):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._cases: dict[str, dict] = {}
        self._load()

    # ------------------------------------------------------------------ io
    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if isinstance(raw, dict):
            self._cases = {k: v for k, v in raw.items() if isinstance(v, dict)}

    def _persist(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._cases, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as exc:
            print("[-] Could not persist cases: " + str(exc))

    # --------------------------------------------------------------- write
    def create(self, title: str, owner: str = "", severity: str = "medium",
               finding_ids: list | None = None, summary: str = "") -> dict:
        title = (title or "").strip()[:160]
        if not title:
            raise ValueError("title is required")
        case_id = new_id()
        case = {
            "id": case_id,
            "title": title,
            "owner": (owner or "").strip()[:80],
            "status": "open",
            "severity": severity if severity in SEVERITY_RANK else "medium",
            "summary": (summary or "").strip()[:4000],
            "finding_ids": list(dict.fromkeys(finding_ids or []))[:500],
            "notes": [],
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
        with self._lock:
            self._cases[case_id] = case
            self._persist()
        return case

    def update(self, case_id: str, **fields) -> dict | None:
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                return None
            if "title" in fields and str(fields["title"]).strip():
                case["title"] = str(fields["title"]).strip()[:160]
            if "owner" in fields:
                case["owner"] = str(fields["owner"]).strip()[:80]
            if "summary" in fields:
                case["summary"] = str(fields["summary"]).strip()[:4000]
            status = fields.get("status")
            if status in STATUSES:
                case["status"] = status
            severity = fields.get("severity")
            if severity in SEVERITY_RANK:
                case["severity"] = severity
            case["updated_at"] = now_iso()
            self._persist()
            return dict(case)

    def link(self, case_id: str, finding_ids: list, detach: bool = False) -> dict | None:
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                return None
            current = list(case.get("finding_ids") or [])
            if detach:
                drop = set(map(str, finding_ids))
                current = [f for f in current if str(f) not in drop]
            else:
                for fid in finding_ids:
                    if fid and fid not in current:
                        current.append(fid)
            case["finding_ids"] = current[:500]
            case["updated_at"] = now_iso()
            self._persist()
            return dict(case)

    def add_note(self, case_id: str, text: str, author: str = "") -> dict | None:
        text = (text or "").strip()[:4000]
        if not text:
            return None
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                return None
            case.setdefault("notes", []).append({
                "at": now_iso(), "author": (author or "").strip()[:80], "text": text})
            case["notes"] = case["notes"][-200:]
            case["updated_at"] = now_iso()
            self._persist()
            return dict(case)

    def delete(self, case_id: str) -> bool:
        with self._lock:
            if case_id not in self._cases:
                return False
            del self._cases[case_id]
            self._persist()
            return True

    # ---------------------------------------------------------------- read
    def get(self, case_id: str) -> dict | None:
        with self._lock:
            case = self._cases.get(case_id)
            return dict(case) if case else None

    def all(self, status: str = "") -> list[dict]:
        with self._lock:
            cases = [dict(c) for c in self._cases.values()]
        if status and status != "all":
            cases = [c for c in cases if c.get("status") == status]
        cases.sort(key=lambda c: (
            SEVERITY_RANK.get(c.get("severity", "medium"), 9),
            c.get("updated_at") or ""), reverse=False)
        return cases

    def summary(self) -> dict:
        with self._lock:
            cases = list(self._cases.values())
        by_status = {name: 0 for name in STATUSES}
        for case in cases:
            by_status[case.get("status", "open")] = \
                by_status.get(case.get("status", "open"), 0) + 1
        return {
            "total": len(cases),
            "by_status": by_status,
            "open": sum(1 for c in cases if c.get("status") != "closed"),
        }
