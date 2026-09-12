"""YARA detection engine.

Compiles every rule file in the rules directory into a single ruleset (one YARA
namespace per file) and scans files in memory. Severity comes from a rule's
own metadata, so rule authors control triage priority.
"""
from __future__ import annotations

import hashlib
import math
import os
import threading
import time
from collections import Counter
from pathlib import Path

import yara

from . import attack
from .ioc import extract as extract_iocs
from .store import SEVERITY_RANK, now_iso

PREVIEW_BYTES = 48
SEVERITY_BY_TAG = {
    "critical": "critical",
    "malware": "high",
    "ransomware": "critical",
    "webshell": "high",
    "exploit": "high",
    "suspicious": "medium",
    "pua": "low",
    "test": "info",
}

FALLBACK_RULE = """
rule SecuritySuite_Fallback_TestRule
{
    meta:
        description = "Fallback rule used when no rule files are present"
        severity = "info"
        author = "security-suite"
    strings:
        $a = "malware" nocase
    condition:
        $a
}
"""


def sha256_of(path: str, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def shannon_entropy(data: bytes) -> float:
    """Bits per byte. Above ~7.2 usually means packed, encrypted or compressed."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return round(
        -sum((c / total) * math.log2(c / total) for c in counts.values()), 3
    )


def printable(raw: bytes) -> str:
    text = raw[:PREVIEW_BYTES]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in text)


class RuleLoadError(Exception):
    pass


class YaraEngine:
    """Holds the compiled ruleset and performs scans. Safe to share across threads."""

    def __init__(self, rules_dir: str, max_file_bytes: int = 64 * 1024 * 1024):
        self.rules_dir = Path(rules_dir)
        self.max_file_bytes = max_file_bytes
        self._lock = threading.RLock()
        self.rules: yara.Rules | None = None
        self.rule_index: list[dict] = []
        self.load_errors: list[dict] = []
        self.using_fallback = False
        self.loaded_at: str | None = None
        self.compile_ms = 0.0
        self.reload()

    # ---------------------------------------------------------------- rules
    def _rule_files(self) -> list[Path]:
        if not self.rules_dir.exists():
            return []
        files = []
        for suffix in ("*.yar", "*.yara"):
            files.extend(sorted(self.rules_dir.rglob(suffix)))
        return files

    def reload(self) -> dict:
        """Recompile rules. Bad files are reported, not silently swallowed."""
        started = time.perf_counter()
        errors: list[dict] = []
        sources: dict[str, str] = {}

        for path in self._rule_files():
            namespace = path.stem
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                yara.compile(source=text)  # validate individually for a precise error
            except (OSError, yara.Error) as exc:
                errors.append({"file": str(path), "error": str(exc)})
                continue
            sources[namespace] = text

        using_fallback = False
        if not sources:
            sources = {"builtin": FALLBACK_RULE}
            using_fallback = True

        try:
            compiled = yara.compile(sources=sources)
        except yara.Error as exc:
            # Should not happen since each file validated, but never leave the
            # engine without a ruleset.
            errors.append({"file": "<combined>", "error": str(exc)})
            compiled = yara.compile(source=FALLBACK_RULE)
            using_fallback = True

        index = self._index_rules(sources)
        with self._lock:
            self.rules = compiled
            self.rule_index = index
            self.load_errors = errors
            self.using_fallback = using_fallback
            self.loaded_at = now_iso()
            self.compile_ms = round((time.perf_counter() - started) * 1000, 1)
        return self.info()

    @staticmethod
    def _index_rules(sources: dict[str, str]) -> list[dict]:
        """Cheap metadata index so the UI can list what is actually loaded."""
        index = []
        for namespace, text in sources.items():
            # No compile here. reload() has already compiled every source in
            # this dict in order to validate it, and the index is built purely
            # by reading the text. Compiling a second time cost ~31% of every
            # reload and the result was discarded unused.
            #
            # yara-python has no rule introspection before a match, so parse the
            # declarations we care about out of the source text.
            current: dict | None = None
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("rule ") and "{" not in stripped[:5]:
                    name = stripped[5:].split("{")[0].split(":")[0].strip()
                    tags = []
                    if ":" in stripped:
                        tags = stripped.split(":", 1)[1].split("{")[0].split()
                    current = {
                        "namespace": namespace, "rule": name, "tags": tags,
                        # Namespace default covers the generated ruleset, which
                        # is not tagged rule by rule.
                        "mitre": list(attack.NAMESPACE_DEFAULTS.get(namespace, ())),
                    }
                    index.append(current)
                elif current is not None and stripped.startswith(("mitre ", "mitre=")):
                    ids = attack.parse_ids(stripped.split("=", 1)[-1])
                    if ids:
                        current["mitre"] = ids
        return index

    def info(self) -> dict:
        with self._lock:
            return {
                "rules_dir": str(self.rules_dir),
                "rule_count": len(self.rule_index),
                "rule_files": sorted({r["namespace"] for r in self.rule_index}),
                "rules": self.rule_index,
                "load_errors": self.load_errors,
                "using_fallback": self.using_fallback,
                "loaded_at": self.loaded_at,
                "compile_ms": self.compile_ms,
            }

    # ---------------------------------------------------------------- scans
    @staticmethod
    def severity_of(meta: dict, tags: list) -> str:
        declared = str(meta.get("severity", "")).lower().strip()
        if declared in SEVERITY_RANK:
            return declared
        for tag in tags:
            mapped = SEVERITY_BY_TAG.get(str(tag).lower())
            if mapped:
                return mapped
        return "medium"

    def scan_bytes(self, data: bytes, label: str = "<buffer>") -> dict:
        with self._lock:
            rules = self.rules
        started = time.perf_counter()
        # Same timeout as scan_file: an adversarial buffer must not be
        # able to park a scan thread indefinitely.
        raw_matches = rules.match(data=data, timeout=60) if rules else []
        return self._result(label, data, raw_matches, started, len(data))

    def scan_file(self, path: str) -> dict:
        """Scan one file. Returns a result dict even when nothing matches."""
        with self._lock:
            rules = self.rules
        stat = os.stat(path)
        if stat.st_size > self.max_file_bytes:
            return {
                "file_path": str(path),
                "skipped": "file larger than max_file_mb",
                "file_size": stat.st_size,
                "matches": [],
                "severity": None,
            }
        started = time.perf_counter()
        # One read for both the preview bytes and the digest. This used to read
        # the head, then let YARA read the file, then call sha256_of() to read
        # it a third time.
        digest = hashlib.sha256()
        head = b""
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                if not head:
                    head = block          # first MiB drives entropy + preview
                digest.update(block)
        raw_matches = rules.match(filepath=str(path), timeout=60) if rules else []
        result = self._result(str(path), head, raw_matches, started, stat.st_size)
        result["sha256"] = digest.hexdigest()
        result["file_name"] = os.path.basename(path)
        result["modified"] = time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime)
        )
        return result

    def _result(self, label, sample: bytes, raw_matches, started, size) -> dict:
        matches = []
        for match in raw_matches:
            meta = dict(match.meta)
            tags = list(match.tags)
            strings = []
            for sm in match.strings:
                for instance in sm.instances[:5]:
                    strings.append(
                        {
                            "identifier": sm.identifier,
                            "offset": instance.offset,
                            "preview": printable(instance.matched_data),
                        }
                    )
            matches.append(
                {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": tags,
                    "meta": meta,
                    "severity": self.severity_of(meta, tags),
                    "description": meta.get("description", ""),
                    # Resolved here so a finding carries its ATT&CK context from
                    # the moment it is written, rather than needing a second
                    # lookup against the ruleset that may since have reloaded.
                    "attack": attack.resolve(meta, match.namespace),
                    "strings": strings[:12],
                }
            )
        severity = None
        iocs = {"indicators": [], "counts": {}, "total": 0}
        if matches:
            severity = min(
                (m["severity"] for m in matches), key=lambda s: SEVERITY_RANK[s]
            )
            # Only extract for files that tripped a rule: a clean scan does not
            # need observables, and running 13 regexes over every file would
            # dominate the scan budget.
            try:
                iocs = extract_iocs(sample)
            except Exception:
                iocs = {"indicators": [], "counts": {}, "total": 0,
                        "error": "extraction failed"}
        return {
            "file_path": str(label),
            "file_size": size,
            "entropy": shannon_entropy(sample),
            "scan_ms": round((time.perf_counter() - started) * 1000, 2),
            "matches": matches,
            "severity": severity,
            "iocs": iocs,
        }
