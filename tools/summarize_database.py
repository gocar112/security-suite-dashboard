"""Summarise local Security Studio state into a small Markdown report."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_json(path: Path, fallback):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def load_ndjson(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return rows
    return rows


def count_records(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.strip():
                    total += 1
    except OSError:
        return 0
    return total


def bullet_map(values: dict) -> list[str]:
    if not values:
        return ["- none"]
    return [f"- {key}: {value}" for key, value in sorted(values.items())]


def summarise(root: Path) -> str:
    data_dir = root / "data"
    nvd_dir = root / "nvds"
    findings = load_ndjson(data_dir / "findings.ndjson")
    triage = load_json(data_dir / "triage.json", {})
    remediation = load_json(data_dir / "remediation.json", {})
    nvd_index = load_json(nvd_dir / "index.json", {})

    event_types = Counter(str(row.get("event_type", "unknown")) for row in findings)
    severities = Counter(
        str(row.get("severity", "info"))
        for row in findings
        if row.get("event_type") == "yara_match"
    )
    statuses = Counter(str(row.get("status", "new")) for row in findings)
    quarantined = sum(
        1 for value in remediation.values()
        if isinstance(value, dict) and value.get("action") == "quarantine"
    )
    quarantine_items = [
        item for item in (root / "quarantine").glob("*")
        if item.name != ".gitkeep"
    ]
    backup_dirs = sorted((data_dir / "log-backups").glob("*"), key=lambda p: p.name)

    generated = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    lines = [
        "# Database Summary",
        "",
        f"Generated: `{generated}`",
        "",
        "## NVD Cache",
        "",
        f"- Last sync: `{nvd_index.get('last_sync', 'not synced')}`",
        f"- Window: `{nvd_index.get('window_start', '-')}` to `{nvd_index.get('window_end', '-')}`",
        f"- Cached records: `{nvd_index.get('cached', count_records(nvd_dir / 'cves.ndjson'))}`",
        f"- Total in window: `{nvd_index.get('total_in_window', '-')}`",
        f"- Truncated: `{nvd_index.get('truncated', '-')}`",
        f"- Pages fetched: `{nvd_index.get('pages_fetched', '-')}`",
        "",
        "Severity cache counts:",
        *bullet_map(nvd_index.get("by_severity", {})),
        "",
        "## Findings Log",
        "",
        f"- Active findings/events: `{len(findings)}`",
        f"- Triage sidecar entries: `{len(triage)}`",
        f"- Remediation state entries: `{len(remediation)}`",
        f"- Quarantined active states: `{quarantined}`",
        f"- Quarantine directory entries: `{len(quarantine_items)}`",
        f"- Log backups: `{len(backup_dirs)}`",
        "",
        "Event types:",
        *bullet_map(dict(event_types)),
        "",
        "Detection severities:",
        *bullet_map(dict(severities)),
        "",
        "Statuses:",
        *bullet_map(dict(statuses)),
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT), help="project root")
    parser.add_argument("--output", default="", help="optional Markdown output path")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    report = summarise(root)
    if args.output:
        target = Path(args.output)
        if not target.is_absolute():
            target = root / target
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(report, encoding="utf-8")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
