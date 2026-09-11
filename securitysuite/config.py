"""Configuration for the Security Suite.

Loads ``config.json`` from the project root when present, otherwise falls back
to defaults that work out of the box on Windows and Linux.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = ROOT / "config.json"


@dataclass
class Config:
    # --- monitoring ---
    watch_paths: list = field(default_factory=lambda: [str(ROOT / "uploads")])
    recursive: bool = True
    poll_interval: float = 2.0
    # A file must stop changing for this long before it is scanned, so we never
    # scan a half-written upload.
    settle_seconds: float = 1.0
    max_file_mb: float = 64.0
    ignore_suffixes: list = field(default_factory=lambda: [".tmp", ".part", ".crdownload", ".swp"])
    scan_existing_on_start: bool = False

    # --- detection ---
    rules_dir: str = str(ROOT / "rules")

    # --- telemetry correlation ---
    lookback_minutes: int = 5
    auth_log_path: str = "/var/log/auth.log"
    telemetry_cache_seconds: float = 15.0
    max_telemetry_events: int = 25

    # --- storage ---
    findings_log: str = str(ROOT / "data" / "findings.ndjson")
    triage_file: str = str(ROOT / "data" / "triage.json")
    history_limit: int = 2000

    # --- server ---
    host: str = "127.0.0.1"
    port: int = 8787

    @property
    def max_file_bytes(self) -> int:
        return int(self.max_file_mb * 1024 * 1024)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: Path | None = None) -> Path:
        path = path or CONFIG_FILE
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path


def load_config(path: Path | None = None) -> Config:
    path = path or CONFIG_FILE
    cfg = Config()
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[!] Ignoring unreadable {path.name}: {exc}")
            return cfg
        known = set(cfg.to_dict())
        for key, value in raw.items():
            if key in known:
                setattr(cfg, key, value)
            else:
                print(f"[!] Unknown config key ignored: {key}")
    # Make sure the directories we write to exist.
    for target in (cfg.findings_log, cfg.triage_file):
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    for watched in cfg.watch_paths:
        os.makedirs(watched, exist_ok=True)
    os.makedirs(cfg.rules_dir, exist_ok=True)
    return cfg
