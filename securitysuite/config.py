"""Configuration for Security Studio.

Loads ``config.json`` from the project root when present, otherwise falls back
to defaults that work out of the box on Windows and Linux.
"""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = ROOT / "config.json"
ENV_FILE = ROOT / ".env"
API_KEY_NAMES = ("VIRUSTOTAL_API_KEY", "NVD_API_KEY")
_env_lock = threading.Lock()


def _load_local_env() -> None:
    """Load simple KEY=value pairs for local adapters without a dependency."""
    env_file = ENV_FILE
    if not env_file.exists():
        return
    try:
        lines = env_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_local_env()


def _validate_api_key(value: str) -> str:
    value = value.strip()
    if not 20 <= len(value) <= 256:
        raise ValueError("API keys must contain 20 to 256 characters")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        raise ValueError("API keys may contain only letters, numbers, dot, dash, and underscore")
    return value


def save_api_keys(updates: dict[str, str], path: Path | None = None) -> dict:
    """Atomically update supported secrets without returning their values."""
    unknown = set(updates) - set(API_KEY_NAMES)
    if unknown:
        raise ValueError("unsupported API key setting")
    clean = {
        name: (_validate_api_key(value) if value else "")
        for name, value in updates.items()
    }
    target = (path or ENV_FILE).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with _env_lock:
        try:
            lines = target.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            lines = ["# Security Studio local secrets - never commit this file."]
        except OSError as exc:
            raise ValueError("could not read the local API key file") from exc

        kept = []
        for line in lines:
            key = line.split("=", 1)[0].strip() if "=" in line else ""
            if key not in clean:
                kept.append(line)
        for name in API_KEY_NAMES:
            if name in clean and clean[name]:
                kept.append(name + "=" + clean[name])

        temporary = target.with_name(target.name + ".tmp")
        try:
            temporary.write_text("\n".join(kept).rstrip() + "\n", encoding="utf-8")
            os.replace(temporary, target)
            try:
                target.chmod(0o600)
            except OSError:
                pass
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise ValueError("could not save the local API key file") from exc

    for name, value in clean.items():
        if value:
            os.environ[name] = value
        else:
            os.environ.pop(name, None)
    return {name: bool(os.getenv(name, "")) for name in API_KEY_NAMES}


@dataclass
class Config:
    # --- monitoring ---
    watch_paths: list = field(default_factory=lambda: [str(ROOT / "SecurityDrop")])
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
    port: int = 8900

    # --- optional external intelligence ---
    virustotal_api_key: str = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", ""))
    # NVD needs no credential; a key only raises the rate limit (5/30s -> 50/30s).
    nvd_api_key: str = field(default_factory=lambda: os.getenv("NVD_API_KEY", ""))
    nvd_cache_dir: str = str(ROOT / "nvds")
    nvd_sync_days: int = 3
    nvd_max_records: int = 4000
    osv_cache_dir: str = str(ROOT / "data" / "osv")
    vt_cache_dir: str = str(ROOT / "data" / "vt")

    # --- remediation (destructive; see securitysuite/remediate.py) ---
    # quarantine_dir MUST sit outside every watch path, or a quarantined
    # file is re-detected forever.
    quarantine_dir: str = str(ROOT / "quarantine")
    remediation_file: str = str(ROOT / "data" / "remediation.json")
    guidance_cache_dir: str = str(ROOT / "data" / "guidance")
    remediation_roots: list = field(default_factory=list)
    # This deployment automatically quarantines critical detections from the
    # dedicated SecurityDrop folder. Delete remains a manual action.
    auto_remediate: bool = True
    auto_remediate_severity: str = "critical"
    auto_remediate_action: str = "quarantine"

    @property
    def max_file_bytes(self) -> int:
        return int(self.max_file_mb * 1024 * 1024)

    def to_dict(self) -> dict:
        values = asdict(self)
        # Credentials belong in the process environment, never in config.json.
        values.pop("virustotal_api_key", None)
        values.pop("nvd_api_key", None)
        return values

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
    os.makedirs(cfg.nvd_cache_dir, exist_ok=True)
    os.makedirs(cfg.osv_cache_dir, exist_ok=True)
    os.makedirs(cfg.vt_cache_dir, exist_ok=True)
    os.makedirs(cfg.quarantine_dir, exist_ok=True)
    os.makedirs(cfg.guidance_cache_dir, exist_ok=True)
    os.makedirs(os.path.dirname(cfg.remediation_file) or ".", exist_ok=True)
    return cfg
