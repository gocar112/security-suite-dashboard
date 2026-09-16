"""Entry point: python -m securitysuite [options]"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import webbrowser

from .config import load_config
from .engine import YaraEngine
from .nvd import NvdClient
from .guidance import Guidance
from .osv import OsvClient
from .remediate import Remediator
from .server import serve
from .store import EventStore
from .telemetry import AuthTelemetry
from .virustotal import VtClient
from .watcher import Monitor
from . import __version__

BANNER = r"""
  ___  ___  ___ _   _ ___ ___ _______   __  ___ _   _ ___ _____ ___
 / __|| __|/ __| | | | _ \_ _|_   _\ \ / / / __| | | |_ _|_   _| __|
 \__ \| _|| (__| |_| |   /| |  | |  \ V /  \__ \ |_| || |  | | | _|
 |___/|___|\___|\___/|_|_\___| |_|   |_|   |___/\___/|___| |_| |___|
"""


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="securitysuite",
        description="YARA-backed SOC detection suite with a live dashboard.",
    )
    parser.add_argument("--host", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, help="dashboard port (default 8787)")
    parser.add_argument("--watch", action="append", metavar="DIR",
                        help="directory to monitor (repeatable, replaces config)")
    parser.add_argument("--rules", metavar="DIR", help="rules directory")
    parser.add_argument("--scan", metavar="PATH",
                        help="scan a file or directory, print JSON, exit")
    parser.add_argument("--headless", action="store_true",
                        help="monitor only, no dashboard server")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open a browser window")
    parser.add_argument("--scan-existing", action="store_true",
                        help="scan files already present at startup")
    return parser.parse_args(argv)


def build(args):
    cfg = load_config()
    if args.host:
        cfg.host = args.host
    if args.port:
        cfg.port = args.port
    if args.watch:
        cfg.watch_paths = args.watch
    if args.rules:
        cfg.rules_dir = args.rules
    if args.scan_existing:
        cfg.scan_existing_on_start = True

    engine = YaraEngine(cfg.rules_dir, cfg.max_file_bytes)
    store = EventStore(cfg.findings_log, cfg.triage_file, cfg.history_limit)
    telemetry = AuthTelemetry(
        cfg.auth_log_path, cfg.lookback_minutes,
        cfg.telemetry_cache_seconds, cfg.max_telemetry_events,
    )
    nvd = NvdClient(cfg.nvd_cache_dir, cfg.nvd_api_key)
    osv = OsvClient(cfg.osv_cache_dir)
    vt = VtClient(cfg.virustotal_api_key, cfg.vt_cache_dir)
    remediator = Remediator(cfg, store, nvd)
    guidance = Guidance(cfg.guidance_cache_dir, nvd)
    monitor = Monitor(cfg, engine, store, telemetry, remediator)
    return cfg, engine, store, telemetry, monitor, nvd, osv, vt, remediator, guidance


def running_instance(cfg, ports):
    """Reuse this version's existing workspace instead of starting a second writer."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for port in ports:
        url = "http://127.0.0.1:" + str(port)
        try:
            with opener.open(url + "/api/instance", timeout=0.3) as response:
                data = json.loads(response.read(2048))
            if (isinstance(data, dict) and data.get("version") == __version__ and
                    isinstance(data.get("findings_log"), str) and
                    os.path.normcase(os.path.abspath(data["findings_log"])) ==
                    os.path.normcase(os.path.abspath(cfg.findings_log))):
                return url
        except (OSError, ValueError, urllib.error.URLError):
            continue
    return None


def main(argv=None) -> int:
    args = parse_args(argv)
    cfg, engine, store, telemetry, monitor, nvd, osv, vt, remediator, guidance = build(args)

    info = engine.info()
    print(BANNER)
    print("[*] Rules      : " + str(info["rule_count"]) + " loaded from " + info["rules_dir"]
          + (" (FALLBACK RULE ONLY)" if info["using_fallback"] else ""))
    for err in info["load_errors"]:
        print("[!] Rule error : " + err["file"] + " -> " + err["error"])
    telemetry_state = telemetry.recent()
    print("[*] Telemetry  : " + telemetry_state["source"] + " -> "
          + telemetry_state["status"]
          + (" (" + telemetry_state.get("detail", "") + ")"
             if telemetry_state.get("detail") else ""))

    nvd_state = nvd.status()
    print("[*] NVD        : " + str(nvd_state.get("cached", 0)) + " CVEs cached, "
          + nvd_state["rate_limit"] + ", tls via " + nvd_state["tls_bundle"]
          + (" (last sync " + nvd_state["last_sync"] + ")" if nvd_state.get("last_sync") else ""))

    if cfg.auto_remediate:
        print("[!] AUTO-REMEDIATE ARMED: " + cfg.auto_remediate_action
              + " at severity " + cfg.auto_remediate_severity
              + " - files will be acted on without confirmation")
    else:
        print("[*] Remediate  : manual only (auto-remediate off)")

    if args.scan:
        result = monitor.scan_path(args.scan)
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    ports = [cfg.port] if args.port else list(range(cfg.port, min(cfg.port + 10, 65536)))
    if not args.headless and not (args.watch or args.rules or args.scan_existing):
        existing = running_instance(cfg, ports)
        if existing:
            print("[*] Dashboard already running: " + existing)
            if not args.no_browser:
                webbrowser.open(existing)
            return 0
    monitor.start()
    print("[*] Watching   : " + ", ".join(cfg.watch_paths))
    print("[*] Findings   : " + cfg.findings_log)

    httpd = None
    if not args.headless:
        bind_error = None
        for port in ports:
            cfg.port = port
            try:
                httpd = serve(cfg, engine, store, telemetry, monitor, nvd, osv, vt,
                              remediator, guidance)
                break
            except ValueError as exc:
                bind_error = exc
                break
            except OSError as exc:
                bind_error = exc
        if httpd is None:
            print("[-] Could not start dashboard: " + str(bind_error))
            monitor.stop()
            return 1
        url = "http://" + cfg.host + ":" + str(cfg.port)
        print("[*] Dashboard  : " + url)
        if not args.no_browser:
            try:
                webbrowser.open(url)
            except Exception:
                pass

    print("[*] Ctrl-C to stop.\n")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        monitor.stop()
        if httpd is not None:
            for job in httpd.ctx.jobs.status()["jobs"]:
                if job["state"] in ("queued", "running"):
                    httpd.ctx.jobs.cancel(job["id"])
            httpd.ctx.inventory.cancel()
            httpd.shutdown()
            httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
