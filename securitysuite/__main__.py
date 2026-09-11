"""Entry point: python -m securitysuite [options]"""
from __future__ import annotations

import argparse
import sys
import time
import webbrowser

from .config import load_config
from .engine import YaraEngine
from .server import serve
from .store import EventStore
from .telemetry import AuthTelemetry
from .watcher import Monitor

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
    monitor = Monitor(cfg, engine, store, telemetry)
    return cfg, engine, store, telemetry, monitor


def main(argv=None) -> int:
    args = parse_args(argv)
    cfg, engine, store, telemetry, monitor = build(args)

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

    if args.scan:
        import json
        result = monitor.scan_path(args.scan)
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    monitor.start()
    print("[*] Watching   : " + ", ".join(cfg.watch_paths))
    print("[*] Findings   : " + cfg.findings_log)

    httpd = None
    if not args.headless:
        try:
            httpd = serve(cfg, engine, store, telemetry, monitor)
        except OSError as exc:
            print("[-] Could not bind " + cfg.host + ":" + str(cfg.port) + " -> " + str(exc))
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
            httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
