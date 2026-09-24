"""API-surface tests: boot the real server and probe its edges.

These cover the input handling that used to drop connections rather than
answer them. No live network calls and no OS auth logs, so they are safe in CI.
"""
from __future__ import annotations

import socket
import sys
import tempfile
import time
import json
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securitysuite.config import load_config
from securitysuite.engine import YaraEngine
from securitysuite.net import get_json, post_json
from securitysuite.server import MAX_BODY, serve
from securitysuite.store import EventStore
from securitysuite.telemetry import AuthTelemetry
from securitysuite.watcher import Monitor


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def get(base: str, path: str):
    """Return (status, body). A dropped connection is reported as status None."""
    try:
        with urllib.request.urlopen(base + path, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception:
        return None, b""


def post(base: str, path: str, payload: dict | None = None, *,
         content_type: str = "application/json", extra_headers: dict | None = None):
    headers = {"Content-Type": content_type, **(extra_headers or {})}
    data = json.dumps(payload or {}).encode("utf-8")
    request = urllib.request.Request(base + path, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception:
        return None, b""


def main() -> int:
    # The intel adapters must never follow a caller-controlled local or
    # cleartext URL. These checks happen before any connection is attempted.
    for target in ("http://example.test/data", "file:///tmp/data.json", "https:///",
                   "https://user:pass@example.test/data"):
        for request in (lambda: get_json(target), lambda: post_json(target, {})):
            try:
                request()
                raise AssertionError("unsafe URL was accepted: " + target)
            except ValueError:
                pass

    tmp = Path(tempfile.mkdtemp(prefix="ss_api_"))
    watch = tmp / "watch"
    watch.mkdir()

    cfg = load_config()
    cfg.watch_paths = [str(watch)]
    cfg.findings_log = str(tmp / "findings.ndjson")
    cfg.triage_file = str(tmp / "triage.json")
    cfg.port = free_port()

    engine = YaraEngine(cfg.rules_dir, cfg.max_file_bytes)
    store = EventStore(cfg.findings_log, cfg.triage_file, 500)
    telemetry = AuthTelemetry(cfg.auth_log_path, 5, 0, 25)
    monitor = Monitor(cfg, engine, store, telemetry, None)
    sample = None
    for i in range(40):
        event = store.add({"event_type": "yara_match", "severity": "high",
                           "file_path": "/x/%d" % i, "matches": []})
        if sample is None:
            sample = event

    httpd = serve(cfg, engine, store, telemetry, monitor)
    base = "http://127.0.0.1:%d" % cfg.port
    try:
        time.sleep(0.5)

        # A malformed integer parameter must be answered, not met with a
        # dropped socket. These raised ValueError out of the handler, so the
        # client saw a connection reset and no response at all.
        for path in ("/api/findings?limit=abc", "/api/findings?limit=",
                     "/api/findings?limit=9e99", "/api/iocs?limit=notanumber",
                     "/api/findings?limit=-5", "/api/nvd/cves?limit=xyz"):
            status, _ = get(base, path)
            assert_true(status is not None,
                        "connection dropped instead of answering %s" % path)
            # 503 is a legitimate answer when an optional adapter is absent;
            # what must never happen is a crash or a dropped socket.
            assert_true(status in (200, 400, 404, 503),
                        "%s returned %s" % (path, status))

        # An oversized limit must be clamped rather than serialising the world.
        status, body = get(base, "/api/findings?limit=999999999")
        assert_true(status == 200, "clamped limit should still succeed")

        # The icon lives in assets/, not web/; this route always 404'd.
        status, body = get(base, "/favicon.ico")
        assert_true(status == 200, "favicon should be served, got %s" % status)
        assert_true(len(body) > 0, "favicon body was empty")

        # Core reads still work.
        for path in ("/", "/briefing", "/app.js", "/styles.css", "/briefing.js",
                     "/briefing.css", "/assets/securitysuite.png", "/api/state",
                     "/api/rules", "/api/findings", "/api/iocs", "/api/model",
                     "/api/intel", "/api/logs"):
            status, _ = get(base, path)
            assert_true(status == 200, "%s returned %s" % (path, status))

        # Writes must still refuse a body that is not JSON (CSRF rail).
        request = urllib.request.Request(
            base + "/api/monitor", data=b'{"action":"pause"}',
            headers={"Content-Type": "text/plain"}, method="POST")
        try:
            urllib.request.urlopen(request, timeout=10)
            raise AssertionError("non-JSON POST was accepted")
        except urllib.error.HTTPError as exc:
            assert_true(exc.code == 403, "expected 403, got %d" % exc.code)

        status, _ = post(base, "/api/monitor", {"action": "pause"},
                         extra_headers={"Origin": "https://example.invalid"})
        assert_true(status == 403, "cross-origin POST should be rejected")

        status, body = post(base, "/api/monitor", {"action": "pause"})
        assert_true(status == 200 and json.loads(body)["paused"],
                    "monitor pause did not succeed")
        status, body = post(base, "/api/monitor", {"action": "resume"})
        assert_true(status == 200 and not json.loads(body)["paused"],
                    "monitor resume did not succeed")

        status, _ = post(base, "/api/scan", {})
        assert_true(status == 400, "empty scan request should be rejected")
        status, body = post(base, "/api/model/predict", {
            "vulnerability_type": "SQL injection",
            "impact": "Sensitive data exposure on an internet-facing service",
            "cvss": 9.1,
        })
        assert_true(status == 200 and b'"mode": "deterministic"' in body,
                    "risk model endpoint did not return an explainable result")
        status, _ = post(base, "/api/model/predict", {"impact": "missing type"})
        assert_true(status == 400, "invalid risk model request should be rejected")

        status, body = post(base, "/api/triage", {
            "id": sample["id"], "status": "acknowledged", "note": "API test",
        })
        assert_true(status == 200 and b'"acknowledged"' in body,
                    "triage route did not update the sample event")
        status, _ = post(base, "/api/findings/clear", {})
        assert_true(status == 409, "clear route must require confirmation")
        status, _ = post(base, "/api/findings/clear", {"confirm": True})
        assert_true(status == 200, "confirmed clear route did not succeed")

        oversized = urllib.request.Request(
            base + "/api/monitor", data=b"x" * (MAX_BODY + 1),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(oversized, timeout=10)
        except urllib.error.HTTPError as exc:
            assert_true(exc.code == 400, "oversized body should receive a 400")
        except Exception as exc:
            raise AssertionError("oversized body dropped the connection: " + str(exc)) from exc

        stream = urllib.request.urlopen(base + "/api/stream", timeout=10)
        try:
            assert_true(stream.status == 200, "SSE stream did not open")
        finally:
            stream.close()

        # /api/state reports stream health.
        status, body = get(base, "/api/state")
        assert_true(b"dropped_subscribers" in body,
                    "/api/state should report stream health")

        print("API tests passed")
        return 0
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
