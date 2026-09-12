"""API-surface tests: boot the real server and probe its edges.

These cover the input handling that used to drop connections rather than
answer them. No live network calls and no OS auth logs, so they are safe in CI.
"""
from __future__ import annotations

import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securitysuite.config import load_config
from securitysuite.engine import YaraEngine
from securitysuite.server import serve
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


def main() -> int:
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
    for i in range(40):
        store.add({"event_type": "yara_match", "severity": "high",
                   "file_path": "/x/%d" % i, "matches": []})

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

        # Hunt endpoint: a good query answers, a bad one explains itself with
        # a 200 and an error field rather than a crash.
        status, body = get(base, "/api/hunt?q=severity%3Ahigh")
        assert_true(status == 200, "hunt query failed: %s" % status)
        assert_true(b'"matched"' in body, "hunt result missing match count")
        status, body = get(base, "/api/hunt?q=bogus%3Ax")
        assert_true(status == 200, "bad hunt query should answer, got %s" % status)
        assert_true(b"unknown field" in body, "bad query did not explain itself")

        # ES modules must be reachable, or the console does not boot at all.
        for path in ("/js/core.js", "/js/router.js", "/js/hunt.js",
                     "/js/palette.js", "/js/attack.js"):
            status, _ = get(base, path)
            assert_true(status == 200, "%s returned %s" % (path, status))

        # ...but the containment fix must still hold: no escaping web/.
        for path in ("/js/../securitysuite/config.py", "/js/../../requirements.txt",
                     "/../securitysuite/server.js"):
            status, body = get(base, path)
            assert_true(status == 404, "%s should be refused, got %s" % (path, status))
            assert_true(b"import" not in body and b"yara-python" not in body,
                        "%s leaked file contents" % path)

        # Core reads still work.
        for path in ("/", "/app.js", "/styles.css", "/api/state",
                     "/api/rules", "/api/findings", "/api/iocs"):
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

        # A refused POST must still drain its request body. protocol_version
        # is HTTP/1.1, so an unread body is parsed as the next request line and
        # resets the connection instead of delivering the refusal. Several in a
        # row, then a normal read, proves the socket stayed in sync.
        for _ in range(5):
            request = urllib.request.Request(
                base + "/api/findings/clear", data=b'{"confirm":true}' * 8,
                headers={"Content-Type": "text/plain"}, method="POST")
            try:
                urllib.request.urlopen(request, timeout=10)
                raise AssertionError("non-JSON POST was accepted")
            except urllib.error.HTTPError as exc:
                assert_true(exc.code == 403, "expected 403, got %d" % exc.code)
        status, _ = get(base, "/api/state")
        assert_true(status == 200,
                    "server unusable after refused POSTs (body left in buffer)")

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
