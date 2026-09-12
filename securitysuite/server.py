"""Dashboard HTTP server - standard library only, no web framework needed.

Serves the static dashboard, a small JSON API, and a Server-Sent Events stream
that pushes findings to the browser the moment they are written.
"""
from __future__ import annotations

import json
import queue
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .store import now_iso

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}
MAX_BODY = 64 * 1024

INTEL_SOURCES = (
    ("vuls", "https://github.com/future-architect/vuls", "bridge"),
    ("nvd", "https://nvd.nist.gov/", "catalog"),
    ("kev", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "catalog"),
    ("osv", "https://osv.dev/", "catalog"),
    ("github", "https://github.com/advisories", "catalog"),
    ("clawfire", "https://clawfire.ai/", "reference"),
    ("virustotal", "https://www.virustotal.com/", "optional"),
)


class Context:
    """Everything the request handler needs, injected onto the server object."""

    def __init__(self, cfg, engine, store, telemetry, monitor):
        self.cfg = cfg
        self.engine = engine
        self.store = store
        self.telemetry = telemetry
        self.monitor = monitor


class Handler(BaseHTTPRequestHandler):
    server_version = "SecuritySuite"
    protocol_version = "HTTP/1.1"

    @property
    def ctx(self) -> Context:
        return self.server.ctx  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):  # quieter console
        if "/api/stream" not in str(args):
            return

    # ----------------------------------------------------------- primitives
    def _host_allowed(self) -> bool:
        """Block DNS-rebinding: only localhost names may talk to the API."""
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]").lower()
        return host in ("localhost", "127.0.0.1", "::1", "")

    def _send(self, code: int, body: bytes, content_type: str, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload, code: int = 200):
        self._send(code, json.dumps(payload, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _static(self, name: str):
        target = (WEB_DIR / name).resolve()
        if not str(target).startswith(str(WEB_DIR.resolve())) or not target.is_file():
            self._json({"error": "not found"}, 404)
            return
        ctype = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    # --------------------------------------------------------------- routes
    def do_GET(self):
        if not self._host_allowed():
            self._json({"error": "host not allowed"}, 403)
            return
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if route == "/":
            self._static("index.html")
        elif route in ("/app.js", "/styles.css", "/favicon.ico"):
            self._static(route.lstrip("/"))
        elif route == "/api/state":
            self._json(self._state())
        elif route == "/api/findings":
            self._json(
                {
                    "findings": self.ctx.store.events(
                        limit=int(params.get("limit", 200)),
                        severity=params.get("severity"),
                        event_type=params.get("type"),
                        status=params.get("status"),
                        search=params.get("q"),
                    )
                }
            )
        elif route == "/api/rules":
            self._json(self.ctx.engine.info())
        elif route == "/api/telemetry":
            self._json(self.ctx.telemetry.recent(force=params.get("force") == "1"))
        elif route == "/api/intel":
            self._json(self._intel())
        elif route == "/api/stream":
            self._stream()
        else:
            self._json({"error": "not found"}, 404)

    do_HEAD = do_GET

    def do_POST(self):
        if not self._host_allowed():
            self._json({"error": "host not allowed"}, 403)
            return
        route = urlparse(self.path).path.rstrip("/") or "/"
        body = self._body()

        if route == "/api/scan":
            target = str(body.get("path", "")).strip()
            if not target:
                self._json({"error": "path is required"}, 400)
                return
            self._json(self.ctx.monitor.scan_path(target))
        elif route == "/api/monitor":
            action = str(body.get("action", "")).lower()
            if action == "pause":
                self.ctx.monitor.pause()
            elif action in ("resume", "start"):
                self.ctx.monitor.resume()
            else:
                self._json({"error": "action must be pause or resume"}, 400)
                return
            status = self.ctx.monitor.status()
            self.ctx.store.broadcast(
                {"event_type": "monitor", "timestamp": now_iso(),
                 "message": "Monitor " + ("paused" if status["paused"] else "resumed")}
            )
            self._json(status)
        elif route == "/api/rules/reload":
            info = self.ctx.engine.reload()
            self.ctx.store.broadcast(
                {"event_type": "monitor", "timestamp": now_iso(),
                 "message": "Reloaded " + str(info["rule_count"]) + " rules"}
            )
            self._json(info)
        elif route == "/api/triage":
            updated = self.ctx.store.set_status(
                str(body.get("id", "")),
                str(body.get("status", "acknowledged")),
                str(body.get("note", "")),
            )
            if updated is None:
                self._json({"error": "finding not found"}, 404)
                return
            self._json(updated)
        else:
            self._json({"error": "not found"}, 404)

    # ---------------------------------------------------------------- state
    def _state(self) -> dict:
        cfg = self.ctx.cfg
        return {
            "stats": self.ctx.store.stats(),
            "monitor": self.ctx.monitor.status(),
            "engine": self.ctx.engine.info(),
            "telemetry": self.ctx.telemetry.recent(),
            "config": {
                "watch_paths": cfg.watch_paths,
                "lookback_minutes": cfg.lookback_minutes,
                "max_file_mb": cfg.max_file_mb,
                "poll_interval": cfg.poll_interval,
                "findings_log": cfg.findings_log,
            },
            "server_time": now_iso(),
        }

    def _intel(self) -> dict:
        """Return source adapters without ever returning credentials to clients."""
        vt_key = str(getattr(self.ctx.cfg, "virustotal_api_key", "") or "").strip()
        vt_status = "optional"
        if vt_key:
            request = urllib.request.Request(
                "https://www.virustotal.com/api/v3/users/me",
                headers={"x-apikey": vt_key, "Accept": "application/json"},
            )
            try:
                with urllib.request.urlopen(request, timeout=2) as response:
                    vt_status = "online" if response.status == 200 else "configured"
            except urllib.error.HTTPError as exc:
                vt_status = "rejected" if exc.code in (401, 403) else "rate limited" if exc.code == 429 else "configured"
            except (urllib.error.URLError, TimeoutError, OSError):
                vt_status = "offline"
        sources = []
        for source_id, url, status in INTEL_SOURCES:
            sources.append({
                "id": source_id,
                "url": url,
                "status": vt_status if source_id == "virustotal" else status,
                "configured": bool(vt_key) if source_id == "virustotal" else True,
            })
        return {
            "status": "live" if vt_status == "online" else "linked",
            "synced_at": now_iso(),
            "sources": sources,
        }

    # ------------------------------------------------------------------ SSE
    def _stream(self):
        sub = self.ctx.store.subscribe()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        last_stats = 0.0
        try:
            self._sse("hello", {"server_time": now_iso()})
            while True:
                try:
                    event = sub.get(timeout=1.0)
                    self._sse("event", event)
                except queue.Empty:
                    pass
                if time.time() - last_stats >= 2.0:
                    self._sse(
                        "stats",
                        {
                            "stats": self.ctx.store.stats(),
                            "monitor": self.ctx.monitor.status(),
                        },
                    )
                    last_stats = time.time()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.ctx.store.unsubscribe(sub)

    def _sse(self, name: str, payload: dict):
        data = json.dumps(payload, default=str)
        self.wfile.write(("event: " + name + "\ndata: " + data + "\n\n").encode("utf-8"))
        self.wfile.flush()


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(cfg, engine, store, telemetry, monitor) -> DashboardServer:
    httpd = DashboardServer((cfg.host, cfg.port), Handler)
    httpd.ctx = Context(cfg, engine, store, telemetry, monitor)  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, name="securitysuite-http",
                              daemon=True)
    thread.start()
    return httpd
