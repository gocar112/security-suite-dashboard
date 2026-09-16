"""Dashboard HTTP server - standard library only, no web framework needed.

Serves the static dashboard, a small JSON API, and a Server-Sent Events stream
that pushes findings to the browser the moment they are written.
"""
from __future__ import annotations

import json
import queue
import threading
import time
import csv
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .ioc import summarise, to_csv
from .connectors import OPNsenseConnector, BitdefenderConnector
from .inventory import NetworkInventory
from .jobs import ScanJobs
from .playbooks import PlaybookService, Training
from .shield import posture
from .store import now_iso
from .workspace import Workspace
from . import __version__

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
}
MAX_BODY = 64 * 1024


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field: " + key)
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("JSON cannot contain " + value)


def _integer(value, default=100, maximum=5000):
    value = default if value is None else value
    if isinstance(value, bool) or not str(value).isdigit():
        raise ValueError("Expected a positive integer")
    return max(1, min(maximum, int(value)))

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

    def __init__(self, cfg, engine, store, telemetry, monitor, nvd=None,
                 osv=None, vt=None, remediator=None, guidance=None):
        self.cfg = cfg
        self.engine = engine
        self.store = store
        self.telemetry = telemetry
        self.monitor = monitor
        self.nvd = nvd
        self.osv = osv
        self.vt = vt
        self.remediator = remediator
        self.guidance = guidance
        self.jobs = ScanJobs(monitor)
        self.inventory = NetworkInventory(store)
        self.workspace = Workspace(cfg, engine, store)
        self.playbooks = PlaybookService(cfg, store, remediator, guidance)
        self.training = Training()
        self.opnsense = OPNsenseConnector()
        self.bitdefender = BitdefenderConnector()


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
        try:
            value = self.headers.get("Host") or ""
            parsed = urlparse("http://" + value)
            return (parsed.hostname in ("localhost", "127.0.0.1", "::1") and
                    (parsed.port or 80) == self.server.server_port and
                    not parsed.username and not parsed.password and not parsed.path and
                    not parsed.query and not parsed.fragment)
        except ValueError:
            return False

    def _csrf_ok(self) -> tuple:
        """Reject cross-origin writes.

        `_body()` never checked Content-Type, so a POST with
        `Content-Type: text/plain` is a CORS *simple request* - no preflight -
        and any page the operator happened to have open could fire one at
        127.0.0.1. It could not read the reply, but a deletion does not need a
        reply. Requiring application/json forces a preflight this server does
        not answer, so the browser blocks it before do_POST is reached.
        """
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return False, "Content-Type must be application/json"
        origin = self.headers.get("Origin")
        if origin:
            if origin != "http://" + (self.headers.get("Host") or ""):
                return False, "cross-origin request refused"
        site = (self.headers.get("Sec-Fetch-Site") or "").lower()
        if site and site not in ("same-origin", "none"):
            return False, "cross-site request refused"
        return True, ""

    def _send(self, code: int, body: bytes, content_type: str, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; "
                         "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                         "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload, code: int = 200):
        self._send(code, json.dumps(payload, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _body(self) -> dict:
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Transfer-Encoding is not supported")
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) != 1:
            raise ValueError("Exactly one Content-Length header is required")
        length = int(lengths[0])
        if length <= 0 or length > MAX_BODY:
            raise ValueError("JSON body must be between 1 and 65536 bytes")
        self.connection.settimeout(15)
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("Incomplete JSON request body")
        body = json.loads(raw, object_pairs_hook=_strict_object,
                          parse_constant=_invalid_constant)
        if type(body) is not dict:
            raise ValueError("JSON body must be an object")
        for field in ("confirm", "dry_run", "allow_directory", "services", "enabled"):
            if field in body and type(body[field]) is not bool:
                raise ValueError(field + " must be a boolean")
        for field in ("path", "id", "action", "severity", "status", "note", "cidr", "text", "answer"):
            if field in body and not isinstance(body[field], str):
                raise ValueError(field + " must be a string")
        for field in ("limit", "days"):
            if field in body and (type(body[field]) is not int or body[field] < 1):
                raise ValueError(field + " must be a positive integer")
        if "extensions" in body and (not isinstance(body["extensions"], list) or
                len(body["extensions"]) > 50 or
                any(not isinstance(value, str) for value in body["extensions"])):
            raise ValueError("extensions must be a list of at most 50 strings")
        return body

    def _discard_body(self):
        """Drain small rejected requests before closing (Windows otherwise resets)."""
        self.close_connection = True
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if 0 < length <= MAX_BODY and not self.headers.get("Transfer-Encoding"):
                self.connection.settimeout(2)
                self.rfile.read(length)
        except (ValueError, OSError):
            pass

    def _static(self, name: str):
        target = (WEB_DIR / name).resolve()
        if not target.is_relative_to(WEB_DIR.resolve()) or not target.is_file():
            self._json({"error": "not found"}, 404)
            return
        ctype = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    # --------------------------------------------------------------- routes
    def do_GET(self):
        try:
            self._get()
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            self.close_connection = True
            self._json({"error": str(exc)}, 400)
        except (OSError, RuntimeError):
            self.close_connection = True
            self._json({"error": "Local service unavailable"}, 503)

    def _get(self):
        if not self._host_allowed():
            self._json({"error": "host not allowed"}, 403)
            return
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if route == "/":
            self._static("index.html")
        elif route in ("/app.js", "/console.js", "/lucide.js", "/styles.css",
                       "/favicon.ico", "/playbook.schema.json"):
            self._static(route.lstrip("/"))
        elif route == "/api/state":
            self._json(self._state())
        elif route == "/api/instance":
            self._json({"version": __version__, "findings_log": self.ctx.cfg.findings_log})
        elif route == "/api/jobs":
            self._json(self.ctx.jobs.status())
        elif route == "/api/drives":
            self._json({"drives": self.ctx.jobs.drives()})
        elif route == "/api/inventory":
            self._json(self.ctx.inventory.status())
        elif route == "/api/inventory/export":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ip", "mac", "services", "last_seen"])
            for device in self.ctx.inventory.status()["devices"]:
                writer.writerow([device["ip"], device["mac"],
                                 ",".join(str(s["port"]) for s in device["services"]), device["last_seen"]])
            self._send(200, output.getvalue().encode(), "text/csv; charset=utf-8",
                       {"Content-Disposition": 'attachment; filename="network-inventory.csv"'})
        elif route == "/api/workspace":
            self._json({"policy": self.ctx.workspace.policy(),
                        "native_av": self.ctx.workspace.native_av,
                        "domains": self.ctx.workspace.domains()})
        elif route == "/api/ids":
            self._json({"alerts": self.ctx.store.events(limit=300, event_type="ids_alert")})
        elif route == "/api/connectors":
            self._json({"opnsense": self.ctx.opnsense.status(),
                        "bitdefender": self.ctx.bitdefender.status()})
        elif route == "/api/domains/export":
            domains = self.ctx.workspace.domains()
            content = "# Reviewed DNS hosts list. Import into your DNS filter to enforce.\n" + "\n".join(
                "0.0.0.0 " + domain for domain in domains) + "\n"
            self._send(200, content.encode(), "text/plain; charset=utf-8",
                       {"Content-Disposition": 'attachment; filename="reviewed-blocklist.txt"'})
        elif route == "/api/playbooks":
            self._json(self.ctx.playbooks.list())
        elif route == "/api/training":
            self._json(self.ctx.training.list())
        elif route == "/api/findings":
            findings = self.ctx.store.events(
                limit=_integer(params.get("limit"), 200),
                severity=params.get("severity"),
                event_type=params.get("type"),
                status=params.get("status"),
                search=params.get("q"),
            )
            if self.ctx.remediator is not None:
                findings = self.ctx.remediator.annotate_many(findings)
            self._json(
                {
                    "findings": findings
                }
            )
        elif route == "/api/rules":
            self._json(self.ctx.engine.info())
        elif route == "/api/telemetry":
            self._json(self.ctx.telemetry.recent(force=params.get("force") == "1"))
        elif route == "/api/intel":
            self._json(self._intel())
        elif route == "/api/shield":
            self._json(posture(self.ctx.cfg, self.ctx.engine, self.ctx.store,
                               self.ctx.remediator))
        elif route == "/api/iocs":
            events = self.ctx.store.events(limit=2000, event_type="yara_match")
            data = summarise(events)
            kind = (params.get("type") or "").strip()
            if kind and kind != "all":
                data["indicators"] = [i for i in data["indicators"] if i["type"] == kind]
            scope = (params.get("scope") or "").strip()
            if scope == "external":
                data["indicators"] = [
                    i for i in data["indicators"]
                    if i["type"] != "ipv4" or i.get("scope") == "external"]
            limit = _integer(params.get("limit"), 300)
            data["shown"] = min(limit, len(data["indicators"]))
            data["indicators"] = data["indicators"][:limit]
            data["source_findings"] = len(events)
            if params.get("format") == "csv":
                body = to_csv(data["indicators"]).encode("utf-8")
                self._send(200, body, "text/csv; charset=utf-8",
                           {"Content-Disposition": 'attachment; filename="iocs.csv"'})
                return
            self._json(data)
        elif route == "/api/remediate":
            if self.ctx.remediator is None:
                self._json({"error": "remediation not enabled"}, 503)
                return
            self._json(self.ctx.remediator.status())
        elif route == "/api/remediate/guidance":
            if self.ctx.guidance is None:
                self._json({"error": "guidance not enabled"}, 503)
                return
            finding_id = (params.get("id") or "").strip()
            if not finding_id:
                self._json({"error": "id is required"}, 400)
                return
            finding = self.ctx.remediator._find(finding_id) if self.ctx.remediator else None
            if finding is None:
                self._json({"error": "unknown finding"}, 404)
                return
            self._json(self.ctx.guidance.for_finding(finding))
        elif route == "/api/vt":
            self._json(self.ctx.vt.status() if self.ctx.vt
                       else {"source": "virustotal", "status": "disabled"})
        elif route == "/api/vt/capabilities":
            if self.ctx.vt is None:
                self._json({"error": "virustotal adapter not enabled"}, 503)
                return
            refresh = params.get("refresh") == "1"
            # An explicit refresh may block; the dashboard poll never does.
            self._json(self.ctx.vt.capabilities(refresh=refresh, block=refresh))
        elif route == "/api/vt/file":
            if self.ctx.vt is None:
                self._json({"error": "virustotal adapter not enabled"}, 503)
                return
            digest = (params.get("hash") or "").strip()
            if not digest:
                self._json({"error": "hash is required"}, 400)
                return
            self._json(self.ctx.vt.lookup_hash(digest))
        elif route in ("/api/vt/livehunt", "/api/vt/retrohunt"):
            if self.ctx.vt is None:
                self._json({"error": "virustotal adapter not enabled"}, 503)
                return
            feature = "livehunt" if route.endswith("livehunt") else "retrohunt"
            result = self.ctx.vt.hunting(feature)
            self._json(result, 200 if result.get("available") else 402)
        elif route == "/api/osv":
            self._json(self.ctx.osv.status() if self.ctx.osv
                       else {"source": "osv", "status": "disabled"})
        elif route == "/api/osv/query":
            if self.ctx.osv is None:
                self._json({"error": "osv adapter not enabled"}, 503)
                return
            self._json(self.ctx.osv.query({
                "commit": params.get("commit", ""),
                "purl": params.get("purl", ""),
                "package": params.get("package", ""),
                "ecosystem": params.get("ecosystem", ""),
                "version": params.get("version", ""),
            }))
        elif route == "/api/nvd":
            self._json(self._nvd_status())
        elif route == "/api/nvd/cves":
            if self.ctx.nvd is None:
                self._json({"error": "nvd adapter not enabled"}, 503)
                return
            self._json({"cves": self.ctx.nvd.cached_records(
                limit=_integer(params.get("limit"), 100),
                severity=params.get("severity", ""))})
        elif route == "/api/nvd/cve":
            if self.ctx.nvd is None:
                self._json({"error": "nvd adapter not enabled"}, 503)
                return
            cve_id = (params.get("id") or "").strip()
            if not cve_id:
                self._json({"error": "id is required"}, 400)
                return
            self._json(self.ctx.nvd.fetch_cve(cve_id))
        elif route == "/api/nvd/search":
            if self.ctx.nvd is None:
                self._json({"error": "nvd adapter not enabled"}, 503)
                return
            query = (params.get("q") or "").strip()
            if not query:
                self._json({"error": "q is required"}, 400)
                return
            self._json(self.ctx.nvd.search(query, _integer(params.get("limit"), 20, 100)))
        elif route == "/api/stream":
            if self.command == "HEAD":
                self._send(200, b"", "text/event-stream")
            else:
                self._stream()
        else:
            self._json({"error": "not found"}, 404)

    do_HEAD = do_GET

    def do_POST(self):
        try:
            self._post()
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            self.close_connection = True
            self._json({"error": str(exc)}, 400)
        except RuntimeError as exc:
            self._json({"error": str(exc)}, 409)
        except OSError:
            self.close_connection = True
            self._json({"error": "Local operation failed; inspect permissions and disk space"}, 503)

    def _post(self):
        if not self._host_allowed():
            self._discard_body()
            self._json({"error": "host not allowed"}, 403)
            return
        route = urlparse(self.path).path.rstrip("/") or "/"
        allowed, why = self._csrf_ok()
        if not allowed:
            self._discard_body()
            self._json({"error": why}, 403)
            return
        body = self._body()

        if route == "/api/jobs":
            result = self.ctx.jobs.start(body.get("path", ""))
            self._json(result, 409 if result.get("error") else 202)
        elif route == "/api/jobs/cancel":
            result = self.ctx.jobs.cancel(body.get("id", ""))
            self._json(result, 404 if result.get("error") else 200)
        elif route == "/api/inventory":
            self._json(self.ctx.inventory.start(body.get("cidr", ""), body.get("services", False)), 202)
        elif route == "/api/inventory/cancel":
            self._json(self.ctx.inventory.cancel())
        elif route == "/api/policy":
            self._json(self.ctx.workspace.set_policy(body))
        elif route == "/api/native-av":
            self._json(self.ctx.workspace.check_native_av())
        elif route == "/api/analysis":
            self._json(self.ctx.workspace.analyze(body))
        elif route == "/api/ids/import":
            self._json(self.ctx.workspace.import_eve(body))
        elif route == "/api/connectors/check":
            self._json({"opnsense": self.ctx.opnsense.health(),
                        "bitdefender": self.ctx.bitdefender.status()})
        elif route == "/api/domains":
            self._json(self.ctx.workspace.save_domains(body))
        elif route in ("/api/playbooks/save", "/api/playbooks/run"):
            result = (self.ctx.playbooks.save(body) if route.endswith("save")
                      else self.ctx.playbooks.run(body))
            self._json(result, 200 if result.get("ok") else 409)
        elif route == "/api/training/grade":
            result = self.ctx.training.grade(body.get("id"), body.get("answer"))
            self._json(result, 200 if result.get("ok") else 400)
        elif route == "/api/scan":
            target = str(body.get("path", "")).strip()
            if not target:
                self._json({"error": "path is required"}, 400)
                return
            result = self.ctx.jobs.start(target)
            self._json(result, 409 if result.get("error") else 202)
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
        elif route == "/api/findings/clear":
            # Every other destructive route demands an explicit confirm; this
            # one wipes the whole dashboard, so it does too.
            if body.get("confirm") is not True:
                self._json({"error": "confirmation required",
                            "detail": "resend with confirm=true"}, 409)
                return
            self._json(self.ctx.store.clear())
        elif route == "/api/osv/query":
            if self.ctx.osv is None:
                self._json({"error": "osv adapter not enabled"}, 503)
                return
            self._json(self.ctx.osv.query(body))
        elif route == "/api/nvd/sync":
            if self.ctx.nvd is None:
                self._json({"error": "nvd adapter not enabled"}, 503)
                return
            days = _integer(body.get("days"), getattr(self.ctx.cfg, "nvd_sync_days", 3), 120)
            result = self.ctx.nvd.sync(days, getattr(self.ctx.cfg, "nvd_max_records", 4000))
            self.ctx.store.broadcast({
                "event_type": "monitor", "timestamp": now_iso(),
                "message": "NVD sync: " + str(result.get("cached", 0)) + " CVEs cached"
                           if "error" not in result else "NVD sync failed: " + result["error"],
            })
            self._json(result)
        elif route == "/api/remediate":
            if self.ctx.remediator is None:
                self._json({"error": "remediation not enabled"}, 503)
                return
            finding_id = str(body.get("id", "")).strip()
            if not finding_id:
                self._json({"error": "id is required"}, 400)
                return
            result = self.ctx.remediator.act(
                finding_id,
                str(body.get("action", "quarantine")),
                confirm=bool(body.get("confirm")),
                dry_run=bool(body.get("dry_run")),
                allow_directory=bool(body.get("allow_directory")),
            )
            # A refusal is a considered answer, not a server fault: 409.
            if result.get("ok"):
                code = 200
            elif result.get("refused") == "unknown finding":
                code = 404
            elif result.get("refused") == "unknown action":
                code = 400
            else:
                code = 409
            self._json(result, code)
        elif route == "/api/remediate/bulk":
            if self.ctx.remediator is None:
                self._json({"error": "remediation not enabled"}, 503)
                return
            result = self.ctx.remediator.bulk(
                severity=str(body.get("severity", "")),
                extensions=body.get("extensions") or [],
                action=str(body.get("action", "quarantine")),
                confirm=bool(body.get("confirm")),
                dry_run=body.get("dry_run", True) is not False,
                limit=int(body.get("limit", 50)),
            )
            self._json(result)
        elif route == "/api/triage":
            if body.get("status", "acknowledged") not in (
                    "new", "acknowledged", "resolved", "false_positive"):
                raise ValueError("Unknown triage status")
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
            "version": __version__,
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

    def _nvd_status(self) -> dict:
        if self.ctx.nvd is None:
            return {"source": "nvd", "status": "disabled"}
        return self.ctx.nvd.status()

    def _intel(self) -> dict:
        """Return source adapters without ever returning credentials to clients."""
        vt_key = str(getattr(self.ctx.cfg, "virustotal_api_key", "") or "").strip()
        vt_state = self.ctx.vt.status() if self.ctx.vt else {}
        vt_status = "offline" if vt_state.get("last_error") else "ready" if vt_key else "optional"
        nvd_state = self._nvd_status()
        nvd_cached = int(nvd_state.get("cached") or 0)
        nvd_status = "offline" if nvd_state.get("last_error") else (
            "syncing" if nvd_state.get("syncing") else
            "online" if nvd_cached else "catalog")

        sources = []
        for source_id, url, status in INTEL_SOURCES:
            entry = {
                "id": source_id,
                "url": url,
                "status": vt_status if source_id == "virustotal" else status,
                "configured": bool(vt_key) if source_id == "virustotal" else True,
            }
            if source_id == "virustotal" and self.ctx.vt is not None:
                vt_state = self.ctx.vt.status()
                vt_tier = vt_state.get("tier", "public")
                entry["tier"] = vt_tier
                entry["hunting"] = vt_state.get("hunting_available", False)
                entry["detail"] = (
                    "enterprise: hunting available" if vt_state.get("hunting_available")
                    else "public tier: hash lookups only"
                    if vt_state.get("configured") else "no key configured")
            if source_id == "osv" and self.ctx.osv is not None:
                osv_state = self.ctx.osv.status()
                entry["status"] = ("offline" if osv_state.get("last_error")
                                   else "online" if osv_state.get("cached_queries")
                                   else "ready")
                entry["cached"] = osv_state.get("cached_queries", 0)
                entry["detail"] = (str(osv_state.get("cached_queries", 0))
                                   + " queries cached")
            if source_id == "nvd":
                entry["status"] = nvd_status
                entry["cached"] = nvd_cached
                entry["last_sync"] = nvd_state.get("last_sync")
                entry["detail"] = (str(nvd_cached) + " CVEs cached"
                                   if nvd_cached else "not synced yet")
            sources.append(entry)
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


def serve(cfg, engine, store, telemetry, monitor, nvd=None, osv=None,
          vt=None, remediator=None, guidance=None) -> DashboardServer:
    if cfg.host not in ("127.0.0.1", "localhost"):
        raise ValueError("Dashboard must bind to loopback; remote control is not authenticated")
    httpd = DashboardServer((cfg.host, cfg.port), Handler)
    httpd.ctx = Context(cfg, engine, store, telemetry, monitor, nvd, osv, vt,
                        remediator, guidance)  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, name="securitysuite-http",
                              daemon=True)
    thread.start()
    return httpd
