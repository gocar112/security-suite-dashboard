"""Real loopback HTTP regression checks without scanning host files or networks."""
import http.client
import json
import tempfile
import socket
import unittest
from pathlib import Path
from unittest.mock import Mock

from securitysuite.config import Config
from securitysuite.remediate import Remediator
from securitysuite.server import serve
from securitysuite.store import EventStore


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.cfg = Config(port=0, findings_log=str(root / "findings.ndjson"),
                         triage_file=str(root / "triage.json"),
                         quarantine_dir=str(root / "quarantine"),
                         remediation_file=str(root / "remediation.json"),
                         watch_paths=[str(root / "watch")])
        cls.engine = Mock()
        cls.engine.info.return_value = {"rule_count": 1004}
        cls.engine.scan_bytes.return_value = {"matches": [], "iocs": {}}
        cls.store = EventStore(cls.cfg.findings_log, cls.cfg.triage_file)
        telemetry = Mock()
        telemetry.recent.return_value = {"count": 0}
        monitor = Mock(cfg=cls.cfg)
        monitor.status.return_value = {"running": False}
        cls.server = serve(cls.cfg, cls.engine, cls.store, telemetry, monitor,
                           remediator=Remediator(cls.cfg, cls.store))
        cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def request(self, route, payload=None, headers=None, method=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            body = json.dumps(payload) if isinstance(payload, (dict, list)) else payload
            final_headers = {"Content-Type": "application/json"} if payload is not None else {}
            final_headers.update(headers or {})
            connection.request(method or ("POST" if payload is not None else "GET"), route,
                               body=body, headers=final_headers)
            response = connection.getresponse()
            content = response.read()
            try:
                value = json.loads(content)
            except ValueError:
                value = content
            return response.status, dict(response.getheaders()), value
        finally:
            connection.close()

    def test_read_routes_and_schema(self):
        for route, key in (("/api/instance", "version"), ("/api/jobs", "jobs"), ("/api/inventory", "devices"),
                           ("/api/workspace", "policy"), ("/api/ids", "alerts"),
                           ("/api/playbooks", "skills"), ("/api/training", "scenarios"),
                           ("/api/connectors", "opnsense"), ("/api/intel", "sources")):
            with self.subTest(route=route):
                status, headers, value = self.request(route)
                self.assertEqual(status, 200)
                self.assertIn(key, value)
                self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(self.request("/playbook.schema.json")[0], 200)

    def test_same_origin_required_for_writes(self):
        self.assertEqual(self.request("/api/analysis", {"text": "safe"}, {
            "Origin": "http://127.0.0.1:9999"})[0], 403)
        self.assertEqual(self.request("/api/analysis", {"text": "safe"}, {
            "Origin": "http://127.0.0.1:" + str(self.port)})[0], 200)
        self.assertEqual(self.request("/api/analysis", {"text": "safe"}, {
            "Content-Type": "text/plain"})[0], 403)
        self.assertEqual(self.request("/api/jobs", {"path": "safe"}, {
            "Sec-Fetch-Site": "cross-site"})[0], 403)

    def test_host_rebinding_and_other_port_rejected(self):
        for host in ("attacker.example", "127.0.0.1:9999", "localhost@attacker.example", ""):
            with self.subTest(host=host):
                self.assertEqual(self.request("/api/jobs", headers={"Host": host})[0], 403)

    def test_invalid_json_and_truthy_confirmation_refused(self):
        for body in ([], 'null', '{"confirm":true,"confirm":false}',
                     '{"enabled":NaN}', '{"confirm":"yes"}', '{"path":[]}',
                     '{"days":-1}', '{"extensions":"exe"}', '{"confirm":1}'):
            with self.subTest(body=body):
                self.assertEqual(self.request("/api/findings/clear", body)[0], 400)
        self.assertEqual(self.request("/api/findings/clear", {})[0], 409)

    def test_clear_confirmation_and_incorrect_queries(self):
        self.store.add({"event_type": "ids_alert", "message": "fixture"})
        self.assertEqual(self.request("/api/findings/clear", {"confirm": True})[0], 200)
        self.assertEqual(self.request("/api/findings?limit=invalid")[0], 400)
        self.assertEqual(self.request("/api/iocs?limit=-10")[0], 400)
        self.assertEqual(self.request("/api/triage", {"status": "random"})[0], 400)

    def test_head_stream_does_not_subscribe(self):
        count = len(self.store._subscribers)
        status, _, content = self.request("/api/stream", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(content, b"")
        self.assertEqual(len(self.store._subscribers), count)

    def test_nonlocal_dashboard_binding_refused(self):
        cfg = Config(host="0.0.0.0", port=0)
        with self.assertRaises(ValueError):
            serve(cfg, Mock(), Mock(), Mock(), Mock())

    def test_short_http_frame_never_changes_policy(self):
        before = self.server.ctx.workspace.policy()["enabled"]
        body = b'{"enabled":true}'
        headers = ("POST /api/policy HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                   "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                   % (self.port, len(body) + 2)).encode()
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as connection:
            connection.sendall(headers + body)
            connection.shutdown(socket.SHUT_WR)
            response = b""
            while chunk := connection.recv(4096):
                response += chunk
        self.assertIn(b"400 Bad Request", response)
        self.assertEqual(self.server.ctx.workspace.policy()["enabled"], before)


if __name__ == "__main__":
    unittest.main()
