import json
import ssl
import threading
import unittest
from unittest.mock import Mock, patch

from securitysuite.inventory import NetworkInventory, validate_scope, _parse_neighbors
from securitysuite.connectors import OPNsenseConnector, BitdefenderConnector


class InventoryTests(unittest.TestCase):
    def test_scope_rejected_before_io(self):
        with patch("securitysuite.inventory._run") as run, patch("securitysuite.inventory._connect") as connect:
            inventory = NetworkInventory(None)
            for scope in ("10.0.0.0/23", "127.0.0.1/32", "169.254.0.0/24",
                          "100.64.0.0/24", "192.168.1.1/24", "::1/128", "10.0.0.1"):
                with self.assertRaises(ValueError):
                    inventory.start(scope)
            run.assert_not_called()
            connect.assert_not_called()
        self.assertEqual(validate_scope("172.16.0.0/24").num_addresses, 256)

    def test_mocked_scan_and_detached_status(self):
        device = {"ip": "192.168.1.1", "hostname": "", "mac": "",
                  "services": [{"port": 443, "name": "https"}], "last_seen": "now"}
        with patch("securitysuite.inventory._neighbors", return_value={"192.168.1.1": "02:00:00:00:00:01"}), patch("securitysuite.inventory._probe", return_value=device) as probe:
            inventory = NetworkInventory(None)
            inventory.start("192.168.1.1/32", True)
            inventory._thread.join(5)
            self.assertFalse(inventory._thread.is_alive())
            snapshot = inventory.status()
            self.assertEqual(snapshot["state"], "complete")
            self.assertEqual(len(snapshot["devices"]), 1)
            self.assertTrue(snapshot["devices"][0]["mac"])
            snapshot["devices"][0]["services"].clear()
            self.assertTrue(inventory.status()["devices"][0]["services"])
            self.assertEqual(probe.call_count, 1)

    def test_cancel_blocks_overlapping_start(self):
        entered, release = threading.Event(), threading.Event()
        def probe(*args):
            entered.set()
            release.wait(5)
        with patch("securitysuite.inventory._neighbors", return_value={}), patch("securitysuite.inventory._probe", side_effect=probe) as probe_mock:
            inventory = NetworkInventory(None)
            inventory.start("10.0.0.0/24")
            try:
                self.assertTrue(entered.wait(3))
                self.assertEqual(inventory.cancel()["state"], "cancelling")
                with self.assertRaises(RuntimeError):
                    inventory.start("10.0.0.1/32")
            finally:
                release.set()
                inventory._thread.join(5)
            self.assertEqual(inventory.status()["state"], "cancelled")
            self.assertFalse(inventory._thread.is_alive())
            self.assertLessEqual(probe_mock.call_count, 16)

    def test_cache_filters_scope_and_failed_entries(self):
        output = "10.0.0.1 dev eth0 lladdr 02:00:00:00:00:01 REACHABLE\n10.0.0.2 lladdr ff:ff:ff:ff:ff:ff\n10.0.0.3 lladdr 02:00:00:00:00:03 FAILED\n8.8.8.8 lladdr 02:00:00:00:00:04"
        self.assertEqual(_parse_neighbors(output, validate_scope("10.0.0.0/24")), {"10.0.0.1": "02:00:00:00:00:01"})


class ConnectorTests(unittest.TestCase):
    def settings(self, url="https://192.168.1.1"):
        return {"OPNSENSE_URL": url, "OPNSENSE_API_KEY": "private-key", "OPNSENSE_API_SECRET": "private-secret"}

    def test_verified_read_only_health(self):
        response = Mock(status=200)
        response.read.return_value = b'{"status":"running","secret":"private-secret"}'
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with patch("securitysuite.connectors.urllib.request.build_opener", return_value=opener) as build:
            connector = OPNsenseConnector(self.settings())
            self.assertIsNone(connector.status()["operational"])
            result = connector.health()
            self.assertTrue(result["operational"])
            request = opener.open.call_args.args[0]
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.full_url, "https://192.168.1.1/api/ids/service/status")
            handler = build.call_args.args[2]
            self.assertEqual(handler._context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(handler._context.check_hostname)
            self.assertNotIn("private-secret", json.dumps(result))
            self.assertNotIn("private-key", json.dumps(result))

    def test_rejects_unsafe_endpoints_without_io(self):
        with patch("securitysuite.connectors.urllib.request.build_opener") as build:
            for url in ("http://192.168.1.1", "https://example.com", "https://127.0.0.1",
                        "https://192.168.1.1/api/firewall/filter/set", "https://user@192.168.1.1", "https://192.168.1.1?secret=foo"):
                self.assertFalse(OPNsenseConnector(self.settings(url)).health()["configured"])
            build.assert_not_called()
        self.assertEqual(OPNsenseConnector({"OPNSENSE_URL": None}).status()["state"], "invalid_configuration")
        self.assertFalse(BitdefenderConnector({"BITDEFENDER_API_KEY": None}).status()["operational"])

    def test_upstream_error_does_not_leak(self):
        with patch("securitysuite.connectors.urllib.request.build_opener") as build:
            build.return_value.open.side_effect = OSError("private-secret private-key")
            result = OPNsenseConnector(self.settings()).health()
            self.assertFalse(result["operational"])
            self.assertNotIn("private-secret", json.dumps(result))

    def test_invalid_and_oversized_responses_fail_closed(self):
        for body in (b'{"status":"private-secret"}', b'{"status":true}', b'[]', b'x' * 65537):
            response = Mock(status=200)
            response.read.return_value = body
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            with patch("securitysuite.connectors.urllib.request.build_opener") as build:
                build.return_value.open.return_value = response
                result = OPNsenseConnector(self.settings()).health()
                self.assertFalse(result["operational"])
                self.assertEqual(result["state"], "error")
                self.assertNotIn("private-secret", json.dumps(result))
                response.read.assert_called_once_with(65537)
