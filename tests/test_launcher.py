import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from securitysuite import __version__
from securitysuite.__main__ import running_instance


class LauncherTests(unittest.TestCase):
    def test_reuses_only_current_version_and_same_workspace(self):
        cfg = SimpleNamespace(findings_log="data/findings.ndjson")
        responses = []
        for version, log in (("old", cfg.findings_log), (__version__, "another/findings.ndjson"),
                             (__version__, cfg.findings_log)):
            response = Mock()
            response.read.return_value = json.dumps({"version": version, "findings_log": log}).encode()
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            responses.append(response)
        with patch("securitysuite.__main__.urllib.request.build_opener") as build:
            build.return_value.open.side_effect = responses
            result = running_instance(cfg, [8787, 8788, 8789])
        self.assertEqual(result, "http://127.0.0.1:8789")

    def test_unavailable_instances_return_none(self):
        with patch("securitysuite.__main__.urllib.request.build_opener") as build:
            build.return_value.open.side_effect = OSError("not running")
            result = running_instance(SimpleNamespace(findings_log="data/findings.ndjson"), [8787])
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
