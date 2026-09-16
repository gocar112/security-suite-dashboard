"""Read-only integration health and honest setup status, with no policy writes.

OPNsense documents GET /api/ids/service/status and key/secret Basic auth here:
https://docs.opnsense.org/development/api/core/ids.html
https://docs.opnsense.org/development/how-tos/api.html
Bitdefender's separate GravityZone API is documented here; it is NOT implemented:
https://www.bitdefender.com/business/support/en/77212-125277-public-api.html
"""
from __future__ import annotations

import base64
import copy
import ipaddress
import json
import os
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping

from .inventory import RFC1918
from .net import USER_AGENT
from .store import now_iso

__all__ = ["OPNsenseConnector", "BitdefenderConnector"]

STATUS_PATH = "/api/ids/service/status"
HTTP_TIMEOUT = 5.0
MAX_RESPONSE_BYTES = 65536


def _endpoint(value: str) -> str:
    """Pin configuration to one HTTPS RFC1918 literal and one read-only path.

    Accept an origin (optional trailing slash) or the exact status URL, with an
    optional explicit port. DNS names, localhost/loopback, IPv6, userinfo,
    queries, fragments, escapes and other paths are rejected. Literal-only
    addressing avoids DNS rebinding or sending credentials to a resolved alias.
    """
    try:
        if not value or any(ord(char) <= 32 or ord(char) >= 127 for char in value):
            raise ValueError
        if any(char in value for char in "\\@%?#"):
            raise ValueError
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme != "https" or parsed.path not in ("", "/", STATUS_PATH):
            raise ValueError
        address = ipaddress.IPv4Address(parsed.hostname)
        if not any(address in block for block in RFC1918):
            raise ValueError
        port = parsed.port
        if parsed.netloc.endswith(":") or (port is not None and not 1 <= port <= 65535):
            raise ValueError
        return "https://" + str(address) + (f":{port}" if port is not None else "") + STATUS_PATH
    except (ValueError, TypeError):
        raise ValueError("OPNSENSE_URL must be an HTTPS RFC1918 IPv4 origin or the exact IDS status URL.") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class OPNsenseConnector:
    """Snapshot OPNSENSE_URL, OPNSENSE_API_KEY and OPNSENSE_API_SECRET at init.

    ``configuration_status()`` is offline; ``health()`` performs one verified
    HTTPS GET with Basic auth; ``status()`` returns the latest health result or
    the unchecked configuration status, without I/O. Recreate to change config.
    No redirects, environment proxies, retries or unverified TLS are used.
    Trust a private CA in the platform store or via Python's SSL_CERT_FILE.

    All results contain state/configured/operational/endpoint/service_status/
    checked_at/error/missing. operational is None until a health check, then
    True only for a recognized running IDS service. This does not attest to
    IPS configuration or network protection. Credentials, response bodies and
    upstream exception messages are never returned. State is not_configured,
    invalid_configuration, configured_unchecked, operational, degraded or error.
    """

    def __init__(self, environ: Mapping[str, str] | None = None):
        env = os.environ if environ is None else environ
        names = ("OPNSENSE_URL", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET")
        raw_values = {name: env.get(name, "") for name in names}
        values = {name: value if isinstance(value, str) else ""
                  for name, value in raw_values.items()}
        self._key = values["OPNSENSE_API_KEY"]
        self._secret = values["OPNSENSE_API_SECRET"]
        self._lock = threading.Lock()
        self._last_health: dict | None = None
        missing = [name for name, value in values.items() if not value.strip()]
        endpoint, error = None, None
        if any(not isinstance(value, str) for value in raw_values.values()):
            error = "OPNsense settings must be strings."
        if values["OPNSENSE_URL"]:
            try:
                endpoint = _endpoint(values["OPNSENSE_URL"])
            except ValueError as exc:
                error = str(exc)
        if ":" in self._key or any(ord(char) < 32 or ord(char) == 127 for char in self._key + self._secret):
            error = "OPNsense API credentials have an invalid format."
        configured = not missing and error is None
        self._configuration = {
            "state": "invalid_configuration" if error else (
                "not_configured" if missing else "configured_unchecked"),
            "configured": configured, "operational": None, "endpoint": endpoint,
            "service_status": None, "checked_at": None, "error": error, "missing": missing,
        }

    def configuration_status(self) -> dict:
        return copy.deepcopy(self._configuration)

    def status(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._last_health or self._configuration)

    def health(self) -> dict:
        with self._lock:
            result = self.configuration_status()
            if not result["configured"]:
                return result
            result.update(state="error", operational=False, checked_at=now_iso())
            token = base64.b64encode((self._key + ":" + self._secret).encode("utf-8")).decode("ascii")
            request = urllib.request.Request(
                result["endpoint"], method="GET",
                headers={"Accept": "application/json", "User-Agent": USER_AGENT,
                         "Authorization": "Basic " + token},
            )
            try:
                context = ssl.create_default_context()
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}), _NoRedirect(),
                    urllib.request.HTTPSHandler(context=context),
                )
                with opener.open(request, timeout=HTTP_TIMEOUT) as response:
                    if response.status != 200:
                        raise urllib.error.HTTPError(request.full_url, response.status, "", {}, None)
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError
                data = json.loads(raw)
                service = data.get("status") if isinstance(data, dict) else None
                if service not in ("running", "stopped", "disabled"):
                    raise ValueError
                result.update(
                    state="operational" if service == "running" else "degraded",
                    operational=service == "running", service_status=service, error=None,
                )
            except urllib.error.HTTPError as exc:
                if 300 <= exc.code < 400:
                    result["error"] = "Redirect refused; configure the exact HTTPS endpoint."
                elif exc.code in (401, 403):
                    result["error"] = "OPNsense denied authentication or IDS status permission."
                else:
                    result["error"] = "OPNsense returned an unsuccessful HTTP status."
                exc.close()
            except (ssl.SSLError, urllib.error.URLError, OSError):
                result["error"] = "OPNsense connection failed; verify endpoint, trusted TLS certificate and reachability."
            except (ValueError, UnicodeError, RecursionError):
                result["error"] = "OPNsense returned an invalid or unsupported IDS status response."
            self._last_health = result
            return copy.deepcopy(result)


class BitdefenderConnector:
    """Offline setup indicator only; no Bitdefender integration is implemented.

    ``status()`` reports presence of BITDEFENDER_API_URL and BITDEFENDER_API_KEY,
    never their values. configured means only both settings are present, with
    implemented=False and operational=False even when configured. It does not
    test endpoint validity, credentials, agent installation or protection.
    """

    def __init__(self, environ: Mapping[str, str] | None = None):
        env = os.environ if environ is None else environ
        self._missing = [name for name in ("BITDEFENDER_API_URL", "BITDEFENDER_API_KEY")
                         if not isinstance(env.get(name, ""), str)
                         or not env.get(name, "").strip()]

    def status(self) -> dict:
        return {
            "state": "setup_only" if not self._missing else "not_configured",
            "configured": not self._missing, "implemented": False, "operational": False,
            "checked_at": None, "error": None, "missing": list(self._missing),
        }
