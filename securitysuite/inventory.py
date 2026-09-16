"""Explicit, bounded household IPv4 inventory; no background or automatic scans.

Only the address blocks in https://www.rfc-editor.org/rfc/rfc1918 are allowed.
Numeric ARP/neighbor cache reads and one ICMP echo per host provide discovery.
Optional TCP connects send no application data; service names are port labels,
not verified product identities. No authentication or configuration is attempted.
"""
from __future__ import annotations

import copy
import ipaddress
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from .store import now_iso

__all__ = ["NetworkInventory", "validate_scope"]

RFC1918 = tuple(ipaddress.IPv4Network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
MAX_WORKERS = 16
SCAN_TIMEOUT = 120.0
PROCESS_TIMEOUT = 2.0
CONNECT_TIMEOUT = 0.4
SERVICE_PORTS = (
    (22, "ssh"), (53, "dns"), (80, "http"), (443, "https"),
    (445, "smb"), (554, "rtsp"), (631, "ipp"), (3389, "rdp"),
)
IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"
IP_RE = re.compile(r"(?<![\w.:])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.:])")
MAC_RE = re.compile(r"(?<![\w:.-])(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}(?![\w:.-])")


def validate_scope(cidr: str) -> ipaddress.IPv4Network:
    """Accept a canonical, explicit RFC1918 IPv4 CIDR, /24 through /32.

    Bare addresses, netmask notation, host bits, IPv6 and every other address
    class are rejected with ValueError before any subprocess or socket runs.
    """
    if not isinstance(cidr, str) or not re.fullmatch(
        r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:2[4-9]|3[0-2])", cidr
    ):
        raise ValueError("Use an explicit RFC1918 IPv4 CIDR from /24 through /32.")
    try:
        network = ipaddress.IPv4Network(cidr, strict=True)
    except ValueError:
        raise ValueError("Use a canonical IPv4 network address without host bits.") from None
    if not any(network.subnet_of(block) for block in RFC1918):
        raise ValueError("Only RFC1918 private IPv4 networks are allowed.")
    return network


def _stopped(cancel: threading.Event, deadline: float) -> bool:
    return cancel.is_set() or time.monotonic() >= deadline


def _run(command: list[str], timeout: float) -> subprocess.CompletedProcess:
    options = {}
    if IS_WINDOWS:
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = subprocess.SW_HIDE
        options = {"startupinfo": startup, "creationflags": subprocess.CREATE_NO_WINDOW}
    return subprocess.run(
        command, shell=False, stdin=subprocess.DEVNULL, capture_output=True,
        text=True, errors="replace", timeout=timeout, check=False, **options,
    )


def _parse_neighbors(output: str, scope: ipaddress.IPv4Network) -> dict[str, str]:
    hosts = {str(address) for address in scope.hosts()}
    neighbors = {}
    for line in output.splitlines():
        if re.search(r"\b(?:FAILED|INCOMPLETE)\b", line, re.IGNORECASE):
            continue
        ip_match, mac_match = IP_RE.search(line), MAC_RE.search(line)
        if not ip_match or not mac_match or ip_match[0] not in hosts:
            continue
        octets = [int(value, 16) for value in re.split("[:-]", mac_match[0])]
        if not any(octets) or octets[0] & 1:
            continue
        neighbors[ip_match[0]] = ":".join(f"{value:02x}" for value in octets)
    return neighbors


def _neighbors(scope: ipaddress.IPv4Network, cancel: threading.Event,
               deadline: float) -> dict[str, str]:
    commands = [["arp", "-a"]] if IS_WINDOWS else (
        [["arp", "-an"]] if IS_MACOS else [["ip", "-4", "neigh", "show"], ["arp", "-an"]]
    )
    for command in commands:
        if _stopped(cancel, deadline):
            break
        try:
            result = _run(command, min(PROCESS_TIMEOUT, max(0.001, deadline - time.monotonic())))
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return _parse_neighbors(result.stdout, scope)
    return {}


def _ping(ip: str, timeout: float) -> bool:
    if IS_WINDOWS:
        command = ["ping", "-4", "-n", "1", "-w", "750", ip]
    else:
        command = ["ping", "-n", "-c", "1", "-W", "750" if IS_MACOS else "1", ip]
    try:
        result = _run(command, timeout)
    except subprocess.TimeoutExpired:
        return False
    if result.returncode != 0:
        return False
    # Windows can return success for an ICMP destination-unreachable reply.
    return not IS_WINDOWS or any(
        re.search(r"(?<![\d.])" + re.escape(ip) + r"(?![\d.]).*\bTTL[=:]\s*\d+", line, re.I)
        for line in result.stdout.splitlines()
    )


def _connect(ip: str, port: int, timeout: float) -> bool:
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            return connection.connect_ex((ip, port)) == 0
    except OSError:
        return False


def _probe(ip: str, services: bool, cancel: threading.Event, deadline: float) -> dict | None:
    if _stopped(cancel, deadline):
        return None
    try:
        alive = _ping(ip, min(PROCESS_TIMEOUT, max(0.001, deadline - time.monotonic())))
    except OSError:
        if not services:
            raise RuntimeError("The ping utility is unavailable.") from None
        alive = False
    found = []
    if services:
        for port, name in SERVICE_PORTS:
            if _stopped(cancel, deadline):
                break
            if _connect(ip, port, min(CONNECT_TIMEOUT, max(0.001, deadline - time.monotonic()))):
                found.append({"port": port, "name": name})
    if _stopped(cancel, deadline) or not (alive or found):
        return None
    return {"ip": ip, "hostname": "", "mac": "", "services": found, "last_seen": now_iso()}


class NetworkInventory:
    """One asynchronous, explicit scan at a time, with optional store broadcasts.

    ``status()``, ``start(cidr, services=False)`` and ``cancel()`` return detached
    dictionaries with exactly state/scope/devices/last_scan/error. States are
    idle, running, cancelling, cancelled, complete and error. Scope is a CIDR
    string or None; last_scan is the last terminal scan's ISO timestamp or None;
    error is a human-readable string or None. Invalid input raises ValueError;
    overlapping starts raise RuntimeError. Construction/status never scan.

    Devices are unique and numerically sorted by IP, with ip/hostname/mac/
    services/last_seen keys. Unknown hostname/MAC values are empty strings.
    last_seen records observation by a probe or cache read, not proof that a
    cached neighbor is currently online. Cache entries can be stale. Hostnames
    are intentionally left empty: reverse DNS cannot hold up discovery.

    A new scan replaces devices. Cancellation keeps partial results and stops
    submission immediately; terminal state follows worker cleanup (at most the
    outstanding subprocess/socket timeout). The 120-second deadline likewise
    allows bounded cleanup. At most 16 futures and 16 workers exist at once.
    A store may be None, or implement broadcast(dict); inventory_status events
    are transient snapshots at start/cancel/completion, never detection findings.
    """

    def __init__(self, store):
        self.store = store
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()
        self._state = "idle"
        self._scope: str | None = None
        self._devices: dict[str, dict] = {}
        self._last_scan: str | None = None
        self._error: str | None = None

    def status(self) -> dict:
        with self._lock:
            return {
                "state": self._state, "scope": self._scope,
                "devices": [copy.deepcopy(self._devices[ip]) for ip in sorted(
                    self._devices, key=ipaddress.IPv4Address)],
                "last_scan": self._last_scan, "error": self._error,
            }

    def _broadcast(self) -> None:
        if self.store is not None:
            try:
                self.store.broadcast({"event_type": "inventory_status", **self.status()})
            except Exception:
                pass  # A failed UI event sink must not prevent worker cleanup.

    def start(self, cidr: str, services: bool = False) -> dict:
        scope = validate_scope(cidr)
        if not isinstance(services, bool):
            raise ValueError("services must be a boolean.")
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("An inventory scan is already running or cancelling.")
            self._scope, self._devices = str(scope), {}
            self._state, self._error = "running", None
            self._cancel = threading.Event()
            self._thread = threading.Thread(
                target=self._scan, args=(scope, services, self._cancel),
                name="network-inventory", daemon=True,
            )
            self._broadcast()
            try:
                self._thread.start()
            except RuntimeError:
                self._state, self._error = "error", "Could not start the inventory worker."
                self._last_scan = now_iso()
                self._broadcast()
            return self.status()

    def cancel(self) -> dict:
        with self._lock:
            if self._state == "running":
                self._cancel.set()
                self._state = "cancelling"
                self._broadcast()
            return self.status()

    def _record(self, device: dict) -> None:
        with self._lock:
            existing = self._devices.get(device["ip"])
            if existing:
                device = {**existing, **device}
                device["mac"] = device["mac"] or existing["mac"]
            self._devices[device["ip"]] = device

    def _read_cache(self, scope, cancel, deadline) -> None:
        for ip, mac in _neighbors(scope, cancel, deadline).items():
            self._record({"ip": ip, "mac": mac, "last_seen": now_iso(), **(
                {} if ip in self._devices else {"hostname": "", "services": []}
            )})

    def _scan(self, scope, services, cancel) -> None:
        deadline = time.monotonic() + SCAN_TIMEOUT
        state, error = "complete", None
        try:
            self._read_cache(scope, cancel, deadline)
            hosts = iter(scope.hosts())
            pending = set()
            with ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="inventory-probe") as pool:
                try:
                    while not _stopped(cancel, deadline):
                        while len(pending) < MAX_WORKERS and not _stopped(cancel, deadline):
                            ip = next(hosts, None)
                            if ip is None:
                                break
                            pending.add(pool.submit(_probe, str(ip), services, cancel, deadline))
                        if not pending:
                            break
                        done, pending = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                        for future in done:
                            device = future.result()
                            if device is not None and not _stopped(cancel, deadline):
                                self._record(device)
                finally:
                    for future in pending:
                        future.cancel()
                    # Exceptions also stop active probes before the pool joins.
                    if sys.exc_info()[0] is not None:
                        cancel.set()
            if not _stopped(cancel, deadline):
                self._read_cache(scope, cancel, deadline)
            if cancel.is_set():
                state = "cancelled"
            elif time.monotonic() >= deadline:
                state, error = "error", "Inventory scan exceeded its time limit; results are partial."
        except Exception:
            state, error = "error", "Inventory scan failed; check local ping availability and permissions."
        finally:
            with self._lock:
                self._state, self._error = state, error
                self._last_scan = now_iso()
                self._broadcast()
